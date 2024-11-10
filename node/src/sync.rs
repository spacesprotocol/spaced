use std::{net::SocketAddr, path::PathBuf, time::Duration};

use anyhow::{anyhow, Context};
use log::info;
use protocol::{
    bitcoin::{Block, BlockHash},
    constants::ChainAnchor,
    hasher::BaseHash,
};
use tokio::sync::broadcast;
use protocol::bitcoin::hashes::Hash;
use crate::{
    config::ExtendedNetwork,
    node::{BlockMeta, BlockSource, Node},
    source::{BitcoinBlockSource, BitcoinRpc, BlockEvent, BlockFetchError, BlockFetcher},
    store::LiveStore,
};

// https://internals.rust-lang.org/t/nicer-static-assertions/15986
macro_rules! const_assert {
    ($($tt:tt)*) => {
        const _: () = assert!($($tt)*);
    }
}

const COMMIT_BLOCK_INTERVAL: u32 = 36;
const_assert!(
    protocol::constants::ROLLOUT_BLOCK_INTERVAL % COMMIT_BLOCK_INTERVAL == 0,
    "commit and rollout intervals must be aligned"
);

pub struct Spaced {
    pub network: ExtendedNetwork,
    pub chain: LiveStore,
    pub block_index: Option<LiveStore>,
    pub rpc: BitcoinRpc,
    pub data_dir: PathBuf,
    pub bind: Vec<SocketAddr>,
    pub num_workers: usize,
}

impl Spaced {
    // Restores state to a valid checkpoint
    pub fn restore(&self, source: &BitcoinBlockSource) -> anyhow::Result<()> {
        let chain_iter = self.chain.store.iter();
        for (snapshot_index, snapshot) in chain_iter.enumerate() {
            let chain_snapshot = snapshot?;
            let chain_checkpoint: ChainAnchor = chain_snapshot.metadata().try_into()?;
            let required_hash = source.get_block_hash(chain_checkpoint.height)?;

            if required_hash != chain_checkpoint.hash {
                info!(
                    "Could not restore to block={} height={}",
                    chain_checkpoint.hash, chain_checkpoint.height
                );
                continue;
            }

            info!(
                "Restoring block={} height={}",
                chain_checkpoint.hash, chain_checkpoint.height
            );

            if let Some(block_index) = self.block_index.as_ref() {
                let index_snapshot = block_index.store.iter().skip(snapshot_index).next();
                if index_snapshot.is_none() {
                    return Err(anyhow!(
                        "Could not restore block index due to missing snapshot"
                    ));
                }
                let index_snapshot = index_snapshot.unwrap()?;
                let index_checkpoint: ChainAnchor = index_snapshot.metadata().try_into()?;
                if index_checkpoint != chain_checkpoint {
                    return Err(anyhow!(
                        "block index checkpoint does not match the chain's checkpoint"
                    ));
                }
                index_snapshot
                    .rollback()
                    .context("could not rollback block index snapshot")?;
            }

            chain_snapshot
                .rollback()
                .context("could not rollback chain snapshot")?;

            self.chain.state.restore(chain_checkpoint.clone());

            if let Some(block_index) = self.block_index.as_ref() {
                block_index.state.restore(chain_checkpoint)
            }
            return Ok(());
        }

        Err(anyhow!("Unable to restore to a valid state"))
    }

    pub fn save_block(
        store: LiveStore,
        block_hash: BlockHash,
        block: BlockMeta,
    ) -> anyhow::Result<()> {
        store
            .state
            .insert(BaseHash::from_slice(block_hash.as_ref()), block);
        Ok(())
    }

    pub fn handle_block(
        &mut self,
        node: &mut Node,
        id: ChainAnchor,
        block: Block,
    ) -> anyhow::Result<()> {
        let index_blocks = self.block_index.is_some();
        let block_result =
            node.apply_block(&mut self.chain, id.height, id.hash, block, index_blocks)?;

        if let Some(index) = self.block_index.as_mut() {
            if let Some(block) = block_result {
                Self::save_block(index.clone(), id.hash, block)?;
            }
        }

        if id.height % COMMIT_BLOCK_INTERVAL == 0 {
            let block_index_writer = self.block_index.clone();

            let tx = self.chain.store.write().expect("write handle");
            let state_meta = ChainAnchor {
                height: id.height,
                hash: id.hash,
            };

            self.chain.state.commit(state_meta.clone(), tx)?;
            if let Some(index) = block_index_writer {
                let tx = index.store.write().expect("write handle");
                index.state.commit(state_meta, tx)?;
            }
        }

        Ok(())
    }

    pub fn protocol_sync(
        &mut self,
        source: BitcoinBlockSource,
        shutdown: broadcast::Sender<()>,
    ) -> anyhow::Result<()> {
        let start_block: ChainAnchor = { self.chain.state.tip.read().expect("read").clone() };
        let mut node = Node::new();

        info!(
            "Start block={} height={}",
            start_block.hash, start_block.height
        );

        let (fetcher, receiver) = BlockFetcher::new(source.clone(), self.num_workers);
        fetcher.start(start_block);

        let mut shutdown_signal = shutdown.subscribe();
        loop {
            if shutdown_signal.try_recv().is_ok() {
                break;
            }
            match receiver.try_recv() {
                Ok(event) => match event {
                    BlockEvent::Block(id, block) => {
                        self.handle_block(&mut node, id, block)?;
                        info!("block={} height={}", id.hash, id.height);
                    }
                    BlockEvent::Error(e) if matches!(e, BlockFetchError::BlockMismatch) => {
                        self.restore(&source)?;
                        let new_tip = self.chain.state.tip.read().expect("read").clone();
                        fetcher.start(new_tip);
                    }
                    BlockEvent::Error(e) => return Err(e.into()),
                },
                Err(e) if matches!(e, std::sync::mpsc::TryRecvError::Empty) => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(_) => {
                    break;
                }
            }
        }

        info!("Shutting down protocol sync");
        fetcher.stop();

        Ok(())
    }

    pub async fn genesis(rpc : &BitcoinRpc, network: ExtendedNetwork) -> anyhow::Result<ChainAnchor> {

        let mut anchor = match network {
            ExtendedNetwork::Testnet => ChainAnchor::TESTNET(),
            ExtendedNetwork::Testnet4 => ChainAnchor::TESTNET4(),
            ExtendedNetwork::Regtest => ChainAnchor::REGTEST(),
            ExtendedNetwork::Mainnet => ChainAnchor::MAINNET(),
            ExtendedNetwork::MainnetAlpha => ChainAnchor::MAINNET_ALPHA(),
            _ => panic!("unsupported network"),
        };

        if anchor.hash == BlockHash::all_zeros() {
            let client = reqwest::Client::new();

            anchor.hash  = match rpc.send_json(&client, &rpc.get_block_hash(anchor.height)).await {
                Ok(hash) => hash,
                Err(e) => {
                    return Err(anyhow!("Could not retrieve activation block at height {}: {}",
                        anchor.height, e));
                }
            }
        }

        Ok(anchor)
    }
}
