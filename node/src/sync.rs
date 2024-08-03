use std::{
    collections::BTreeMap,
    convert::Into,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, RwLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, Context};
use log::info;
use protocol::{
    bitcoin::{Block, BlockHash, Transaction},
    hasher::BaseHash,
    opcodes::OP_OPEN,
    script::{SpaceInstruction, SpaceScript},
    sname::{NameLike, SName},
    Params,
};
use tokio::sync::broadcast;

use crate::{
    node::{BlockSource, Node, ValidatedBlock},
    source::{
        BitcoinBlockSource, BitcoinRpc, BlockEvent, BlockFetchError, BlockFetcher, RpcBlockId,
    },
    store::{LiveStore, StoreCheckpoint},
};
use crate::config::{ExtendedNetwork};

const COMMIT_BLOCK_INTERVAL: u32 = 36;

pub struct Spaced {
    pub network: ExtendedNetwork,
    pub mempool: Mempool,
    pub chain: LiveStore,
    pub block_index: Option<LiveStore>,
    pub params: Params,
    pub rpc: BitcoinRpc,
    pub data_dir: PathBuf,
    pub bind: Vec<SocketAddr>,
    pub tx_count: u64,
}

#[derive(Clone)]
pub struct Mempool {
    pub(crate) opens: Arc<RwLock<BTreeMap<String, MempoolTransaction>>>,
}

#[derive(Clone)]
pub struct MempoolTransaction {
    pub seen: u64,
    pub tx: Transaction,
}

impl Spaced {
    // Restores state to a valid checkpoint
    pub fn restore(&self, source: &BitcoinBlockSource) -> anyhow::Result<()> {
        let chain_iter = self.chain.store.iter();
        for (snapshot_index, snapshot) in chain_iter.enumerate() {
            let chain_snapshot = snapshot?;
            let chain_checkpoint: StoreCheckpoint = chain_snapshot.metadata().try_into()?;
            let required_hash = source.get_block_hash(chain_checkpoint.block_height)?;

            if required_hash != chain_checkpoint.block_hash {
                info!(
                    "Could not restore to block={} height={}",
                    chain_checkpoint.block_hash, chain_checkpoint.block_height
                );
                continue;
            }

            info!(
                "Restoring block={} height={}",
                chain_checkpoint.block_hash, chain_checkpoint.block_height
            );

            if let Some(block_index) = self.block_index.as_ref() {
                let index_snapshot = block_index.store.iter().skip(snapshot_index).next();
                if index_snapshot.is_none() {
                    return Err(anyhow!(
                        "Could not restore block index due to missing snapshot"
                    ));
                }
                let index_snapshot = index_snapshot.unwrap()?;
                let index_checkpoint: StoreCheckpoint = index_snapshot.metadata().try_into()?;
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
        block: ValidatedBlock,
    ) -> anyhow::Result<()> {
        store
            .state
            .insert(BaseHash::from_slice(block_hash.as_ref()), block);
        Ok(())
    }

    pub fn handle_block(
        &mut self,
        node: &mut Node,
        id: RpcBlockId,
        block: Block,
    ) -> anyhow::Result<()> {
        let index_blocks = self.block_index.is_some();

        let (block_result, tx_count) =
            node.apply_block(&mut self.chain, id.height, id.hash, block, index_blocks)?;

        if let Some(index) = self.block_index.as_mut() {
            if let Some(block) = block_result {
                Self::save_block(index.clone(), id.hash, block)?;
            }
        }

        if id.height % COMMIT_BLOCK_INTERVAL == 0 {
            let block_index_writer = self.block_index.clone();

            let tx = self.chain.store.write().expect("write handle");
            let state_meta = StoreCheckpoint {
                block_height: id.height,
                block_hash: id.hash,
                tx_count,
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
        let node_tip: StoreCheckpoint = { self.chain.state.metadata.read().expect("read").clone() };
        let mut node = Node::new(node_tip, self.params);

        let start_block = RpcBlockId {
            height: node.tip.block_height,
            hash: node.tip.block_hash,
        };
        info!(
            "Start block={} height={}",
            start_block.hash, start_block.height
        );

        let rpc = source.rpc.clone();
        let client = reqwest::blocking::Client::new();
        let (block_fetcher, receiver) = BlockFetcher::new(rpc.clone(), client.clone());

        block_fetcher.start(start_block);

        let mut shutdown_signal = shutdown.subscribe();
        loop {
            if shutdown_signal.try_recv().is_ok() {
                block_fetcher.stop();
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
                        node.tip = self.chain.state.metadata.read().expect("read").clone();
                        let block_id = RpcBlockId {
                            height: node.tip.block_height,
                            hash: node.tip.block_hash,
                        };
                        block_fetcher.start(block_id);
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
        Ok(())
    }

    pub const fn params(network: ExtendedNetwork) -> protocol::Params {
        match network {
            ExtendedNetwork::Mainnet => Self::BITCOIN,
            ExtendedNetwork::Testnet => Self::TESTNET,
            ExtendedNetwork::Testnet4 => Self::TESTNET4,
            ExtendedNetwork::Signet => Self::SIGNET,
            ExtendedNetwork::Regtest => Self::REGTEST
        }
    }

    // Mainnet not yet supported
    /// `NetworkParams` for mainnet bitcoin.
    pub const BITCOIN: protocol::Params = protocol::Params {
        activation_block: [0u8;32],
        activation_block_height: 0,
        rollout_block_interval: 144,
        rollout_batch_size: 10,
        auction_block_interval: 144 * 10,
        auction_bid_extension: 144,
        space_refresh_block_interval: 144 * 365,
    };

    /// `NetworkParams` for testnet bitcoin.
    pub const TESTNET: protocol::Params = protocol::Params {
        activation_block: [
            0xb8, 0x9d, 0xd5, 0xe4, 0x5e, 0xd7, 0x0a, 0x50,
            0x73, 0x25, 0x2e, 0x0f, 0x5f, 0xba, 0x4a, 0x9e,
            0xd2, 0x37, 0x73, 0x9d, 0x3b, 0x5a, 0x19, 0x58,
            0x1a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ],
        activation_block_height: 2865460,
        rollout_block_interval: 144,
        rollout_batch_size: 10,
        auction_block_interval: 144 * 10,
        auction_bid_extension: 144,
        space_refresh_block_interval: 144 * 365,
    };

    pub const TESTNET4: protocol::Params = protocol::Params {
        activation_block: [
            0x66, 0x02, 0x57, 0xdf, 0x48, 0xcb, 0xd5, 0x82,
            0xf0, 0xa8, 0x5d, 0x9e, 0xad, 0x85, 0x3d, 0x68,
            0x8f, 0x7a, 0x90, 0x0d, 0x56, 0x79, 0xe0, 0x63,
            0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ],
        activation_block_height: 38580,
        rollout_block_interval: 144,
        rollout_batch_size: 10,
        auction_block_interval: 144 * 10,
        auction_bid_extension: 144,
        space_refresh_block_interval: 144 * 365,
    };

    /// `NetworkParams` for signet bitcoin.
    pub const SIGNET: protocol::Params = protocol::Params {
        activation_block: [
            0xdb, 0x47, 0x46, 0xac, 0x36, 0x05, 0x02, 0x75,
            0x19, 0x88, 0x92, 0x69, 0x7f, 0xf2, 0xe5, 0x18,
            0x32, 0x2b, 0x00, 0x85, 0x6d, 0xc6, 0x55, 0x57,
            0xd1, 0x23, 0xbe, 0x22, 0x5e, 0x00, 0x00, 0x00,
        ],
        activation_block_height: 202459,
        rollout_block_interval: 144,
        rollout_batch_size: 10,
        auction_block_interval: 144 * 10,
        auction_bid_extension: 144,
        space_refresh_block_interval: 144 * 365,
    };
    /// `NetworkParams` for regtest bitcoin.
    pub const REGTEST: protocol::Params = protocol::Params {
        activation_block: [
            6, 34, 110, 70, 17, 26, 11, 89, 202, 175, 18, 96, 67,
            235, 91, 191, 40, 195, 79, 58, 94, 51, 42, 31, 199,
            178, 183, 60, 241, 136, 145, 15,
        ],
        activation_block_height: 0,
        rollout_block_interval: 144,
        rollout_batch_size: 10,
        auction_block_interval: 144 * 10,
        auction_bid_extension: 144,
        space_refresh_block_interval: 144 * 365,
    };
}

impl Mempool {
    pub fn process(&self, txs: Vec<(Transaction, u64)>) {
        for (mem, time) in txs {
            if let Some(name) = self.scan_for_opens(&mem) {
                self.opens.write().expect("write lock").insert(
                    name.to_string(),
                    MempoolTransaction {
                        seen: time,
                        tx: mem,
                    },
                );
            }
        }

        // Remove opens older than 24 hours
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_secs();

        for (key, mem) in self.opens.read().expect("read").iter() {
            if now > mem.seen && now - mem.seen > 24 * 60 * 60 {
                self.opens.write().expect("write").remove(key);
            }
        }
    }

    pub(crate) fn get_open(&self, space: &str) -> Option<MempoolTransaction> {
        self.opens
            .read()
            .expect("read")
            .get(space)
            .map(|mem| mem.clone())
    }

    /// Does not check for %100 valid opens. It's merely intended
    /// as a hint to warn users wanting to open the same auction
    /// during mempool period
    fn scan_for_opens(&self, tx: &Transaction) -> Option<SName> {
        let mut stack = Vec::new();
        for input in tx.input.iter() {
            if input.witness.tapscript().is_none() {
                continue;
            }
            let script = input.witness.tapscript().unwrap();
            let mut iter = script.space_instructions();
            while let Some(Ok(instruction)) = iter.next() {
                match instruction {
                    SpaceInstruction::PushBytes(data) => stack.push(data),
                    SpaceInstruction::Op(op) => {
                        if op.code == OP_OPEN {
                            if stack.is_empty() {
                                return None;
                            }
                            let data = stack.pop().expect("an item");
                            if data.is_empty() {
                                return None;
                            }

                            let name = SName::try_from(data[0]);
                            if name.is_ok() {
                                let name = name.unwrap();
                                if name.label_count() == 1 {
                                    return Some(name);
                                }
                            }
                            return None;
                        }
                    }
                }
            }
        }
        None
    }
}
