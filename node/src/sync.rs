use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use anyhow::{anyhow, Context};
use bdk::bitcoin::{BlockHash, Transaction};
use bdk_bitcoind_rpc::BlockEvent;
use log::{info, warn};
use tokio::sync::{broadcast};
use crate::node::{BlockSource, Node, SyncError, ValidatedBlock};
use protocol::bitcoin::{Block, Network};
use protocol::hasher::BaseHash;
use protocol::opcodes::OP_OPEN;
use protocol::Params;
use protocol::script::{SpaceInstruction, SpaceScript};
use protocol::sname::{NameLike, SName};
use crate::store::{LiveStore, StoreCheckpoint};
use crate::source::{RpcBlockchain};

const COMMIT_BLOCK_INTERVAL: u32 = 32;


pub struct Spaced {
    pub network: Network,
    pub mempool: Mempool,
    pub chain: LiveStore,
    pub block_index: Option<LiveStore>,
    pub params: Params,
    pub source: RpcBlockchain,
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
    pub fn restore(&self) -> anyhow::Result<()> {
        let chain_iter = self.chain.store.iter();
        for (snapshot_index, snapshot) in chain_iter.enumerate() {
            let chain_snapshot = snapshot?;
            let chain_checkpoint: StoreCheckpoint = chain_snapshot.metadata().try_into()?;
            let required_hash = self.source.get_block_hash(chain_checkpoint.block_height)?;

            if required_hash != chain_checkpoint.block_hash {
                info!("Could not restore to block={} height={}",
                    chain_checkpoint.block_hash,
                    chain_checkpoint.block_height
                );
                continue;
            }

            info!("Restoring block={} height={}", chain_checkpoint.block_hash, chain_checkpoint.block_height);

            if let Some(block_index) = self.block_index.as_ref() {
                let index_snapshot = block_index.store.iter()
                    .skip(snapshot_index).next();
                if index_snapshot.is_none() {
                    return Err(anyhow!("Could not restore block index due to missing snapshot"));
                }
                let index_snapshot = index_snapshot.unwrap()?;
                let index_checkpoint: StoreCheckpoint = index_snapshot.metadata().try_into()?;
                if index_checkpoint != chain_checkpoint {
                    return Err(anyhow!("block index checkpoint does not match the chain's checkpoint"));
                }
                index_snapshot.rollback().context("could not rollback index snapshot")?;
            }

            chain_snapshot.rollback().context("could not rollback chain snapshot")?;

            let mut chain_meta = self.chain.state.metadata.write()
                .map_err(|_| anyhow!("chain metadata write lock error"))?;
            *chain_meta = chain_checkpoint.clone();

            if let Some(block_index) = self.block_index.as_ref() {
                let mut index_meta = block_index.state.metadata.write().
                    map_err(|_| anyhow!("index metadata write lock error"))?;
                *index_meta = chain_checkpoint;
            }
            return Ok(());
        }

        Err(anyhow!("Unable to restore to a valid state"))
    }

    pub fn save_block(store: LiveStore, block_hash: BlockHash, block: ValidatedBlock) -> anyhow::Result<()> {
        store.state.insert(BaseHash::from_slice(block_hash.as_ref()), block);
        Ok(())
    }

    pub fn handle_block(&mut self, node: &mut Node, emission: BlockEvent<Block>) -> anyhow::Result<()> {
        let height = emission.block_height();
        let hash = emission.block_hash();

        let index_blocks = self.block_index.is_some();
        let (block_result, tx_count) = node
            .apply_block(&mut self.chain, height, hash, emission.block, index_blocks)?;


        if let Some(index) = self.block_index.as_mut() {
            if let Some(block) = block_result {
                Self::save_block(index.clone(), hash, block)?;
            }
        }

        if height % COMMIT_BLOCK_INTERVAL == 0 {
            let block_index_writer = self.block_index.clone();

            let tx = self.chain.store.write().expect("write handle");
            let state_meta = StoreCheckpoint {
                block_height: height,
                block_hash: hash,
                tx_count,
            };

            self.chain.state.commit(state_meta.clone(), tx)?;
            if let Some(index) = block_index_writer {
                let tx = index.store.write().expect("write handle");
                index.state.commit(state_meta, tx)?;
            }
        }

        info!("block={} height={}", hash, height);
        Ok(())
    }

    pub fn protocol_sync(&mut self, mut shutdown_signal: broadcast::Receiver<()>) -> anyhow::Result<()> {
        let mut sc: StoreCheckpoint = {
            self.chain.state.metadata.read().expect("read").clone()
        };

        let source = self.source.clone();
        info!("block={} height={}", sc.block_hash, sc.block_height);
        let mut node = Node::new(sc.clone(), self.params);

        let mut emitter = source.emitter(sc.to_checkpoint(), sc.block_height);
        loop {
            if shutdown_signal.try_recv().is_ok() {
                break;
            }
            match emitter.next_block()? {
                Some(block) => {
                    if let Err(e) = self.handle_block(&mut node, block) {
                        if e.downcast_ref::<SyncError>().is_some() {
                            warn!("Sync error: {}", e);
                            self.restore()?;

                            sc = {
                                self.chain.state.metadata.read().expect("read").clone()
                            };
                            emitter = source.emitter(sc.to_checkpoint(), sc.block_height);
                        }
                    }
                }
                None => {
                    // TODO: mempool check for opens
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }

        info!("Shutting down protocol sync");
        Ok(())
    }

    pub const fn params(network: protocol::bitcoin::Network) -> protocol::Params {
        let hashes = [Self::BITCOIN, Self::TESTNET, Self::SIGNET, Self::REGTEST];
        hashes[network as usize]
    }

    // Mainnet
    /// `NetworkParams` for mainnet bitcoin.
    pub const BITCOIN: protocol::Params = protocol::Params {
        activation_block: [0u8; 32],
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
            0xb8, 0x9d, 0xd5, 0xe4, 0x5e, 0xd7, 0x0a, 0x50, 0x73, 0x25, 0x2e, 0x0f, 0x5f,
            0xba, 0x4a, 0x9e, 0xd2, 0x37, 0x73, 0x9d, 0x3b, 0x5a, 0x19, 0x58, 0x1a, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        ],
        activation_block_height: 2865460,
        rollout_block_interval: 144,
        rollout_batch_size: 10,
        auction_block_interval: 144 * 10,
        auction_bid_extension: 144,
        space_refresh_block_interval: 144 * 365,
    };

    /// `NetworkParams` for signet bitcoin.
    pub const SIGNET: protocol::Params = protocol::Params {
        activation_block: [
            0xdb, 0x47, 0x46, 0xac, 0x36, 0x05, 0x02, 0x75, 0x19, 0x88, 0x92,
            0x69, 0x7f, 0xf2, 0xe5, 0x18, 0x32, 0x2b, 0x00, 0x85, 0x6d, 0xc6,
            0x55, 0x57, 0xd1, 0x23, 0xbe, 0x22, 0x5e, 0x00, 0x00, 0x00
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
            6, 34, 110, 70, 17, 26, 11, 89, 202, 175, 18, 96, 67, 235, 91, 191, 40, 195, 79, 58, 94,
            51, 42, 31, 199, 178, 183, 60, 241, 136, 145, 15,
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
                    });
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
        self.opens.read().expect("read").get(space).map(|mem| mem.clone())
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
