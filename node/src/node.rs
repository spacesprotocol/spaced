pub extern crate spacedb;
pub extern crate protocol;

use std::error::Error;
use std::fmt;
use protocol::{Covenant, FullSpaceOut, Params, RevokeReason, SpaceOut};
use protocol::validate::{ErrorOut, MetaOutKind, TxInKind, TxOutKind, ValidatedTransaction, Validator};
use anyhow::{anyhow, Result};
use bincode::{Decode, Encode};
use serde::{Deserialize, Serialize};
use protocol::bitcoin::{Amount, Block, BlockHash, OutPoint};
use protocol::hasher::{BidHash, KeyHasher, OutpointHash, SpaceHash};
use protocol::prepare::PreparedTransaction;
use crate::store::{ChainState, ChainStore, LiveSnapshot, LiveStore, Sha256, StoreCheckpoint};
use protocol::sname::{NameLike};

pub trait BlockSource {
    fn get_block_hash(&self, height: u32) -> Result<BlockHash>;
    fn get_block(&self, hash: &BlockHash) -> Result<Block>;
    fn get_median_time(&self) -> anyhow::Result<u64>;
    fn get_block_count(&self) -> Result<u64>;
}

#[derive(Debug, Clone)]
pub struct Node {
    tip: StoreCheckpoint,
    params: Params,
    validator: Validator,
}

/// A block structure containing validated transactions
/// relevant to the Spaces protocol
#[derive(Clone, Serialize, Deserialize, Encode, Decode)]
pub struct ValidatedBlock {
    tx_data: Vec<ValidatedTransaction>,
}

#[derive(Debug)]
pub struct SyncError {
    checkpoint: StoreCheckpoint,
    connect_to: (u32, BlockHash),
}

impl fmt::Display for SyncError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Could not connect block={}, height={} to checkpoint [block={}, height{}]",
            self.connect_to.1, self.connect_to.0, self.checkpoint.block_hash, self.checkpoint.block_height
        )
    }
}

impl Error for SyncError {}

impl Node {
    pub fn new(tip: StoreCheckpoint, params: Params) -> Self {
        Self {
            validator: Validator::new(params),
            params,
            tip,
        }
    }

    pub fn apply_block(
        &mut self,
        chain: &mut LiveStore,
        height: u32,
        block_hash: BlockHash,
        block: Block,
        get_block_data: bool,
    ) -> Result<(Option<ValidatedBlock>, u64)> {
        if self.tip.block_hash != block.header.prev_blockhash || self.tip.block_height + 1 != height {
            return Err(SyncError {
                checkpoint: self.tip.clone(),
                connect_to: (height, block_hash),
            }.into());
        }
        let mut tx_count = 0;

        let mut block_data = ValidatedBlock {
            tx_data: vec![],
        };

        let rollout = (height - 1) % self.params.rollout_block_interval as u32 == 0;
        if rollout {
            let batch = Self::get_rollout_batch(self.params.rollout_batch_size as usize, chain)?;
            let coinbase = block.coinbase()
                .expect("expected a coinbase tx to be present in the block").clone();

            let validated = self.validator.rollout(height, coinbase, batch);
            if get_block_data {
                block_data.tx_data.push(validated.clone());
            }

            self.apply_tx(&mut chain.state, validated);
        }

        for tx in block.txdata {
            let prepared_tx = {
                PreparedTransaction::from_tx::<LiveSnapshot, Sha256>(&mut chain.state, tx)?
            };

            if let Some(prepared_tx) = prepared_tx {
                let validated_tx = self.validator.process(height, prepared_tx);
                if get_block_data {
                    block_data.tx_data.push(validated_tx.clone());
                }
                self.apply_tx(&mut chain.state, validated_tx);
                tx_count += 1;
            }
        }

        self.tip = StoreCheckpoint {
            block_height: height,
            block_hash,
            tx_count,
        };

        if get_block_data && !block_data.tx_data.is_empty() {
            return Ok((Some(block_data), tx_count));
        }
        Ok((None, tx_count))
    }

    fn apply_tx(&self, state: &mut LiveSnapshot, changeset: ValidatedTransaction) {
        // Remove spends
        for input in changeset.input {
            match input {
                TxInKind::CoinIn(_) => {
                    // not relevant to spaces
                }
                TxInKind::SpaceIn(spacein) => {
                    // remove spend
                    let spend = OutpointHash::from_outpoint::<Sha256>
                        (spacein.txin.previous_output);
                    state.remove(spend);
                }
            }
        }

        // Apply outputs
        for (index, output) in changeset.output.into_iter().enumerate() {
            match output {
                TxOutKind::CoinOut(_) => {
                    // not relevant to spaces
                }
                TxOutKind::SpaceOut(spaceout) => {
                    if let Some(space) = spaceout.space.as_ref() {
                        assert!(!matches!(space.covenant, Covenant::Bid { .. }), "bid unexpected");
                    }
                    let outpoint = OutPoint {
                        txid: changeset.txid,
                        vout: index as u32,
                    };

                    // Space => Outpoint
                    if let Some(space) = spaceout.space.as_ref() {
                        let space_key = SpaceHash::from(
                            Sha256::hash(space.name.to_bytes())
                        );
                        state.insert_space(space_key, outpoint.into());
                    }
                    // Outpoint => SpaceOut
                    let outpoint_key = OutpointHash::from_outpoint::<Sha256>
                        (outpoint);
                    state.insert_spaceout(outpoint_key, spaceout);
                }
            }
        }

        // Apply meta outputs
        for meta_output in changeset.meta_output {
            match meta_output {
                MetaOutKind::ErrorOut(errrout) => {
                    match errrout {
                        ErrorOut::Reject(_) => {
                            // no state changes as it doesn't
                            // modify any existing spaces
                        }
                        ErrorOut::Revoke(params) => {
                            match params.reason {
                                RevokeReason::BidPsbt(_) |
                                RevokeReason::PrematureClaim |
                                RevokeReason::BadSpend => {
                                    // Since these are caused by spends
                                    // Outpoint -> Spaceout mapping is already removed,
                                    let space = params.spaceout.spaceout.space.unwrap();
                                    let base_hash = Sha256::hash(space.name.to_bytes());

                                    // Remove Space -> Outpoint
                                    let space_key = SpaceHash::from(base_hash);
                                    state.remove(space_key);

                                    // Remove any bids from pre-auction pool
                                    match space.covenant {
                                        Covenant::Bid { total_burned,
                                            claim_height, .. } => {
                                            if claim_height.is_none() {
                                                let bid_key =
                                                    BidHash::from_bid(total_burned, base_hash);
                                                state.remove(bid_key);
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                                RevokeReason::Expired => {
                                    // Space => Outpoint mapping will be removed
                                    // since this type of revocation only happens when an
                                    // expired space is being re-opened for auction.
                                    // No bids here so only remove Outpoint -> Spaceout
                                    let hash = OutpointHash::from_outpoint::<Sha256>
                                        (params.spaceout.outpoint);
                                    state.remove(hash);
                                }
                            }
                        }
                    }
                }
                MetaOutKind::RolloutOut(rollout) => {
                    let base_hash = Sha256::hash(rollout.spaceout.space
                        .as_ref().expect("a space in rollout").name.to_bytes());
                    let bid_key = BidHash::from_bid(rollout.bid_value, base_hash);

                    let outpoint_key = OutpointHash::from_outpoint::<Sha256>
                        (rollout.outpoint);

                    state.remove(bid_key);
                    state.insert_spaceout(outpoint_key, rollout.spaceout);
                }
                MetaOutKind::SpaceOut(carried) => {
                    // Only bids are expected in meta outputs
                    let base_hash = Sha256::hash(carried.spaceout.
                        space.as_ref().expect("space").name.to_bytes());

                    let (bid_value, previous_bid) = unwrap_bid_value(&carried.spaceout);

                    let bid_hash = BidHash::from_bid(bid_value, base_hash);
                    let space_key = SpaceHash::from(base_hash);

                    match carried.spaceout.space.as_ref().expect("space").covenant {
                        Covenant::Bid { claim_height, .. } => {
                            if claim_height.is_none() {
                                let prev_bid_hash = BidHash::from_bid(previous_bid, base_hash);
                                state.update_bid(Some(prev_bid_hash), bid_hash, space_key);
                            }
                        }
                        _ => panic!("expected bid")
                    }

                    state.insert_space(space_key, carried.outpoint.into());

                    let outpoint_key = OutpointHash::from_outpoint::<Sha256>(carried.outpoint);
                    state.insert_spaceout(outpoint_key, carried.spaceout);
                }
            }
        }
    }

    fn get_rollout_batch(size: usize, chain: &mut LiveStore) -> Result<Vec<FullSpaceOut>> {
        let (iter, snapshot) = chain.store.rollout_iter()?;
        assert_eq!(snapshot.metadata(), chain.state.inner()?.metadata(), "rollout snapshots don't match");
        assert!(!chain.state.is_dirty(), "rollout must begin on clean state");

        let mut spaceouts = Vec::with_capacity(size);

        for element in iter.take(size) {
            let (_, raw_hash) = element?;
            let mut hash = [0u8; 32];
            hash.copy_from_slice(raw_hash.as_slice());

            let space_hash = SpaceHash::from_raw(hash)?;
            let full = chain.state.get_space_info(&space_hash)?;

            if let Some(full) = full {
                match full.spaceout.space.as_ref().unwrap().covenant {
                    Covenant::Bid { .. } => {}
                    _ => return Err(anyhow!("expected spaceouts with bid covenants"))
                }
                spaceouts.push(full);
            }
        }

        Ok(spaceouts)
    }
}

fn unwrap_bid_value(spaceout: &SpaceOut) -> (Amount, Amount) {
    if let Covenant::Bid { total_burned, burn_increment: value, .. } =
        spaceout.space.as_ref().expect("space associated with this spaceout").covenant {
        return (total_burned, total_burned - value);
    }
    panic!("expected a bid covenant")
}
