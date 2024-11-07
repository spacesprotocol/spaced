pub extern crate protocol;
pub extern crate spacedb;

use std::{error::Error, fmt};

use anyhow::{anyhow, Result};
use bincode::{Decode, Encode};
use protocol::{
    bitcoin::{Amount, Block, BlockHash, OutPoint},
    constants::{ChainAnchor, ROLLOUT_BATCH_SIZE, ROLLOUT_BLOCK_INTERVAL},
    hasher::{BidKey, KeyHasher, OutpointKey, SpaceKey},
    prepare::TxContext,
    sname::NameLike,
    validate::{TxChangeSet, UpdateKind, Validator},
    Covenant, FullSpaceOut, RevokeReason, SpaceOut,
};
use serde::{Deserialize, Serialize};
use wallet::bitcoin::Transaction;

use crate::{
    source::BitcoinRpcError,
    store::{ChainState, ChainStore, LiveSnapshot, LiveStore, Sha256},
};

pub trait BlockSource {
    fn get_block_hash(&self, height: u32) -> Result<BlockHash, BitcoinRpcError>;
    fn get_block(&self, hash: &BlockHash) -> Result<Block, BitcoinRpcError>;
    fn get_median_time(&self) -> Result<u64, BitcoinRpcError>;
    fn get_block_count(&self) -> Result<u64, BitcoinRpcError>;
    fn get_best_chain(&self) -> Result<ChainAnchor, BitcoinRpcError>;
}

#[derive(Debug, Clone)]
pub struct Node {
    validator: Validator,
}

/// A block structure containing validated transaction metadata
/// relevant to the Spaces protocol
#[derive(Clone, Serialize, Deserialize, Encode, Decode)]
pub struct BlockMeta {
    pub tx_meta: Vec<TxChangeSet>,
}

#[derive(Debug)]
pub struct SyncError {
    checkpoint: ChainAnchor,
    connect_to: (u32, BlockHash),
}

impl fmt::Display for SyncError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Could not connect block={}, height={} to checkpoint [block={}, height={}]",
            self.connect_to.1, self.connect_to.0, self.checkpoint.hash, self.checkpoint.height
        )
    }
}

impl Error for SyncError {}

impl Node {
    pub fn new() -> Self {
        Self {
            validator: Validator::new(),
        }
    }

    pub fn apply_block(
        &mut self,
        chain: &mut LiveStore,
        height: u32,
        block_hash: BlockHash,
        block: Block,
        get_block_data: bool,
    ) -> Result<Option<BlockMeta>> {
        {
            let tip = chain.state.tip.read().expect("read tip");
            if tip.hash != block.header.prev_blockhash || tip.height + 1 != height {
                return Err(SyncError {
                    checkpoint: tip.clone(),
                    connect_to: (height, block_hash),
                }
                .into());
            }
        }

        let mut block_data = BlockMeta { tx_meta: vec![] };

        if (height - 1) % ROLLOUT_BLOCK_INTERVAL == 0 {
            let batch = Self::get_rollout_batch(ROLLOUT_BATCH_SIZE, chain)?;
            let coinbase = block
                .coinbase()
                .expect("expected a coinbase tx to be present in the block")
                .clone();

            let validated = self.validator.rollout(height, &coinbase, batch);
            if get_block_data {
                block_data.tx_meta.push(validated.clone());
            }

            self.apply_tx(&mut chain.state, &coinbase, validated);
        }

        for tx in block.txdata {
            let prepared_tx =
                { TxContext::from_tx::<LiveSnapshot, Sha256>(&mut chain.state, &tx)? };

            if let Some(prepared_tx) = prepared_tx {
                let validated_tx = self.validator.process(height, &tx, prepared_tx);

                if get_block_data {
                    block_data.tx_meta.push(validated_tx.clone());
                }
                self.apply_tx(&mut chain.state, &tx, validated_tx);
            }
        }
        let mut tip = chain.state.tip.write().expect("write tip");
        tip.height = height;
        tip.hash = block_hash;

        if get_block_data && !block_data.tx_meta.is_empty() {
            return Ok(Some(block_data));
        }
        Ok(None)
    }

    fn apply_tx(&self, state: &mut LiveSnapshot, tx: &Transaction, changeset: TxChangeSet) {
        // Remove spends
        for spend in changeset.spends.into_iter() {
            let previous = tx.input[spend.n].previous_output;
            let spend = OutpointKey::from_outpoint::<Sha256>(previous);
            state.remove(spend);
        }

        // Apply outputs
        for create in changeset.creates.into_iter() {
            if let Some(space) = create.space.as_ref() {
                assert!(
                    !matches!(space.covenant, Covenant::Bid { .. }),
                    "bid unexpected"
                );
            }
            let outpoint = OutPoint {
                txid: changeset.txid,
                vout: create.n as u32,
            };

            // Space => Outpoint
            if let Some(space) = create.space.as_ref() {
                let space_key = SpaceKey::from(Sha256::hash(space.name.to_bytes()));
                state.insert_space(space_key, outpoint.into());
            }
            // Outpoint => SpaceOut
            let outpoint_key = OutpointKey::from_outpoint::<Sha256>(outpoint);
            state.insert_spaceout(outpoint_key, create);
        }

        // Apply meta outputs
        for update in changeset.updates {
            match update.kind {
                UpdateKind::Revoke(params) => {
                    match params {
                        RevokeReason::BidPsbt(_)
                        | RevokeReason::PrematureClaim
                        | RevokeReason::BadSpend => {
                            // Since these are caused by spends
                            // Outpoint -> Spaceout mapping is already removed,
                            let space = update.output.spaceout.space.unwrap();
                            let base_hash = Sha256::hash(space.name.to_bytes());

                            // Remove Space -> Outpoint
                            let space_key = SpaceKey::from(base_hash);
                            state.remove(space_key);

                            // Remove any bids from pre-auction pool
                            match space.covenant {
                                Covenant::Bid {
                                    total_burned,
                                    claim_height,
                                    ..
                                } => {
                                    if claim_height.is_none() {
                                        let bid_key = BidKey::from_bid(total_burned, base_hash);
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
                            let hash =
                                OutpointKey::from_outpoint::<Sha256>(update.output.outpoint());
                            state.remove(hash);
                        }
                    }
                }
                UpdateKind::Rollout(rollout) => {
                    let base_hash = Sha256::hash(
                        update
                            .output
                            .spaceout
                            .space
                            .as_ref()
                            .expect("a space in rollout")
                            .name
                            .to_bytes(),
                    );
                    let bid_key = BidKey::from_bid(rollout.priority, base_hash);

                    let outpoint_key =
                        OutpointKey::from_outpoint::<Sha256>(update.output.outpoint());

                    state.remove(bid_key);
                    state.insert_spaceout(outpoint_key, update.output.spaceout);
                }
                UpdateKind::Bid => {
                    // Only bids are expected in meta outputs
                    let base_hash = Sha256::hash(
                        update
                            .output
                            .spaceout
                            .space
                            .as_ref()
                            .expect("space")
                            .name
                            .to_bytes(),
                    );

                    let (bid_value, previous_bid) = unwrap_bid_value(&update.output.spaceout);

                    let bid_hash = BidKey::from_bid(bid_value, base_hash);
                    let space_key = SpaceKey::from(base_hash);

                    match update
                        .output
                        .spaceout
                        .space
                        .as_ref()
                        .expect("space")
                        .covenant
                    {
                        Covenant::Bid { claim_height, .. } => {
                            if claim_height.is_none() {
                                let prev_bid_hash = BidKey::from_bid(previous_bid, base_hash);
                                state.update_bid(Some(prev_bid_hash), bid_hash, space_key);
                            }
                        }
                        _ => panic!("expected bid"),
                    }

                    let carried_outpoint = update.output.outpoint();
                    state.insert_space(space_key, carried_outpoint.into());

                    let outpoint_key = OutpointKey::from_outpoint::<Sha256>(carried_outpoint);
                    state.insert_spaceout(outpoint_key, update.output.spaceout);
                }
            }
        }
    }

    fn get_rollout_batch(size: usize, chain: &mut LiveStore) -> Result<Vec<FullSpaceOut>> {
        let (iter, snapshot) = chain.store.rollout_iter()?;
        assert_eq!(
            snapshot.metadata(),
            chain.state.inner()?.metadata(),
            "rollout snapshots don't match"
        );
        assert!(!chain.state.is_dirty(), "rollout must begin on clean state");

        let mut spaceouts = Vec::with_capacity(size);

        for element in iter.take(size) {
            let (_, raw_hash) = element?;
            let mut hash = [0u8; 32];
            hash.copy_from_slice(raw_hash.as_slice());

            let space_hash = SpaceKey::from_raw(hash)?;
            let full = chain.state.get_space_info(&space_hash)?;

            if let Some(full) = full {
                match full.spaceout.space.as_ref().unwrap().covenant {
                    Covenant::Bid { .. } => {}
                    _ => return Err(anyhow!("expected spaceouts with bid covenants")),
                }
                spaceouts.push(full);
            }
        }

        Ok(spaceouts)
    }
}

fn unwrap_bid_value(spaceout: &SpaceOut) -> (Amount, Amount) {
    if let Covenant::Bid {
        total_burned,
        burn_increment: value,
        ..
    } = spaceout
        .space
        .as_ref()
        .expect("space associated with this spaceout")
        .covenant
    {
        return (total_burned, total_burned - value);
    }
    panic!("expected a bid covenant")
}
