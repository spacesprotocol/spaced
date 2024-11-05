use alloc::{collections::btree_map::BTreeMap, vec, vec::Vec};

#[cfg(feature = "bincode")]
use bincode::{Decode, Encode};
use bitcoin::{Amount, OutPoint, Transaction, Txid};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{
    constants::{AUCTION_DURATION, AUCTION_EXTENSION_ON_BID, RENEWAL_INTERVAL, ROLLOUT_BATCH_SIZE},
    prepare::{is_magic_lock_time, AuctionedOutput, TrackableOutput, TxContext, SSTXO},
    script::{OpOpenContext, ScriptError, SpaceKind},
    sname::SName,
    BidPsbtReason, Covenant, FullSpaceOut, RejectReason, RevokeReason, Space, SpaceOut,
};

#[derive(Debug, Clone)]
pub struct Validator {}

#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
/// A `TxChangeSet` captures all resulting state changes.
pub struct TxChangeSet {
    #[cfg_attr(feature = "bincode", bincode(with_serde))]
    pub txid: Txid,
    /// List of transaction inputs.
    pub spends: Vec<SpaceIn>,
    /// List of transaction outputs.
    pub creates: Vec<SpaceOut>,
    /// Updates to outputs that are not part of the actual transaction such as bid
    /// or "auctioned" outputs.
    pub updates: Vec<UpdateOut>,
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub struct SpaceIn {
    pub n: usize,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub script_error: Option<ScriptError>,
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case", tag = "type"))]
pub enum UpdateKind {
    Revoke(RevokeReason),
    Rollout(RolloutDetails),
    Bid,
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub struct UpdateOut {
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub kind: UpdateKind,
    pub output: FullSpaceOut,
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub struct RolloutDetails {
    #[cfg_attr(feature = "bincode", bincode(with_serde))]
    pub priority: Amount,
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub struct RevokeParams {
    pub reason: RevokeReason,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub struct RejectParams {
    #[cfg_attr(feature = "bincode", bincode(with_serde))]
    pub name: SName,
    pub reason: RejectReason,
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub struct EventOutput {
    #[cfg_attr(feature = "bincode", bincode(with_serde))]
    pub outpoint: OutPoint,
    pub spaceout: SpaceOut,
}

impl Validator {
    pub fn new() -> Validator {
        Self {}
    }

    pub fn process(&self, height: u32, tx: &Transaction, mut ctx: TxContext) -> TxChangeSet {
        // Auctioned outputs could technically be spent in the same transaction
        // making the bid psbt unusable. We need to clear any spent ones
        // before proceeding with further validation
        Self::clear_auctioned_spent(tx, &mut ctx);

        let mut changeset = TxChangeSet {
            txid: tx.compute_txid(),
            spends: vec![],
            creates: vec![],
            updates: vec![],
        };

        let mut default_space_data = Vec::new();
        let mut space_data = BTreeMap::new();
        let mut reserve = false;

        for fullspacein in ctx.inputs.into_iter() {
            changeset.spends.push(SpaceIn {
                n: fullspacein.n,
                script_error: None,
            });

            // Process spends of existing space outputs
            self.process_spend(
                height,
                tx,
                &mut ctx.auctioned_output,
                fullspacein.n,
                fullspacein.sstxo,
                &mut changeset,
            );

            // Process any space scripts
            if let Some(script) = fullspacein.script {
                if script.is_err() {
                    let last = changeset.spends.last_mut().unwrap();
                    last.script_error = Some(script.unwrap_err());
                } else {
                    let mut script = script.unwrap();
                    if !script.reserve {
                        if let Some(open) = script.open {
                            self.process_open(
                                height,
                                open,
                                &mut ctx.auctioned_output,
                                &mut changeset,
                            );
                        }
                        if let Some(data) = script.default_sdata {
                            default_space_data = data;
                        }
                        space_data.append(&mut script.sdata);
                    } else {
                        // Script uses reserved op codes
                        reserve = true;
                    }
                }
            }
        }

        // If one of the input scripts is using reserved op codes
        // then all space outputs with the transfer covenant must be marked as reserved
        // This does not have an effect on meta outputs
        if reserve {
            for out in changeset.creates.iter_mut() {
                if let Some(space) = out.space.as_mut() {
                    if matches!(space.covenant, Covenant::Transfer { .. }) {
                        space.covenant = Covenant::Reserved
                    }
                }
            }
        }

        // Set default space data if any
        if !default_space_data.is_empty() {
            changeset.creates.iter_mut().for_each(|output| {
                if let Some(space) = output.space.as_mut() {
                    match &mut space.covenant {
                        Covenant::Transfer { data, .. } => {
                            *data = Some(default_space_data.clone());
                        }
                        _ => {}
                    }
                }
            });
        }

        // Set space specific data
        if !space_data.is_empty() {
            for (key, value) in space_data.into_iter() {
                if let Some(spaceout) = changeset.creates.get_mut(key as usize) {
                    if let Some(space) = spaceout.space.as_mut() {
                        match &mut space.covenant {
                            Covenant::Transfer { data, .. } => {
                                *data = Some(value);
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        // Check if any outputs should be tracked
        if is_magic_lock_time(&tx.lock_time) {
            for (n, output) in tx.output.iter().enumerate() {
                match changeset.creates.iter().find(|x| x.n == n) {
                    None => {
                        if output.is_magic_output() {
                            changeset.creates.push(SpaceOut {
                                n,
                                value: output.value,
                                script_pubkey: output.script_pubkey.clone(),
                                space: None,
                            })
                        }
                    }
                    Some(_) => {
                        // already tracked
                    }
                }
            }
        }

        changeset
    }

    pub fn rollout(
        &self,
        height: u32,
        coinbase: &Transaction,
        entries: Vec<FullSpaceOut>,
    ) -> TxChangeSet {
        assert!(coinbase.is_coinbase(), "expected a coinbase tx");
        assert!(entries.len() <= ROLLOUT_BATCH_SIZE, "bad rollout size");

        let mut tx = TxChangeSet {
            txid: coinbase.compute_txid(),
            spends: vec![],
            creates: vec![],
            updates: vec![],
        };

        for mut entry in entries {
            let space_ref = entry.spaceout.space.as_mut().expect("space");

            let rollout_bid = match &mut space_ref.covenant {
                Covenant::Bid {
                    total_burned,
                    claim_height,
                    ..
                } => {
                    assert!(
                        claim_height.is_none(),
                        "space {} is already rolled out",
                        space_ref.name
                    );
                    *claim_height = Some(height + AUCTION_DURATION);
                    *total_burned
                }
                _ => {
                    panic!("expected a bid in the rollout");
                }
            };

            tx.updates.push(UpdateOut {
                kind: UpdateKind::Rollout(RolloutDetails {
                    priority: rollout_bid,
                }),
                output: entry,
            });
        }

        tx
    }

    // Auctioned outputs could technically be spent in the same transaction
    // this function checks for such spends and updates the prepared tx
    // accordingly
    #[inline]
    fn clear_auctioned_spent(tx: &Transaction, meta: &mut TxContext) {
        if let Some(auctioned) = meta
            .auctioned_output
            .as_ref()
            .and_then(|out| Some(out.bid_psbt.outpoint))
        {
            if tx
                .input
                .iter()
                .any(|input| input.previous_output == auctioned)
            {
                meta.auctioned_output.as_mut().unwrap().output = None;
            }
        }
    }

    fn process_open(
        &self,
        height: u32,
        open: OpOpenContext,
        auctiond: &mut Option<AuctionedOutput>,
        changeset: &mut TxChangeSet,
    ) {
        let spend_index = changeset
            .spends
            .iter()
            .position(|s| s.n == open.input_index)
            .expect("open must have an input index revealing the space in witness");

        let name = match open.spaceout {
            SpaceKind::ExistingSpace(mut prev) => {
                let prev_space = prev.spaceout.space.as_mut().unwrap();
                if !prev_space.is_expired(height) {
                    let reject = ScriptError::Reject(RejectParams {
                        name: prev.spaceout.space.unwrap().name,
                        reason: RejectReason::AlreadyExists,
                    });
                    changeset.spends[spend_index].script_error = Some(reject);
                    return;
                }

                // Revoke the previously expired space
                changeset.updates.push(UpdateOut {
                    kind: UpdateKind::Revoke(RevokeReason::Expired),
                    output: FullSpaceOut {
                        txid: prev.txid,
                        spaceout: prev.spaceout.clone(),
                    },
                });
                prev.spaceout.space.unwrap().name
            }
            SpaceKind::NewSpace(name) => name,
        };

        let mut auctiond = match auctiond.take() {
            None => {
                let reject = ScriptError::Reject(RejectParams {
                    name,
                    reason: RejectReason::BidPSBT(BidPsbtReason::Required),
                });

                changeset.spends[spend_index].script_error = Some(reject);
                return;
            }
            Some(auctiond) => auctiond,
        };

        if auctiond.output.is_none() {
            let reject = ScriptError::Reject(RejectParams {
                name,
                reason: RejectReason::BidPSBT(BidPsbtReason::OutputSpent),
            });
            changeset.spends[spend_index].script_error = Some(reject);
            return;
        }

        Self::detach_existing_space(&mut auctiond, changeset);

        let mut auctioned_spaceout = auctiond.output.unwrap();
        let contract = auctiond.bid_psbt;

        auctioned_spaceout.space = Some(Space {
            name,
            covenant: Covenant::Bid {
                burn_increment: contract.burn_amount,
                signature: contract.signature,
                total_burned: contract.burn_amount,
                claim_height: None,
            },
        });

        let fullspaceout = FullSpaceOut {
            txid: contract.outpoint.txid,
            spaceout: auctioned_spaceout,
        };

        if !fullspaceout.verify_bid_sig() {
            let reject = ScriptError::Reject(RejectParams {
                name: fullspaceout.spaceout.space.unwrap().name,
                reason: RejectReason::BidPSBT(BidPsbtReason::BadSignature),
            });
            changeset.spends[spend_index].script_error = Some(reject);
            return;
        }

        changeset.updates.push(UpdateOut {
            kind: UpdateKind::Bid,
            output: fullspaceout,
        });
    }

    /// Auctioned output may already be representing another space,
    /// so we'll need to revoke it, and then we could attach this
    /// any new space to the output
    #[inline]
    fn detach_existing_space(auctioned: &mut AuctionedOutput, changeset: &mut TxChangeSet) {
        if let Some(spaceout) = &auctioned.output {
            if spaceout.space.is_none() {
                return;
            }
            changeset.updates.push(UpdateOut {
                output: FullSpaceOut {
                    txid: auctioned.bid_psbt.outpoint.txid,
                    spaceout: spaceout.clone(),
                },
                kind: UpdateKind::Revoke(RevokeReason::BadSpend),
            });
        }
    }

    /// All spends with a spent spaces transaction output must be
    /// marked as spent as this function only does additional processing for spends of spaces
    fn process_spend(
        &self,
        height: u32,
        tx: &Transaction,
        auctioned: &mut Option<AuctionedOutput>,
        input_index: usize,
        stxo: SSTXO,
        changeset: &mut TxChangeSet,
    ) {
        let spaceout = &stxo.previous_output;
        let space = match &spaceout.space {
            None => {
                // a tracked output not associated with a space
                return;
            }
            Some(space) => space,
        };

        let input = tx.input.get(input_index).expect("input");
        if space.is_expired(height) {
            changeset.updates.push(UpdateOut {
                output: FullSpaceOut {
                    txid: input.previous_output.txid,
                    spaceout: spaceout.clone(),
                },
                kind: UpdateKind::Revoke(RevokeReason::Expired),
            });
            return;
        }

        match space.covenant {
            Covenant::Bid {
                claim_height,
                total_burned,
                ..
            } => {
                self.process_bid_spend(
                    height,
                    tx,
                    auctioned,
                    input_index,
                    stxo,
                    total_burned,
                    claim_height,
                    changeset,
                );
            }
            Covenant::Transfer { .. } => {
                self.process_transfer(
                    height,
                    tx,
                    input_index,
                    stxo.previous_output.clone(),
                    space.data_owned(),
                    changeset,
                );
            }
            Covenant::Reserved => {
                // Keep it unspent so it remains locked in our UTXO set
                if let Some(pos) = changeset.spends.iter().position(|i| i.n == input_index) {
                    changeset.spends.remove(pos);
                }
            }
        }
    }

    fn process_bid_spend(
        &self,
        height: u32,
        tx: &Transaction,
        auctioned: &mut Option<AuctionedOutput>,
        input_index: usize,
        stxo: SSTXO,
        total_burned: Amount,
        claim_height: Option<u32>,
        changeset: &mut TxChangeSet,
    ) {
        let input = tx.input.get(input_index as usize).expect("input");
        let mut spaceout = stxo.previous_output;
        let space_ref = spaceout.space.as_mut().unwrap();
        // Handle bid spends
        if space_ref.is_bid_spend(tx.version, input) {
            // Bid spends must have an auctioned output
            let auctioned_output = auctioned.take();
            if auctioned_output.is_none() {
                changeset.updates.push(UpdateOut {
                    output: FullSpaceOut {
                        txid: input.previous_output.txid,
                        spaceout,
                    },
                    kind: UpdateKind::Revoke(RevokeReason::BidPsbt(BidPsbtReason::Required)),
                });
                return;
            }
            let auctioned_output = auctioned_output.unwrap();
            if auctioned_output.output.is_none() {
                changeset.updates.push(UpdateOut {
                    output: FullSpaceOut {
                        txid: input.previous_output.txid,
                        spaceout,
                    },
                    kind: UpdateKind::Revoke(RevokeReason::BidPsbt(BidPsbtReason::OutputSpent)),
                });
                return;
            }

            if auctioned_output.bid_psbt.burn_amount == Amount::ZERO {
                changeset.updates.push(UpdateOut {
                    output: FullSpaceOut {
                        txid: input.previous_output.txid,
                        spaceout,
                    },
                    kind: UpdateKind::Revoke(RevokeReason::BidPsbt(BidPsbtReason::LowBidAmount)),
                });
                return;
            }

            let claim_height = if let Some(claim_height) = claim_height {
                // Extend auction if necessary
                let extension = height + AUCTION_EXTENSION_ON_BID;
                Some(core::cmp::max(extension, claim_height))
            } else {
                // pre-auction phase
                None
            };

            space_ref.covenant = Covenant::Bid {
                signature: auctioned_output.bid_psbt.signature,
                total_burned: total_burned + auctioned_output.bid_psbt.burn_amount,
                burn_increment: auctioned_output.bid_psbt.burn_amount,
                claim_height,
            };

            let auctioned_spaceout = auctioned_output.output.unwrap();
            assert_eq!(
                auctioned_spaceout.n,
                auctioned_output.bid_psbt.outpoint.vout as usize
            );
            let mut fullspaceout = FullSpaceOut {
                txid: auctioned_output.bid_psbt.outpoint.txid,
                spaceout: auctioned_spaceout,
            };
            fullspaceout.spaceout.space = Some(spaceout.space.unwrap());

            if !fullspaceout.verify_bid_sig() {
                changeset.updates.push(UpdateOut {
                    output: fullspaceout,
                    kind: UpdateKind::Revoke(RevokeReason::BidPsbt(BidPsbtReason::BadSignature)),
                });
                return;
            }

            changeset.updates.push(UpdateOut {
                output: fullspaceout,
                kind: UpdateKind::Bid,
            });
            return;
        }

        // Handle non-bid spends:
        // Check register attempt before claim height
        if claim_height.is_none() || *claim_height.as_ref().unwrap() > height {
            changeset.updates.push(UpdateOut {
                output: FullSpaceOut {
                    txid: input.previous_output.txid,
                    spaceout,
                },
                kind: UpdateKind::Revoke(RevokeReason::PrematureClaim),
            });
            return;
        }

        // Registration spend:
        self.process_transfer(height, tx, input_index, spaceout, None, changeset);
    }

    fn process_transfer(
        &self,
        height: u32,
        tx: &Transaction,
        input_index: usize,
        mut spaceout: SpaceOut,
        existing_data: Option<Vec<u8>>,
        changeset: &mut TxChangeSet,
    ) {
        let input = tx.input.get(input_index).expect("input");
        let output_index = input_index + 1;
        let output = tx.output.get(output_index);
        match output {
            None => {
                // No corresponding output found
                changeset.updates.push(UpdateOut {
                    output: FullSpaceOut {
                        txid: input.previous_output.txid,
                        spaceout,
                    },
                    kind: UpdateKind::Revoke(RevokeReason::BadSpend),
                });
            }
            Some(output) => {
                // check if there's an existing space output created by this transaction
                // representing another space somehow (should never be possible anyway?)
                if changeset
                    .creates
                    .iter()
                    .position(|x| x.n == input_index)
                    .is_some()
                {
                    changeset.updates.push(UpdateOut {
                        output: FullSpaceOut {
                            txid: input.previous_output.txid,
                            spaceout,
                        },
                        kind: UpdateKind::Revoke(RevokeReason::BadSpend),
                    });
                    return;
                }

                spaceout.n = output_index;
                spaceout.value = output.value;
                spaceout.script_pubkey = output.script_pubkey.clone();

                let mut space = spaceout.space.unwrap();
                space.covenant = Covenant::Transfer {
                    expire_height: height + RENEWAL_INTERVAL,
                    data: existing_data,
                };
                spaceout.space = Some(space);
                changeset.creates.push(spaceout);
            }
        }
    }
}
