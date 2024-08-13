use alloc::vec::Vec;
use std::collections::BTreeMap;

#[cfg(feature = "bincode")]
use bincode::{Decode, Encode};
use bitcoin::{absolute, transaction::Version, Amount, OutPoint, Transaction, TxIn, TxOut, Txid};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{
    constants::{AUCTION_DURATION, AUCTION_EXTENSION_ON_BID, RENEWAL_INTERVAL, ROLLOUT_BATCH_SIZE},
    prepare::{
        is_magic_lock_time, AuctionedOutput, FullTxIn, PreparedTransaction, TrackableOutput, SSTXO,
    },
    script::{OpOpenContext, ScriptError, SpaceKind},
    sname::SName,
    BidPsbtReason, Covenant, FullSpaceOut, RejectReason, RevokeReason, Space, SpaceOut,
};

#[derive(Debug, Clone)]
pub struct Validator {}

#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
/// A `ValidatedTransaction` is a validated protocol transaction that is a superset of
/// a Bitcoin transaction. It includes additional metadata
/// and captures all resulting state changes.
pub struct ValidatedTransaction {
    #[cfg_attr(feature = "bincode", bincode(with_serde))]
    pub version: Version,
    /// Txid cache
    #[cfg_attr(feature = "bincode", bincode(with_serde))]
    pub txid: Txid,
    /// Block height or timestamp. Transaction cannot be included in a block until this height/time.
    #[cfg_attr(feature = "bincode", bincode(with_serde))]
    pub lock_time: absolute::LockTime,
    /// List of transaction inputs.
    #[cfg_attr(feature = "serde", serde(rename = "vin"))]
    pub input: Vec<TxInKind>,
    /// List of transaction outputs.
    #[cfg_attr(feature = "serde", serde(rename = "vout"))]
    pub output: Vec<TxOutKind>,
    /// Meta outputs are not part of the actual transaction,
    /// but they capture other state changes caused by it
    #[cfg_attr(feature = "serde", serde(rename = "vmetaout"))]
    pub meta_output: Vec<MetaOutKind>,
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
#[cfg_attr(feature = "serde", serde(untagged))]
pub enum TxInKind {
    #[cfg_attr(feature = "serde", serde(rename = "coinout"))]
    CoinIn(#[cfg_attr(feature = "bincode", bincode(with_serde))] TxIn),
    #[cfg_attr(feature = "serde", serde(rename = "spaceout"))]
    SpaceIn(SpaceIn),
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub struct SpaceIn {
    #[cfg_attr(feature = "bincode", bincode(with_serde))]
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub txin: TxIn,
    pub script_error: Option<ScriptError>,
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
#[cfg_attr(feature = "serde", serde(untagged))]
pub enum TxOutKind {
    CoinOut(#[cfg_attr(feature = "bincode", bincode(with_serde))] TxOut),
    SpaceOut(SpaceOut),
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
#[cfg_attr(feature = "serde", serde(untagged))]
pub enum MetaOutKind {
    ErrorOut(ErrorOut),
    RolloutOut(RolloutOut),
    SpaceOut(FullSpaceOut),
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub struct RolloutOut {
    #[cfg_attr(feature = "bincode", bincode(with_serde))]
    pub outpoint: OutPoint,
    #[cfg_attr(feature = "bincode", bincode(with_serde))]
    pub bid_value: Amount,

    #[cfg_attr(feature = "serde", serde(flatten))]
    pub spaceout: SpaceOut,
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
#[cfg_attr(feature = "serde", serde(tag = "action"))]
pub enum ErrorOut {
    #[cfg_attr(feature = "serde", serde(rename = "reject"))]
    Reject(RejectParams),
    #[cfg_attr(feature = "serde", serde(rename = "revoke"))]
    Revoke(RevokeParams),
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub struct RevokeParams {
    pub reason: RevokeReason,
    #[cfg_attr(feature = "serde", serde(rename = "target"))]
    pub spaceout: FullSpaceOut,
}

#[derive(Clone, Debug)]
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

    pub fn process(&self, height: u32, mut tx: PreparedTransaction) -> ValidatedTransaction {
        // Auctioned outputs could technically be spent in the same transaction
        // making the bid psbt unusable. We need to clear any spent ones
        // before proceeding with further validation
        Self::clear_auctioned_spent(&mut tx);

        let mut changeset = ValidatedTransaction {
            txid: tx.txid,
            version: tx.version,
            lock_time: tx.lock_time,
            input: Vec::with_capacity(tx.inputs.len()),
            output: tx
                .outputs
                .into_iter()
                .map(|out| TxOutKind::CoinOut(out))
                .collect(),
            meta_output: vec![],
        };

        let mut default_space_data = Vec::new();
        let mut space_data = BTreeMap::new();
        let mut reserve = false;

        for (input_index, full_txin) in tx.inputs.into_iter().enumerate() {
            match full_txin {
                FullTxIn::FullSpaceIn(spacein) => {
                    changeset.input.push(TxInKind::SpaceIn(SpaceIn {
                        txin: spacein.input.clone(),
                        script_error: None,
                    }));

                    // Process spends of existing space outputs
                    self.process_spend(
                        height,
                        tx.version.0,
                        &mut tx.auctioned_output,
                        spacein.input,
                        input_index as u32,
                        spacein.sstxo,
                        &mut changeset,
                    );

                    // Process any space scripts
                    if let Some(script) = spacein.script {
                        if script.is_err() {
                            match &mut changeset.input.last_mut().unwrap() {
                                TxInKind::CoinIn(_) => {
                                    // Do nothing
                                }
                                TxInKind::SpaceIn(spacein) => {
                                    spacein.script_error = Some(script.unwrap_err());
                                }
                            }
                        } else {
                            let mut script = script.unwrap();
                            if !script.reserve {
                                if let Some(open) = script.open {
                                    self.process_open(
                                        height,
                                        open,
                                        &mut tx.auctioned_output,
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
                FullTxIn::CoinIn(coinin) => {
                    changeset.input.push(TxInKind::CoinIn(coinin));
                }
            }
        }

        // If one of the input scripts is using reserved op codes
        // then all space outputs with the transfer covenant must be marked as reserved
        // This does not have an effect on meta outputs
        if reserve {
            for out in changeset.output.iter_mut() {
                match out {
                    TxOutKind::SpaceOut(spaceout) => {
                        if let Some(space) = spaceout.space.as_mut() {
                            if matches!(space.covenant, Covenant::Transfer { .. }) {
                                space.covenant = Covenant::Reserved
                            }
                        }
                    }
                    TxOutKind::CoinOut(_) => {
                        // do nothing
                    }
                }
            }
        }

        // Set default space data if any
        if !default_space_data.is_empty() {
            changeset.output.iter_mut().for_each(|output| match output {
                TxOutKind::SpaceOut(spaceout) => match spaceout.space.as_mut() {
                    None => {}
                    Some(space) => match &mut space.covenant {
                        Covenant::Transfer { data, .. } => {
                            *data = Some(default_space_data.clone());
                        }
                        _ => {}
                    },
                },
                _ => {}
            });
        }

        // Set space specific data
        if !space_data.is_empty() {
            for (key, value) in space_data.into_iter() {
                match changeset.output.get_mut(key as usize) {
                    None => {
                        // do nothing
                    }
                    Some(output) => match output {
                        TxOutKind::SpaceOut(spaceout) => match spaceout.space.as_mut() {
                            None => {}
                            Some(space) => match &mut space.covenant {
                                Covenant::Transfer { data, .. } => {
                                    *data = Some(value);
                                }
                                _ => {}
                            },
                        },
                        _ => {}
                    },
                }
            }
        }

        // Check if any outputs should be tracked
        if is_magic_lock_time(&changeset.lock_time) {
            for output in changeset.output.iter_mut() {
                match output {
                    TxOutKind::CoinOut(txout) => {
                        if txout.is_magic_output() {
                            *output = TxOutKind::SpaceOut(SpaceOut {
                                value: txout.value,
                                script_pubkey: txout.script_pubkey.clone(),
                                space: None,
                            })
                        }
                    }
                    _ => {}
                }
            }
        }

        changeset
    }

    pub fn rollout(
        &self,
        height: u32,
        coinbase: Transaction,
        entries: Vec<FullSpaceOut>,
    ) -> ValidatedTransaction {
        assert!(coinbase.is_coinbase(), "expected a coinbase tx");
        assert!(entries.len() <= ROLLOUT_BATCH_SIZE, "bad rollout size");

        let mut tx = ValidatedTransaction {
            version: coinbase.version,
            txid: coinbase.compute_txid(),
            lock_time: coinbase.lock_time,
            input: coinbase
                .input
                .into_iter()
                .map(|input| TxInKind::CoinIn(input))
                .collect(),
            output: coinbase
                .output
                .into_iter()
                .map(|out| TxOutKind::CoinOut(out))
                .collect(),
            meta_output: vec![],
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

            tx.meta_output.push(MetaOutKind::RolloutOut(RolloutOut {
                outpoint: entry.outpoint,
                bid_value: rollout_bid,
                spaceout: entry.spaceout,
            }));
        }

        tx
    }

    // Auctioned outputs could technically be spent in the same transaction
    // this function checks for such spends and updates the prepared tx
    // accordingly
    #[inline]
    fn clear_auctioned_spent(tx: &mut PreparedTransaction) {
        if let Some(auctioned) = tx
            .auctioned_output
            .as_ref()
            .and_then(|out| Some(out.bid_psbt.outpoint))
        {
            if tx.inputs.iter().any(|input| match input {
                FullTxIn::FullSpaceIn(prev) => prev.input.previous_output == auctioned,
                FullTxIn::CoinIn(prev) => prev.previous_output == auctioned,
            }) {
                tx.auctioned_output.as_mut().unwrap().output = None;
            }
        }
    }

    fn process_open(
        &self,
        height: u32,
        open: OpOpenContext,
        auctiond: &mut Option<AuctionedOutput>,
        changeset: &mut ValidatedTransaction,
    ) {
        let name = match open.spaceout {
            SpaceKind::ExistingSpace(mut prev) => {
                let prev_space = prev.spaceout.space.as_mut().unwrap();
                if !prev_space.is_expired(height) {
                    changeset
                        .meta_output
                        .push(MetaOutKind::ErrorOut(ErrorOut::Reject(RejectParams {
                            name: prev.spaceout.space.unwrap().name,
                            reason: RejectReason::AlreadyExists,
                        })));
                    return;
                }

                // Revoke the previously expired space
                changeset
                    .meta_output
                    .push(MetaOutKind::ErrorOut(ErrorOut::Revoke(RevokeParams {
                        spaceout: FullSpaceOut {
                            outpoint: prev.outpoint,
                            spaceout: prev.spaceout.clone(),
                        },
                        reason: RevokeReason::Expired,
                    })));
                prev.spaceout.space.unwrap().name
            }
            SpaceKind::NewSpace(name) => name,
        };

        let mut auctiond = match auctiond.take() {
            None => {
                changeset
                    .meta_output
                    .push(MetaOutKind::ErrorOut(ErrorOut::Reject(RejectParams {
                        name,
                        reason: RejectReason::BidPSBT(BidPsbtReason::Required),
                    })));
                return;
            }
            Some(auctiond) => auctiond,
        };

        if auctiond.output.is_none() {
            changeset
                .meta_output
                .push(MetaOutKind::ErrorOut(ErrorOut::Reject(RejectParams {
                    name,
                    reason: RejectReason::BidPSBT(BidPsbtReason::OutputSpent),
                })));
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
            outpoint: contract.outpoint,
            spaceout: auctioned_spaceout,
        };

        if !fullspaceout.verify_bid_sig() {
            changeset
                .meta_output
                .push(MetaOutKind::ErrorOut(ErrorOut::Reject(RejectParams {
                    name: fullspaceout.spaceout.space.unwrap().name,
                    reason: RejectReason::BidPSBT(BidPsbtReason::BadSignature),
                })));
            return;
        }

        changeset
            .meta_output
            .push(MetaOutKind::SpaceOut(fullspaceout));
    }

    /// Auctioned output may already be representing another space,
    /// so we'll need to revoke it, and then we could attach this
    /// any new space to the output
    #[inline]
    fn detach_existing_space(
        auctioned: &mut AuctionedOutput,
        changeset: &mut ValidatedTransaction,
    ) {
        if let Some(spaceout) = &auctioned.output {
            if spaceout.space.is_none() {
                return;
            }

            changeset
                .meta_output
                .push(MetaOutKind::ErrorOut(ErrorOut::Revoke(RevokeParams {
                    spaceout: FullSpaceOut {
                        outpoint: auctioned.bid_psbt.outpoint,
                        spaceout: spaceout.clone(),
                    },
                    reason: RevokeReason::BadSpend,
                })));
        }
    }

    /// All spends with an spent spaces transaction output must be
    /// marked as spent as this function only does additional processing for spends of spaces
    fn process_spend(
        &self,
        height: u32,
        tx_version: i32,
        auctioned: &mut Option<AuctionedOutput>,
        input: TxIn,
        input_index: u32,
        stxo: SSTXO,
        changeset: &mut ValidatedTransaction,
    ) {
        let spaceout = &stxo.previous_output;
        let space = match &spaceout.space {
            None => {
                // a tracked output not associated with a space
                return;
            }
            Some(space) => space,
        };

        if space.is_expired(height) {
            changeset
                .meta_output
                .push(MetaOutKind::ErrorOut(ErrorOut::Revoke(RevokeParams {
                    spaceout: FullSpaceOut {
                        outpoint: input.previous_output,
                        spaceout: spaceout.clone(),
                    },
                    reason: RevokeReason::Expired,
                })));
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
                    tx_version,
                    auctioned,
                    input,
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
                    input,
                    input_index,
                    stxo.previous_output.clone(),
                    space.data_owned(),
                    changeset,
                );
            }
            Covenant::Reserved => {
                // Treat it as a coin spend, so it remains locked in our UTXO set
                changeset.input[input_index as usize] = TxInKind::CoinIn(input);
            }
        }
    }

    fn process_bid_spend(
        &self,
        height: u32,
        tx_version: i32,
        auctioned: &mut Option<AuctionedOutput>,
        input: TxIn,
        input_index: u32,
        stxo: SSTXO,
        total_burned: Amount,
        claim_height: Option<u32>,
        changeset: &mut ValidatedTransaction,
    ) {
        let mut spaceout = stxo.previous_output;
        let space_ref = spaceout.space.as_mut().unwrap();
        // Handle bid spends
        if space_ref.is_bid_spend(tx_version, &input) {
            // Bid spends must have an auctioned output
            let auctioned_output = auctioned.take();
            if auctioned_output.is_none() {
                changeset
                    .meta_output
                    .push(MetaOutKind::ErrorOut(ErrorOut::Revoke(RevokeParams {
                        spaceout: FullSpaceOut {
                            outpoint: input.previous_output,
                            spaceout,
                        },
                        reason: RevokeReason::BidPsbt(BidPsbtReason::Required),
                    })));
                return;
            }
            let auctioned_output = auctioned_output.unwrap();
            if auctioned_output.output.is_none() {
                changeset
                    .meta_output
                    .push(MetaOutKind::ErrorOut(ErrorOut::Revoke(RevokeParams {
                        spaceout: FullSpaceOut {
                            outpoint: input.previous_output,
                            spaceout,
                        },
                        reason: RevokeReason::BidPsbt(BidPsbtReason::OutputSpent),
                    })));
                return;
            }

            if auctioned_output.bid_psbt.burn_amount == Amount::ZERO {
                changeset
                    .meta_output
                    .push(MetaOutKind::ErrorOut(ErrorOut::Revoke(RevokeParams {
                        spaceout: FullSpaceOut {
                            outpoint: input.previous_output,
                            spaceout,
                        },
                        reason: RevokeReason::BidPsbt(BidPsbtReason::LowBidAmount),
                    })));
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

            let mut fullspaceout = FullSpaceOut {
                outpoint: auctioned_output.bid_psbt.outpoint,
                spaceout: auctioned_output.output.unwrap(),
            };
            fullspaceout.spaceout.space = Some(spaceout.space.unwrap());

            if !fullspaceout.verify_bid_sig() {
                changeset
                    .meta_output
                    .push(MetaOutKind::ErrorOut(ErrorOut::Revoke(RevokeParams {
                        spaceout: fullspaceout,
                        reason: RevokeReason::BidPsbt(BidPsbtReason::BadSignature),
                    })));
                return;
            }

            changeset
                .meta_output
                .push(MetaOutKind::SpaceOut(fullspaceout));
            return;
        }

        // Handle non-bid spends:
        // Check register attempt before claim height
        if claim_height.is_none() || *claim_height.as_ref().unwrap() > height {
            changeset
                .meta_output
                .push(MetaOutKind::ErrorOut(ErrorOut::Revoke(RevokeParams {
                    spaceout: FullSpaceOut {
                        outpoint: input.previous_output,
                        spaceout,
                    },
                    reason: RevokeReason::PrematureClaim,
                })));
            return;
        }

        // Registration spend:
        self.process_transfer(height, input, input_index, spaceout, None, changeset);
    }

    fn process_transfer(
        &self,
        height: u32,
        input: TxIn,
        input_index: u32,
        spaceout: SpaceOut,
        existing_data: Option<Vec<u8>>,
        changeset: &mut ValidatedTransaction,
    ) {
        let output_index = input_index + 1;
        let output = changeset.output.get_mut(output_index as usize);
        match output {
            Some(output) => {
                let txout = match output {
                    TxOutKind::CoinOut(txout) => txout.clone(),
                    _ => {
                        changeset
                            .meta_output
                            .push(MetaOutKind::ErrorOut(ErrorOut::Revoke(RevokeParams {
                                spaceout: FullSpaceOut {
                                    outpoint: input.previous_output,
                                    spaceout,
                                },
                                reason: RevokeReason::BadSpend,
                            })));
                        return;
                    }
                };

                let mut space = spaceout.space.unwrap();
                space.covenant = Covenant::Transfer {
                    expire_height: height + RENEWAL_INTERVAL,
                    data: existing_data,
                };

                *output = TxOutKind::SpaceOut(SpaceOut {
                    value: txout.value,
                    script_pubkey: txout.script_pubkey,
                    space: Some(space),
                });
            }
            None => {
                // No corresponding output found
                changeset
                    .meta_output
                    .push(MetaOutKind::ErrorOut(ErrorOut::Revoke(RevokeParams {
                        spaceout: FullSpaceOut {
                            outpoint: input.previous_output,
                            spaceout,
                        },
                        reason: RevokeReason::BadSpend,
                    })));
            }
        };
    }
}
