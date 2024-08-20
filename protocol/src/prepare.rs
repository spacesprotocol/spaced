use alloc::vec::Vec;

use bitcoin::{
    absolute::LockTime,
    opcodes::all::OP_RETURN,
    secp256k1::{schnorr, schnorr::Signature},
    transaction::Version,
    Amount, OutPoint, Transaction, TxIn, TxOut, Txid,
};

use crate::{
    errors::Result,
    hasher::{KeyHasher, SpaceHash},
    script::{ScriptMachine, ScriptResult},
    SpaceOut,
};

const COMPRESSED_PSBT_SIZE: usize = 65;

pub struct BidPsbt {
    pub(crate) outpoint: OutPoint,
    pub(crate) signature: Signature,
    pub(crate) burn_amount: Amount,
}

/// A subset of a Bitcoin transaction relevant to the Spaces protocol
/// along with all the data necessary to validate it.
pub struct PreparedTransaction {
    pub version: Version,

    pub lock_time: LockTime,

    /// The Bitcoin transaction id
    pub txid: Txid,

    /// List of transaction inputs
    pub inputs: Vec<FullTxIn>,

    /// List of transaction outputs
    pub outputs: Vec<TxOut>,

    pub auctioned_output: Option<AuctionedOutput>,
}

pub enum FullTxIn {
    FullSpaceIn(FullSpaceIn),
    CoinIn(TxIn),
}

pub struct FullSpaceIn {
    pub input: TxIn,
    pub sstxo: SSTXO,
    pub script: Option<ScriptResult<ScriptMachine>>,
}

/// Spent Spaces Transaction Output
pub struct SSTXO {
    pub previous_output: SpaceOut,
}

// An output being carried in an OP_RETURN that must be unspent
pub struct AuctionedOutput {
    pub output: Option<SpaceOut>,

    /// The bid contract found in the OP_RETURN
    pub bid_psbt: BidPsbt,
}

pub trait DataSource {
    fn get_space_outpoint(
        &mut self,
        space_hash: &SpaceHash,
    ) -> crate::errors::Result<Option<OutPoint>>;

    fn get_spaceout(&mut self, outpoint: &OutPoint) -> crate::errors::Result<Option<SpaceOut>>;
}

impl PreparedTransaction {
    #[inline(always)]
    pub fn spending_space_in<T: DataSource>(src: &mut T, tx: &Transaction) -> Result<bool> {
        for input in tx.input.iter() {
            if src.get_spaceout(&input.previous_output)?.is_some() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Creates a [PreparedTransaction] from a Bitcoin [Transaction], loading all necessary data
    /// for validation from the provided data source `src`. This function executes the Space script
    /// and loads any additional context required for further validation.
    ///
    /// Key behaviors and assumptions:
    ///
    /// 1. OP_RETURN Priority:
    ///    - The OP_RETURN at index 0 is assumed to carry the bid PSBT.
    ///    - This PSBT is consumed by either an input spending a Space UTXO or an OP_OPEN revealed
    ///      in the input witness. If both are present in the same input, the spend takes priority.
    ///
    /// 2. Multiple Space Scripts:
    ///    - If Space scripts are revealed in multiple inputs, they are executed in input order.
    ///    - Execution stops at the first error encountered in a script but has no effect on other
    ///      scripts in the transaction.
    ///
    /// Returns `Some(PreparedTransaction)` if the transaction is relevant to the Spaces protocol.
    /// Returns `None` if the transaction is not relevant.
    pub fn from_tx<T: DataSource, H: KeyHasher>(
        src: &mut T,
        tx: Transaction,
    ) -> Result<Option<PreparedTransaction>> {
        if !Self::spending_space_in(src, &tx)? {
            if tx.is_magic_output() {
                return Ok(Some(PreparedTransaction {
                    version: tx.version,
                    lock_time: tx.lock_time,
                    txid: tx.compute_txid(),
                    inputs: tx
                        .input
                        .into_iter()
                        .map(|input| FullTxIn::CoinIn(input))
                        .collect(),
                    outputs: tx.output,
                    // even if such an output exists, it can be ignored
                    // as there's no spends of existing space outputs
                    auctioned_output: None,
                }));
            }
            return Ok(None);
        }

        let mut inputs = Vec::with_capacity(tx.input.len());
        let auctioned_output = match Self::get_bid_psbt(&tx) {
            None => None,
            Some(out) => Some(AuctionedOutput {
                output: src.get_spaceout(&out.outpoint)?,
                bid_psbt: out,
            }),
        };

        let txid = tx.compute_txid();
        for input in tx.input.into_iter() {
            let spaceout = match src.get_spaceout(&input.previous_output)? {
                None => {
                    inputs.push(FullTxIn::CoinIn(input));
                    continue;
                }
                Some(out) => out,
            };

            let sstxo = SSTXO {
                previous_output: spaceout,
            };

            let mut spacein = FullSpaceIn {
                input,
                sstxo,
                script: None,
            };

            // Run any space scripts
            if let Some(script) = spacein.input.witness.tapscript() {
                spacein.script = Some(ScriptMachine::execute::<T, H>(src, script)?);
            }
            inputs.push(FullTxIn::FullSpaceIn(spacein))
        }

        Ok(Some(PreparedTransaction {
            version: tx.version,
            lock_time: tx.lock_time,
            txid,
            inputs,
            outputs: tx.output,
            auctioned_output: auctioned_output,
        }))
    }

    /// Carried PSBT must be the first output in a transaction
    fn get_bid_psbt(tx: &Transaction) -> Option<BidPsbt> {
        if tx.input.is_empty() || tx.output.is_empty() || !tx.output[0].script_pubkey.is_op_return()
        {
            return None;
        }

        let cpsbt = match Self::cpsbt_from_script(tx.output[0].script_pubkey.as_bytes()) {
            None => return None,
            Some(c) => c,
        };

        let bid = BidPsbt {
            outpoint: OutPoint {
                txid: tx.input[0].previous_output.txid,
                vout: cpsbt.vout as u32,
            },
            signature: cpsbt.signature,
            burn_amount: tx.output[0].value,
        };
        Some(bid)
    }

    fn cpsbt_from_script(script: &[u8]) -> Option<CPsbt> {
        if script.len() != COMPRESSED_PSBT_SIZE + 2
        /* 1-byte OP_RETURN + 1-byte len */
        {
            return None;
        }
        if script[0] != OP_RETURN.to_u8() {
            return None;
        }

        let script_ref: &[u8] = script.as_ref();
        let cpsbt: &[u8] = &script_ref[2..];

        let cpsbt = CPsbt {
            vout: cpsbt[0],
            signature: match schnorr::Signature::from_slice(&cpsbt[1..]) {
                Ok(sig) => sig,
                Err(_) => return None,
            },
        };
        Some(cpsbt)
    }
}

pub struct CPsbt {
    pub vout: u8,
    pub signature: schnorr::Signature,
}

pub trait TrackableOutput {
    fn is_magic_output(&self) -> bool;
}

impl TrackableOutput for Transaction {
    fn is_magic_output(&self) -> bool {
        if is_magic_lock_time(&self.lock_time) {
            return self.output.iter().any(|out| out.is_magic_output());
        }
        false
    }
}

pub fn is_magic_lock_time(lock_time: &LockTime) -> bool {
    if let LockTime::Seconds(s) = lock_time {
        return s.to_consensus_u32() % 1000 == 222;
    }
    false
}

impl TrackableOutput for TxOut {
    fn is_magic_output(&self) -> bool {
        self.value.to_sat() % 10 == 2
    }
}
