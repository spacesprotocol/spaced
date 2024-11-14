use alloc::vec::Vec;

use bitcoin::{
    absolute::LockTime,
    opcodes::all::OP_RETURN,
    secp256k1::{schnorr, schnorr::Signature},
    Amount, OutPoint, Transaction, TxOut,
};

use crate::{
    errors::Result,
    hasher::{KeyHasher, SpaceKey},
    script::{ScriptResult, SpaceScript},
    SpaceOut,
};

const COMPRESSED_PSBT_SIZE: usize = 65;

pub struct BidPsbt {
    pub(crate) outpoint: OutPoint,
    pub(crate) signature: Signature,
    pub(crate) burn_amount: Amount,
}

pub struct TxContext {
    pub inputs: Vec<InputContext>,
    pub auctioned_output: Option<AuctionedOutput>,
}

pub struct InputContext {
    pub n: usize,
    pub sstxo: SSTXO,
    pub script: Option<ScriptResult<SpaceScript>>,
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
    fn get_space_outpoint(&mut self, space_hash: &SpaceKey) -> Result<Option<OutPoint>>;

    fn get_spaceout(&mut self, outpoint: &OutPoint) -> Result<Option<SpaceOut>>;
}

impl TxContext {
    #[inline(always)]
    pub fn spending_spaces<T: DataSource>(src: &mut T, tx: &Transaction) -> Result<bool> {
        for input in tx.input.iter() {
            if src.get_spaceout(&input.previous_output)?.is_some() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Creates a [TxContext] from a Bitcoin [Transaction], loading all necessary data
    /// for validation from the provided data source `src`. This function executes the Space script
    /// and loads any additional context required for further validation.
    ///
    /// Returns `Some(PreparedTransaction)` if the transaction is relevant to the Spaces protocol.
    /// Returns `None` if the transaction is not relevant.
    pub fn from_tx<T: DataSource, H: KeyHasher>(
        src: &mut T,
        tx: &Transaction,
    ) -> Result<Option<TxContext>> {
        if !Self::spending_spaces(src, &tx)? {
            if is_magic_lock_time(&tx.lock_time)
                && tx.output.iter().any(|out| out.is_magic_output())
            {
                return Ok(Some(TxContext {
                    inputs: vec![],
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

        for (n, input) in tx.input.iter().enumerate() {
            let spaceout = match src.get_spaceout(&input.previous_output)? {
                None => continue,
                Some(out) => out,
            };
            let sstxo = SSTXO {
                previous_output: spaceout,
            };
            let mut spacein = InputContext {
                n,
                sstxo,
                script: None,
            };

            // Run any space scripts
            if let Some(script) = input.witness.tapscript() {
                spacein.script = SpaceScript::eval::<T, H>(src, script)?;
            }
            inputs.push(spacein)
        }

        Ok(Some(TxContext {
            inputs,
            auctioned_output,
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

pub fn is_magic_lock_time(lock_time: &LockTime) -> bool {
    if let LockTime::Seconds(s) = lock_time {
        return s.to_consensus_u32() % 1000 == 222;
    }
    false
}

impl TrackableOutput for TxOut {
    fn is_magic_output(&self) -> bool {
        is_magic_amount(self.value)
    }
}

pub fn is_magic_amount(amount: Amount) -> bool {
    amount.to_sat() % 10 == 2
}
