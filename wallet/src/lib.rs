use std::{
    collections::BTreeMap,
    fmt::Debug,
    fs,
    path::PathBuf,
    time::{Duration, SystemTime},
};

use anyhow::{anyhow, Context};
use bdk_wallet::{
    chain::{BlockId, ConfirmationTime},
    wallet::{
        coin_selection::{CoinSelectionAlgorithm, CoinSelectionResult, Error, Excess},
        tx_builder::TxOrdering,
        ChangeSet, InsertTxError,
    },
    KeychainKind, LocalOutput, SignOptions, WeightedUtxo,
};
use bincode::config;
use bitcoin::{
    absolute::{Height, LockTime},
    psbt::raw::ProprietaryKey,
    script,
    sighash::{Prevouts, SighashCache},
    taproot,
    taproot::LeafVersion,
    Amount, Block, BlockHash, FeeRate, Network, OutPoint, Psbt, Sequence, TapLeafHash,
    TapSighashType, Transaction, TxOut, Witness,
};
use protocol::{
    bitcoin::{
        constants::genesis_block,
        key::{rand, UntweakedKeypair},
        opcodes,
        taproot::{ControlBlock, TaprootBuilder},
        Address, ScriptBuf, XOnlyPublicKey,
    },
    prepare::TrackableOutput,
};
use serde::{ser::SerializeSeq, Deserialize, Deserializer, Serialize, Serializer};

use crate::{
    address::SpaceAddress,
    builder::{is_connector_dust, is_space_dust, SpacesAwareCoinSelection},
};

pub extern crate bdk_wallet;
pub extern crate bitcoin;

pub mod address;
pub mod builder;
pub mod export;

const WALLET_SPACE_MAGIC: &[u8; 12] = b"WALLET_SPACE";

pub struct SpacesWallet {
    pub config: WalletConfig,
    pub spaces: bdk_wallet::wallet::Wallet,
    pub spaces_db: bdk_file_store::Store<ChangeSet>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletInfo {
    pub label: String,
    /// Earliest block to rescan when looking for the wallet's transactions
    pub start_block: u32,
    pub tip: u32,
    pub descriptors: Vec<DescriptorInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DescriptorInfo {
    pub descriptor: String,
    pub internal: bool,
    pub spaces: bool,
}

#[derive(Debug, Clone)]
pub struct SpaceScriptSigningInfo {
    pub(crate) ctx: secp256k1::Secp256k1<secp256k1::All>,
    pub(crate) script: ScriptBuf,
    pub(crate) control_block: ControlBlock,
    pub(crate) temp_key_pair: UntweakedKeypair,
    pub(crate) tweaked_address: ScriptBuf,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DoubleUtxo {
    pub spend: FullTxOut,
    pub auction: FullTxOut,
    pub confirmed: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FullTxOut {
    pub outpoint: OutPoint,
    pub(crate) txout: TxOut,
}

pub struct WalletConfig {
    pub name: String,
    pub data_dir: PathBuf,
    pub start_block: u32,
    pub network: Network,
    pub genesis_hash: Option<BlockHash>,
    pub space_descriptors: WalletDescriptors,
}

pub struct WalletDescriptors {
    pub external: String,
    pub internal: String,
}

impl SpacesWallet {
    pub fn name(&self) -> &str {
        &self.config.name
    }

    pub fn new(config: WalletConfig) -> anyhow::Result<Self> {
        if !config.data_dir.exists() {
            fs::create_dir_all(config.data_dir.clone())?;
        }

        let spaces_path = config.data_dir.join("spaces.db");
        let mut spaces_db =
            bdk_file_store::Store::<ChangeSet>::open_or_create_new(WALLET_SPACE_MAGIC, spaces_path)
                .context("create store for spaces")?;

        let genesis_hash = match config.genesis_hash {
            None => genesis_block(config.network).block_hash(),
            Some(hash) => hash,
        };

        let spaces_changeset = spaces_db.aggregate_changesets()?;
        let spaces_wallet = bdk_wallet::wallet::Wallet::new_or_load_with_genesis_hash(
            &config.space_descriptors.external,
            &config.space_descriptors.internal,
            spaces_changeset,
            config.network,
            genesis_hash,
        )?;

        let wallet = Self {
            config,
            spaces: spaces_wallet,
            spaces_db,
        };

        wallet.clear_unused_signing_info();
        Ok(wallet)
    }

    pub fn rebuild(self) -> anyhow::Result<Self> {
        let config = self.config;
        drop(self.spaces_db);
        fs::remove_file(config.data_dir.join("spaces.db"))?;
        fs::remove_file(config.data_dir.join("coins.db"))?;
        Ok(SpacesWallet::new(config)?)
    }

    pub fn get_info(&self) -> WalletInfo {
        let mut descriptors = Vec::with_capacity(2);

        descriptors.push(DescriptorInfo {
            descriptor: self
                .spaces
                .public_descriptor(KeychainKind::External)
                .to_string(),
            internal: false,
            spaces: true,
        });
        descriptors.push(DescriptorInfo {
            descriptor: self
                .spaces
                .public_descriptor(KeychainKind::Internal)
                .to_string(),
            internal: true,
            spaces: true,
        });

        WalletInfo {
            label: self.config.name.clone(),
            start_block: self.config.start_block,
            tip: self.spaces.local_chain().tip().height(),
            descriptors,
        }
    }

    pub fn next_unused_space_address(&mut self) -> SpaceAddress {
        let info = self.spaces.next_unused_address(KeychainKind::External);
        SpaceAddress(info.address)
    }

    pub fn apply_block_connected_to(
        &mut self,
        height: u32,
        block: &Block,
        block_id: BlockId,
    ) -> anyhow::Result<()> {
        self.spaces
            .apply_block_connected_to(&block, height, block_id)?;

        Ok(())
    }

    pub fn insert_tx(
        &mut self,
        tx: Transaction,
        position: ConfirmationTime,
    ) -> Result<bool, InsertTxError> {
        self.spaces.insert_tx(tx.clone(), position)
    }

    pub fn commit(&mut self) -> anyhow::Result<()> {
        if let Some(changeset) = self.spaces.take_staged() {
            self.spaces_db.append_changeset(&changeset)?;
        }

        Ok(())
    }

    /// List outputs that can be safely auctioned off
    pub fn list_bidouts(
        &mut self,
        selection: &SpacesAwareCoinSelection,
    ) -> anyhow::Result<Vec<DoubleUtxo>> {
        let mut unspent: Vec<LocalOutput> = self.spaces.list_unspent().collect();
        let mut not_auctioned = vec![];

        if unspent.is_empty() {
            return Ok(not_auctioned);
        }

        // Sort UTXOs by transaction ID and then by output index (vout)
        // to group UTXOs from the same transaction together and in sequential order
        unspent.sort_by(|a, b| {
            a.outpoint
                .txid
                .cmp(&b.outpoint.txid)
                .then_with(|| a.outpoint.vout.cmp(&b.outpoint.vout))
        });

        // Iterate over a sliding window of 2 UTXOs at a time
        for window in unspent.windows(2) {
            let (utxo1, utxo2) = (&window[0], &window[1]);
            // Check if the UTXOs form a valid double utxo pair:
            // - Both UTXOs must be from the same transaction (matching txid)
            // - The first UTXO's vout must be even
            // - The second UTXO's vout must be the first UTXO's vout + 1
            if utxo1.outpoint.txid == utxo2.outpoint.txid
                && utxo1.outpoint.vout % 2 == 0
                && utxo1.keychain == KeychainKind::Internal
                && utxo2.outpoint.vout == utxo1.outpoint.vout + 1
                && utxo2.keychain == KeychainKind::External

                // Adding these as additional safety checks since:
                // 1. outputs less than dust threshold
                //    are protected from being spent to fund txs.
                // 2. outputs representing spaces use "space dust" values.
                //
                // All these checks are needed because we don't actaully know
                // if an unconfirmed output is a spaceout representing a space ...
                // TODO: store metadata to simplify things and make it safer to use
                && utxo1.txout.value < SpacesAwareCoinSelection::DUST_THRESHOLD
                && utxo2.txout.value < SpacesAwareCoinSelection::DUST_THRESHOLD
                && is_connector_dust(utxo1.txout.value)
                && !is_space_dust(utxo2.txout.value)
                && utxo2.txout.is_magic_output()

                // Exclude any outputs that we know to be spaces
                && !selection.exclude_outputs.iter()
                .any(|sel|
                    sel.is_space &&
                        (sel.outpoint == utxo1.outpoint || sel.outpoint == utxo2.outpoint)
                )
                // Check if confirmed only are required
                && (!selection.confirmed_only || utxo1.confirmation_time.is_confirmed())
            {
                not_auctioned.push(DoubleUtxo {
                    spend: FullTxOut {
                        outpoint: utxo1.outpoint,
                        txout: utxo1.txout.clone(),
                    },
                    auction: FullTxOut {
                        outpoint: utxo2.outpoint,
                        txout: utxo2.txout.clone(),
                    },
                    confirmed: utxo1.confirmation_time.is_confirmed(),
                });
            }
        }

        Ok(not_auctioned)
    }

    pub fn new_bid_psbt(
        &mut self,
        total_burned: Amount,
        selection: &SpacesAwareCoinSelection,
    ) -> anyhow::Result<(Psbt, DoubleUtxo)> {
        let all: Vec<_> = self.list_bidouts(selection)?;

        let msg = if selection.confirmed_only {
            "The wallet already has an unconfirmed bid for this space in the mempool, but no \
            confirmed bid utxos are available to replace it with a different amount."
        } else {
            "No bid outputs found"
        };

        let placeholder = all
            // always prefer confirmed ones since
            // we don't monitor mempool for other competing bids
            // this makes replacements smoother
            .iter()
            .find(|x| x.confirmed)
            .or_else(|| all.first())
            .ok_or_else(|| anyhow::anyhow!("{}", msg))?
            .clone();

        let refund_value = total_burned + placeholder.auction.txout.value;

        let mut bid_psbt = {
            let mut builder = self
                .spaces
                .build_tx()
                .coin_selection(RequiredUtxosOnlyCoinSelectionAlgorithm);

            builder
                .version(2)
                .allow_dust(true)
                .ordering(TxOrdering::Untouched)
                .nlocktime(LockTime::Blocks(Height::ZERO))
                .enable_rbf_with_sequence(Sequence::ENABLE_RBF_NO_LOCKTIME)
                .manually_selected_only()
                .sighash(TapSighashType::SinglePlusAnyoneCanPay.into())
                .add_utxo(placeholder.auction.outpoint)?
                .add_recipient(
                    placeholder.auction.txout.script_pubkey.clone(),
                    refund_value,
                );
            builder.finish()?
        };

        let finalized = self.spaces.sign(
            &mut bid_psbt,
            SignOptions {
                allow_all_sighashes: true,
                ..Default::default()
            },
        )?;
        if !finalized {
            return Err(anyhow::anyhow!("signing bid psbt failed"));
        }

        Ok((bid_psbt, placeholder))
    }

    pub fn compress_bid_psbt(op_return_vout: u8, psbt: &Psbt) -> anyhow::Result<[u8; 65]> {
        if psbt.inputs.len() != 1 || psbt.inputs[0].final_script_witness.is_none() {
            return Err(anyhow::anyhow!(
                "bid psbt witness stack must have exactly one input"
            ));
        }
        let witness = &psbt.inputs[0].final_script_witness.as_ref().unwrap()[0];
        if witness.len() != 65 || witness[64] != TapSighashType::SinglePlusAnyoneCanPay as u8 {
            return Err(anyhow::anyhow!(
                "bid psbt witness must be a taproot key spend with \
            sighash type SingleAnyoneCanPay"
            ));
        }

        let mut compressed = [0u8; 65];
        compressed[0] = op_return_vout;
        compressed[1..].copy_from_slice(&witness[..64]);
        Ok(compressed)
    }

    pub fn spaces_signer(key: &str) -> ProprietaryKey {
        ProprietaryKey {
            prefix: b"spaces".to_vec(),
            subtype: 0u8,
            key: key.as_bytes().to_vec(),
        }
    }

    pub fn sign(
        &mut self,
        mut psbt: Psbt,
        mut extra_prevouts: Option<BTreeMap<OutPoint, TxOut>>,
    ) -> anyhow::Result<Transaction> {
        // mark any spends needing the spaces signer to be signed later
        for (input_index, input) in psbt.inputs.iter_mut().enumerate() {
            if extra_prevouts.is_none() {
                extra_prevouts = Some(BTreeMap::new());
            }
            if input.witness_utxo.is_some() {
                extra_prevouts.as_mut().unwrap().insert(
                    psbt.unsigned_tx.input[input_index].previous_output,
                    input.witness_utxo.clone().unwrap(),
                );
            }

            if input.final_script_witness.is_none() && input.witness_utxo.is_some() {
                if self.spaces.is_mine(
                    input
                        .witness_utxo
                        .as_ref()
                        .unwrap()
                        .script_pubkey
                        .as_script(),
                ) {
                    input
                        .proprietary
                        .insert(Self::spaces_signer("tbs"), Vec::new());
                    input.final_script_witness = Some(Witness::default());
                    continue;
                }

                let signing_info =
                    self.get_signing_info(&input.witness_utxo.as_ref().unwrap().script_pubkey);
                if let Some(info) = signing_info {
                    input
                        .proprietary
                        .insert(Self::spaces_signer("reveal_signing_info"), info);
                    input.final_script_witness = Some(Witness::default());
                }
            }
        }

        for input in psbt.inputs.iter_mut() {
            if input.proprietary.contains_key(&Self::spaces_signer("tbs")) {
                // To be signed by the default spaces signer
                input.final_script_witness = None;
                input.final_script_sig = None;
            }
        }
        if !self.spaces.sign(&mut psbt, SignOptions::default())? {
            return Err(anyhow!("could not finalize psbt using spaces signer"));
        }

        let mut reveals: BTreeMap<u32, SpaceScriptSigningInfo> = BTreeMap::new();

        for (idx, input) in psbt.inputs.iter_mut().enumerate() {
            let reveal_key = Self::spaces_signer("reveal_signing_info");
            if input.proprietary.contains_key(&reveal_key) {
                let raw = input.proprietary.get(&reveal_key).expect("signing info");
                let signing_info = SpaceScriptSigningInfo::from_slice(raw.as_slice())
                    .context("expected reveal signing info")?;

                let script = input.witness_utxo.as_ref().unwrap().script_pubkey.clone();
                self.save_signing_info(script, raw.clone())?;

                reveals.insert(idx as u32, signing_info);
            }
        }

        let mut tx = psbt.extract_tx()?;
        if reveals.len() == 0 {
            return Ok(tx);
        }

        let mut prevouts = Vec::new();
        let extras = extra_prevouts.unwrap_or_else(|| BTreeMap::new());

        for input in tx.input.iter() {
            if let Some(prevout) = extras.get(&input.previous_output) {
                prevouts.push(prevout.clone());
                continue;
            }

            let space_utxo = self.spaces.get_utxo(input.previous_output);
            if let Some(space_utxo) = space_utxo {
                prevouts.push(space_utxo.txout);
                continue;
            }

            return Err(anyhow!("couldn't find txout for {}", input.previous_output));
        }

        let prevouts = Prevouts::All(&prevouts);
        let mut sighash_cache = SighashCache::new(&mut tx);

        for (reveal_idx, signing_info) in reveals {
            let sighash = sighash_cache.taproot_script_spend_signature_hash(
                reveal_idx as usize,
                &prevouts,
                TapLeafHash::from_script(&signing_info.script, LeafVersion::TapScript),
                TapSighashType::Default,
            )?;

            let msg = bitcoin::secp256k1::Message::from_digest_slice(sighash.as_ref())?;
            let signature = signing_info
                .ctx
                .sign_schnorr(&msg, &signing_info.temp_key_pair);
            let sighash_type = TapSighashType::Default;

            let witness = sighash_cache
                .witness_mut(reveal_idx as usize)
                .expect("witness should exist");
            witness.push(
                taproot::Signature {
                    signature,
                    sighash_type,
                }
                .to_vec(),
            );
            witness.push(&signing_info.script);
            witness.push(&signing_info.control_block.serialize());
        }

        Ok(tx)
    }

    fn get_signing_info(&self, script: &ScriptBuf) -> Option<Vec<u8>> {
        let script_info_dir = self.config.data_dir.join("script_solutions");
        let filename = hex::encode(script.as_bytes());
        let file_path = script_info_dir.join(filename);
        fs::read(file_path).ok()
    }

    fn save_signing_info(&self, script: ScriptBuf, raw: Vec<u8>) -> anyhow::Result<()> {
        let script_info_dir = self.config.data_dir.join("script_solutions");
        fs::create_dir_all(&script_info_dir).context("could not create script_info directory")?;
        let filename = hex::encode(script.as_bytes());
        let file_path = script_info_dir.join(filename);
        fs::write(file_path, raw)?;
        Ok(())
    }

    fn clear_unused_signing_info(&self) {
        let script_info_dir = self.config.data_dir.join("script_solutions");
        let one_week_ago = SystemTime::now() - Duration::from_secs(7 * 24 * 60 * 60);

        let entries = match fs::read_dir(&script_info_dir) {
            Ok(entries) => entries,
            Err(_) => return,
        };

        for entry in entries.flatten() {
            let metadata = match entry.metadata() {
                Ok(metadata) => metadata,
                Err(_) => continue,
            };

            let modified_time = match metadata.modified() {
                Ok(time) => time,
                Err(_) => continue,
            };

            if modified_time < one_week_ago {
                let _ = fs::remove_file(entry.path());
            }
        }
    }
}

#[derive(Debug)]
pub struct RequiredUtxosOnlyCoinSelectionAlgorithm;

impl CoinSelectionAlgorithm for RequiredUtxosOnlyCoinSelectionAlgorithm {
    fn coin_select(
        &self,
        required_utxos: Vec<WeightedUtxo>,
        _optional_utxos: Vec<WeightedUtxo>,
        _fee_rate: FeeRate,
        _target_amount: u64,
        _drain_script: &bitcoin::Script,
    ) -> Result<CoinSelectionResult, Error> {
        let utxos = required_utxos.iter().map(|w| w.utxo.clone()).collect();
        Ok(CoinSelectionResult {
            selected: utxos,
            fee_amount: 0,
            excess: Excess::NoChange {
                dust_threshold: 0,
                remaining_amount: 0,
                change_fee: 0,
            },
        })
    }
}

impl SpaceScriptSigningInfo {
    fn new(network: Network, nop_script: script::Builder) -> anyhow::Result<Self> {
        let secp256k1 = bitcoin::secp256k1::Secp256k1::new();
        let key_pair = UntweakedKeypair::new(&secp256k1, &mut rand::thread_rng());
        let (public_key, _) = XOnlyPublicKey::from_keypair(&key_pair);
        let script = nop_script
            .push_slice(&public_key.serialize())
            .push_opcode(opcodes::all::OP_CHECKSIG)
            .into_script();

        let taproot_spend_info = TaprootBuilder::new()
            .add_leaf(0, script.clone())
            .expect("failed adding leaf to taproot builder")
            .finalize(&secp256k1, public_key)
            .expect("failed finalizing taproot builder");
        let control_block = taproot_spend_info
            .control_block(&(script.clone(), LeafVersion::TapScript))
            .expect("failed computing control block");
        let tweaked_address = Address::p2tr_tweaked(taproot_spend_info.output_key(), network);

        Ok(SpaceScriptSigningInfo {
            ctx: secp256k1,
            script,
            tweaked_address: tweaked_address.script_pubkey(),
            control_block,
            temp_key_pair: key_pair,
        })
    }

    pub fn satisfaction_weight(&self) -> usize {
        // 1-byte varint(control_block)
        1 + self.control_block.size() +
            // 1-byte varint(script)
            1 + self.script.len() +
            // 1-byte varint(sig+sighash) + <sig(64)+sigHash(1)>
            1 + 65
    }

    pub(crate) fn to_vec(&self) -> Vec<u8> {
        bincode::serde::encode_to_vec(self, config::standard()).expect("signing info")
    }

    pub fn from_slice(data: &[u8]) -> anyhow::Result<Self> {
        let (de, _) = bincode::serde::decode_from_slice(data, config::standard())?;
        Ok(de)
    }
}

impl Serialize for SpaceScriptSigningInfo {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(4))?;
        seq.serialize_element(&self.script.to_bytes())?;
        seq.serialize_element(&self.tweaked_address.to_bytes())?;
        seq.serialize_element(&self.control_block.serialize())?;
        seq.serialize_element(&self.temp_key_pair.secret_bytes().to_vec())?;

        seq.end()
    }
}

impl<'de> Deserialize<'de> for SpaceScriptSigningInfo {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct OpenSigningInfoVisitor;

        impl<'de> serde::de::Visitor<'de> for OpenSigningInfoVisitor {
            type Value = SpaceScriptSigningInfo;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("OpenSigningInfo")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let script_bytes: Vec<u8> = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let address_bytes: Vec<u8> = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                let control_block_bytes: Vec<u8> = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(2, &self))?;
                let temp_key_pair_bytes: Vec<u8> = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(3, &self))?;

                let ctx = bitcoin::secp256k1::Secp256k1::new();
                let script = ScriptBuf::from_bytes(script_bytes).clone();
                let tweaked_address = ScriptBuf::from_bytes(address_bytes).clone();

                let control_block = ControlBlock::decode(control_block_bytes.as_slice())
                    .map_err(serde::de::Error::custom)?;
                let temp_key_pair =
                    UntweakedKeypair::from_seckey_slice(&ctx, temp_key_pair_bytes.as_slice())
                        .map_err(serde::de::Error::custom)?;

                Ok(SpaceScriptSigningInfo {
                    ctx,
                    script,
                    tweaked_address,
                    control_block,
                    temp_key_pair,
                })
            }
        }

        deserializer.deserialize_seq(OpenSigningInfoVisitor)
    }
}
