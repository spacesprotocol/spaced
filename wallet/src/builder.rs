use std::{
    cmp::min,
    collections::BTreeMap,
    default::Default,
    ops::{Add, Mul},
    str::FromStr,
};

use anyhow::{anyhow, Context};
use bdk_wallet::{
    wallet::{
        coin_selection::{
            CoinSelectionAlgorithm, CoinSelectionResult, DefaultCoinSelectionAlgorithm, Error,
        },
        tx_builder::TxOrdering,
    },
    KeychainKind, TxBuilder, WeightedUtxo,
};
use bitcoin::{
    absolute::LockTime, psbt, psbt::Input, script, script::PushBytesBuf, Address, Amount, FeeRate,
    Network, OutPoint, Psbt, Script, ScriptBuf, Sequence, Transaction, TxOut, Txid, Witness,
};
use protocol::{
    bitcoin::absolute::Height,
    constants::{BID_PSBT_INPUT_SEQUENCE, BID_PSBT_TX_VERSION},
    script::SpaceScript,
    Covenant, FullSpaceOut, Space,
};
use serde::{Deserialize, Serialize};

use crate::{address::SpaceAddress, DoubleUtxo, FullTxOut, SpaceScriptSigningInfo, SpacesWallet};

#[derive(Debug, Clone)]
pub struct Builder {
    /// The requests to bundle into transactions
    requests: Vec<StackRequest>,

    /// The fee rate
    fee_rate: Option<FeeRate>,

    /// Outputs that can be auctioned off during the bidding process
    /// If not specified it will create the minimum number of auction
    /// outputs needed to fulfill the given requests
    auction_outputs: Option<u8>,

    /// Whether to allow invalid transactions
    /// e.g. opens for name that already exist ... etc.
    /// enable only for testing purposes!
    force: bool,
}

pub struct BuilderIterator<'a> {
    stack: Vec<StackOp>,
    fee_rate: FeeRate,
    dust: Option<Amount>,
    pub wallet: &'a mut SpacesWallet,
    force: bool,
    median_time: u64,
    coin_selection: SpacesAwareCoinSelection,
}

pub enum BuilderStack {
    Request(StackRequest),
    CommitInfo((SpaceScriptSigningInfo, TxOut)),
}

#[derive(Debug, Clone)]
pub struct DoubleOutput {
    pub txid: Txid,
    pub connecting_vout: (u32, TxOut),
    pub auctioned_vout: (u32, TxOut),
}

#[derive(Debug, Clone)]
pub enum StackRequest {
    Open(OpenRequest),
    Bid(BidRequest),
    Register(RegisterRequest),
    Transfer(TransferRequest),
    Execute(ExecuteRequest),
}

pub enum StackOp {
    Prepare(CreateParams),
    Open(OpenParams),
    Bid(BidRequest),
    Execute(ExecuteParams),
}

pub struct SpaceScriptRevealParams {
    signing: SpaceScriptSigningInfo,
    commitment: FullTxOut,
}

pub struct OpenParams {
    reveals: Vec<SpaceScriptRevealParams>,
    amount: Amount,
}

pub struct ExecuteParams {
    reveal: SpaceScriptRevealParams,
    context: Vec<SpaceTransfer>,
}

#[derive(Debug, Clone)]
pub struct RegisterRequest {
    pub space: FullSpaceOut,
    pub to: Option<SpaceAddress>,
}

#[derive(Debug, Clone)]
pub enum TransferRequest {
    Space(SpaceTransfer),
    Coin(CoinTransfer),
}

#[derive(Debug, Clone)]
pub struct SpaceTransfer {
    pub space: FullSpaceOut,
    pub recipient: Address,
}

#[derive(Debug, Clone)]
pub struct CoinTransfer {
    pub amount: Amount,
    pub recipient: Address,
}

#[derive(Debug, Clone)]
pub struct ExecuteRequest {
    pub context: Vec<SpaceTransfer>,
    pub script: script::Builder,
}

pub struct CreateParams {
    opens: Vec<OpenRequest>,
    executes: Vec<ExecuteRequest>,
    transfers: Vec<TransferRequest>,
    auction_outputs: Option<u8>,
}

#[derive(Clone, Debug)]
pub struct OpenRequest {
    name: String,
    initial_amount: Amount,
}

#[derive(Clone, Debug)]
pub struct BidRequest {
    space: FullSpaceOut,
    amount: Amount,
}

trait TxBuilderSpacesUtils<'a, Cs: CoinSelectionAlgorithm> {
    fn add_refund(&mut self, info: &FullSpaceOut) -> anyhow::Result<&mut Self>;
    fn add_bid(
        &mut self,
        prev_space: Option<&Space>,
        offer: Psbt,
        placeholder: DoubleUtxo,
        amount: Amount,
        allow_unsafe: bool,
    ) -> anyhow::Result<&mut Self>;

    fn add_reveal(
        &mut self,
        commitment: FullTxOut,
        signing: SpaceScriptSigningInfo,
    ) -> anyhow::Result<&mut Self>;

    fn add_transfer(&mut self, request: TransferRequest) -> anyhow::Result<&mut Self>;
}

impl<'a, Cs: CoinSelectionAlgorithm> TxBuilderSpacesUtils<'a, Cs> for TxBuilder<'a, Cs> {
    fn add_refund(&mut self, info: &FullSpaceOut) -> anyhow::Result<&mut Self> {
        let (input, txout) = match info.refund_psbt_data() {
            None => return Err(anyhow!("expected a space in the bidding process")),
            Some(out) => out,
        };

        let tap_key_spend_weight = 66;
        self.version(BID_PSBT_TX_VERSION.0);
        self.add_foreign_utxo_with_sequence(
            info.outpoint(),
            input,
            tap_key_spend_weight,
            BID_PSBT_INPUT_SEQUENCE,
        )?;
        self.add_recipient(txout.script_pubkey, txout.value);

        Ok(self)
    }

    fn add_bid(
        &mut self,
        prev_space: Option<&Space>,
        offer: Psbt,
        placeholder: DoubleUtxo,
        amount: Amount,
        force: bool,
    ) -> anyhow::Result<&mut Self> {
        let burn_amount = match prev_space {
            None => amount,
            Some(space) => match &space.covenant {
                Covenant::Bid { total_burned, .. } => {
                    let min_bid = if force {
                        *total_burned
                    } else {
                        total_burned.add(Amount::from_sat(1))
                    };
                    if amount < min_bid {
                        return Err(anyhow!("Minimum bid is {} sats", min_bid.to_sat()));
                    }
                    amount - *total_burned
                }
                _ => return Err(anyhow!("Space not in auction")),
            },
        };

        let mut spend_input = psbt::Input {
            witness_utxo: Some(placeholder.spend.txout.clone()),
            final_script_witness: Some(Witness::default()),
            final_script_sig: Some(ScriptBuf::new()),
            proprietary: BTreeMap::new(),
            ..Default::default()
        };
        spend_input
            .proprietary
            .insert(SpacesWallet::spaces_signer("tbs"), Vec::new());

        let compressed_psbt = PushBytesBuf::try_from(SpacesWallet::compress_bid_psbt(
            placeholder.auction.outpoint.vout as u8,
            &offer,
        )?)
        .expect("compressed psbt script bytes");

        let carrier = ScriptBuf::new_op_return(&compressed_psbt);

        self.add_foreign_utxo_with_sequence(
            placeholder.spend.outpoint,
            spend_input,
            66,
            Sequence::ENABLE_RBF_NO_LOCKTIME,
        )?;
        self.add_recipient(carrier, burn_amount);

        Ok(self)
    }

    fn add_reveal(
        &mut self,
        commitment: FullTxOut,
        signing_info: SpaceScriptSigningInfo,
    ) -> anyhow::Result<&mut Self> {
        let mut psbt_input = Input {
            witness_utxo: Some(commitment.txout.clone()),
            // to be signed later
            final_script_witness: Some(Witness::default()),
            final_script_sig: Some(ScriptBuf::new()),
            proprietary: BTreeMap::new(),
            ..Default::default()
        };

        // Used by the internal signer after the psbt is built
        psbt_input.proprietary.insert(
            SpacesWallet::spaces_signer("reveal_signing_info"),
            signing_info.to_vec(),
        );

        self.add_foreign_utxo_with_sequence(
            commitment.outpoint,
            psbt_input,
            signing_info.satisfaction_weight(),
            Sequence::ENABLE_RBF_NO_LOCKTIME,
        )?;
        Ok(self)
    }

    fn add_transfer(&mut self, request: TransferRequest) -> anyhow::Result<&mut Self> {
        match request {
            TransferRequest::Space(request) => {
                let output_value = space_dust(
                    request
                        .space
                        .spaceout
                        .script_pubkey
                        .minimal_non_dust()
                        .mul(2),
                );

                let mut spend_input = psbt::Input {
                    witness_utxo: Some(TxOut {
                        value: request.space.spaceout.value,
                        script_pubkey: request.space.spaceout.script_pubkey,
                    }),
                    final_script_witness: Some(Witness::default()),
                    final_script_sig: Some(ScriptBuf::new()),
                    proprietary: BTreeMap::new(),
                    ..Default::default()
                };
                spend_input
                    .proprietary
                    .insert(SpacesWallet::spaces_signer("tbs"), Vec::new());
                self.add_foreign_utxo(
                    OutPoint {
                        txid: request.space.txid,
                        vout: request.space.spaceout.n as u32,
                    },
                    spend_input,
                    66,
                )?;

                self.add_recipient(
                    request.recipient.script_pubkey(),
                    // TODO: another reason we need to keep more metadata
                    // we use a special dust value here so that list auction
                    // outputs won't accidentally auction off this output
                    output_value,
                );
            }
            TransferRequest::Coin(request) => {
                self.add_recipient(request.recipient.script_pubkey(), request.amount);
            }
        }

        Ok(self)
    }
}

impl Builder {
    fn prepare_all(
        coin_selection: SpacesAwareCoinSelection,
        median_time: u64,
        w: &mut SpacesWallet,
        auction_outputs: Option<u8>,
        reveals: Option<&Vec<SpaceScriptSigningInfo>>,
        space_transfers: Vec<SpaceTransfer>,
        coin_transfers: Vec<CoinTransfer>,
        fee_rate: FeeRate,
        dust: Option<Amount>,
    ) -> anyhow::Result<(Transaction, Vec<FullTxOut>)> {
        let mut vout: u32 = 0;
        let mut tap_outputs = Vec::new();
        let change_address = w
            .spaces
            .next_unused_address(KeychainKind::Internal)
            .script_pubkey();

        let mut placeholder_outputs = Vec::new();
        if let Some(placeholders) = auction_outputs {
            for _ in 0..placeholders {
                // Each placeholder is 2 UTXOs: Keeping outputs adjacent to detect if
                // one is spent in an auction.
                // pointer/spend output
                let addr1 = w
                    .spaces
                    .next_unused_address(KeychainKind::Internal)
                    .script_pubkey();
                let dust = match dust {
                    None => addr1.minimal_non_dust().mul(2),
                    Some(dust) => dust,
                };
                let connector_dust = connector_dust(dust);
                let magic_dust = magic_dust(dust);

                placeholder_outputs.push((addr1, connector_dust));
                let addr2 = w.spaces.next_unused_address(KeychainKind::External);
                placeholder_outputs.push((addr2.script_pubkey(), magic_dust));
            }
        }

        let commit_psbt = {
            let mut builder = w.spaces
                .build_tx()
                .coin_selection(coin_selection);
            builder.nlocktime(magic_lock_time(median_time));

            builder.ordering(TxOrdering::Untouched);
            for (addr, amount) in placeholder_outputs {
                builder.add_recipient(addr, amount);
                vout += 1;
            }

            if let Some(tap_data) = reveals {
                for tap_item in tap_data {
                    let dust = match dust {
                        None => tap_item.tweaked_address.minimal_non_dust().mul(2),
                        Some(dust) => dust,
                    };
                    let magic_dust = magic_dust(dust);

                    builder.add_recipient(tap_item.tweaked_address.clone(), magic_dust);
                    tap_outputs.push(vout);
                    vout += 1;
                }
            }

            if !coin_transfers.is_empty() {
                for coin in coin_transfers {
                    builder.add_transfer(TransferRequest::Coin(coin))?;
                    vout += 1;
                }
            }

            // handle transfers
            if !space_transfers.is_empty() {
                // Must be an odd number of outputs so that
                // transfers align correctly
                // TODO: use the actual change output instead of creating this
                if vout % 2 == 0 {
                    let dust = match dust {
                        None => change_address.minimal_non_dust().mul(2),
                        Some(dust) => dust,
                    };
                    builder.add_recipient(change_address, dust);
                }
                for transfer in space_transfers {
                    builder.add_transfer(TransferRequest::Space(transfer))?;
                }
            }

            builder.enable_rbf().fee_rate(fee_rate);
            let r = builder.finish()?;
            r
        };

        let tx = w.sign(commit_psbt, None)?;
        let txid = tx.compute_txid();
        let commitments = tap_outputs
            .into_iter()
            .map(|vout| FullTxOut {
                outpoint: OutPoint { txid, vout },
                txout: tx.output[vout as usize].clone(),
            })
            .collect();

        Ok((tx, commitments))
    }
}

pub struct TaggedTransaction {
    pub tx: Transaction,
    pub tags: Vec<TransactionTag>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum TransactionTag {
    FeeBump,
    AuctionOutputs,
    Commitment,
    Transfers,
    Open,
    Bid,
    Script,
    ForceSpendTestOnly,
}

impl Iterator for BuilderIterator<'_> {
    type Item = anyhow::Result<TaggedTransaction>;

    fn next(&mut self) -> Option<Self::Item> {
        let op = match self.stack.pop() {
            None => return None,
            Some(req) => req,
        };

        match op {
            StackOp::Prepare(params) => {
                let mut tags = Vec::new();
                if !params.transfers.is_empty() {
                    tags.push(TransactionTag::Transfers);
                }
                if params.auction_outputs.is_some() {
                    tags.push(TransactionTag::AuctionOutputs);
                }
                if !params.opens.is_empty() || !params.executes.is_empty() {
                    tags.push(TransactionTag::Commitment);
                }

                let mut reveals = Vec::with_capacity(params.opens.len() + params.executes.len());
                let mut amounts = Vec::with_capacity(params.opens.len());

                for req in params.opens {
                    let tap = Builder::create_open_tap_data(self.wallet.config.network, &req.name)
                        .context("could not initialize tap data for name");
                    if tap.is_err() {
                        return Some(Err(tap.unwrap_err()));
                    }
                    reveals.push(tap.unwrap());
                    amounts.push(req.initial_amount);
                }

                let mut contexts = Vec::with_capacity(params.executes.len());
                for execute in params.executes {
                    let signing_info =
                        SpaceScriptSigningInfo::new(self.wallet.config.network, execute.script);
                    if signing_info.is_err() {
                        return Some(Err(signing_info.unwrap_err()));
                    }
                    reveals.push(signing_info.unwrap());
                    contexts.push(execute.context);
                }

                let prep = Builder::prepare_all(
                    self.coin_selection.clone(),
                    self.median_time,
                    self.wallet,
                    params.auction_outputs,
                    Some(&reveals),
                    params
                        .transfers
                        .iter()
                        .filter_map(|req| match req {
                            TransferRequest::Space(transfer) => Some(transfer.clone()),
                            _ => None,
                        })
                        .collect(),
                    params
                        .transfers
                        .iter()
                        .filter_map(|req| match req {
                            TransferRequest::Coin(transfer) => Some(transfer.clone()),
                            _ => None,
                        })
                        .collect(),
                    self.fee_rate,
                    self.dust,
                );
                if prep.is_err() {
                    return Some(Err(prep.unwrap_err()));
                }

                let (tx, commitments) = prep.unwrap();

                let mut reveals_iter = reveals.into_iter();
                let mut commitments_iter = commitments.into_iter();

                let open_reveals = reveals_iter
                    .by_ref()
                    .take(amounts.len())
                    .collect::<Vec<SpaceScriptSigningInfo>>()
                    .into_iter();
                let open_commitments = commitments_iter
                    .by_ref()
                    .take(amounts.len())
                    .collect::<Vec<FullTxOut>>()
                    .into_iter();

                for ((signing, commitment), amount) in
                    open_reveals.zip(open_commitments).zip(amounts)
                {
                    self.stack.push(StackOp::Open(OpenParams {
                        reveals: vec![SpaceScriptRevealParams {
                            signing: signing.clone(),
                            commitment,
                        }],
                        amount,
                    }))
                }

                for ((signing, commitment), context) in
                    reveals_iter.zip(commitments_iter).zip(contexts)
                {
                    self.stack.push(StackOp::Execute(ExecuteParams {
                        reveal: SpaceScriptRevealParams {
                            signing,
                            commitment,
                        },
                        context,
                    }))
                }

                Some(Ok(TaggedTransaction { tx, tags }))
            }
            StackOp::Open(params) => {
                let tx = Builder::open_tx(
                    self.coin_selection.clone(),
                    self.wallet,
                    params,
                    self.fee_rate,
                    self.force,
                );
                Some(tx.map(|tx| TaggedTransaction {
                    tx,
                    tags: vec![TransactionTag::Open],
                }))
            }
            StackOp::Execute(params) => {
                let tx = Builder::execute_tx(
                    self.coin_selection.clone(),
                    self.wallet,
                    params,
                    self.fee_rate,
                    self.force,
                );
                Some(tx.map(|tx| TaggedTransaction {
                    tx,
                    tags: vec![TransactionTag::Script],
                }))
            }
            StackOp::Bid(bid) => {
                let tx = Builder::bid_tx(
                    self.coin_selection.clone(),
                    self.wallet,
                    bid.space,
                    bid.amount,
                    self.fee_rate,
                    self.force,
                );
                Some(tx.map(|tx| TaggedTransaction {
                    tx,
                    tags: vec![TransactionTag::Bid],
                }))
            }
        }
    }
}

impl Builder {
    pub fn new() -> Self {
        Builder {
            requests: Vec::new(),
            fee_rate: None,
            auction_outputs: None,
            force: false,
        }
    }

    pub fn fee_rate(mut self, fee_rate: FeeRate) -> Self {
        self.fee_rate = Some(fee_rate);
        self
    }

    pub fn force(mut self, force: bool) -> Self {
        self.force = force;
        self
    }

    pub fn auction_outputs(mut self, num: u8) -> Self {
        self.auction_outputs = Some(num);
        self
    }

    pub fn add_bid(mut self, space: FullSpaceOut, amount: Amount) -> Self {
        self.requests
            .push(StackRequest::Bid(BidRequest { space, amount }));
        self
    }

    pub fn add_open(mut self, name: &str, initial_amount: Amount) -> Self {
        self.requests.push(StackRequest::Open(OpenRequest {
            name: name.to_string(),
            initial_amount,
        }));
        self
    }

    pub fn add_register(mut self, space: FullSpaceOut, to: Option<SpaceAddress>) -> Self {
        self.requests
            .push(StackRequest::Register(RegisterRequest { space, to }));
        self
    }

    pub fn add_transfer(mut self, request: TransferRequest) -> Self {
        self.requests.push(StackRequest::Transfer(request));
        self
    }

    pub fn add_execute(
        mut self,
        spaces: Vec<SpaceTransfer>,
        space_script: script::Builder,
    ) -> Self {
        self.requests.push(StackRequest::Execute(ExecuteRequest {
            context: spaces,
            script: space_script,
        }));
        self
    }

    pub fn build_iter(
        self,
        dust: Option<Amount>,
        median_time: u64,
        wallet: &mut SpacesWallet,
        coin_selection: SpacesAwareCoinSelection,
    ) -> anyhow::Result<BuilderIterator> {
        let fee_rate = self
            .fee_rate
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("fee_rate is required"))?
            .clone();

        let (open_count, bid_count) =
            self.requests
                .iter()
                .fold((0, 0), |mut counts, req| match req {
                    StackRequest::Open(_) => {
                        counts.0 += 1;
                        counts
                    }
                    StackRequest::Bid(_) => {
                        counts.1 += 1;
                        counts
                    }
                    _ => counts,
                });

        let required_auction_outputs = open_count + bid_count as u8;
        let available = if required_auction_outputs > 0 {
            wallet.list_auction_outputs()?
        } else {
            Vec::new()
        };

        // check how many bid outputs we need to create
        let auction_outputs = match self.auction_outputs {
            None => {
                if required_auction_outputs > available.len() as u8 {
                    Some(required_auction_outputs - available.len() as u8)
                } else {
                    None
                }
            }
            Some(count) => {
                if required_auction_outputs > available.len() as u8 + count {
                    return Err(anyhow!(
                        "number of required placeholders {} \
                    exceeds currently available {} + requested {}",
                        required_auction_outputs,
                        available.len(),
                        count
                    ));
                }
                Some(count)
            }
        };

        let mut stack = Vec::new();

        let mut opens = Vec::new();
        let mut bids = Vec::new();
        let mut transfers = Vec::new();
        let mut executes = Vec::new();
        for req in self.requests {
            match req {
                StackRequest::Open(params) => opens.push(params),
                StackRequest::Bid(params) => bids.push(params),
                StackRequest::Register(params) => {
                    let to = match params.to {
                        None => wallet.next_unused_space_address(),
                        Some(address) => address,
                    };
                    transfers.push(TransferRequest::Space(SpaceTransfer {
                        space: params.space,
                        recipient: to.0,
                    }))
                }
                StackRequest::Transfer(params) => transfers.push(params),
                StackRequest::Execute(params) => executes.push(params),
            }
        }

        if !bids.is_empty() {
            for bid in bids {
                stack.push(StackOp::Bid(bid))
            }
        }
        if !opens.is_empty()
            || !transfers.is_empty()
            || !executes.is_empty()
            || auction_outputs.is_some()
        {
            stack.push(StackOp::Prepare(CreateParams {
                opens,
                executes,
                transfers,
                auction_outputs,
            }));
        }

        Ok(BuilderIterator {
            stack,
            dust,
            fee_rate,
            wallet,
            force: self.force,
            median_time,
            coin_selection,
        })
    }

    fn bid_tx(
        coin_selection: SpacesAwareCoinSelection,
        w: &mut SpacesWallet,
        prev: FullSpaceOut,
        bid: Amount,
        fee_rate: FeeRate,
        force: bool,
    ) -> anyhow::Result<Transaction> {
        let (offer, placeholder) = w.new_bid_psbt(bid)?;
        let bid_psbt = {
            let mut builder = w.spaces
                .build_tx()
                .coin_selection(coin_selection);
            builder
                .ordering(TxOrdering::Untouched)
                .nlocktime(LockTime::Blocks(Height::ZERO))
                .enable_rbf_with_sequence(BID_PSBT_INPUT_SEQUENCE)
                .add_bid(
                    Some(prev.spaceout.space.as_ref().unwrap()),
                    offer,
                    placeholder,
                    bid,
                    force,
                )?
                .add_refund(&prev)?
                .fee_rate(fee_rate);
            builder.finish()?
        };

        let signed = w.sign(bid_psbt, None)?;
        Ok(signed)
    }

    fn open_tx(
        coin_selection: SpacesAwareCoinSelection,
        w: &mut SpacesWallet,
        params: OpenParams,
        fee_rate: FeeRate,
        force: bool,
    ) -> anyhow::Result<Transaction> {
        let (offer, placeholder) = w.new_bid_psbt(params.amount)?;
        let mut extra_prevouts = BTreeMap::new();
        let open_psbt = {
            let mut builder = w.spaces
                .build_tx()
                .coin_selection(coin_selection);
            builder.ordering(TxOrdering::Untouched).add_bid(
                None,
                offer,
                placeholder,
                params.amount,
                force,
            )?;

            for reveal in params.reveals {
                builder.add_reveal(reveal.commitment.clone(), reveal.signing)?;
                extra_prevouts.insert(reveal.commitment.outpoint, reveal.commitment.txout);
            }

            builder.enable_rbf().fee_rate(fee_rate);
            builder.finish()?
        };

        let signed = w.sign(open_psbt, Some(extra_prevouts))?;
        Ok(signed)
    }

    fn execute_tx(
        coin_selection: SpacesAwareCoinSelection,
        w: &mut SpacesWallet,
        params: ExecuteParams,
        fee_rate: FeeRate,
        _force: bool,
    ) -> anyhow::Result<Transaction> {
        let mut extra_prevouts = BTreeMap::new();
        let reveal_psbt = {
            let change_address = w
                .spaces
                .next_unused_address(KeychainKind::Internal)
                .script_pubkey();
            let mut builder = w.spaces
                .build_tx()
                .coin_selection(coin_selection);

            builder
                .ordering(TxOrdering::Untouched)
                // Added first to keep an odd number of outputs before adding transfers
                .add_recipient(change_address, Amount::from_sat(1000));

            extra_prevouts.insert(
                params.reveal.commitment.outpoint,
                params.reveal.commitment.txout.clone(),
            );

            for transfer in params.context {
                builder.add_transfer(TransferRequest::Space(transfer))?;
            }

            builder
                // add reveal last to not disrupt space inputs order
                .add_reveal(params.reveal.commitment, params.reveal.signing)?
                .enable_rbf()
                .fee_rate(fee_rate);
            builder.finish()?
        };

        let signed = w.sign(reveal_psbt, Some(extra_prevouts))?;
        Ok(signed)
    }

    fn create_open_tap_data(
        network: Network,
        name: &str,
    ) -> anyhow::Result<SpaceScriptSigningInfo> {
        let sname = protocol::slabel::SLabel::from_str(name).expect("valid space name");
        let nop = SpaceScript::nop_script(SpaceScript::create_open(sname));
        SpaceScriptSigningInfo::new(network, nop)
    }
}

/// A coin selection algorithm that :
/// 1. Guarantees required utxos are ordered first appending
/// any funding/change outputs to the end of the selected utxos.
/// 2. Excludes all dust outputs to avoid accidentally spending space utxos
/// 3. Enables adding additional output exclusions
#[derive(Debug, Clone)]
pub struct SpacesAwareCoinSelection {
    pub default_algorithm: DefaultCoinSelectionAlgorithm,
    // Exclude outputs
    pub exclude_outputs: Vec<OutPoint>,
}

impl SpacesAwareCoinSelection {
    // Will skip any outputs with value less than the dust threshold
    // to avoid accidentally spending space outputs
    pub const DUST_THRESHOLD: Amount = Amount::from_sat(1200);
    pub fn new(excluded: Vec<OutPoint>) -> Self {
        Self {
            default_algorithm: DefaultCoinSelectionAlgorithm::default(),
            exclude_outputs: excluded,
        }
    }
}

impl CoinSelectionAlgorithm for SpacesAwareCoinSelection {
    fn coin_select(
        &self,
        required_utxos: Vec<WeightedUtxo>,
        mut optional_utxos: Vec<WeightedUtxo>,
        fee_rate: FeeRate,
        target_amount: u64,
        drain_script: &Script,
    ) -> Result<CoinSelectionResult, Error> {
        let required = required_utxos
            .iter()
            .map(|w| w.utxo.clone())
            .collect::<Vec<_>>();

        // Filter out UTXOs that are either explicitly excluded or below the dust threshold
        optional_utxos.retain(|weighted_utxo| {
            weighted_utxo.utxo.txout().value > SpacesAwareCoinSelection::DUST_THRESHOLD
                && !self
                    .exclude_outputs
                    .contains(&weighted_utxo.utxo.outpoint())
        });

        let mut result = self.default_algorithm.coin_select(
            required_utxos,
            optional_utxos,
            fee_rate,
            target_amount,
            drain_script,
        )?;

        let mut optional = Vec::with_capacity(result.selected.len() - required.len());
        for utxo in result.selected.drain(..) {
            if !required.iter().any(|u| u == &utxo) {
                optional.push(utxo);
            }
        }

        let mut selected = Vec::with_capacity(required.len() + optional.len());
        selected.extend(required);
        selected.extend(optional);

        Ok(CoinSelectionResult {
            selected,
            fee_amount: result.fee_amount,
            excess: result.excess,
        })
    }
}

pub fn magic_lock_time(median_time: u64) -> LockTime {
    let median_time = min(median_time, u32::MAX as u64) as u32;
    let magic_time = median_time - (median_time % 1000) - (1000 - 222);
    LockTime::from_time(magic_time).expect("valid time")
}

pub fn magic_dust(amount: Amount) -> Amount {
    let amount = amount.to_sat();
    Amount::from_sat(amount - (amount % 10) + 2)
}

pub fn connector_dust(amount: Amount) -> Amount {
    let amount = amount.to_sat();
    Amount::from_sat(amount - (amount % 10) + 4)
}

pub fn is_connector_dust(amount: Amount) -> bool {
    amount.to_sat() % 10 == 4
}

// Special dust value to indicate this output is a space
// could be removed once we track output metadata in some db
pub fn space_dust(amount: Amount) -> Amount {
    let amount = amount.to_sat();
    Amount::from_sat(amount - (amount % 10) + 6)
}

pub fn is_space_dust(amount: Amount) -> bool {
    amount.to_sat() % 10 == 6
}
