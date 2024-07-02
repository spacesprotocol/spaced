use std::collections::BTreeMap;
use std::str::FromStr;
use std::time::Duration;
use anyhow::{anyhow};
use bdk::bitcoin::{Address, Amount, FeeRate, Network, Sequence};
use bdk::{KeychainKind, LocalOutput, Utxo, WeightedUtxo};
use bdk::bitcoin::psbt::Input;
use bdk_bitcoind_rpc::bitcoincore_rpc::{jsonrpc};
use log::{info};
use crate::store::ChainState;
use tokio::select;
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::sync::mpsc::Receiver;
use protocol::bitcoin::{Txid};
use protocol::hasher::{KeyHasher, SpaceHash};
use protocol::sname::{NameLike, SName};
use crate::store::{LiveSnapshot, Sha256};
use wallet::{DoubleUtxo, SuperWallet};
use crate::rpc::{RpcWalletRequest, RpcWalletTxBuilder};
use crate::source::{BroadcastError, RpcBlockchain};
use clap::ValueEnum;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use protocol::{FullSpaceOut};
use protocol::prepare::DataSource;
use wallet::address::SpaceAddress;
use wallet::builder::{CoinTransfer, SpacesAwareCoinSelection, SpaceTransfer, TransactionTag, TransferRequest};
use crate::node::BlockSource;
use crate::sync::Mempool;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxEntry {
    pub txid: Txid,
    pub tags: Vec<TransactionTag>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<BTreeMap<String, String>>,
}


pub enum WalletCommand {
    BatchTx {
        request: RpcWalletTxBuilder,
        resp: crate::rpc::Responder<anyhow::Result<Vec<TxEntry>>>,
    },
    GetNewAddress {
        kind: AddressKind,
        resp: crate::rpc::Responder<anyhow::Result<String>>,
    },
    BumpFee {
        txid: Txid,
        fee_rate: FeeRate,
        resp: crate::rpc::Responder<anyhow::Result<Vec<TxEntry>>>,
    },
    ListSpaces {
        resp: crate::rpc::Responder<anyhow::Result<Vec<FullSpaceOut>>>
    },
    ListAuctionOutputs {
        resp: crate::rpc::Responder<anyhow::Result<Vec<DoubleUtxo>>>
    },
    ListUnspent {
        resp: crate::rpc::Responder<anyhow::Result<Vec<LocalOutput>>>
    },
    GetBalance {
        resp: crate::rpc::Responder<anyhow::Result<JointBalance>>,
    },
    UnloadWallet,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, ValueEnum)]
pub enum AddressKind {
    Coin,
    Space,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmedBalance {
    total: Amount,
    spendable: Amount,
    immature: Amount,
    locked: Amount,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnconfirmedBalance {
    total: Amount,
    locked: Amount,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JointBalance {
    pub confirmed: ConfirmedBalance,
    pub unconfirmed: UnconfirmedBalance,
}

#[derive(Clone)]
pub struct RpcWallet {
    pub sender: mpsc::Sender<WalletCommand>,
}

impl RpcWallet {
    pub fn new() -> (Self, Receiver<WalletCommand>) {
        let (sender, receiver) =
            mpsc::channel(10);
        (Self {
            sender,
        }, receiver)
    }

    fn estimate_fee_rate(source: &RpcBlockchain) -> Option<FeeRate> {
        let mut args = Vec::new();
        // conf_target
        args.push(jsonrpc::arg(6));
        args.push(jsonrpc::arg("conservative".to_string()));

        let client = source.client.get_jsonrpc_client();
        let json_request = client.build_request("estimatesmartfee", &args);
        if let Ok(response)  = client.send_request(json_request) {
            if let Some(result) = response.result {
                if let Ok(parsed_result) = serde_json::from_str::<Value>(result.get()) {
                    // Extract the feerate
                    if let Some(fee_rate) = parsed_result["feerate"].as_f64() {
                        // Convert BTC/kB to sat/vB
                        let fee_rate_sat_vb = (fee_rate * 100_000_000.0 / 1000.0).round() as u64;
                        return FeeRate::from_sat_per_vb(fee_rate_sat_vb);
                    }
                }
            }
        }

        None
    }

    fn get_joint_balance(state: &mut LiveSnapshot, wallet: &mut SuperWallet) -> anyhow::Result<JointBalance> {
        let (_, coinouts) = Self::get_space_outputs(wallet, state)?;

        let (spaces_confirmed, spaces_pending) =
            coinouts.iter().fold((Amount::from_sat(0), Amount::from_sat(0)),
                                 |mut balances, utxo| {
                                     if utxo.confirmation_time.is_confirmed() {
                                         balances.0 += utxo.txout.value;
                                     } else {
                                         balances.1 += utxo.txout.value;
                                     }
                                     balances
                                 });

        let spaces = wallet.spaces.get_balance();
        let coins = wallet.coins.get_balance();

        Ok(JointBalance {
            confirmed: ConfirmedBalance {
                total: spaces_confirmed + spaces.immature + coins.confirmed + coins.immature,
                spendable: spaces_confirmed + coins.confirmed,
                immature: spaces.immature + coins.immature,
                locked: spaces.confirmed - spaces_confirmed,
            },
            unconfirmed: UnconfirmedBalance {
                total: spaces_pending + coins.trusted_pending + coins.untrusted_pending,
                locked: (spaces.untrusted_pending + spaces.trusted_pending) - spaces_pending,
            },
        })
    }

    fn handle_fee_bump(source: &RpcBlockchain, wallet: &mut SuperWallet, txid: Txid, fee_rate: FeeRate)
                       -> anyhow::Result<Vec<TxEntry>> {
        let mut builder = wallet.coins.build_fee_bump(txid)?;
        builder.fee_rate(fee_rate);

        let psbt = builder.finish()?;
        let tx = wallet.sign(psbt, None)?;

        let confirmation = source.broadcast_tx(tx.clone())?;
        wallet.insert_tx(tx, confirmation)?;
        wallet.commit()?;

        Ok(vec![TxEntry {
            txid,
            tags: vec![TransactionTag::FeeBump],
            error: None,
        }])
    }

    fn wallet_handle_commands(network: Network,
                              source: &RpcBlockchain,
                              mut state: &mut LiveSnapshot,
                              mempool: &Mempool,
                              wallet: &mut SuperWallet,
                              command: WalletCommand,
    ) -> anyhow::Result<()> {
        match command {
            WalletCommand::BatchTx { request, resp } => {
                let batch_result =
                    Self::batch_tx(network, mempool.clone(), &source, wallet, &mut state, request);
                _ = resp.send(batch_result);
            }
            WalletCommand::BumpFee { txid, fee_rate, resp } => {
                let result = Self::handle_fee_bump(source, wallet, txid, fee_rate);
                _ = resp.send(result);
            }
            WalletCommand::GetNewAddress { kind, resp } => {
                let address = match kind {
                    AddressKind::Coin => wallet.coins.next_unused_address(KeychainKind::External)
                        .map(|info| info.address.to_string()),
                    AddressKind::Space => wallet.next_unused_space_address()
                        .map(|address| address.to_string()),
                };
                _ = resp.send(address);
            }
            WalletCommand::ListUnspent { resp } => {
                let mut all = Vec::new();
                match Self::get_space_outputs(wallet, state) {
                    Ok((_, mut coinouts)) => {
                        all.append(&mut coinouts);
                        for output in wallet.coins.list_unspent() {
                            all.push(output);
                        }
                        _ = resp.send(Ok(all));
                    }
                    Err(error) => {
                        _ = resp.send(Err(error));
                    }
                }
            }
            WalletCommand::ListSpaces { resp } => {
                let result = Self::get_space_outputs(wallet, state);
                match result {
                    Ok((spaceouts, _)) => {
                        _ = resp.send(
                            Ok(spaceouts.into_iter()
                                .filter(|s| s.spaceout.space.is_some()).collect())
                        );
                    }
                    Err(error) => {
                        _ = resp.send(Err(error));
                    }
                }
            }
            WalletCommand::ListAuctionOutputs { resp } => {
                let result = wallet.list_auction_outputs();
                _ = resp.send(result);
            }
            WalletCommand::GetBalance { resp } => {
                let balance = Self::get_joint_balance(state, wallet);
                _ = resp.send(balance);
            }
            WalletCommand::UnloadWallet => {
                info!("Unloading wallet '{}' ...", wallet.name);
            }
        }
        Ok(())
    }

    fn wallet_sync(
        network: Network,
        source: RpcBlockchain,
        mut state: LiveSnapshot,
        mempool: Mempool,
        mut wallet: SuperWallet,
        mut commands: Receiver<WalletCommand>,
        mut shutdown: broadcast::Receiver<()>,
    ) -> anyhow::Result<()> {
        let fallback_height = std::cmp::max(
            wallet.coins.local_chain().tip().height() as i32 - 20, 0) as u32;
        let mut emitter = source.emitter(wallet.coins.local_chain().tip(), fallback_height);

        loop {
            if shutdown.try_recv().is_ok() {
                info!("Shutting down wallet sync");
                break;
            }
            if let Ok(command) = commands.try_recv() {
                Self::wallet_handle_commands(
                    network, &source, &mut state, &mempool, &mut wallet, command)?;
            }
            if let Some(event) = emitter.next_block()? {
                wallet.apply_block(event.block_height(), &event.block)?;
                continue;
            }

            // TODO: update wallet mempool
            std::thread::sleep(Duration::from_millis(100));
        }
        Ok(())
    }

    fn get_spaces_coin_selection(
        wallet: &mut SuperWallet,
        state: &mut LiveSnapshot,
    ) -> anyhow::Result<SpacesAwareCoinSelection> {
        let weight = wallet.spaces
            .get_descriptor_for_keychain(KeychainKind::External)
            .max_weight_to_satisfy()?;
        let (_, cointouts) = Self::get_space_outputs(wallet, state)?;

        let coinouts: Vec<_> = cointouts
            .into_iter().filter(|x| x.confirmation_time.is_confirmed())
            .map(|coin| {
                WeightedUtxo {
                    satisfaction_weight: weight,
                    utxo: Utxo::Foreign {
                        outpoint: coin.outpoint,
                        sequence: Some(Sequence::ENABLE_RBF_NO_LOCKTIME),
                        psbt_input: Box::new(Input {
                            witness_utxo: Some(coin.txout),
                            ..Default::default()
                        }),
                    },
                }
            }).collect();
        Ok(SpacesAwareCoinSelection::new(coinouts))
    }

    /// Finds confirmed unspent outputs in the spaces wallet that could be spent for their coin value
    fn get_space_outputs(wallet: &mut SuperWallet, store: &mut LiveSnapshot)
                         -> anyhow::Result<(Vec<FullSpaceOut>, Vec<LocalOutput>)> {
        let available = wallet.spaces.list_output()
            .filter(|x|
                x.keychain == KeychainKind::External && !x.is_spent);
        let mut coinouts = Vec::new();
        let mut spaceouts = Vec::new();

        for output in available {
            let result = store.get_spaceout(&output.outpoint)?;
            match result {
                None => {
                    coinouts.push(output);
                }
                Some(spaceout) => {
                    spaceouts.push(FullSpaceOut {
                        outpoint: output.outpoint,
                        spaceout,
                    })
                }
            }
        }
        Ok((spaceouts, coinouts))
    }

    fn resolve(
        network: Network,
        store: &mut LiveSnapshot,
        to: &str,
        require_space_address: bool,
    ) -> anyhow::Result<Option<Address>> {
        if let Ok(address) = Address::from_str(to) {
            if require_space_address {
                return Err(anyhow!("recipient must be a space address"));
            }
            return Ok(Some(address.require_network(network)?));
        }
        if let Ok(space_address) = SpaceAddress::from_str(to) {
            return Ok(Some(space_address.0));
        }

        let sname = match SName::from_str(to) {
            Ok(sname) => sname,
            Err(_) => {
                return Err(anyhow!("recipient must be a valid space name or an address"));
            }
        };

        let spacehash = SpaceHash::from(Sha256::hash(sname.to_bytes()));
        let script_pubkey = match store.get_space_info(&spacehash)? {
            None => return Ok(None),
            Some(fullspaceout) => fullspaceout.spaceout.script_pubkey
        };

        Ok(Some(Address::from_script(script_pubkey.as_script(), network)?))
    }

    fn batch_tx(
        network: Network,
        mempool: Mempool,
        source: &RpcBlockchain,
        wallet: &mut SuperWallet,
        store: &mut LiveSnapshot,
        tx: RpcWalletTxBuilder,
    ) -> anyhow::Result<Vec<TxEntry>> {
        let fee_rate = match tx.fee_rate.as_ref() {
            None => {
                match Self::estimate_fee_rate(source) {
                    None => return Err(anyhow!("could not estimate fee rate")),
                    Some(r) => r
                }
            }
            Some(r) => r.clone()
        };

        let mut builder = wallet::builder::Builder::new();
        builder = builder.fee_rate(fee_rate);

        if tx.auction_outputs.is_some() {
            builder = builder.auction_outputs(tx.auction_outputs.unwrap());
        }
        builder = builder.force(tx.force);

        for req in tx.requests {
            match req {
                RpcWalletRequest::SendCoins(params) => {
                    let recipient = match Self::resolve(network, store, &params.to, false)? {
                        None => return Err(anyhow!("sendcoins: could not resolve '{}'", params.to)),
                        Some(r) => r
                    };
                    builder = builder.add_transfer(TransferRequest::Coin(CoinTransfer {
                        amount: params.amount,
                        recipient: recipient.clone(),
                    }));
                }
                RpcWalletRequest::Transfer(params) => {
                    let spaces: Vec<_> = params.spaces.iter()
                        .filter_map(|space| SName::from_str(space).ok()).collect();
                    if spaces.len() != params.spaces.len() {
                        return Err(anyhow!("sendspaces: some names were malformed"));
                    }
                    let recipient = match Self::resolve(network, store, &params.to, true)? {
                        None => return Err(anyhow!("sendspaces: could not resolve '{}'", params.to)),
                        Some(r) => r
                    };
                    for space in spaces {
                        let spacehash = SpaceHash::from(Sha256::hash(space.to_bytes()));
                        match store.get_space_info(&spacehash)? {
                            None => return Err(anyhow!("sendspaces: you don't own `{}`", space)),
                            Some(full) if
                            full.spaceout.space.is_none() ||
                                !full.spaceout.space.as_ref().unwrap().is_owned() ||
                                !wallet.spaces
                                    .is_mine(full.spaceout.script_pubkey.as_script()) => {
                                return Err(anyhow!("sendspaces: you don't own `{}`", space));
                            }
                            Some(full) => {
                                builder = builder.add_transfer(TransferRequest::Space(SpaceTransfer {
                                    space: full,
                                    recipient: recipient.clone(),
                                }));
                            }
                        };
                    }
                }
                RpcWalletRequest::Open(params) => {
                    let name = SName::from_str(&params.name)?;
                    if !tx.force {
                        // Warn if already exists
                        let spacehash = SpaceHash::from(Sha256::hash(name.to_bytes()));
                        let spaceout = store.get_space_info(&spacehash)?;
                        if spaceout.is_some() {
                            return Err(anyhow!("open '{}': space already exists", params.name));
                        }

                        // Warn if seen in mempool
                        if let Some(mem_tx) = mempool.get_open(&params.name) {
                            return Err(anyhow!("An existing open for `{}` \
                            in mempool: tx: #{} seen at: {}",
                                params.name, mem_tx.tx.txid(), mem_tx.seen));
                        }
                    }

                    builder = builder.add_open(&params.name, Amount::from_sat(params.amount));
                }
                RpcWalletRequest::Bid(params) => {
                    let name = SName::from_str(&params.name)?;
                    let spacehash = SpaceHash::from(Sha256::hash(name.to_bytes()));
                    let spaceout = store.get_space_info(&spacehash)?;
                    if spaceout.is_none() {
                        return Err(anyhow!("bid '{}': space does not exist", params.name));
                    }
                    builder = builder.add_bid(spaceout.unwrap(), Amount::from_sat(params.amount));
                }
                RpcWalletRequest::Register(params) => {
                    let name = SName::from_str(&params.name)?;
                    let spacehash = SpaceHash::from(Sha256::hash(name.to_bytes()));
                    let spaceout = store.get_space_info(&spacehash)?;
                    if spaceout.is_none() {
                        return Err(anyhow!("register '{}': space does not exist", params.name));
                    }
                    let utxo = spaceout.unwrap();
                    if !wallet.spaces.is_mine(&utxo.spaceout.script_pubkey) {
                        return Err(anyhow!("register '{}': you don't own this space", params.name));
                    }

                    if !tx.force {
                        let claim_height = utxo.spaceout.space.as_ref().unwrap().claim_height();
                        let tip_height = wallet.spaces.local_chain().tip().height();

                        if claim_height.is_none() {
                            return Err(anyhow!("register '{}': cannot register a space in pre-auctions", params.name));
                        }

                        let claim_height = claim_height.unwrap();
                        if claim_height > tip_height {
                            return Err(anyhow!("register '{}': cannot register until claim height {}",
                                params.name, claim_height));
                        }
                    }

                    let address = match params.to {
                        None => {
                            match wallet.next_unused_space_address() {
                                Ok(address) => address,
                                Err(_) => {
                                    return Err(anyhow!("register '{}': could not create a recipient address",
                                        params.name));
                                }
                            }
                        }
                        Some(address) => {
                            match SpaceAddress::from_str(&address) {
                                Ok(addr) => addr,
                                Err(_) => {
                                    return Err(anyhow!("transfer '{}': recipient must be a valid space address",
                                        params.name));
                                }
                            }
                        }
                    };

                    builder = builder.add_register(utxo, Some(address));
                }
                RpcWalletRequest::Execute(params) => {
                    let mut spaces = Vec::new();
                    for space in params.context.iter() {
                        let name = SName::from_str(&space)?;
                        let spacehash = SpaceHash::from(Sha256::hash(name.to_bytes()));
                        let spaceout = store.get_space_info(&spacehash)?;
                        if spaceout.is_none() {
                            return Err(anyhow!("execute on '{}': space does not exist", space));
                        }
                        let spaceout = spaceout.unwrap();
                        if !wallet.spaces.is_mine(&spaceout.spaceout.script_pubkey) {
                            return Err(anyhow!("execute on '{}': you don't own this space", space));
                        }
                        let address = match wallet.next_unused_space_address() {
                            Ok(address) => address,
                            Err(_) => {
                                return Err(anyhow!("execute on '{}': could not create a recipient address",
                                        space));
                            }
                        };
                        spaces.push(SpaceTransfer {
                            space: spaceout,
                            recipient: address.0,
                        });
                    }
                    builder = builder.add_execute(spaces, params.space_script);
                }
            }
        }

        let median_time = source.get_median_time()?;
        let coin_selection = Self::get_spaces_coin_selection(wallet, store)?;

        let mut tx_iter = builder.build_iter(tx.dust, median_time, wallet, coin_selection)?;

        let mut result_set = Vec::new();
        while let Some(tx_result) = tx_iter.next() {
            let tagged = tx_result?;
            let is_bid = tagged.tags.iter().any(|tag| *tag == TransactionTag::Bid);
            result_set.push(TxEntry {
                txid: tagged.tx.txid(),
                tags: tagged.tags,
                error: None,
            });

            let result = source.broadcast_tx(tagged.tx.clone());
            match result {
                Ok(confirmation) => {
                    tx_iter.wallet.insert_tx(tagged.tx, confirmation)?;
                    tx_iter.wallet.commit()?;
                }
                Err(e) => {
                    let mut error_data = BTreeMap::new();
                    if let BroadcastError::Rpc(rpc) = e {
                        if is_bid {
                            if rpc.message.contains("replacement-adds-unconfirmed") {
                                error_data.insert("hint".to_string(),
                                                  "If you have don't have confirmed auction outputs, you cannot \
                                                  replace bids in the mempool.".to_string());
                            }

                            if let Some(fee_rate) = fee_rate_from_message(&rpc.message) {
                                error_data.insert(
                                    "hint".to_string(),
                                    format!("A competing bid in the mempool; replace \
                                                  with a feerate > {} sat/vB.",
                                            fee_rate.to_sat_per_vb_ceil()),
                                );
                            }
                        }

                        error_data.insert("rpc_code".to_string(), rpc.code.to_string());
                        error_data.insert("message".to_string(), rpc.message);
                        result_set.last_mut().unwrap().error = Some(error_data);
                    } else {
                        error_data.insert("message".to_string(), format!("{:?}", e));
                        result_set.last_mut().unwrap().error = Some(error_data);
                    }
                    break;
                }
            }
        }

        Ok(result_set)
    }

    pub async fn service(
        network: Network,
        mempool: Mempool,
        source: RpcBlockchain,
        store: LiveSnapshot,
        mut channel: Receiver<(SuperWallet, Receiver<WalletCommand>)>,
        shutdown: broadcast::Sender<()>,
    ) -> anyhow::Result<()> {
        let mut shutdown_signal = shutdown.subscribe();
        let mut wallet_results = FuturesUnordered::new();

        loop {
            select! {
                _ = shutdown_signal.recv() => {
                    info!("Shutting down wallet service...");
                    break;
                }
                wallet = channel.recv() => {
                    if let Some( (wallet, wallet_commands) ) = wallet {
                        let wallet_name = wallet.name().to_string();
                        info!("Loaded wallet: {}", wallet_name);

                        let wallet_chain = store.clone();
                        let wallet_mem = mempool.clone();
                        let wallet_source = source.clone();
                        let wallet_shutdown = shutdown.subscribe();
                        let (tx, rx) = oneshot::channel();

                        std::thread::spawn(move || {
                            _ = tx.send(Self::wallet_sync(network, wallet_source, wallet_chain,
                                wallet_mem, wallet, wallet_commands, wallet_shutdown)
                            );
                        });
                        wallet_results.push(named_future(wallet_name, rx));
                    }
                }
                Some((name, res)) = wallet_results.next() => {
                    if let Ok(res) = res {
                        match res {
                        Ok(_) => info!("Wallet `{}` shutdown normally", name),
                            Err(e) => {
                                return Err(anyhow!("An error occurred with wallet `{}`: {}", name, e))
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    pub async fn send_batch_tx(&self, request: RpcWalletTxBuilder) -> anyhow::Result<Vec<TxEntry>> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender.send(WalletCommand::BatchTx { request, resp }).await?;
        resp_rx.await?
    }

    pub async fn send_get_new_address(&self, kind: AddressKind) -> anyhow::Result<String> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender.send(WalletCommand::GetNewAddress { kind, resp }).await?;
        resp_rx.await?
    }

    pub async fn send_fee_bump(&self, txid: Txid, fee_rate: FeeRate) -> anyhow::Result<Vec<TxEntry>> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender.send(WalletCommand::BumpFee { txid, fee_rate, resp }).await?;
        resp_rx.await?
    }

    pub async fn send_list_spaces(&self) -> anyhow::Result<Vec<FullSpaceOut>> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender.send(WalletCommand::ListSpaces { resp }).await?;
        resp_rx.await?
    }

    pub async fn send_list_auction_outputs(&self) -> anyhow::Result<Vec<DoubleUtxo>> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender.send(WalletCommand::ListAuctionOutputs { resp }).await?;
        resp_rx.await?
    }

    pub async fn send_list_unspent(&self) -> anyhow::Result<Vec<LocalOutput>> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender.send(WalletCommand::ListUnspent { resp }).await?;
        resp_rx.await?
    }

    pub async fn send_get_balance(&self) -> anyhow::Result<JointBalance> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender.send(WalletCommand::GetBalance { resp }).await?;
        resp_rx.await?
    }

    pub async fn unload_wallet(&self) {
        _ = self.sender.send(WalletCommand::UnloadWallet);
    }
}

// Extracts fee rate from example rpc message: "insufficient fee, rejecting replacement
// 96bb0d5fa00a35e888ff8afb5b41903955b8f34b5b2de01d874ae579a4d1eba0;
// new feerate 0.01000000 BTC/kvB <= old feerate 0.01000000 BTC/kvB"
fn fee_rate_from_message(message: &str) -> Option<FeeRate> {
    // Check if the message contains the expected error
    if !message.contains("insufficient fee, rejecting replacement") {
        return None;
    }

    let parts: Vec<&str> = message.split(';').collect();
    let fee_part = parts.get(1)?;

    let fee_rates: Vec<&str> = fee_part.trim().split("<=").collect();
    let old_fee_str = fee_rates.get(1)?;

    let fee_value = old_fee_str
        .split_whitespace()
        .nth(2)?
        .parse::<f64>()
        .ok()?;

    let fee_rate_sat_vb = (fee_value * 100_000.0) as u64;
    FeeRate::from_sat_per_vb(fee_rate_sat_vb)
}

async fn named_future<T>(name: String, rx: tokio::sync::oneshot::Receiver<T>) -> (String, Result<T, tokio::sync::oneshot::error::RecvError>) {
    (name, rx.await)
}
