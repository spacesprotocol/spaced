use std::{collections::BTreeMap, str::FromStr, time::Duration};

use anyhow::anyhow;
use clap::ValueEnum;
use futures::{stream::FuturesUnordered, StreamExt};
use log::{info, warn};
use protocol::{
    bitcoin::Txid,
    constants::ChainAnchor,
    hasher::{KeyHasher, SpaceKey},
    prepare::DataSource,
    script::SpaceScript,
    slabel::SLabel,
    Space,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::{
    select,
    sync::{broadcast, mpsc, mpsc::Receiver, oneshot},
};
use wallet::{
    address::SpaceAddress,
    bdk_wallet,
    bdk_wallet::{
        chain::{local_chain::CheckPoint, BlockId},
        KeychainKind, LocalOutput,
    },
    bitcoin,
    bitcoin::{Address, Amount, FeeRate, OutPoint},
    builder::{
        CoinTransfer, SpaceTransfer, SpacesAwareCoinSelection, TransactionTag, TransferRequest,
    },
    DoubleUtxo, SpacesWallet, WalletInfo,
};

use crate::{
    config::ExtendedNetwork,
    node::BlockSource,
    rpc::{LoadedWallet, RpcWalletRequest, RpcWalletTxBuilder},
    source::{
        BitcoinBlockSource, BitcoinRpc, BitcoinRpcError, BlockEvent, BlockFetchError, BlockFetcher,
    },
    store::{ChainState, LiveSnapshot, Sha256},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxResponse {
    pub txid: Txid,
    pub tags: Vec<TransactionTag>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletResponse {
    pub sent: Vec<TxResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletOutput {
    #[serde(flatten)]
    pub output: LocalOutput,
    pub space: Option<Space>,
    pub is_spaceout: bool,
}

pub enum WalletCommand {
    GetInfo {
        resp: crate::rpc::Responder<anyhow::Result<WalletInfo>>,
    },
    BatchTx {
        request: RpcWalletTxBuilder,
        resp: crate::rpc::Responder<anyhow::Result<WalletResponse>>,
    },
    GetNewAddress {
        kind: AddressKind,
        resp: crate::rpc::Responder<anyhow::Result<String>>,
    },
    BumpFee {
        txid: Txid,
        fee_rate: FeeRate,
        resp: crate::rpc::Responder<anyhow::Result<Vec<TxResponse>>>,
    },
    ListSpaces {
        resp: crate::rpc::Responder<anyhow::Result<Vec<WalletOutput>>>,
    },
    ListAuctionOutputs {
        resp: crate::rpc::Responder<anyhow::Result<Vec<DoubleUtxo>>>,
    },
    ListUnspent {
        resp: crate::rpc::Responder<anyhow::Result<Vec<WalletOutput>>>,
    },
    ForceSpendOutput {
        outpoint: OutPoint,
        fee_rate: FeeRate,
        resp: crate::rpc::Responder<anyhow::Result<TxResponse>>,
    },
    GetBalance {
        resp: crate::rpc::Responder<anyhow::Result<Balance>>,
    },
    UnloadWallet,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, ValueEnum)]
pub enum AddressKind {
    Coin,
    Space,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Balance {
    pub balance: Amount,
    pub details: BalanceDetails,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalanceDetails {
    #[serde(flatten)]
    pub balance: bdk_wallet::wallet::Balance,
    pub dust: Amount,
}

#[derive(Clone)]
pub struct RpcWallet {
    pub sender: mpsc::Sender<WalletCommand>,
}

impl RpcWallet {
    pub fn new() -> (Self, Receiver<WalletCommand>) {
        let (sender, receiver) = mpsc::channel(10);
        (Self { sender }, receiver)
    }

    fn estimate_fee_rate(source: &BitcoinBlockSource) -> Option<FeeRate> {
        let params = json!([/* conf_target= */ 6, "unset"]);

        let estimate_req = source.rpc.make_request("estimatesmartfee", params);
        if let Ok(res) = source
            .rpc
            .send_json_blocking::<serde_json::Value>(&source.client, &estimate_req)
        {
            if let Some(fee_rate) = res["feerate"].as_f64() {
                // Convert BTC/kB to sat/vB
                let fee_rate_sat_vb = (fee_rate * 100_000.0).ceil() as u64;
                return FeeRate::from_sat_per_vb(fee_rate_sat_vb);
            }
        }

        None
    }

    fn get_balance(state: &mut LiveSnapshot, wallet: &mut SpacesWallet) -> anyhow::Result<Balance> {
        let unspent = Self::list_unspent(wallet, state)?;
        let balance = wallet.spaces.balance();

        let details = BalanceDetails {
            balance,
            dust: unspent
                .into_iter()
                .filter(|output|
                    (output.is_spaceout || output.output.txout.value <= SpacesAwareCoinSelection::DUST_THRESHOLD) &&
                        // trusted pending only
                        (output.output.confirmation_time.is_confirmed() || output.output.keychain == KeychainKind::Internal)
                )
                .map(|output| output.output.txout.value)
                .sum(),
        };

        Ok(Balance {
            balance: (details.balance.confirmed + details.balance.trusted_pending) - details.dust,
            details,
        })
    }

    fn handle_fee_bump(
        source: &BitcoinBlockSource,
        wallet: &mut SpacesWallet,
        txid: Txid,
        fee_rate: FeeRate,
    ) -> anyhow::Result<Vec<TxResponse>> {
        let mut builder = wallet.spaces.build_fee_bump(txid)?;
        builder.fee_rate(fee_rate);

        let psbt = builder.finish()?;
        let tx = wallet.sign(psbt, None)?;

        let confirmation = source.rpc.broadcast_tx(&source.client, &tx)?;
        wallet.insert_tx(tx, confirmation)?;
        wallet.commit()?;

        Ok(vec![TxResponse {
            txid,
            tags: vec![TransactionTag::FeeBump],
            error: None,
        }])
    }

    fn handle_force_spend_output(
        source: &BitcoinBlockSource,
        wallet: &mut SpacesWallet,
        output: OutPoint,
        fee_rate: FeeRate,
    ) -> anyhow::Result<TxResponse> {
        let addre = wallet.spaces.next_unused_address(KeychainKind::External);
        let mut builder = wallet
            .spaces
            .build_tx()
            .coin_selection(SpacesAwareCoinSelection::new(vec![]));

        builder.fee_rate(fee_rate);
        builder.add_utxo(output)?;
        builder.add_recipient(addre.script_pubkey(), Amount::from_sat(5000));

        let psbt = builder.finish()?;
        let tx = wallet.sign(psbt, None)?;

        let txid = tx.compute_txid();
        let confirmation = source.rpc.broadcast_tx(&source.client, &tx)?;
        wallet.insert_tx(tx, confirmation)?;
        wallet.commit()?;

        Ok(TxResponse {
            txid,
            tags: vec![TransactionTag::ForceSpendTestOnly],
            error: None,
        })
    }

    fn wallet_handle_commands(
        network: ExtendedNetwork,
        source: &BitcoinBlockSource,
        mut state: &mut LiveSnapshot,
        wallet: &mut SpacesWallet,
        command: WalletCommand,
    ) -> anyhow::Result<()> {
        match command {
            WalletCommand::GetInfo { resp } => _ = resp.send(Ok(wallet.get_info())),
            WalletCommand::BatchTx { request, resp } => {
                let batch_result = Self::batch_tx(network, &source, wallet, &mut state, request);
                _ = resp.send(batch_result);
            }
            WalletCommand::BumpFee {
                txid,
                fee_rate,
                resp,
            } => {
                let result = Self::handle_fee_bump(source, wallet, txid, fee_rate);
                _ = resp.send(result);
            }
            WalletCommand::ForceSpendOutput {
                outpoint,
                fee_rate,
                resp,
            } => {
                let result = Self::handle_force_spend_output(source, wallet, outpoint, fee_rate);
                _ = resp.send(result);
            }
            WalletCommand::GetNewAddress { kind, resp } => {
                let address = match kind {
                    AddressKind::Coin => wallet
                        .spaces
                        .next_unused_address(KeychainKind::External)
                        .address
                        .to_string(),
                    AddressKind::Space => wallet.next_unused_space_address().to_string(),
                };
                _ = resp.send(Ok(address));
            }
            WalletCommand::ListUnspent { resp } => {
                _ = resp.send(Self::list_unspent(wallet, state));
            }
            WalletCommand::ListSpaces { resp } => {
                let result = Self::list_unspent(wallet, state);
                match result {
                    Ok(unspent) => {
                        _ = resp.send(Ok(unspent
                            .into_iter()
                            .filter(|s| s.space.is_some())
                            .collect()));
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
                let balance = Self::get_balance(state, wallet);
                _ = resp.send(balance);
            }
            WalletCommand::UnloadWallet => {
                info!("Unloading wallet '{}' ...", wallet.name());
            }
        }
        Ok(())
    }

    fn wallet_sync(
        network: ExtendedNetwork,
        source: BitcoinBlockSource,
        mut state: LiveSnapshot,
        mut wallet: SpacesWallet,
        mut commands: Receiver<WalletCommand>,
        mut shutdown: broadcast::Receiver<()>,
        num_workers: usize,
    ) -> anyhow::Result<()> {
        let (fetcher, receiver) = BlockFetcher::new(source.clone(), num_workers);

        let mut wallet_tip = {
            let tip = wallet.spaces.local_chain().tip();
            ChainAnchor {
                height: tip.height(),
                hash: tip.hash(),
            }
        };

        fetcher.start(wallet_tip);

        loop {
            if shutdown.try_recv().is_ok() {
                info!("Shutting down wallet sync");
                break;
            }
            if let Ok(command) = commands.try_recv() {
                Self::wallet_handle_commands(network, &source, &mut state, &mut wallet, command)?;
            }
            if let Ok(event) = receiver.try_recv() {
                match event {
                    BlockEvent::Block(id, block) => {
                        wallet.apply_block_connected_to(
                            id.height,
                            &block,
                            wallet::bdk_wallet::chain::BlockId {
                                height: wallet_tip.height,
                                hash: wallet_tip.hash,
                            },
                        )?;

                        wallet_tip.height = id.height;
                        wallet_tip.hash = id.hash;

                        if id.height % 12 == 0 {
                            wallet.commit()?;
                        }
                    }
                    BlockEvent::Error(e) if matches!(e, BlockFetchError::BlockMismatch) => {
                        let mut checkpoint_in_chain = None;
                        let best_chain = source.get_best_chain()?;
                        for cp in wallet.spaces.local_chain().iter_checkpoints() {
                            if cp.height() > best_chain.height {
                                continue;
                            }

                            let hash = source.get_block_hash(cp.height())?;
                            if cp.height() != 0 && hash == cp.hash() {
                                checkpoint_in_chain = Some(cp);
                                break;
                            }
                        }

                        let restore_point = match checkpoint_in_chain {
                            None => {
                                // We couldn't find a restore point
                                warn!("Rebuilding wallet `{}`", wallet.config.name);
                                let birthday = wallet.config.start_block;
                                let hash = source.get_block_hash(birthday)?;
                                let cp = CheckPoint::new(BlockId {
                                    height: birthday,
                                    hash,
                                });
                                wallet = wallet.rebuild()?;
                                wallet.spaces.insert_checkpoint(cp.block_id())?;
                                cp
                            }
                            Some(cp) => cp,
                        };

                        wallet_tip.height = restore_point.block_id().height;
                        wallet_tip.hash = restore_point.block_id().hash;

                        info!(
                            "Restore wallet `{}` to block={} height={}",
                            wallet.name(),
                            wallet_tip.hash,
                            wallet_tip.height
                        );
                        fetcher.start(wallet_tip);
                    }
                    BlockEvent::Error(e) => return Err(e.into()),
                }

                continue;
            }

            // TODO: update wallet mempool
            std::thread::sleep(Duration::from_millis(10));
        }

        fetcher.stop();
        Ok(())
    }

    fn get_spaces_coin_selection(
        wallet: &mut SpacesWallet,
        state: &mut LiveSnapshot,
    ) -> anyhow::Result<SpacesAwareCoinSelection> {
        // Filters out all "space outs" from the selection.
        // Note: This exclusion only applies to confirmed space outs; unconfirmed ones are not excluded.
        // In practice, this should be fine since Spaces coin selection skips dust by default,
        // so explicitly excluding space outs may be redundant.
        let excluded = Self::list_unspent(wallet, state)?
            .into_iter()
            .filter(|out| out.is_spaceout)
            .map(|out| out.output.outpoint)
            .collect::<Vec<_>>();

        Ok(SpacesAwareCoinSelection::new(excluded))
    }

    fn list_unspent(
        wallet: &mut SpacesWallet,
        store: &mut LiveSnapshot,
    ) -> anyhow::Result<Vec<WalletOutput>> {
        let mut wallet_outputs = Vec::new();

        for output in wallet.spaces.list_unspent() {
            let mut details = WalletOutput {
                output,
                space: None,
                is_spaceout: false,
            };

            let result = store.get_spaceout(&details.output.outpoint)?;
            if let Some(spaceout) = result {
                details.is_spaceout = true;
                details.space = spaceout.space;
            }
            wallet_outputs.push(details)
        }
        Ok(wallet_outputs)
    }

    fn resolve(
        network: ExtendedNetwork,
        store: &mut LiveSnapshot,
        to: &str,
        require_space_address: bool,
    ) -> anyhow::Result<Option<Address>> {
        if let Ok(address) = Address::from_str(to) {
            if require_space_address {
                return Err(anyhow!("recipient must be a space address"));
            }
            return Ok(Some(address.require_network(network.fallback_network())?));
        }
        if let Ok(space_address) = SpaceAddress::from_str(to) {
            return Ok(Some(space_address.0));
        }

        let sname = match SLabel::from_str(to) {
            Ok(sname) => sname,
            Err(_) => {
                return Err(anyhow!(
                    "recipient must be a valid space name or an address"
                ));
            }
        };

        let spacehash = SpaceKey::from(Sha256::hash(sname.as_ref()));
        let script_pubkey = match store.get_space_info(&spacehash)? {
            None => return Ok(None),
            Some(fullspaceout) => fullspaceout.spaceout.script_pubkey,
        };

        Ok(Some(Address::from_script(
            script_pubkey.as_script(),
            network.fallback_network(),
        )?))
    }

    fn batch_tx(
        network: ExtendedNetwork,
        source: &BitcoinBlockSource,
        wallet: &mut SpacesWallet,
        store: &mut LiveSnapshot,
        tx: RpcWalletTxBuilder,
    ) -> anyhow::Result<WalletResponse> {
        if let Some(dust) = tx.dust {
            if dust > SpacesAwareCoinSelection::DUST_THRESHOLD {
                // Allowing higher dust may space outs to be accidentally
                // spent during coin selection
                return Err(anyhow!(
                    "dust cannot be higher than {}",
                    SpacesAwareCoinSelection::DUST_THRESHOLD
                ));
            }
        }

        let fee_rate = match tx.fee_rate.as_ref() {
            None => match Self::estimate_fee_rate(source) {
                None => return Err(anyhow!("could not estimate fee rate")),
                Some(r) => r,
            },
            Some(r) => r.clone(),
        };
        info!("Using fee rate: {} sat/vB", fee_rate.to_sat_per_vb_ceil());

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
                        None => {
                            return Err(anyhow!("sendcoins: could not resolve '{}'", params.to))
                        }
                        Some(r) => r,
                    };
                    builder = builder.add_transfer(TransferRequest::Coin(CoinTransfer {
                        amount: params.amount,
                        recipient: recipient.clone(),
                    }));
                }
                RpcWalletRequest::Transfer(params) => {
                    let spaces: Vec<_> = params
                        .spaces
                        .iter()
                        .filter_map(|space| SLabel::from_str(space).ok())
                        .collect();
                    if spaces.len() != params.spaces.len() {
                        return Err(anyhow!("sendspaces: some names were malformed"));
                    }
                    let recipient = match Self::resolve(network, store, &params.to, true)? {
                        None => {
                            return Err(anyhow!("sendspaces: could not resolve '{}'", params.to))
                        }
                        Some(r) => r,
                    };
                    for space in spaces {
                        let spacehash = SpaceKey::from(Sha256::hash(space.as_ref()));
                        match store.get_space_info(&spacehash)? {
                            None => return Err(anyhow!("sendspaces: you don't own `{}`", space)),
                            Some(full)
                                if full.spaceout.space.is_none()
                                    || !full.spaceout.space.as_ref().unwrap().is_owned()
                                    || !wallet
                                        .spaces
                                        .is_mine(full.spaceout.script_pubkey.as_script()) =>
                            {
                                return Err(anyhow!("sendspaces: you don't own `{}`", space));
                            }
                            Some(full) => {
                                builder =
                                    builder.add_transfer(TransferRequest::Space(SpaceTransfer {
                                        space: full,
                                        recipient: recipient.clone(),
                                    }));
                            }
                        };
                    }
                }
                RpcWalletRequest::Open(params) => {
                    let name = SLabel::from_str(&params.name)?;
                    if !tx.force {
                        // Warn if already exists
                        let spacehash = SpaceKey::from(Sha256::hash(name.as_ref()));
                        let spaceout = store.get_space_info(&spacehash)?;
                        if spaceout.is_some() {
                            return Err(anyhow!("open '{}': space already exists", params.name));
                        }
                    }

                    builder = builder.add_open(&params.name, Amount::from_sat(params.amount));
                }
                RpcWalletRequest::Bid(params) => {
                    let name = SLabel::from_str(&params.name)?;
                    let spacehash = SpaceKey::from(Sha256::hash(name.as_ref()));
                    let spaceout = store.get_space_info(&spacehash)?;
                    if spaceout.is_none() {
                        return Err(anyhow!("bid '{}': space does not exist", params.name));
                    }
                    builder = builder.add_bid(spaceout.unwrap(), Amount::from_sat(params.amount));
                }
                RpcWalletRequest::Register(params) => {
                    let name = SLabel::from_str(&params.name)?;
                    let spacehash = SpaceKey::from(Sha256::hash(name.as_ref()));
                    let spaceout = store.get_space_info(&spacehash)?;
                    if spaceout.is_none() {
                        return Err(anyhow!("register '{}': space does not exist", params.name));
                    }
                    let utxo = spaceout.unwrap();
                    if !wallet.spaces.is_mine(&utxo.spaceout.script_pubkey) {
                        return Err(anyhow!(
                            "register '{}': you don't own this space",
                            params.name
                        ));
                    }

                    if !tx.force {
                        let claim_height = utxo.spaceout.space.as_ref().unwrap().claim_height();
                        let tip_height = wallet.spaces.local_chain().tip().height();

                        if claim_height.is_none() {
                            return Err(anyhow!(
                                "register '{}': cannot register a space in pre-auctions",
                                params.name
                            ));
                        }

                        let claim_height = claim_height.unwrap();
                        if claim_height > tip_height {
                            return Err(anyhow!(
                                "register '{}': cannot register until claim height {}",
                                params.name,
                                claim_height
                            ));
                        }
                    }

                    let address = match params.to {
                        None => wallet.next_unused_space_address(),
                        Some(address) => match SpaceAddress::from_str(&address) {
                            Ok(addr) => addr,
                            Err(_) => {
                                return Err(anyhow!(
                                    "transfer '{}': recipient must be a valid space address",
                                    params.name
                                ));
                            }
                        },
                    };

                    builder = builder.add_register(utxo, Some(address));
                }
                RpcWalletRequest::Execute(params) => {
                    let mut spaces = Vec::new();
                    for space in params.context.iter() {
                        let name = SLabel::from_str(&space)?;
                        let spacehash = SpaceKey::from(Sha256::hash(name.as_ref()));
                        let spaceout = store.get_space_info(&spacehash)?;
                        if spaceout.is_none() {
                            return Err(anyhow!("execute on '{}': space does not exist", space));
                        }
                        let spaceout = spaceout.unwrap();
                        if !wallet.spaces.is_mine(&spaceout.spaceout.script_pubkey) {
                            return Err(anyhow!(
                                "execute on '{}': you don't own this space",
                                space
                            ));
                        }
                        let address = wallet.next_unused_space_address();
                        spaces.push(SpaceTransfer {
                            space: spaceout,
                            recipient: address.0,
                        });
                    }

                    let script = SpaceScript::nop_script(params.space_script);
                    builder = builder.add_execute(spaces, script);
                }
            }
        }

        let median_time = source.get_median_time()?;
        let coin_selection = Self::get_spaces_coin_selection(wallet, store)?;

        let mut tx_iter = builder.build_iter(tx.dust, median_time, wallet, coin_selection)?;

        let mut result_set = Vec::new();
        let mut raw_set = Vec::new();
        let mut has_errors = false;
        while let Some(tx_result) = tx_iter.next() {
            let tagged = tx_result?;

            let is_bid = tagged.tags.iter().any(|tag| *tag == TransactionTag::Bid);
            result_set.push(TxResponse {
                txid: tagged.tx.compute_txid(),
                tags: tagged.tags,
                error: None,
            });

            let raw = bitcoin::consensus::encode::serialize_hex(&tagged.tx);
            raw_set.push(raw);
            let result = source.rpc.broadcast_tx(&source.client, &tagged.tx);
            match result {
                Ok(confirmation) => {
                    tx_iter.wallet.insert_tx(tagged.tx, confirmation)?;
                    tx_iter.wallet.commit()?;
                }
                Err(e) => {
                    has_errors = true;
                    let mut error_data = BTreeMap::new();
                    if let BitcoinRpcError::Rpc(rpc) = e {
                        if is_bid {
                            if rpc.message.contains("replacement-adds-unconfirmed") {
                                error_data.insert(
                                    "hint".to_string(),
                                    "If you have don't have confirmed auction outputs, you cannot \
                                                  replace bids in the mempool."
                                        .to_string(),
                                );
                            }

                            if let Some(fee_rate) = fee_rate_from_message(&rpc.message) {
                                error_data.insert(
                                    "hint".to_string(),
                                    format!(
                                        "A competing bid in the mempool; replace \
                                                  with a feerate > {} sat/vB.",
                                        fee_rate.to_sat_per_vb_ceil()
                                    ),
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

        Ok(WalletResponse {
            sent: result_set,
            raw: if has_errors { Some(raw_set) } else { None },
        })
    }

    pub async fn service(
        network: ExtendedNetwork,
        rpc: BitcoinRpc,
        store: LiveSnapshot,
        mut channel: Receiver<LoadedWallet>,
        shutdown: broadcast::Sender<()>,
        num_workers: usize,
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
                    if let Some( loaded ) = wallet {
                        let wallet_name = loaded.wallet.name().to_string();
                        info!("Loaded wallet: {}", wallet_name);

                        let wallet_chain = store.clone();
                        let rpc = rpc.clone();
                        let wallet_shutdown = shutdown.subscribe();
                        let (tx, rx) = oneshot::channel();

                        std::thread::spawn(move || {
                            let source = BitcoinBlockSource::new(rpc);
                            _ = tx.send(Self::wallet_sync(
                                network,
                                source,
                                wallet_chain,
                                loaded.wallet,
                                loaded.rx,
                                wallet_shutdown,
                                num_workers
                            ));
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

    pub async fn send_get_info(&self) -> anyhow::Result<WalletInfo> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender.send(WalletCommand::GetInfo { resp }).await?;
        resp_rx.await?
    }

    pub async fn send_batch_tx(
        &self,
        request: RpcWalletTxBuilder,
    ) -> anyhow::Result<WalletResponse> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender
            .send(WalletCommand::BatchTx { request, resp })
            .await?;
        resp_rx.await?
    }

    pub async fn send_get_new_address(&self, kind: AddressKind) -> anyhow::Result<String> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender
            .send(WalletCommand::GetNewAddress { kind, resp })
            .await?;
        resp_rx.await?
    }

    pub async fn send_fee_bump(
        &self,
        txid: Txid,
        fee_rate: FeeRate,
    ) -> anyhow::Result<Vec<TxResponse>> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender
            .send(WalletCommand::BumpFee {
                txid,
                fee_rate,
                resp,
            })
            .await?;
        resp_rx.await?
    }

    pub async fn send_force_spend(
        &self,
        outpoint: OutPoint,
        fee_rate: FeeRate,
    ) -> anyhow::Result<TxResponse> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender
            .send(WalletCommand::ForceSpendOutput {
                outpoint,
                fee_rate,
                resp,
            })
            .await?;
        resp_rx.await?
    }

    pub async fn send_list_spaces(&self) -> anyhow::Result<Vec<WalletOutput>> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender.send(WalletCommand::ListSpaces { resp }).await?;
        resp_rx.await?
    }

    pub async fn send_list_auction_outputs(&self) -> anyhow::Result<Vec<DoubleUtxo>> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender
            .send(WalletCommand::ListAuctionOutputs { resp })
            .await?;
        resp_rx.await?
    }

    pub async fn send_list_unspent(&self) -> anyhow::Result<Vec<WalletOutput>> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender
            .send(WalletCommand::ListUnspent { resp })
            .await?;
        resp_rx.await?
    }

    pub async fn send_get_balance(&self) -> anyhow::Result<Balance> {
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

    let fee_value = old_fee_str.split_whitespace().nth(2)?.parse::<f64>().ok()?;

    let fee_rate_sat_vb = (fee_value * 100_000.0) as u64;
    FeeRate::from_sat_per_vb(fee_rate_sat_vb)
}

async fn named_future<T>(
    name: String,
    rx: tokio::sync::oneshot::Receiver<T>,
) -> (String, Result<T, tokio::sync::oneshot::error::RecvError>) {
    (name, rx.await)
}
