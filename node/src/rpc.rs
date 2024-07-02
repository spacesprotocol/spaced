use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use anyhow::{anyhow, Context};
use bdk::bitcoin::{Amount, BlockHash, FeeRate, Txid};
use bdk::{KeychainKind, LocalOutput};
use bdk::bitcoin::Network::Signet;
use bdk::keys::bip39::{Language, Mnemonic, WordCount};
use bdk::keys::{DerivableKey, ExtendedKey, GeneratableKey, GeneratedKey};
use bdk::miniscript::Tap;
use bdk::template::Bip84;
use bdk_bitcoind_rpc::bitcoincore_rpc::RpcApi;
use bdk_chain::bitcoin::Network;
use bdk_chain::BlockId;
use protocol::bitcoin::{OutPoint};
use jsonrpsee::core::async_trait;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::server::Server;
use jsonrpsee::types::{ErrorObjectOwned};
use log::{info};
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc, oneshot, RwLock};
use tokio::task::JoinSet;
use protocol::{FullSpaceOut, Params, SpaceOut};
use protocol::bitcoin::bip32::Xpriv;
use protocol::bitcoin::Network::{Regtest, Testnet};
use protocol::hasher::{BaseHash, SpaceHash};
use crate::store::{LiveSnapshot, ChainState};
use protocol::prepare::DataSource;
use wallet::{CoinDescriptors, DoubleUtxo, derivation, SpaceDescriptors, SuperWallet, WalletConfig};
use wallet::derivation::SpaceDerivation;
use crate::node::{ValidatedBlock};
use crate::source::RpcBlockchain;
use crate::wallets::{AddressKind, JointBalance, RpcWallet, TxEntry, WalletCommand};

pub(crate) type Responder<T> = oneshot::Sender<T>;

pub enum ChainStateCommand {
    GetSpaceInfo {
        hash: SpaceHash,
        resp: Responder<anyhow::Result<Option<FullSpaceOut>>>,
    },

    GetSpaceout {
        outpoint: OutPoint,
        resp: Responder<anyhow::Result<Option<SpaceOut>>>,
    },
    GetSpaceOutpoint {
        hash: SpaceHash,
        resp: Responder<anyhow::Result<Option<OutPoint>>>,
    },
    GetBlockData {
        block_hash: BlockHash,
        resp: Responder<anyhow::Result<Option<ValidatedBlock>>>,
    },
    EstimateBid {
        target: usize,
        resp: Responder<anyhow::Result<u64>>,
    },
    GetRollout {
        target: usize,
        resp: Responder<anyhow::Result<Vec<(u32, SpaceHash)>>>,
    },
}

#[derive(Clone)]
pub struct AsyncChainState {
    sender: mpsc::Sender<ChainStateCommand>,
}

#[rpc(server, client)]
pub trait Rpc {
    #[method(name = "getspaceinfo")]
    async fn get_space_info(
        &self,
        space_hash: String,
    ) -> Result<Option<FullSpaceOut>, ErrorObjectOwned>;

    #[method(name = "estimatebid")]
    async fn estimate_bid(
        &self,
        target: usize,
    ) -> Result<u64, ErrorObjectOwned>;

    #[method(name = "getrollout")]
    async fn get_rollout(
        &self,
        target: usize,
    ) -> Result<Vec<(u32, SpaceHash)>, ErrorObjectOwned>;

    #[method(name = "getspaceowner")]
    async fn get_space_owner(
        &self,
        space_hash: String,
    ) -> Result<Option<OutPoint>, ErrorObjectOwned>;

    #[method(name = "getspaceout")]
    async fn get_spaceout(
        &self,
        outpoint: OutPoint,
    ) -> Result<Option<SpaceOut>, ErrorObjectOwned>;


    #[method(name = "getblockdata")]
    async fn get_block_data(
        &self,
        block_hash: BlockHash,
    ) -> Result<Option<ValidatedBlock>, ErrorObjectOwned>;

    #[method(name = "walletload")]
    async fn wallet_load(
        &self,
        name: String,
    ) -> Result<(), ErrorObjectOwned>;

    #[method(name = "walletcreate")]
    async fn wallet_create(
        &self,
        name: String,
    ) -> Result<(), ErrorObjectOwned>;

    #[method(name = "walletsendrequest")]
    async fn wallet_send_request(
        &self,
        wallet: String,
        request: RpcWalletTxBuilder,
    ) -> Result<Vec<TxEntry>, ErrorObjectOwned>;

    #[method(name = "walletgetnewaddress")]
    async fn wallet_get_new_address(
        &self,
        wallet: String,
        kind: AddressKind,
    ) -> Result<String, ErrorObjectOwned>;

    #[method(name = "walletbumpfee")]
    async fn wallet_bump_fee(
        &self,
        wallet: String,
        txid: Txid,
        fee_rate: FeeRate,
    ) -> Result<Vec<TxEntry>, ErrorObjectOwned>;

    #[method(name = "walletlistspaces")]
    async fn wallet_list_spaces(
        &self,
        wallet: String,
    ) -> Result<Vec<FullSpaceOut>, ErrorObjectOwned>;

    #[method(name = "walletlistunspent")]
    async fn wallet_list_unspent(
        &self,
        wallet: String,
    ) -> Result<Vec<LocalOutput>, ErrorObjectOwned>;

    #[method(name = "walletlistauctionoutputs")]
    async fn wallet_list_auction_outputs(
        &self,
        wallet: String,
    ) -> Result<Vec<DoubleUtxo>, ErrorObjectOwned>;

    #[method(name = "walletgetbalance")]
    async fn wallet_get_balance(
        &self,
        wallet: String,
    ) -> Result<JointBalance, ErrorObjectOwned>;
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RpcWalletTxBuilder {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auction_outputs: Option<u8>,
    pub requests: Vec<RpcWalletRequest>,
    pub fee_rate: Option<FeeRate>,
    pub dust: Option<Amount>,
    pub force: bool,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "request")]
pub enum RpcWalletRequest {
    #[serde(rename = "open")]
    Open(OpenParams),
    #[serde(rename = "bid")]
    Bid(BidParams),
    #[serde(rename = "register")]
    Register(RegisterParams),
    #[serde(rename = "execute")]
    Execute(ExecuteParams),
    #[serde(rename = "sendspaces")]
    Transfer(TransferSpacesParams),
    #[serde(rename = "sendcoins")]
    SendCoins(SendCoinsParams),
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TransferSpacesParams {
    pub spaces: Vec<String>,
    pub to: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SendCoinsParams {
    pub amount: Amount,
    pub to: String,
}


#[derive(Clone, Serialize, Deserialize)]
pub struct ExecuteParams {
    pub context: Vec<String>,
    pub space_script: protocol::script::ScriptBuilder,
}


#[derive(Clone, Serialize, Deserialize)]
pub struct OpenParams {
    pub name: String,
    pub amount: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BidParams {
    pub name: String,
    pub amount: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TransferParams {
    pub name: String,
    pub to: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RegisterParams {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
}

#[derive(Clone)]
pub struct RpcServerImpl {
    wallet_manager: WalletManager,
    store: AsyncChainState,

}

#[derive(Clone)]
pub struct WalletManager {
    pub data_dir: PathBuf,
    pub network: Network,
    pub params: Params,
    pub source: RpcBlockchain,
    pub wallet_loader: mpsc::Sender<(SuperWallet, mpsc::Receiver<WalletCommand>)>,
    pub wallets: Arc<RwLock<BTreeMap<String, RpcWallet>>>,
}

const RPC_WALLET_NOT_LOADED: i32 = -18;

impl WalletManager {


    pub async fn create_wallet(&self, name: String) -> anyhow::Result<()> {
        let wallet_path = self.data_dir.join(&name);
        if wallet_path.exists() {
            return Err(anyhow!("Wallet already exists"));
        }

        let mnemonic: GeneratedKey<_, Tap> =
            Mnemonic::generate((WordCount::Words12, Language::English))
                .map_err(|_| anyhow!("Mnemonic generation error"))?;


        fs::create_dir_all(&wallet_path)?;
        let secret_file_path = wallet_path.join("insecure_secret");
        let mut file = fs::File::create(secret_file_path)?;
        file.write_all(mnemonic.to_string().as_bytes())?;

        let birthday = self.get_wallet_birthday().await?;
        self.load_wallet(name, Some(birthday)).await?;
        Ok(())
    }

    pub async fn load_wallet(&self, name: String, checkpoint: Option<BlockId>) -> anyhow::Result<()> {
        let wallet_path = self.data_dir.join(name.clone());
        if !wallet_path.exists() {
            return Err(anyhow!("Wallet does not exist"));
        }

        let secret_file_path = wallet_path.join("insecure_secret");
        let mut file = fs::File::open(secret_file_path)?;
        let mut mnemonic = String::new();
        file.read_to_string(&mut mnemonic)?;
        let mnemonic = mnemonic.trim();

        let mut genesis_hash = None;
        // Use testnet in the wallet if regtest is specified to work around
        // a bug in bdk comparing regtest descriptors
        let network = if self.network == Regtest {
            genesis_hash = Some(
                bdk::bitcoin::constants::genesis_block(Regtest)
                    .header.block_hash()
            );
            Testnet
        } else if self.network == Signet {
            genesis_hash = Some(
                bdk::bitcoin::constants::genesis_block(Signet)
                    .header.block_hash()
            );
            Testnet
        } else {
            self.network
        };

        let xpriv = Self::descriptor_from_mnemonic(network, mnemonic)?;

        let coins_descriptors = Self::default_coin_descriptors(xpriv);
        let space_descriptors = Self::default_spaces_descriptors(xpriv);

        let mut wallet = SuperWallet::new(WalletConfig {
            data_dir: wallet_path,
            name: name.clone(),
            network,
            genesis_hash,
            coins_descriptors,
            space_descriptors,
        })?;

        if let Some(checkpoint) = checkpoint {
            wallet.coins.insert_checkpoint(checkpoint)?;
            wallet.spaces.insert_checkpoint(checkpoint)?;
            wallet.commit()?;
        }

        let (rpc_wallet, rpc_wallet_rx) = RpcWallet::new();
        self.wallet_loader.send((wallet, rpc_wallet_rx)).await?;
        let mut wallets = self.wallets.write().await;
        wallets.insert(name, rpc_wallet);
        Ok(())
    }

    async fn get_wallet_birthday(&self) -> anyhow::Result<BlockId> {
        let blocking_source = self.source.clone();
        tokio::task::spawn_blocking(move || {
            let result = blocking_source.client.get_blockchain_info()?;
            let height = std::cmp::max(result.blocks as i32 - 20 , 0) as u32;
            let hash = blocking_source.client.get_block_hash(height as u64)?;
            Ok::<BlockId, anyhow::Error>(BlockId {
                height,
                hash,
            })
        }).await?
    }

    fn descriptor_from_mnemonic(network: Network, m: &str) -> anyhow::Result<Xpriv> {
        let mnemonic = Mnemonic::parse(m).unwrap();
        let xkey: ExtendedKey = mnemonic.clone()
            .into_extended_key()?;
        Ok(xkey.into_xprv(network).expect("xpriv"))
    }

    fn default_coin_descriptors(x: Xpriv) -> CoinDescriptors<Bip84<Xpriv>> {
        CoinDescriptors {
            external: Bip84(x, KeychainKind::External),
            change: Some(Bip84(x, KeychainKind::Internal)),
        }
    }

    fn default_spaces_descriptors(x: Xpriv) -> SpaceDescriptors<SpaceDerivation<Xpriv>> {
        SpaceDescriptors {
            external: derivation::SpaceDerivation(x, KeychainKind::External),
            internal: derivation::SpaceDerivation(x, KeychainKind::Internal),
        }
    }
}

impl RpcServerImpl {
    pub fn new(
        store: AsyncChainState,
        wallet_manager: WalletManager,
    ) -> Self {
        RpcServerImpl {
            wallet_manager,
            store,
        }
    }

    async fn wallet(&self, wallet: &str) -> Result<RpcWallet, ErrorObjectOwned> {
        let wallets = self.wallet_manager.wallets.read().await;
        wallets.get(wallet).cloned().ok_or_else(||
            ErrorObjectOwned::owned(
                RPC_WALLET_NOT_LOADED,
                format!("Wallet '{}' not loaded", wallet),
                None::<String>,
            )
        )
    }


    pub async fn listen(self, addrs: Vec<SocketAddr>, signal: broadcast::Sender<()>) -> anyhow::Result<()> {
        let mut listeners: Vec<Server> = Vec::with_capacity(addrs.len());
        for addr in addrs.iter() {
            let server = Server::builder()
                .build(addr).await?;
            listeners.push(server);
        }

        let mut set = JoinSet::new();
        for listener in listeners {
            let addr = listener.local_addr()?;
            info!("Listening at {addr}");

            let handle = listener.start(self.clone().into_rpc());

            let mut signal = signal.subscribe();
            set.spawn(async move {
                tokio::select! {
                    _ = handle.clone().stopped() => {
                        // Server stopped normally
                    },
                    _ = signal.recv() => {
                        // Shutdown signal received
                        info!("Shutting down listener {addr}...");
                        _ = handle.stop();
                    }
                }
            });
        }

        while let Some(task_result) = set.join_next().await {
            if let Err(e) = task_result {
                _ = signal.send(());
                return Err(anyhow!("A server listener failed: {:?}", e));
            }
        }

        Ok(())
    }
}


#[async_trait]
impl RpcServer for RpcServerImpl {
    async fn get_space_info(&self, space_hash_str: String) -> Result<Option<FullSpaceOut>, ErrorObjectOwned> {
        let mut space_hash = [0u8; 32];
        hex::decode_to_slice(space_hash_str, &mut space_hash).map_err(|_| ErrorObjectOwned::owned(
            -1, "expected a 32-byte hex encoded space hash a", None::<String>,
        ))?;
        let space_hash = SpaceHash::from_raw(space_hash).map_err(|_| ErrorObjectOwned::owned(
            -1, "expected a 32-byte hex encoded space hash b", None::<String>,
        ))?;

        let info = self.store.get_space_info(space_hash).await.map_err(|error|
            ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))?;
        Ok(info)
    }

    async fn estimate_bid(&self, target: usize) -> Result<u64, ErrorObjectOwned> {
        let info = self.store.estimate_bid(target).await.map_err(|error|
            ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))?;
        Ok(info)
    }

    async fn get_rollout(&self, target: usize) -> Result<Vec<(u32, SpaceHash)>, ErrorObjectOwned> {
        let rollouts = self.store.get_rollout(target).await.map_err(|error|
            ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))?;
        Ok(rollouts)
    }

    async fn get_space_owner(&self, space_hash_str: String) -> Result<Option<OutPoint>, ErrorObjectOwned> {
        let mut space_hash = [0u8; 32];
        hex::decode_to_slice(space_hash_str, &mut space_hash).map_err(|_| ErrorObjectOwned::owned(
            -1, "expected a 32-byte hex encoded space hash", None::<String>,
        ))?;
        let space_hash = SpaceHash::from_raw(space_hash).map_err(|_| ErrorObjectOwned::owned(
            -1, "expected a 32-byte hex encoded space hash", None::<String>,
        ))?;

        let info = self.store.get_space_outpoint(space_hash).await.map_err(|error|
            ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))?;

        Ok(info)
    }

    async fn get_spaceout(&self, outpoint: OutPoint) -> Result<Option<SpaceOut>, ErrorObjectOwned> {
        let spaceout = self.store.get_spaceout(outpoint).await.map_err(|error|
            ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))?;
        Ok(spaceout)
    }

    async fn get_block_data(&self, block_hash: BlockHash) -> Result<Option<ValidatedBlock>, ErrorObjectOwned> {
        let data = self.store.get_block_data(block_hash).await.map_err(|error|
            ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))?;
        Ok(data)
    }

    async fn wallet_load(&self, name: String) -> Result<(), ErrorObjectOwned> {
        self.wallet_manager.load_wallet(name, None)
            .await.map_err(|error|
            ErrorObjectOwned::owned(RPC_WALLET_NOT_LOADED, error.to_string(), None::<String>))
    }

    async fn wallet_create(&self, name: String) -> Result<(), ErrorObjectOwned> {
        self.wallet_manager.create_wallet(name.clone()).await.map_err(|error|
            ErrorObjectOwned::owned(RPC_WALLET_NOT_LOADED, error.to_string(), None::<String>))
    }

    async fn wallet_send_request(&self, wallet: String, request: RpcWalletTxBuilder) -> Result<Vec<TxEntry>, ErrorObjectOwned> {
        let result = self.wallet(&wallet).await?
            .send_batch_tx(request).await.map_err(|error|
            ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))?;
        Ok(result)
    }

    async fn wallet_get_new_address(&self, wallet: String, kind: AddressKind) -> Result<String, ErrorObjectOwned> {
        self.wallet(&wallet).await?
            .send_get_new_address(kind).await.map_err(|error|
            ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))
    }

    async fn wallet_bump_fee(&self, wallet: String, txid: Txid, fee_rate: FeeRate) -> Result<Vec<TxEntry>, ErrorObjectOwned> {
        self.wallet(&wallet).await?
            .send_fee_bump(txid, fee_rate).await.map_err(|error|
            ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))
    }

    async fn wallet_list_unspent(&self, wallet: String) -> Result<Vec<LocalOutput>, ErrorObjectOwned> {
        self.wallet(&wallet).await?
            .send_list_unspent().await.map_err(|error|
            ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))
    }

    async fn wallet_list_spaces(&self, wallet: String) -> Result<Vec<FullSpaceOut>, ErrorObjectOwned> {
        self.wallet(&wallet).await?
            .send_list_spaces().await.map_err(|error|
            ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))
    }

    async fn wallet_list_auction_outputs(&self, wallet: String) -> Result<Vec<DoubleUtxo>, ErrorObjectOwned> {
        self.wallet(&wallet).await?
            .send_list_auction_outputs().await.map_err(|error|
            ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))
    }

    async fn wallet_get_balance(&self, wallet: String) -> Result<JointBalance, ErrorObjectOwned> {
        self.wallet(&wallet).await?
            .send_get_balance().await.map_err(|error|
            ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))
    }
}

impl AsyncChainState {
    pub fn new(sender: mpsc::Sender<ChainStateCommand>) -> Self {
        Self { sender }
    }

    pub async fn handler(mut chain_state: LiveSnapshot, mut block_index: Option<LiveSnapshot>, mut rx: mpsc::Receiver<ChainStateCommand>) {
        while let Some(cmd) = rx.recv().await {
            match cmd {
                ChainStateCommand::GetSpaceInfo { hash, resp } => {
                    let result = chain_state
                        .get_space_info(&hash);
                    let _ = resp.send(result);
                }
                ChainStateCommand::GetSpaceout { outpoint, resp } => {
                    let result = chain_state
                        .get_spaceout(&outpoint).context("could not fetch spaceout");
                    let _ = resp.send(result);
                }
                ChainStateCommand::GetSpaceOutpoint { hash, resp } => {
                    let result = chain_state
                        .get_space_outpoint(&hash).context("could not fetch spaceout");
                    let _ = resp.send(result);
                }
                ChainStateCommand::GetBlockData { block_hash, resp } => {
                    match &mut block_index {
                        None => {
                            let _ = resp.send(Err(anyhow!("block index must be enabled")));
                        }
                        Some(index) => {
                            let hash = BaseHash::from_slice(block_hash.as_ref());
                            let _ = resp.send(index.get(hash)
                                .context("Could not fetch blockdata from index")
                            );
                        }
                    }
                }
                ChainStateCommand::EstimateBid { target, resp } => {
                    let estimate = chain_state.estimate_bid(target);
                    _ = resp.send(estimate);
                }
                ChainStateCommand::GetRollout { target, resp } => {
                    let rollouts = chain_state.get_rollout(target);
                    _ = resp.send(rollouts);
                }
            }
        };
    }

    pub async fn estimate_bid(&self, target: usize) -> anyhow::Result<u64> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender.send(ChainStateCommand::EstimateBid { target, resp }).await?;
        resp_rx.await?
    }

    pub async fn get_rollout(&self, target: usize) -> anyhow::Result<Vec<(u32, SpaceHash)>> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender.send(ChainStateCommand::GetRollout { target, resp }).await?;
        resp_rx.await?
    }

    pub async fn get_space_info(&self, hash: SpaceHash) -> anyhow::Result<Option<FullSpaceOut>> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender.send(ChainStateCommand::GetSpaceInfo { hash, resp }).await?;
        resp_rx.await?
    }

    pub async fn get_space_outpoint(&self, hash: SpaceHash) -> anyhow::Result<Option<OutPoint>> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender.send(ChainStateCommand::GetSpaceOutpoint { hash, resp }).await?;
        resp_rx.await?
    }

    pub async fn get_spaceout(&self, outpoint: OutPoint) -> anyhow::Result<Option<SpaceOut>> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender.send(ChainStateCommand::GetSpaceout { outpoint, resp }).await?;
        resp_rx.await?
    }

    pub async fn get_block_data(&self, block_hash: BlockHash) -> anyhow::Result<Option<ValidatedBlock>> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender.send(ChainStateCommand::GetBlockData { block_hash, resp }).await?;
        resp_rx.await?
    }
}
