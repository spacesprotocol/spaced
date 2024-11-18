use std::{
    collections::BTreeMap, fs, io::Write, net::SocketAddr, path::PathBuf, str::FromStr, sync::Arc,
};

use anyhow::{anyhow, Context};
use bdk::{
    bitcoin::{Amount, BlockHash, FeeRate, Network, Txid},
    chain::BlockId,
    keys::{
        bip39::{Language, Mnemonic, WordCount},
        DerivableKey, ExtendedKey, GeneratableKey, GeneratedKey,
    },
    miniscript::Tap,
    KeychainKind,
};
use jsonrpsee::{core::async_trait, proc_macros::rpc, server::Server, types::ErrorObjectOwned};
use log::info;
use protocol::{
    bitcoin::{
        bip32::Xpriv,
        Network::{Regtest, Testnet},
        OutPoint,
    },
    constants::ChainAnchor,
    hasher::{BaseHash, KeyHasher, SpaceKey},
    prepare::DataSource,
    slabel::SLabel,
    FullSpaceOut, SpaceOut,
};
use serde::{Deserialize, Serialize};
use tokio::{
    select,
    sync::{broadcast, mpsc, oneshot, RwLock},
    task::JoinSet,
};
use wallet::{
    bdk_wallet as bdk, bdk_wallet::template::Bip86, bitcoin::hashes::Hash, export::WalletExport,
    DoubleUtxo, SpacesWallet, WalletConfig, WalletDescriptors, WalletInfo,
};

use crate::{
    config::ExtendedNetwork,
    node::{BlockMeta, TxEntry},
    source::BitcoinRpc,
    store::{ChainState, LiveSnapshot, RolloutEntry, Sha256},
    wallets::{
        AddressKind, Balance, RpcWallet, TxResponse, WalletCommand, WalletOutput, WalletResponse,
    },
};

pub(crate) type Responder<T> = oneshot::Sender<T>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    pub chain: ExtendedNetwork,
    pub tip: ChainAnchor,
}

pub enum ChainStateCommand {
    GetTip {
        resp: Responder<anyhow::Result<ChainAnchor>>,
    },
    GetSpace {
        hash: SpaceKey,
        resp: Responder<anyhow::Result<Option<FullSpaceOut>>>,
    },

    GetSpaceout {
        outpoint: OutPoint,
        resp: Responder<anyhow::Result<Option<SpaceOut>>>,
    },
    GetSpaceOutpoint {
        hash: SpaceKey,
        resp: Responder<anyhow::Result<Option<OutPoint>>>,
    },
    GetTxMeta {
        txid: Txid,
        resp: Responder<anyhow::Result<Option<TxEntry>>>,
    },
    GetBlockMeta {
        block_hash: BlockHash,
        resp: Responder<anyhow::Result<Option<BlockMeta>>>,
    },
    EstimateBid {
        target: usize,
        resp: Responder<anyhow::Result<u64>>,
    },
    GetRollout {
        target: usize,
        resp: Responder<anyhow::Result<Vec<RolloutEntry>>>,
    },
}

#[derive(Clone)]
pub struct AsyncChainState {
    sender: mpsc::Sender<ChainStateCommand>,
}

#[rpc(server, client)]
pub trait Rpc {
    #[method(name = "getserverinfo")]
    async fn get_server_info(&self) -> Result<ServerInfo, ErrorObjectOwned>;

    #[method(name = "getspace")]
    async fn get_space(
        &self,
        space_or_hash: &str,
    ) -> Result<Option<FullSpaceOut>, ErrorObjectOwned>;

    #[method(name = "getspaceowner")]
    async fn get_space_owner(
        &self,
        space_or_hash: &str,
    ) -> Result<Option<OutPoint>, ErrorObjectOwned>;

    #[method(name = "getspaceout")]
    async fn get_spaceout(&self, outpoint: OutPoint) -> Result<Option<SpaceOut>, ErrorObjectOwned>;

    #[method(name = "estimatebid")]
    async fn estimate_bid(&self, target: usize) -> Result<u64, ErrorObjectOwned>;

    #[method(name = "getrollout")]
    async fn get_rollout(&self, target: usize) -> Result<Vec<RolloutEntry>, ErrorObjectOwned>;

    #[method(name = "getblockmeta")]
    async fn get_block_meta(
        &self,
        block_hash: BlockHash,
    ) -> Result<Option<BlockMeta>, ErrorObjectOwned>;

    #[method(name = "gettxmeta")]
    async fn get_tx_meta(&self, txid: Txid) -> Result<Option<TxEntry>, ErrorObjectOwned>;

    #[method(name = "walletload")]
    async fn wallet_load(&self, name: &str) -> Result<(), ErrorObjectOwned>;

    #[method(name = "walletimport")]
    async fn wallet_import(&self, wallet: WalletExport) -> Result<(), ErrorObjectOwned>;

    #[method(name = "walletgetinfo")]
    async fn wallet_get_info(&self, name: &str) -> Result<WalletInfo, ErrorObjectOwned>;

    #[method(name = "walletexport")]
    async fn wallet_export(&self, name: &str) -> Result<WalletExport, ErrorObjectOwned>;

    #[method(name = "walletcreate")]
    async fn wallet_create(&self, name: &str) -> Result<(), ErrorObjectOwned>;

    #[method(name = "walletsendrequest")]
    async fn wallet_send_request(
        &self,
        wallet: &str,
        request: RpcWalletTxBuilder,
    ) -> Result<WalletResponse, ErrorObjectOwned>;

    #[method(name = "walletgetnewaddress")]
    async fn wallet_get_new_address(
        &self,
        wallet: &str,
        kind: AddressKind,
    ) -> Result<String, ErrorObjectOwned>;

    #[method(name = "walletbumpfee")]
    async fn wallet_bump_fee(
        &self,
        wallet: &str,
        txid: Txid,
        fee_rate: FeeRate,
    ) -> Result<Vec<TxResponse>, ErrorObjectOwned>;

    #[method(name = "walletforcespend")]
    async fn wallet_force_spend(
        &self,
        wallet: &str,
        outpoint: OutPoint,
        fee_rate: FeeRate,
    ) -> Result<TxResponse, ErrorObjectOwned>;

    #[method(name = "walletlistspaces")]
    async fn wallet_list_spaces(&self, wallet: &str)
        -> Result<Vec<WalletOutput>, ErrorObjectOwned>;

    #[method(name = "walletlistunspent")]
    async fn wallet_list_unspent(
        &self,
        wallet: &str,
    ) -> Result<Vec<WalletOutput>, ErrorObjectOwned>;

    #[method(name = "walletlistbidouts")]
    async fn wallet_list_bidouts(&self, wallet: &str) -> Result<Vec<DoubleUtxo>, ErrorObjectOwned>;

    #[method(name = "walletgetbalance")]
    async fn wallet_get_balance(&self, wallet: &str) -> Result<Balance, ErrorObjectOwned>;
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RpcWalletTxBuilder {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bidouts: Option<u8>,
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
    pub space_script: Vec<u8>,
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
    client: reqwest::Client,
}

#[derive(Clone)]
pub struct WalletManager {
    pub data_dir: PathBuf,
    pub network: ExtendedNetwork,
    pub rpc: BitcoinRpc,
    pub wallet_loader: mpsc::Sender<LoadedWallet>,
    pub wallets: Arc<RwLock<BTreeMap<String, RpcWallet>>>,
}

pub struct LoadedWallet {
    pub(crate) rx: mpsc::Receiver<WalletCommand>,
    pub(crate) wallet: SpacesWallet,
}

const RPC_WALLET_NOT_LOADED: i32 = -18;

impl LoadedWallet {
    fn new(wallet: SpacesWallet, rx: mpsc::Receiver<WalletCommand>) -> Self {
        Self { rx, wallet }
    }
}

impl WalletManager {
    pub async fn import_wallet(
        &self,
        client: &reqwest::Client,
        wallet: WalletExport,
    ) -> anyhow::Result<()> {
        let wallet_path = self.data_dir.join(&wallet.label);
        if wallet_path.exists() {
            return Err(anyhow!(format!(
                "Wallet with label `{}` already exists",
                wallet.label
            )));
        }

        fs::create_dir_all(&wallet_path)?;
        let wallet_export_path = wallet_path.join("wallet.json");
        let mut file = fs::File::create(wallet_export_path)?;
        file.write_all(wallet.to_string().as_bytes())?;

        self.load_wallet(client, &wallet.label).await?;
        Ok(())
    }

    pub async fn export_wallet(&self, name: &str) -> anyhow::Result<WalletExport> {
        let wallet_dir = self.data_dir.join(name);
        if !wallet_dir.exists() {
            return Err(anyhow!("Wallet does not exist"));
        }
        let wallet = fs::read_to_string(wallet_dir.join("wallet.json"))?;
        let export: WalletExport = serde_json::from_str(&wallet)?;
        Ok(export)
    }

    pub async fn create_wallet(&self, client: &reqwest::Client, name: &str) -> anyhow::Result<()> {
        let mnemonic: GeneratedKey<_, Tap> =
            Mnemonic::generate((WordCount::Words12, Language::English))
                .map_err(|_| anyhow!("Mnemonic generation error"))?;

        let start_block = self.get_wallet_start_block(client).await?;
        self.setup_new_wallet(name.to_string(), mnemonic.to_string(), start_block)?;
        self.load_wallet(client, name).await?;
        Ok(())
    }

    fn setup_new_wallet(
        &self,
        name: String,
        mnemonic: String,
        start_block: BlockId,
    ) -> anyhow::Result<()> {
        let wallet_path = self.data_dir.join(&name);
        if wallet_path.exists() {
            return Err(anyhow!(format!("Wallet `{}` already exists", name)));
        }

        let export = self.wallet_from_mnemonic(name.clone(), mnemonic.to_string(), start_block)?;
        fs::create_dir_all(&wallet_path)?;
        let wallet_export_path = wallet_path.join("wallet.json");
        let mut file = fs::File::create(wallet_export_path)?;
        file.write_all(export.to_string().as_bytes())?;
        Ok(())
    }

    fn wallet_from_mnemonic(
        &self,
        name: String,
        mnemonic: String,
        start_block: BlockId,
    ) -> anyhow::Result<WalletExport> {
        let (network, _) = self.fallback_network();
        let xpriv = Self::descriptor_from_mnemonic(network, &mnemonic.to_string())?;

        let (external, internal) = Self::default_descriptors(xpriv);
        let tmp = bdk::wallet::Wallet::new_or_load(external, internal, None, network)?;
        let export =
            WalletExport::export_wallet(&tmp, &name, start_block.height).map_err(|e| anyhow!(e))?;

        Ok(export)
    }

    fn fallback_network(&self) -> (Network, Option<BlockHash>) {
        let mut genesis_hash = None;

        let network = match self.network {
            ExtendedNetwork::Testnet => Network::Testnet,
            ExtendedNetwork::Testnet4 => {
                genesis_hash = Some(BlockHash::from_byte_array([
                    67, 240, 139, 218, 176, 80, 227, 91, 86, 124, 134, 75, 145, 244, 127, 80, 174,
                    114, 90, 226, 222, 83, 188, 251, 186, 242, 132, 218, 0, 0, 0, 0,
                ]));
                Network::Testnet
            }

            // Use testnet in the wallet if regtest is specified to work around
            // a bug in bdk comparing regtest descriptors
            // TODO: might have been fixed already?
            ExtendedNetwork::Regtest => {
                genesis_hash = Some(
                    bdk::bitcoin::constants::genesis_block(Regtest)
                        .header
                        .block_hash(),
                );
                Network::Regtest
            }
            ExtendedNetwork::Signet => {
                genesis_hash = Some(
                    bdk::bitcoin::constants::genesis_block(Network::Signet)
                        .header
                        .block_hash(),
                );
                Testnet
            }
            _ => self.network.fallback_network(),
        };

        (network, genesis_hash)
    }

    pub async fn load_wallet(&self, client: &reqwest::Client, name: &str) -> anyhow::Result<()> {
        let wallet_dir = self.data_dir.join(name);
        if !wallet_dir.exists() {
            return Err(anyhow!("Wallet does not exist"));
        }

        let file = fs::File::open(wallet_dir.join("wallet.json"))?;

        let (network, genesis_hash) = self.fallback_network();
        let export: WalletExport = serde_json::from_reader(file)?;

        let mut wallet = SpacesWallet::new(WalletConfig {
            start_block: export.blockheight,
            data_dir: wallet_dir,
            name: name.to_string(),
            network,
            genesis_hash,
            space_descriptors: WalletDescriptors {
                external: export.descriptor(),
                internal: export
                    .change_descriptor()
                    .expect("expected a change descriptor"),
            },
        })?;

        let wallet_tip = wallet.spaces.local_chain().tip().height();

        if wallet_tip < export.blockheight {
            let block_id = self.get_block_hash(client, export.blockheight).await?;
            wallet.spaces.insert_checkpoint(block_id)?;
            wallet.commit()?;
        }

        let (rpc_wallet, rpc_wallet_rx) = RpcWallet::new();
        let loaded_wallet = LoadedWallet::new(wallet, rpc_wallet_rx);

        self.wallet_loader.send(loaded_wallet).await?;
        let mut wallets = self.wallets.write().await;
        wallets.insert(name.to_string(), rpc_wallet);
        Ok(())
    }

    async fn get_block_hash(
        &self,
        client: &reqwest::Client,
        height: u32,
    ) -> anyhow::Result<BlockId> {
        let hash = self
            .rpc
            .send_json(&client, &self.rpc.get_block_hash(height))
            .await?;

        Ok(BlockId { height, hash })
    }

    async fn get_wallet_start_block(&self, client: &reqwest::Client) -> anyhow::Result<BlockId> {
        let count: i32 = self
            .rpc
            .send_json(&client, &self.rpc.get_block_count())
            .await?;
        let height = std::cmp::max(count - 20, 0) as u32;

        let hash = self
            .rpc
            .send_json(&client, &self.rpc.get_block_hash(height))
            .await?;

        Ok(BlockId { height, hash })
    }

    fn descriptor_from_mnemonic(network: Network, m: &str) -> anyhow::Result<Xpriv> {
        let mnemonic = Mnemonic::parse(m).unwrap();
        let xkey: ExtendedKey = mnemonic.clone().into_extended_key()?;
        Ok(xkey.into_xprv(network).expect("xpriv"))
    }

    fn default_descriptors(x: Xpriv) -> (Bip86<Xpriv>, Bip86<Xpriv>) {
        (
            Bip86(x, KeychainKind::External),
            Bip86(x, KeychainKind::Internal),
        )
    }
}

impl RpcServerImpl {
    pub fn new(store: AsyncChainState, wallet_manager: WalletManager) -> Self {
        RpcServerImpl {
            wallet_manager,
            store,
            client: reqwest::Client::new(),
        }
    }

    async fn wallet(&self, wallet: &str) -> Result<RpcWallet, ErrorObjectOwned> {
        let wallets = self.wallet_manager.wallets.read().await;
        wallets.get(wallet).cloned().ok_or_else(|| {
            ErrorObjectOwned::owned(
                RPC_WALLET_NOT_LOADED,
                format!("Wallet '{}' not loaded", wallet),
                None::<String>,
            )
        })
    }

    pub async fn listen(
        self,
        addrs: Vec<SocketAddr>,
        signal: broadcast::Sender<()>,
    ) -> anyhow::Result<()> {
        let mut listeners: Vec<Server> = Vec::with_capacity(addrs.len());
        for addr in addrs.iter() {
            let server = Server::builder().build(addr).await?;
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
    async fn get_server_info(&self) -> Result<ServerInfo, ErrorObjectOwned> {
        let chain = self.wallet_manager.network;
        let tip = self
            .store
            .get_tip()
            .await
            .map_err(|error| ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))?;
        Ok(ServerInfo { chain, tip })
    }

    async fn get_space(
        &self,
        space_or_hash: &str,
    ) -> Result<Option<FullSpaceOut>, ErrorObjectOwned> {
        let space_hash = get_space_key(space_or_hash)?;

        let info = self
            .store
            .get_space(space_hash)
            .await
            .map_err(|error| ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))?;
        Ok(info)
    }

    async fn get_space_owner(
        &self,
        space_or_hash: &str,
    ) -> Result<Option<OutPoint>, ErrorObjectOwned> {
        let space_hash = get_space_key(space_or_hash)?;
        let info = self
            .store
            .get_space_outpoint(space_hash)
            .await
            .map_err(|error| ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))?;

        Ok(info)
    }

    async fn get_spaceout(&self, outpoint: OutPoint) -> Result<Option<SpaceOut>, ErrorObjectOwned> {
        let spaceout = self
            .store
            .get_spaceout(outpoint)
            .await
            .map_err(|error| ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))?;
        Ok(spaceout)
    }

    async fn estimate_bid(&self, target: usize) -> Result<u64, ErrorObjectOwned> {
        let info = self
            .store
            .estimate_bid(target)
            .await
            .map_err(|error| ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))?;
        Ok(info)
    }

    async fn get_rollout(&self, target: usize) -> Result<Vec<RolloutEntry>, ErrorObjectOwned> {
        let rollouts = self
            .store
            .get_rollout(target)
            .await
            .map_err(|error| ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))?;
        Ok(rollouts)
    }

    async fn get_block_meta(
        &self,
        block_hash: BlockHash,
    ) -> Result<Option<BlockMeta>, ErrorObjectOwned> {
        let data = self
            .store
            .get_block_meta(block_hash)
            .await
            .map_err(|error| ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))?;

        Ok(data)
    }

    async fn get_tx_meta(&self, txid: Txid) -> Result<Option<TxEntry>, ErrorObjectOwned> {
        let data = self
            .store
            .get_tx_meta(txid)
            .await
            .map_err(|error| ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))?;
        Ok(data)
    }

    async fn wallet_load(&self, name: &str) -> Result<(), ErrorObjectOwned> {
        self.wallet_manager
            .load_wallet(&self.client, name)
            .await
            .map_err(|error| {
                ErrorObjectOwned::owned(RPC_WALLET_NOT_LOADED, error.to_string(), None::<String>)
            })
    }

    async fn wallet_import(&self, content: WalletExport) -> Result<(), ErrorObjectOwned> {
        self.wallet_manager
            .import_wallet(&self.client, content)
            .await
            .map_err(|error| {
                ErrorObjectOwned::owned(RPC_WALLET_NOT_LOADED, error.to_string(), None::<String>)
            })
    }

    async fn wallet_get_info(&self, wallet: &str) -> Result<WalletInfo, ErrorObjectOwned> {
        self.wallet(&wallet)
            .await?
            .send_get_info()
            .await
            .map_err(|error| ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))
    }

    async fn wallet_export(&self, name: &str) -> Result<WalletExport, ErrorObjectOwned> {
        self.wallet_manager
            .export_wallet(name)
            .await
            .map_err(|error| {
                ErrorObjectOwned::owned(RPC_WALLET_NOT_LOADED, error.to_string(), None::<String>)
            })
    }

    async fn wallet_create(&self, name: &str) -> Result<(), ErrorObjectOwned> {
        self.wallet_manager
            .create_wallet(&self.client, name)
            .await
            .map_err(|error| {
                ErrorObjectOwned::owned(RPC_WALLET_NOT_LOADED, error.to_string(), None::<String>)
            })
    }
    async fn wallet_send_request(
        &self,
        wallet: &str,
        request: RpcWalletTxBuilder,
    ) -> Result<WalletResponse, ErrorObjectOwned> {
        let result = self
            .wallet(&wallet)
            .await?
            .send_batch_tx(request)
            .await
            .map_err(|error| ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))?;
        Ok(result)
    }

    async fn wallet_get_new_address(
        &self,
        wallet: &str,
        kind: AddressKind,
    ) -> Result<String, ErrorObjectOwned> {
        self.wallet(&wallet)
            .await?
            .send_get_new_address(kind)
            .await
            .map_err(|error| ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))
    }

    async fn wallet_bump_fee(
        &self,
        wallet: &str,
        txid: Txid,
        fee_rate: FeeRate,
    ) -> Result<Vec<TxResponse>, ErrorObjectOwned> {
        self.wallet(&wallet)
            .await?
            .send_fee_bump(txid, fee_rate)
            .await
            .map_err(|error| ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))
    }

    async fn wallet_force_spend(
        &self,
        wallet: &str,
        outpoint: OutPoint,
        fee_rate: FeeRate,
    ) -> Result<TxResponse, ErrorObjectOwned> {
        self.wallet(&wallet)
            .await?
            .send_force_spend(outpoint, fee_rate)
            .await
            .map_err(|error| ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))
    }

    async fn wallet_list_spaces(
        &self,
        wallet: &str,
    ) -> Result<Vec<WalletOutput>, ErrorObjectOwned> {
        self.wallet(&wallet)
            .await?
            .send_list_spaces()
            .await
            .map_err(|error| ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))
    }

    async fn wallet_list_unspent(
        &self,
        wallet: &str,
    ) -> Result<Vec<WalletOutput>, ErrorObjectOwned> {
        self.wallet(&wallet)
            .await?
            .send_list_unspent()
            .await
            .map_err(|error| ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))
    }

    async fn wallet_list_bidouts(&self, wallet: &str) -> Result<Vec<DoubleUtxo>, ErrorObjectOwned> {
        self.wallet(&wallet)
            .await?
            .send_list_bidouts()
            .await
            .map_err(|error| ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))
    }

    async fn wallet_get_balance(&self, wallet: &str) -> Result<Balance, ErrorObjectOwned> {
        self.wallet(&wallet)
            .await?
            .send_get_balance()
            .await
            .map_err(|error| ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))
    }
}

impl AsyncChainState {
    pub fn new(sender: mpsc::Sender<ChainStateCommand>) -> Self {
        Self { sender }
    }

    async fn get_indexed_tx(
        index: &mut Option<LiveSnapshot>,
        txid: &Txid,
        client: &reqwest::Client,
        rpc: &BitcoinRpc,
        chain_state: &mut LiveSnapshot,
    ) -> Result<Option<TxEntry>, anyhow::Error> {
        let info: serde_json::Value = rpc
            .send_json(client, &rpc.get_raw_transaction(&txid, true))
            .await
            .map_err(|e| anyhow!("Could not retrieve tx ({})", e))?;

        let block_hash =
            BlockHash::from_str(info.get("blockhash").and_then(|t| t.as_str()).ok_or_else(
                || anyhow!("Could not retrieve block hash for tx (is it in the mempool?)"),
            )?)?;
        let block = Self::get_indexed_block(index, &block_hash, client, rpc, chain_state).await?;

        if let Some(block) = block {
            return Ok(block
                .tx_meta
                .into_iter()
                .find(|tx| &tx.changeset.txid == txid));
        }
        Ok(None)
    }

    async fn get_indexed_block(
        index: &mut Option<LiveSnapshot>,
        block_hash: &BlockHash,
        client: &reqwest::Client,
        rpc: &BitcoinRpc,
        chain_state: &mut LiveSnapshot,
    ) -> Result<Option<BlockMeta>, anyhow::Error> {
        let index = index
            .as_mut()
            .ok_or_else(|| anyhow!("block index must be enabled"))?;
        let hash = BaseHash::from_slice(block_hash.as_ref());
        let block: Option<BlockMeta> = index
            .get(hash)
            .context("Could not fetch block from index")?;

        if let Some(block_set) = block {
            return Ok(Some(block_set));
        }

        let info: serde_json::Value = rpc
            .send_json(client, &rpc.get_block_header(block_hash))
            .await
            .map_err(|e| anyhow!("Could not retrieve block ({})", e))?;

        let height = info
            .get("height")
            .and_then(|t| t.as_u64())
            .ok_or_else(|| anyhow!("Could not retrieve block height"))?;

        let tip = chain_state.tip.read().expect("read meta").clone();
        if height > tip.height as u64 {
            return Err(anyhow!(
                "Spaces is syncing at height {}, requested block height {}",
                tip.height,
                height
            ));
        }
        Ok(None)
    }

    pub async fn handle_command(
        client: &reqwest::Client,
        rpc: &BitcoinRpc,
        chain_state: &mut LiveSnapshot,
        block_index: &mut Option<LiveSnapshot>,
        cmd: ChainStateCommand,
    ) {
        match cmd {
            ChainStateCommand::GetTip { resp } => {
                let tip = chain_state.tip.read().expect("read meta").clone();
                _ = resp.send(Ok(tip))
            }
            ChainStateCommand::GetSpace { hash, resp } => {
                let result = chain_state.get_space_info(&hash);
                let _ = resp.send(result);
            }
            ChainStateCommand::GetSpaceout { outpoint, resp } => {
                let result = chain_state
                    .get_spaceout(&outpoint)
                    .context("could not fetch spaceout");
                let _ = resp.send(result);
            }
            ChainStateCommand::GetSpaceOutpoint { hash, resp } => {
                let result = chain_state
                    .get_space_outpoint(&hash)
                    .context("could not fetch spaceout");
                let _ = resp.send(result);
            }
            ChainStateCommand::GetBlockMeta { block_hash, resp } => {
                let res =
                    Self::get_indexed_block(block_index, &block_hash, client, rpc, chain_state)
                        .await;
                let _ = resp.send(res);
            }
            ChainStateCommand::GetTxMeta { txid, resp } => {
                let res = Self::get_indexed_tx(block_index, &txid, client, rpc, chain_state).await;
                let _ = resp.send(res);
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
    }

    pub async fn handler(
        client: &reqwest::Client,
        rpc: BitcoinRpc,
        mut chain_state: LiveSnapshot,
        mut block_index: Option<LiveSnapshot>,
        mut rx: mpsc::Receiver<ChainStateCommand>,
        mut shutdown: broadcast::Receiver<()>,
    ) {
        loop {
            select! {
                _ = shutdown.recv() => {
                     break;
                }
                Some(cmd) = rx.recv() => {
                    Self::handle_command(client, &rpc, &mut chain_state, &mut block_index, cmd).await;
                }
            }
        }

        info!("Shutting down chain state...");
    }

    pub async fn estimate_bid(&self, target: usize) -> anyhow::Result<u64> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender
            .send(ChainStateCommand::EstimateBid { target, resp })
            .await?;
        resp_rx.await?
    }

    pub async fn get_rollout(&self, target: usize) -> anyhow::Result<Vec<RolloutEntry>> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender
            .send(ChainStateCommand::GetRollout { target, resp })
            .await?;
        resp_rx.await?
    }

    pub async fn get_space(&self, hash: SpaceKey) -> anyhow::Result<Option<FullSpaceOut>> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender
            .send(ChainStateCommand::GetSpace { hash, resp })
            .await?;
        resp_rx.await?
    }

    pub async fn get_space_outpoint(&self, hash: SpaceKey) -> anyhow::Result<Option<OutPoint>> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender
            .send(ChainStateCommand::GetSpaceOutpoint { hash, resp })
            .await?;
        resp_rx.await?
    }

    pub async fn get_tip(&self) -> anyhow::Result<ChainAnchor> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender.send(ChainStateCommand::GetTip { resp }).await?;
        resp_rx.await?
    }

    pub async fn get_spaceout(&self, outpoint: OutPoint) -> anyhow::Result<Option<SpaceOut>> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender
            .send(ChainStateCommand::GetSpaceout { outpoint, resp })
            .await?;
        resp_rx.await?
    }

    pub async fn get_block_meta(&self, block_hash: BlockHash) -> anyhow::Result<Option<BlockMeta>> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender
            .send(ChainStateCommand::GetBlockMeta { block_hash, resp })
            .await?;
        resp_rx.await?
    }

    pub async fn get_tx_meta(&self, txid: Txid) -> anyhow::Result<Option<TxEntry>> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender
            .send(ChainStateCommand::GetTxMeta { txid, resp })
            .await?;
        resp_rx.await?
    }
}

fn get_space_key(space_or_hash: &str) -> Result<SpaceKey, ErrorObjectOwned> {
    if space_or_hash.len() != 64 {
        return Ok(SpaceKey::from(Sha256::hash(
            SLabel::try_from(space_or_hash)
                .map_err(|_| {
                    ErrorObjectOwned::owned(
                        -1,
                        "expected a space name prefixed with @ or a hex encoded space hash",
                        None::<String>,
                    )
                })?
                .as_ref(),
        )));
    }

    let mut hash = [0u8; 32];
    hex::decode_to_slice(space_or_hash, &mut hash).map_err(|_| {
        ErrorObjectOwned::owned(
            -1,
            "expected a space name prefixed with @ or a hex encoded space hash",
            None::<String>,
        )
    })?;

    Ok(SpaceKey::from(hash))
}
