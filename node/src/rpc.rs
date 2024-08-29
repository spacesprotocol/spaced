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
    template::Bip84,
    KeychainKind, LocalOutput,
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
    hasher::{BaseHash, SpaceHash},
    prepare::DataSource,
    FullSpaceOut, SpaceOut,
};
use serde::{Deserialize, Serialize};
use tokio::{
    select,
    sync::{broadcast, mpsc, oneshot, RwLock},
    task::JoinSet,
};
use wallet::{
    bdk_wallet as bdk, bitcoin::hashes::Hash, derivation::SpaceDerivation, DoubleUtxo,
    SpacesWallet, WalletConfig, WalletExport, WalletInfo,
};

use crate::{
    config::ExtendedNetwork,
    node::ValidatedBlock,
    source::BitcoinRpc,
    store::{ChainState, LiveSnapshot},
    wallets::{AddressKind, JointBalance, RpcWallet, TxResponse, WalletCommand, WalletResponse},
};

pub(crate) type Responder<T> = oneshot::Sender<T>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    chain: ExtendedNetwork,
    tip: ChainAnchor,
}

pub enum ChainStateCommand {
    GetTip {
        resp: Responder<anyhow::Result<ChainAnchor>>,
    },
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
    #[method(name = "getserverinfo")]
    async fn get_server_info(&self) -> Result<ServerInfo, ErrorObjectOwned>;

    #[method(name = "getspaceinfo")]
    async fn get_space_info(
        &self,
        space_hash: String,
    ) -> Result<Option<FullSpaceOut>, ErrorObjectOwned>;

    #[method(name = "estimatebid")]
    async fn estimate_bid(&self, target: usize) -> Result<u64, ErrorObjectOwned>;

    #[method(name = "getrollout")]
    async fn get_rollout(&self, target: usize) -> Result<Vec<(u32, SpaceHash)>, ErrorObjectOwned>;

    #[method(name = "getspaceowner")]
    async fn get_space_owner(
        &self,
        space_hash: String,
    ) -> Result<Option<OutPoint>, ErrorObjectOwned>;

    #[method(name = "getspaceout")]
    async fn get_spaceout(&self, outpoint: OutPoint) -> Result<Option<SpaceOut>, ErrorObjectOwned>;

    #[method(name = "getblockdata")]
    async fn get_block_data(
        &self,
        block_hash: BlockHash,
    ) -> Result<Option<ValidatedBlock>, ErrorObjectOwned>;

    #[method(name = "walletload")]
    async fn wallet_load(&self, name: String) -> Result<(), ErrorObjectOwned>;

    #[method(name = "walletimport")]
    async fn wallet_import(&self, content: String) -> Result<(), ErrorObjectOwned>;

    #[method(name = "walletgetinfo")]
    async fn wallet_get_info(&self, name: String) -> Result<WalletInfo, ErrorObjectOwned>;

    #[method(name = "walletexport")]
    async fn wallet_export(&self, name: String) -> Result<String, ErrorObjectOwned>;

    #[method(name = "walletcreate")]
    async fn wallet_create(&self, name: String) -> Result<(), ErrorObjectOwned>;

    #[method(name = "walletsendrequest")]
    async fn wallet_send_request(
        &self,
        wallet: String,
        request: RpcWalletTxBuilder,
    ) -> Result<WalletResponse, ErrorObjectOwned>;

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
    ) -> Result<Vec<TxResponse>, ErrorObjectOwned>;

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
    async fn wallet_get_balance(&self, wallet: String) -> Result<JointBalance, ErrorObjectOwned>;
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
        content: &str,
    ) -> anyhow::Result<()> {
        let wallet = WalletExport::from_str(content)?;

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

        self.load_wallet(client, wallet.label).await?;
        Ok(())
    }

    pub async fn export_wallet(&self, name: String) -> anyhow::Result<String> {
        let wallet_dir = self.data_dir.join(&name);
        if !wallet_dir.exists() {
            return Err(anyhow!("Wallet does not exist"));
        }
        Ok(fs::read_to_string(wallet_dir.join("wallet.json"))?)
    }

    pub async fn create_wallet(
        &self,
        client: &reqwest::Client,
        name: String,
    ) -> anyhow::Result<()> {
        let mnemonic: GeneratedKey<_, Tap> =
            Mnemonic::generate((WordCount::Words12, Language::English))
                .map_err(|_| anyhow!("Mnemonic generation error"))?;

        let start_block = self.get_wallet_start_block(client).await?;
        self.setup_new_wallet(name.clone(), mnemonic.to_string(), start_block)?;
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

        let coins_descriptors = Self::default_coin_descriptors(xpriv);
        let space_descriptors = Self::default_spaces_descriptors(xpriv);

        let export = WalletExport::from_descriptors(
            name,
            start_block.height,
            network,
            coins_descriptors.0,
            space_descriptors.0,
        )?;

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
            ExtendedNetwork::Regtest => {
                genesis_hash = Some(
                    bdk::bitcoin::constants::genesis_block(Regtest)
                        .header
                        .block_hash(),
                );
                Network::Testnet
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

    // TODO: remove in the next update
    pub async fn migrate_legacy_v0_0_1_wallet(
        &self,
        name: String,
        wallet_dir: PathBuf,
    ) -> anyhow::Result<bool> {
        let legacy_secret = wallet_dir
            .join("insecure_secret")
            .to_str()
            .unwrap()
            .replace("/testnet/wallets/", "/test/wallets/");
        let legacy_secret = std::path::PathBuf::from(legacy_secret);

        if !legacy_secret.exists() {
            return Ok(false);
        }

        let mnemonic = fs::read_to_string(legacy_secret)?.trim().to_string();
        let start_block = match self.network {
            ExtendedNetwork::Testnet => ChainAnchor::TESTNET(),
            ExtendedNetwork::Testnet4 => ChainAnchor::TESTNET4(),
            ExtendedNetwork::Regtest => ChainAnchor::REGTEST(),
            _ => panic!("could not migrate legacy wallet: unsupported network"),
        };

        self.setup_new_wallet(
            name,
            mnemonic,
            BlockId {
                height: start_block.height,
                hash: start_block.hash,
            },
        )?;

        Ok(true)
    }

    pub async fn load_wallet(&self, client: &reqwest::Client, name: String) -> anyhow::Result<()> {
        let wallet_dir = self.data_dir.join(name.clone());
        if !wallet_dir.exists() {
            if self
                .migrate_legacy_v0_0_1_wallet(name.clone(), wallet_dir.clone())
                .await?
            {
                info!("Migrated legacy wallet {}", name);
            } else {
                return Err(anyhow!("Wallet does not exist"));
            }
        }

        let file = fs::File::open(wallet_dir.join("wallet.json"))?;

        let (network, genesis_hash) = self.fallback_network();
        let export: WalletExport = serde_json::from_reader(file)?;

        let mut wallet = SpacesWallet::new(WalletConfig {
            start_block: export.block_height,
            data_dir: wallet_dir,
            name: name.clone(),
            network,
            genesis_hash,
            coins_descriptors: export.descriptors(),
            space_descriptors: export.space_descriptors(),
        })?;

        let wallet_tip = wallet.coins.local_chain().tip().height();

        if wallet_tip < export.block_height {
            let block_id = self.get_block_hash(client, export.block_height).await?;
            wallet.coins.insert_checkpoint(block_id)?;
            wallet.spaces.insert_checkpoint(block_id)?;
            wallet.commit()?;
        }

        let (rpc_wallet, rpc_wallet_rx) = RpcWallet::new();
        let loaded_wallet = LoadedWallet::new(wallet, rpc_wallet_rx);

        self.wallet_loader.send(loaded_wallet).await?;
        let mut wallets = self.wallets.write().await;
        wallets.insert(name, rpc_wallet);
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

    fn default_coin_descriptors(x: Xpriv) -> (Bip84<Xpriv>, Bip84<Xpriv>) {
        (
            Bip84(x, KeychainKind::External),
            Bip84(x, KeychainKind::Internal),
        )
    }

    fn default_spaces_descriptors(x: Xpriv) -> (SpaceDerivation<Xpriv>, SpaceDerivation<Xpriv>) {
        (
            SpaceDerivation(x, KeychainKind::External),
            SpaceDerivation(x, KeychainKind::Internal),
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

    async fn get_space_info(
        &self,
        space_hash_str: String,
    ) -> Result<Option<FullSpaceOut>, ErrorObjectOwned> {
        let mut space_hash = [0u8; 32];
        hex::decode_to_slice(space_hash_str, &mut space_hash).map_err(|_| {
            ErrorObjectOwned::owned(
                -1,
                "expected a 32-byte hex encoded space hash a",
                None::<String>,
            )
        })?;
        let space_hash = SpaceHash::from_raw(space_hash).map_err(|_| {
            ErrorObjectOwned::owned(
                -1,
                "expected a 32-byte hex encoded space hash b",
                None::<String>,
            )
        })?;

        let info = self
            .store
            .get_space_info(space_hash)
            .await
            .map_err(|error| ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))?;
        Ok(info)
    }

    async fn estimate_bid(&self, target: usize) -> Result<u64, ErrorObjectOwned> {
        let info = self
            .store
            .estimate_bid(target)
            .await
            .map_err(|error| ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))?;
        Ok(info)
    }

    async fn get_rollout(&self, target: usize) -> Result<Vec<(u32, SpaceHash)>, ErrorObjectOwned> {
        let rollouts = self
            .store
            .get_rollout(target)
            .await
            .map_err(|error| ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))?;
        Ok(rollouts)
    }

    async fn get_space_owner(
        &self,
        space_hash_str: String,
    ) -> Result<Option<OutPoint>, ErrorObjectOwned> {
        let mut space_hash = [0u8; 32];
        hex::decode_to_slice(space_hash_str, &mut space_hash).map_err(|_| {
            ErrorObjectOwned::owned(
                -1,
                "expected a 32-byte hex encoded space hash",
                None::<String>,
            )
        })?;
        let space_hash = SpaceHash::from_raw(space_hash).map_err(|_| {
            ErrorObjectOwned::owned(
                -1,
                "expected a 32-byte hex encoded space hash",
                None::<String>,
            )
        })?;

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

    async fn get_block_data(
        &self,
        block_hash: BlockHash,
    ) -> Result<Option<ValidatedBlock>, ErrorObjectOwned> {
        let data = self
            .store
            .get_block_data(block_hash)
            .await
            .map_err(|error| ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))?;

        Ok(data)
    }

    async fn wallet_load(&self, name: String) -> Result<(), ErrorObjectOwned> {
        self.wallet_manager
            .load_wallet(&self.client, name)
            .await
            .map_err(|error| {
                ErrorObjectOwned::owned(RPC_WALLET_NOT_LOADED, error.to_string(), None::<String>)
            })
    }

    async fn wallet_import(&self, content: String) -> Result<(), ErrorObjectOwned> {
        self.wallet_manager
            .import_wallet(&self.client, &content)
            .await
            .map_err(|error| {
                ErrorObjectOwned::owned(RPC_WALLET_NOT_LOADED, error.to_string(), None::<String>)
            })
    }

    async fn wallet_get_info(&self, wallet: String) -> Result<WalletInfo, ErrorObjectOwned> {
        self.wallet(&wallet)
            .await?
            .send_get_info()
            .await
            .map_err(|error| ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))
    }

    async fn wallet_export(&self, name: String) -> Result<String, ErrorObjectOwned> {
        self.wallet_manager
            .export_wallet(name)
            .await
            .map_err(|error| {
                ErrorObjectOwned::owned(RPC_WALLET_NOT_LOADED, error.to_string(), None::<String>)
            })
    }

    async fn wallet_create(&self, name: String) -> Result<(), ErrorObjectOwned> {
        self.wallet_manager
            .create_wallet(&self.client, name.clone())
            .await
            .map_err(|error| {
                ErrorObjectOwned::owned(RPC_WALLET_NOT_LOADED, error.to_string(), None::<String>)
            })
    }
    async fn wallet_send_request(
        &self,
        wallet: String,
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
        wallet: String,
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
        wallet: String,
        txid: Txid,
        fee_rate: FeeRate,
    ) -> Result<Vec<TxResponse>, ErrorObjectOwned> {
        self.wallet(&wallet)
            .await?
            .send_fee_bump(txid, fee_rate)
            .await
            .map_err(|error| ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))
    }

    async fn wallet_list_spaces(
        &self,
        wallet: String,
    ) -> Result<Vec<FullSpaceOut>, ErrorObjectOwned> {
        self.wallet(&wallet)
            .await?
            .send_list_spaces()
            .await
            .map_err(|error| ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))
    }

    async fn wallet_list_unspent(
        &self,
        wallet: String,
    ) -> Result<Vec<LocalOutput>, ErrorObjectOwned> {
        self.wallet(&wallet)
            .await?
            .send_list_unspent()
            .await
            .map_err(|error| ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))
    }

    async fn wallet_list_auction_outputs(
        &self,
        wallet: String,
    ) -> Result<Vec<DoubleUtxo>, ErrorObjectOwned> {
        self.wallet(&wallet)
            .await?
            .send_list_auction_outputs()
            .await
            .map_err(|error| ErrorObjectOwned::owned(-1, error.to_string(), None::<String>))
    }

    async fn wallet_get_balance(&self, wallet: String) -> Result<JointBalance, ErrorObjectOwned> {
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

    pub async fn handle_command(
        chain_state: &mut LiveSnapshot,
        block_index: &mut Option<LiveSnapshot>,
        cmd: ChainStateCommand,
    ) {
        match cmd {
            ChainStateCommand::GetTip { resp } => {
                let tip = chain_state.tip.read().expect("read meta").clone();
                _ = resp.send(Ok(tip))
            }
            ChainStateCommand::GetSpaceInfo { hash, resp } => {
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
            ChainStateCommand::GetBlockData { block_hash, resp } => match block_index {
                None => {
                    let _ = resp.send(Err(anyhow!("block index must be enabled")));
                }
                Some(index) => {
                    let hash = BaseHash::from_slice(block_hash.as_ref());
                    let _ = resp.send(
                        index
                            .get(hash)
                            .context("Could not fetch blockdata from index"),
                    );
                }
            },
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
                    Self::handle_command(&mut chain_state, &mut block_index, cmd).await;
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

    pub async fn get_rollout(&self, target: usize) -> anyhow::Result<Vec<(u32, SpaceHash)>> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender
            .send(ChainStateCommand::GetRollout { target, resp })
            .await?;
        resp_rx.await?
    }

    pub async fn get_space_info(&self, hash: SpaceHash) -> anyhow::Result<Option<FullSpaceOut>> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender
            .send(ChainStateCommand::GetSpaceInfo { hash, resp })
            .await?;
        resp_rx.await?
    }

    pub async fn get_space_outpoint(&self, hash: SpaceHash) -> anyhow::Result<Option<OutPoint>> {
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

    pub async fn get_block_data(
        &self,
        block_hash: BlockHash,
    ) -> anyhow::Result<Option<ValidatedBlock>> {
        let (resp, resp_rx) = oneshot::channel();
        self.sender
            .send(ChainStateCommand::GetBlockData { block_hash, resp })
            .await?;
        resp_rx.await?
    }
}
