use std::sync::Arc;

use anyhow::anyhow;
use env_logger::Env;
use log::error;
use spaced::{
    config::{safe_exit, Args},
    rpc::{AsyncChainState, LoadedWallet, RpcServerImpl, WalletManager},
    source::BitcoinBlockSource,
    store,
    sync::Spaced,
    wallets::RpcWallet,
};
use store::LiveSnapshot;
use tokio::{
    sync::{broadcast, mpsc},
    task::{JoinHandle, JoinSet},
};

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    let sigterm = tokio::signal::ctrl_c();

    let mut app = Composer::new();
    let shutdown = app.shutdown.clone();

    tokio::spawn(async move {
        sigterm.await.expect("could not listen for shutdown");
        let _ = shutdown.send(());
    });

    match app.run().await {
        Ok(_) => {}
        Err(e) => {
            error!("{}", e.to_string());
            safe_exit(1);
        }
    }
}

struct Composer {
    shutdown: broadcast::Sender<()>,
    services: JoinSet<anyhow::Result<()>>,
}

impl Composer {
    fn new() -> Self {
        let (shutdown, _) = broadcast::channel(1);
        Self {
            shutdown,
            services: JoinSet::new(),
        }
    }

    async fn setup_rpc_wallet(&mut self, spaced: &Spaced, rx: mpsc::Receiver<LoadedWallet>) {
        let wallet_service = RpcWallet::service(
            spaced.network,
            spaced.rpc.clone(),
            spaced.chain.state.clone(),
            rx,
            self.shutdown.clone(),
        );

        self.services.spawn(async move {
            wallet_service
                .await
                .map_err(|e| anyhow!("Wallet service error: {}", e))
        });
    }

    async fn setup_rpc_services(&mut self, spaced: &Spaced) {
        let (wallet_loader_tx, wallet_loader_rx) = mpsc::channel(1);

        let wallet_manager = WalletManager {
            data_dir: spaced.data_dir.join("wallets"),
            network: spaced.network,
            rpc: spaced.rpc.clone(),
            wallet_loader: wallet_loader_tx,
            wallets: Arc::new(Default::default()),
        };

        let (async_chain_state, async_chain_state_handle) = create_async_store(
            spaced.chain.state.clone(),
            spaced.block_index.as_ref().map(|index| index.state.clone()),
            self.shutdown.subscribe(),
        )
        .await;

        self.services.spawn(async {
            async_chain_state_handle
                .await
                .map_err(|e| anyhow!("Chain state error: {}", e))
        });
        let rpc_server = RpcServerImpl::new(async_chain_state.clone(), wallet_manager);

        let bind = spaced.bind.clone();
        let shutdown = self.shutdown.clone();

        self.services.spawn(async move {
            rpc_server
                .listen(bind, shutdown)
                .await
                .map_err(|e| anyhow!("RPC Server error: {}", e))
        });

        self.setup_rpc_wallet(spaced, wallet_loader_rx).await;
    }

    async fn setup_sync_service(&mut self, mut spaced: Spaced) {
        let (spaced_sender, spaced_receiver) = tokio::sync::oneshot::channel();

        let shutdown = self.shutdown.clone();
        let rpc = spaced.rpc.clone();

        std::thread::spawn(move || {
            let source = BitcoinBlockSource::new(rpc);
            _ = spaced_sender.send(spaced.protocol_sync(source, shutdown));
        });

        self.services.spawn(async move {
            spaced_receiver
                .await?
                .map_err(|e| anyhow!("Protocol sync error: {}", e))
        });
    }

    async fn run(&mut self) -> anyhow::Result<()> {
        let spaced = Args::configure()?;
        self.setup_rpc_services(&spaced).await;
        self.setup_sync_service(spaced).await;

        while let Some(res) = self.services.join_next().await {
            res??
        }

        Ok(())
    }
}

async fn create_async_store(
    chain_state: LiveSnapshot,
    block_index: Option<LiveSnapshot>,
    shutdown: broadcast::Receiver<()>,
) -> (AsyncChainState, JoinHandle<()>) {
    let (tx, rx) = mpsc::channel(32);
    let async_store = AsyncChainState::new(tx);

    let handle = tokio::spawn(async move {
        AsyncChainState::handler(chain_state, block_index, rx, shutdown).await
    });
    (async_store, handle)
}
