use std::sync::Arc;
use anyhow::anyhow;

use env_logger::Env;
use log::{error, info};
use tokio::{select, try_join};
use tokio::sync::{broadcast, mpsc};
use tokio::task::{JoinHandle};
use spaced::store;
use store::{LiveSnapshot};
use spaced::config::{Args, safe_exit};
use spaced::rpc::{AsyncChainState, RpcServerImpl, WalletManager};
use spaced::wallets::RpcWallet;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let sigint = tokio::signal::ctrl_c();

    let mut spaced = Args::configure()?;
    let network = spaced.network;
    let (shutdown_sender, _) = broadcast::channel(1);

    let wallet_source = spaced.source.clone();
    let mempool = spaced.mempool.clone();
    let params = spaced.params;

    let wallet_chain_state = spaced.chain.state.clone();

    let (
        async_chain_state,
        async_chain_state_handle
    ) = create_async_store(
        spaced.chain.state.clone(),
        spaced.block_index.as_ref().map(|index| index.state.clone()),
        shutdown_sender.subscribe(),
    ).await;

    let (wallet_loader_tx, wallet_loader_rx) = mpsc::channel(4);
    let wallet_manager = WalletManager {
        source: wallet_source,
        data_dir: spaced.data_dir.join("wallets"),
        network: spaced.network,
        params,
        wallet_loader: wallet_loader_tx,
        wallets: Arc::new(Default::default()),
    };

    let rpc_server = RpcServerImpl::new(async_chain_state.clone(), wallet_manager);

    let rpc_task_server = rpc_server.clone();
    let rpc_task_shutdown = shutdown_sender.clone();
    let rpc_server_bind = spaced.bind.clone();
    let rpc_handle = rpc_task_server.listen(rpc_server_bind, rpc_task_shutdown);

    let spaced_shutdown_sender = shutdown_sender.clone();

    let (spaced_sender, spaced_receiver) = tokio::sync::oneshot::channel();
    let source = spaced.source.clone();
    std::thread::spawn(move || {
        _ = spaced_sender.send(
            spaced.protocol_sync(spaced_shutdown_sender.subscribe())
        );
    });

    let wallet_service_shutdown = shutdown_sender.clone();
    let wallet_service =
        RpcWallet::service(network, mempool, source, wallet_chain_state, wallet_loader_rx, wallet_service_shutdown);

    let signal = shutdown_sender.clone();
    tokio::spawn(async move {
        _ = sigint.await;
        _ = signal.send(());
    });


    let shutdown_result = try_join!(
        async {
            let res = spaced_receiver.await;
            _ = shutdown_sender.send(());
            if let Ok(res) = res {
                if let Err(e) = res {
                    error!("Protocol sync: {}", e);
                    return Err(anyhow!("Protocol sync error: {}", e));
                }
            }
            Ok(())
        },
        async {
            let res = rpc_handle.await;
             _ = shutdown_sender.send(());
            if let Err(e) = res {
                error!("RPC Server: {}", e);
                return Err(anyhow!("RPC Server error: {}", e));
            }
            Ok(())
        },
        async {
            let res = wallet_service.await;
            _ = shutdown_sender.send(());
            if let Err(e) = res {
                error!("Wallet service: {}", e);
                return Err(anyhow!("Wallet service error: {}", e));
            }
            Ok(())
        },
        async {
            let res = async_chain_state_handle.await
            .map_err(|e| anyhow!("Async chain state error: {}", e));
            _ = shutdown_sender.send(());
            res
        }
    );

    if !shutdown_result.is_ok() {
        safe_exit(1);
    }
    Ok(())
}

async fn create_async_store(
    chain_state: LiveSnapshot,
    block_index: Option<LiveSnapshot>,
    mut shutdown: broadcast::Receiver<()>,
) -> (AsyncChainState, JoinHandle<()>) {
    let (tx, rx) = mpsc::channel(32);
    let async_store = AsyncChainState::new(tx);

    let handle = tokio::spawn(async move {
        select! {
            _ = AsyncChainState::handler(chain_state, block_index, rx) => {
                // Handler completed normally
            }
            Ok(_) = shutdown.recv() => {
                info!("Shutting down database...");
            }
        }
    });
    (async_store, handle)
}
