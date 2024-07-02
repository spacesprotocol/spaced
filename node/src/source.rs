use std::error::Error;
use std::fmt;
use std::time::Duration;
use protocol::bitcoin::{Block, BlockHash, Transaction};
use crate::node::{BlockSource};
use bdk_bitcoind_rpc::bitcoincore_rpc::{Auth, Client, jsonrpc, RawTx, RpcApi};
use bdk_bitcoind_rpc::bitcoincore_rpc::jsonrpc::error::RpcError;
use bdk_bitcoind_rpc::Emitter;
use bdk_chain::ConfirmationTime;
use bdk_chain::local_chain::CheckPoint;
use log::info;

#[derive(Clone, Debug)]
pub struct BlockchainRpcConfig {
    pub auth: Auth,
    pub url: String,
}

pub struct RpcBlockchain {
    config: BlockchainRpcConfig,
    pub client: Client,
}

pub enum ScanStatus {
    Complete(CheckPoint),
    Shutdown,
}


#[derive(Debug)]
pub enum BroadcastError {
    Client(jsonrpc::Error),
    Rpc(RpcError),
    MempoolTimeout,
}

impl fmt::Display for BroadcastError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BroadcastError::Client(err) => write!(f, "Client error: {}", err),
            BroadcastError::Rpc(err) => write!(f, "RPC error: {}:{}", err.code, err.message),
            BroadcastError::MempoolTimeout => write!(f, "Mempool timeout"),
        }
    }
}

impl Error for BroadcastError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            BroadcastError::Client(err) => Some(err),
            BroadcastError::Rpc(_) => None,
            BroadcastError::MempoolTimeout => None,
        }
    }
}

impl RpcBlockchain {
    pub(crate) fn broadcast_tx(&self, tx: Transaction) -> Result<ConfirmationTime, BroadcastError> {
        let txid = tx.txid();
        info!("broadcasting {}", txid);

        let mut args = Vec::new();
        args.push(jsonrpc::arg(tx.raw_hex()));
        args.push(jsonrpc::arg(serde_json::Value::Null));

        // maxburnrate
        args.push(jsonrpc::arg("1000000.0".to_string()));

        let client = self.client.get_jsonrpc_client();
        let json_request = client.build_request("sendrawtransaction", &args);
        let broadcast_result = client.send_request(json_request)
            .map_err(|e| { BroadcastError::Client(e) })?;

        const MAX_RETRIES: usize = 10;

        match broadcast_result.error {
            None => {
                let mut retry_count = 0;
                while retry_count < MAX_RETRIES {
                    match self.client.get_mempool_entry(&txid) {
                        Ok(mem) => {
                            return Ok(ConfirmationTime::Unconfirmed {
                                last_seen: mem.time,
                            });
                        }
                        Err(_) => {}
                    }
                    std::thread::sleep(Duration::from_millis(100));
                    retry_count += 1;
                }
                return Err(BroadcastError::MempoolTimeout);
            }
            Some(error) => {
                return Err(BroadcastError::Rpc(error));
            }
        }
    }
}

impl Clone for RpcBlockchain {
    fn clone(&self) -> Self {
        Self::new(self.config.clone()).expect("new client")
    }
}

impl RpcBlockchain {
    pub fn new(config: BlockchainRpcConfig) -> anyhow::Result<Self> {
        Ok(Self {
            client: Client::new(&config.url, config.auth.clone())?,
            config,
        })
    }

    pub fn emitter(&self, checkpoint: CheckPoint, fallback_height: u32) -> Emitter<Client> {
        Emitter::new(&self.client, checkpoint, fallback_height)
    }
}

impl BlockSource for RpcBlockchain {
    fn get_block_hash(&self, height: u32) -> anyhow::Result<BlockHash> {
        Ok(self.client.get_block_hash(height as u64)?)
    }

    fn get_block(&self, hash: &BlockHash) -> anyhow::Result<Block> {
        Ok(self.client.get_block(hash)?)
    }

    fn get_median_time(&self) -> anyhow::Result<u64> {
        let info = self.client.get_blockchain_info()?;
        Ok(info.median_time)
    }

    fn get_block_count(&self) -> anyhow::Result<u64> {
        Ok(self.client.get_block_count()?)
    }
}
