extern crate core;

use std::{fs, path::PathBuf};

use base64::{prelude::BASE64_STANDARD, Engine};
use clap::{Parser, Subcommand};
use jsonrpsee::{
    core::{client::Error, ClientError},
    http_client::{HttpClient, HttpClientBuilder},
};
use protocol::{
    bitcoin::{Amount, FeeRate, OutPoint, Txid},
    opcodes::OP_SETALL,
    Covenant, FullSpaceOut,
};
use serde::{Deserialize, Serialize};
use spaced::{
    config::{default_spaces_rpc_port, ExtendedNetwork},
    rpc::{
        BidParams, ExecuteParams, OpenParams, RegisterParams, RpcClient, RpcWalletRequest,
        RpcWalletTxBuilder, SendCoinsParams, TransferSpacesParams,
    },
    wallets::AddressKind,
};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
    /// Bitcoin network to use
    #[arg(long)]
    chain: spaced::config::ExtendedNetwork,
    /// Spaced RPC URL [default: based on specified chain]
    #[arg(long)]
    spaced_rpc_url: Option<String>,
    /// Specify wallet to use
    #[arg(long, short, global = true, default_value = "default")]
    wallet: String,
    /// Custom dust amount in sat for auction outputs
    #[arg(long, short, global = true)]
    dust: Option<u64>,
    /// Force invalid transaction (for testing only)
    #[arg(long, global = true, default_value = "false")]
    force: bool,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug, Clone)]
enum Commands {
    /// Generate a new wallet
    #[command(name = "createwallet")]
    CreateWallet {
        #[arg(default_value = "default")]
        name: String,
    },
    /// Load a wallet
    #[command(name = "loadwallet")]
    LoadWallet {
        #[arg(default_value = "default")]
        name: String,
    },
    /// Export a wallet
    #[command(name = "exportwallet")]
    ExportWallet {
        #[arg(default_value = "default")]
        name: String,
    },
    /// Import a wallet
    #[command(name = "importwallet")]
    ImportWallet {
        // Wallet json file to import
        path: PathBuf,
    },
    /// Export a wallet
    #[command(name = "getwalletinfo")]
    GetWalletInfo {
        #[arg(default_value = "default")]
        name: String,
    },
    /// Export a wallet
    #[command(name = "getserverinfo")]
    GetServerInfo,
    /// Open an auction
    Open {
        /// Space name
        space: String,
        /// Amount in sats
        #[arg(default_value = "1000")]
        initial_bid: u64,
        /// Fee rate to use in sat/vB
        #[arg(long, short)]
        fee_rate: Option<u64>,
    },
    /// Place a bid
    Bid {
        /// Space name
        space: String,
        /// Amount in satoshi
        amount: u64,
        /// Fee rate to use in sat/vB
        #[arg(long, short)]
        fee_rate: Option<u64>,
    },
    /// Register a won auction
    Register {
        /// Space name
        space: String,
        /// Recipient address
        address: Option<String>,
        /// Fee rate to use in sat/vB
        #[arg(long, short)]
        fee_rate: Option<u64>,
    },
    /// Get space info
    #[command(name = "getspace")]
    GetSpace {
        /// The space name
        space: String,
    },
    /// Transfer ownership of a set of spaces to the given name or address
    #[command(
        name = "transfer",
        override_usage = "space-cli transfer [SPACES]... --to <SPACE-OR-ADDRESS>"
    )]
    Transfer {
        /// Spaces to send
        #[arg(display_order = 0)]
        spaces: Vec<String>,
        /// Recipient space name or address (must be a space address)
        #[arg(long, display_order = 1)]
        to: String,
        /// Fee rate to use in sat/vB
        #[arg(long, short)]
        fee_rate: Option<u64>,
    },
    /// Estimates the minimum bid needed for a rollout within the given target blocks
    #[command(name = "estimatebid")]
    EstimateBid {
        /// Rollout within target blocks
        #[arg(default_value = "0")]
        target: usize,
    },
    /// Send the specified amount of BTC to the given name or address
    #[command(
        name = "send",
        override_usage = "space-cli send <AMOUNT> --to <SPACE-OR-ADDRESS>"
    )]
    SendCoins {
        /// Amount to send in satoshi
        #[arg(display_order = 0)]
        amount: u64,
        /// Recipient space name or address
        #[arg(long, display_order = 1)]
        to: String,
        /// Fee rate to use in sat/vB
        #[arg(long, short)]
        fee_rate: Option<u64>,
    },
    /// Get wallet balance
    #[command(name = "balance")]
    Balance,
    /// Pre-create outputs that can be auctioned off during the bidding process
    #[command(name = "createauctionoutputs")]
    CreateAuctionOutputs {
        /// Number of output pairs to create
        /// Each pair can be used to make a bid
        pairs: u8,
        /// Fee rate to use in sat/vB
        #[arg(long, short)]
        fee_rate: Option<u64>,
    },
    /// Bump the fee for a transaction created by this wallet
    #[command(name = "bumpfee")]
    BumpFee {
        txid: Txid,
        /// Fee rate to use in sat/vB
        #[arg(long, short)]
        fee_rate: u64,
    },
    /// Get a spaceout - a Bitcoin output relevant to the Spaces protocol.
    #[command(name = "getspaceout")]
    GetSpaceOut {
        /// The OutPoint
        outpoint: OutPoint,
    },
    /// Get the estimated rollout batch for the specified interval
    #[command(name = "getrolloutestimate")]
    GetRolloutEstimate {
        // Get the estimated rollout for the target interval. Every ~144 blocks (a rollout interval),
        // 10 spaces are released for auction. Specify 0 [default] for the coming interval, 1
        // for the interval after and so on.
        #[arg(default_value = "0")]
        target_interval: usize,
    },
    /// Associate the specified data with a given space (experimental may be removed)
    #[command(name = "setdata")]
    SetData {
        /// Space name
        space: String,
        /// Base64 encoded data
        data: String,
        /// Fee rate to use in sat/vB
        #[arg(long, short)]
        fee_rate: Option<u64>,
    },
    /// List won spaces including ones
    /// still in auction with a winning bid
    #[command(name = "listspaces")]
    ListSpaces,
    /// List unspent auction outputs i.e. outputs that can be
    /// auctioned off in the bidding process
    #[command(name = "listauctionoutputs")]
    ListAuctionOutputs,
    /// List unspent coins owned by wallet
    #[command(name = "listunspent")]
    ListUnspent,
    /// Get a new Bitcoin address suitable for receiving spaces and coins
    /// (Spaces compatible bitcoin wallets only)
    #[command(name = "getnewspaceaddress")]
    GetSpaceAddress,
    /// Get a new Bitcoin address suitable for receiving coins
    /// compatible with most bitcoin wallets
    #[command(name = "getnewaddress")]
    GetCoinAddress,
}

struct SpaceCli {
    wallet: String,
    dust: Option<Amount>,
    force: bool,
    network: ExtendedNetwork,
    rpc_url: String,
    client: HttpClient,
}

impl SpaceCli {
    async fn configure() -> anyhow::Result<(Self, Args)> {
        let mut args = Args::parse();
        if args.spaced_rpc_url.is_none() {
            args.spaced_rpc_url = Some(default_spaced_rpc_url(&args.chain));
        }

        let client = HttpClientBuilder::default().build(args.spaced_rpc_url.clone().unwrap())?;
        Ok((
            Self {
                wallet: args.wallet.clone(),
                dust: args.dust.map(|d| Amount::from_sat(d)),
                force: args.force,
                network: args.chain,
                rpc_url: args.spaced_rpc_url.clone().unwrap(),
                client,
            },
            args,
        ))
    }

    async fn send_request(
        &self,
        req: Option<RpcWalletRequest>,
        auction_outputs: Option<u8>,
        fee_rate: Option<u64>,
    ) -> Result<(), ClientError> {
        let fee_rate = fee_rate.map(|fee| FeeRate::from_sat_per_vb(fee).unwrap());
        let result = self
            .client
            .wallet_send_request(
                self.wallet.clone(),
                RpcWalletTxBuilder {
                    auction_outputs,
                    requests: match req {
                        None => vec![],
                        Some(req) => vec![req],
                    },
                    fee_rate,
                    dust: self.dust,
                    force: self.force,
                },
            )
            .await?;

        println!(
            "{}",
            serde_json::to_string_pretty(&result).expect("serialize")
        );
        Ok(())
    }
}

fn normalize_space(space: &str) -> String {
    let lowercase = space.to_ascii_lowercase();
    if lowercase.starts_with('@') {
        lowercase
    } else {
        format!("@{}", lowercase)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RpcError {
    code: i32,
    message: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let (cli, args) = SpaceCli::configure().await?;
    let result = handle_commands(&cli, args.command).await;

    match result {
        Ok(_) => {}
        Err(error) => match ClientError::from(error) {
            Error::Call(rpc) => {
                let error = RpcError {
                    code: rpc.code(),
                    message: rpc.message().to_string(),
                };
                println!(
                    "{}",
                    serde_json::to_string_pretty(&error).expect("serialize")
                );
            }
            Error::Transport(err) => {
                println!(
                    "Transport error: {}: Rpc url: {} (network: {})",
                    err, cli.rpc_url, cli.network
                );
            }
            Error::RestartNeeded(err) => {
                println!("Restart needed: {}", err);
            }
            Error::ParseError(err) => {
                println!("Parse error: {}", err);
            }
            Error::InvalidSubscriptionId => {
                println!("Invalid subscription ID");
            }
            Error::InvalidRequestId(err) => {
                println!("Invalid request ID: {}", err);
            }
            Error::RequestTimeout => {
                println!("Request timeout");
            }
            Error::MaxSlotsExceeded => {
                println!("Max concurrent requests exceeded");
            }
            Error::Custom(msg) => {
                println!("Custom error: {}", msg);
            }
            Error::HttpNotImplemented => {
                println!("HTTP not implemented");
            }
            Error::EmptyBatchRequest(err) => {
                println!("Empty batch request: {}", err);
            }
            Error::RegisterMethod(err) => {
                println!("Register method error: {}", err);
            }
        },
    }
    Ok(())
}

async fn handle_commands(
    cli: &SpaceCli,
    command: Commands,
) -> std::result::Result<(), ClientError> {
    match command {
        Commands::GetRolloutEstimate {
            target_interval: target,
        } => {
            let hashes = cli.client.get_rollout(target).await?;
            let mut spaceouts = Vec::with_capacity(hashes.len());
            for (priority, spacehash) in hashes {
                let outpoint = cli
                    .client
                    .get_space_owner(hex::encode(spacehash.as_slice()))
                    .await?;

                if let Some(outpoint) = outpoint {
                    if let Some(spaceout) = cli.client.get_spaceout(outpoint).await? {
                        spaceouts.push((priority, FullSpaceOut { outpoint, spaceout }));
                    }
                }
            }

            let data: Vec<_> = spaceouts
                .into_iter()
                .map(|(priority, spaceout)| {
                    let space = spaceout.spaceout.space.unwrap();
                    (
                        space.name.to_string(),
                        match space.covenant {
                            Covenant::Bid { .. } => priority,
                            _ => 0,
                        },
                    )
                })
                .collect();

            println!("{}", serde_json::to_string_pretty(&data)?);
        }
        Commands::EstimateBid { target } => {
            let response = cli.client.estimate_bid(target).await?;
            println!("{} sat", Amount::from_sat(response).to_string());
        }
        Commands::GetSpace { space } => {
            let space = normalize_space(&space);
            let response = cli.client.get_space(space).await?;
            println!("{}", serde_json::to_string_pretty(&response)?);
        }
        Commands::GetSpaceOut { outpoint } => {
            let response = cli.client.get_spaceout(outpoint).await?;
            println!("{}", serde_json::to_string_pretty(&response)?);
        }
        Commands::CreateWallet { name } => {
            cli.client.wallet_create(name).await?;
        }
        Commands::LoadWallet { name } => {
            cli.client.wallet_load(name).await?;
        }
        Commands::ImportWallet { path } => {
            let content =
                fs::read_to_string(path).map_err(|e| ClientError::Custom(e.to_string()))?;
            cli.client.wallet_import(content).await?;
        }
        Commands::ExportWallet { name } => {
            let result = cli.client.wallet_export(name).await?;
            println!("{}", result);
        }
        Commands::GetWalletInfo { name } => {
            let result = cli.client.wallet_get_info(name).await?;
            println!("{}", serde_json::to_string_pretty(&result).expect("result"));
        }
        Commands::GetServerInfo => {
            let result = cli.client.get_server_info().await?;
            println!("{}", serde_json::to_string_pretty(&result).expect("result"));
        }
        Commands::Open {
            ref space,
            initial_bid,
            fee_rate,
        } => {
            cli.send_request(
                Some(RpcWalletRequest::Open(OpenParams {
                    name: normalize_space(space),
                    amount: initial_bid,
                })),
                None,
                fee_rate,
            )
            .await?
        }
        Commands::Bid {
            space,
            amount,
            fee_rate,
        } => {
            cli.send_request(
                Some(RpcWalletRequest::Bid(BidParams {
                    name: normalize_space(&space),
                    amount,
                })),
                None,
                fee_rate,
            )
            .await?
        }
        Commands::CreateAuctionOutputs { pairs, fee_rate } => {
            cli.send_request(None, Some(pairs), fee_rate).await?
        }
        Commands::Register {
            space,
            address,
            fee_rate,
        } => {
            cli.send_request(
                Some(RpcWalletRequest::Register(RegisterParams {
                    name: normalize_space(&space),
                    to: address,
                })),
                None,
                fee_rate,
            )
            .await?
        }
        Commands::Transfer {
            spaces,
            to,
            fee_rate,
        } => {
            let spaces: Vec<_> = spaces.into_iter().map(|s| normalize_space(&s)).collect();
            cli.send_request(
                Some(RpcWalletRequest::Transfer(TransferSpacesParams {
                    spaces,
                    to,
                })),
                None,
                fee_rate,
            )
            .await?
        }
        Commands::SendCoins {
            amount,
            to,
            fee_rate,
        } => {
            cli.send_request(
                Some(RpcWalletRequest::SendCoins(SendCoinsParams {
                    amount: Amount::from_sat(amount),
                    to,
                })),
                None,
                fee_rate,
            )
            .await?
        }
        Commands::SetData {
            mut space,
            data,
            fee_rate,
        } => {
            space = normalize_space(&space);
            let data = match BASE64_STANDARD.decode(data) {
                Ok(data) => data,
                Err(e) => {
                    return Err(ClientError::Custom(format!(
                        "Could not base64 decode data: {}",
                        e
                    )))
                }
            };
            let builder = protocol::script::ScriptBuilder::new()
                .push_slice(data.as_slice())
                .push_opcode(OP_SETALL.into());
            cli.send_request(
                Some(RpcWalletRequest::Execute(ExecuteParams {
                    context: vec![space],
                    space_script: builder,
                })),
                None,
                fee_rate,
            )
            .await?;
        }
        Commands::ListUnspent => {
            let spaces = cli.client.wallet_list_unspent(cli.wallet.clone()).await?;
            println!("{}", serde_json::to_string_pretty(&spaces)?);
        }
        Commands::ListAuctionOutputs => {
            let spaces = cli
                .client
                .wallet_list_auction_outputs(cli.wallet.clone())
                .await?;
            println!("{}", serde_json::to_string_pretty(&spaces)?);
        }
        Commands::ListSpaces => {
            let spaces = cli.client.wallet_list_spaces(cli.wallet.clone()).await?;
            println!("{}", serde_json::to_string_pretty(&spaces)?);
        }
        Commands::Balance => {
            let balance = cli.client.wallet_get_balance(cli.wallet.clone()).await?;
            println!("{}", serde_json::to_string_pretty(&balance)?);
        }
        Commands::GetCoinAddress => {
            let response = cli
                .client
                .wallet_get_new_address(cli.wallet.clone(), AddressKind::Coin)
                .await?;
            println!("{}", response);
        }
        Commands::GetSpaceAddress => {
            let response = cli
                .client
                .wallet_get_new_address(cli.wallet.clone(), AddressKind::Space)
                .await?;
            println!("{}", response);
        }
        Commands::BumpFee { txid, fee_rate } => {
            let fee_rate = FeeRate::from_sat_per_vb(fee_rate).expect("valid fee rate");
            let response = cli
                .client
                .wallet_bump_fee(cli.wallet.clone(), txid, fee_rate)
                .await?;
            println!("{}", serde_json::to_string_pretty(&response)?);
        }
    }

    Ok(())
}

fn default_spaced_rpc_url(chain: &ExtendedNetwork) -> String {
    format!("http://127.0.0.1:{}", default_spaces_rpc_port(chain))
}
