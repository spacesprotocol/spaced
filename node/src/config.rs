use std::{
    collections::{HashMap, HashSet},
    env,
    ffi::OsString,
    fmt::Display,
    fs,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
};

use clap::{
    error::{ContextKind, ContextValue},
    ArgGroup, Parser, ValueEnum,
};
use directories::ProjectDirs;
use jsonrpsee::core::Serialize;
use log::error;
use protocol::bitcoin::Network;
use serde::Deserialize;
use toml::Value;

use crate::{
    source::{BitcoinRpc, BitcoinRpcAuth},
    store::{LiveStore, Store},
    sync::Spaced,
};

const RPC_OPTIONS: &str = "RPC Server Options";

/// Spaces protocol Bitcoin Daemon
#[derive(Parser, Debug, Serialize, Deserialize)]
#[clap(group(
    ArgGroup::new("bitcoin_rpc_auth")
    .required(false)
    .multiple(false)
    .args(&["bitcoin_rpc_cookie","bitcoin_rpc_user"])
))]
#[command(args_override_self = true, author, version, about, long_about = None)]
pub struct Args {
    /// Path to a configuration file
    #[arg(long, env = "SPACED_CONFIG")]
    config: Option<PathBuf>,
    #[arg(long, env = "SPACED_BLOCK_INDEX", default_value = "false")]
    block_index: bool,
    #[arg(long, env = "SPACED_DATA_DIR")]
    data_dir: Option<PathBuf>,
    /// Network to use
    #[arg(long, env = "SPACED_CHAIN")]
    chain: ExtendedNetwork,
    /// Number of concurrent workers allowed during syncing
    #[arg(short, long, env = "SPACED_JOBS", default_value = "8")]
    jobs: u8,
    /// Bitcoin RPC URL
    #[arg(long, env = "SPACED_BITCOIN_RPC_URL")]
    bitcoin_rpc_url: Option<String>,
    /// Bitcoin RPC cookie file path
    #[arg(long, env = "SPACED_BITCOIN_RPC_COOKIE")]
    bitcoin_rpc_cookie: Option<PathBuf>,
    /// Bitcoin RPC user
    #[arg(
        long,
        requires = "bitcoin_rpc_password",
        env = "SPACED_BITCOIN_RPC_USER"
    )]
    bitcoin_rpc_user: Option<String>,
    /// Bitcoin RPC password
    #[arg(long, env = "SPACED_BITCOIN_RPC_PASSWORD")]
    bitcoin_rpc_password: Option<String>,
    /// Bind to given address to listen for JSON-RPC connections.
    /// This option can be specified multiple times (default: 127.0.0.1 and ::1 i.e., localhost)
    #[arg(long, help_heading = Some(RPC_OPTIONS), default_values = ["127.0.0.1", "::1"], env = "SPACED_RPC_BIND")]
    rpc_bind: Vec<String>,
    /// Listen for JSON-RPC connections on <port>
    #[arg(long, help_heading = Some(RPC_OPTIONS), env = "SPACED_RPC_PORT")]
    rpc_port: Option<u16>,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExtendedNetwork {
    Mainnet,
    Testnet,
    Testnet4,
    Signet,
    Regtest,
}

impl ExtendedNetwork {
    pub fn fallback_network(&self) -> Network {
        match self {
            ExtendedNetwork::Mainnet => Network::Bitcoin,
            ExtendedNetwork::Testnet => Network::Testnet,
            ExtendedNetwork::Signet => Network::Signet,
            ExtendedNetwork::Regtest => Network::Regtest,
            ExtendedNetwork::Testnet4 => Network::Testnet,
        }
    }
}

impl Args {
    /// Configures spaced node by processing command line arguments
    /// and configuration files
    pub fn configure() -> anyhow::Result<Spaced> {
        let mut args = Args::merge_args_config(None);
        let default_dirs = get_default_node_dirs();

        // Update from a configuration file if it exists
        args = match args.config {
            None => {
                let default_path = default_dirs.config_dir().join("Spaces.toml");
                args.config = Some(default_path.clone());

                match default_path.exists() {
                    true => Args::merge_args_config(Some(default_path)),
                    false => args,
                }
            }
            Some(user_specified_path) => Args::merge_args_config(Some(user_specified_path)),
        };

        if args.bitcoin_rpc_url.is_none() {
            args.bitcoin_rpc_url = Some(default_bitcoin_rpc_url(&args.chain).to_string())
        }
        if args.rpc_port.is_none() {
            args.rpc_port = Some(default_spaces_rpc_port(&args.chain));
        }

        let data_dir = match args.data_dir {
            None => default_dirs.data_dir().join(args.chain.to_string()),
            Some(data_dir) => data_dir,
        };

        let default_port = args.rpc_port.unwrap();
        let rpc_bind_addresses: Vec<SocketAddr> = args
            .rpc_bind
            .iter()
            .filter_map(|s| {
                s.parse::<SocketAddr>()
                    .or_else(|_| {
                        s.parse::<IpAddr>()
                            .map(|ip| SocketAddr::new(ip, default_port))
                    })
                    .ok()
            })
            .collect();

        let genesis = Spaced::genesis(args.chain);
        let bitcoin_rpc_auth = if let Some(cookie) = args.bitcoin_rpc_cookie {
            let cookie = std::fs::read_to_string(cookie)?;
            BitcoinRpcAuth::Cookie(cookie)
        } else if let Some(user) = args.bitcoin_rpc_user {
            BitcoinRpcAuth::UserPass(user, args.bitcoin_rpc_password.expect("password"))
        } else {
            BitcoinRpcAuth::None
        };

        let rpc = BitcoinRpc::new(
            &args.bitcoin_rpc_url.expect("bitcoin rpc url"),
            bitcoin_rpc_auth,
        );

        fs::create_dir_all(data_dir.clone())?;

        let proto_db_path = data_dir.join("protocol.sdb");
        let initial_sync = !proto_db_path.exists();

        let chain_store = Store::open(proto_db_path)?;
        let chain = LiveStore {
            state: chain_store.begin(&genesis)?,
            store: chain_store,
        };

        let block_index = if args.block_index {
            let block_db_path = data_dir.join("block_index.sdb");
            if !initial_sync && !block_db_path.exists() {
                return Err(anyhow::anyhow!(
                    "Block index must be enabled from the initial sync."
                ));
            }
            let block_store = Store::open(block_db_path)?;
            let index = LiveStore {
                state: block_store.begin(&genesis).expect("begin block index"),
                store: block_store,
            };
            {
                let tip_1 = index.state.tip.read().expect("index");
                let tip_2 = chain.state.tip.read().expect("tip");
                if tip_1.height != tip_2.height || tip_1.hash != tip_2.hash {
                    return Err(anyhow::anyhow!(
                        "Protocol and block index states don't match."
                    ));
                }
            }
            Some(index)
        } else {
            None
        };

        Ok(Spaced {
            network: args.chain,
            rpc,
            data_dir,
            bind: rpc_bind_addresses,
            chain,
            block_index,
            num_workers: args.jobs as usize,
        })
    }

    /// Merges configuration file if set and command line arguments (latter takes priority)
    fn merge_args_config(config_file: Option<PathBuf>) -> Self {
        let mut config_args_keys = None;
        let config_args = match load_args(config_file) {
            None => Args::try_parse_from(env::args_os()),
            Some((config_args, keys)) => {
                config_args_keys = Some(keys);
                let cmd_args = env::args_os().collect::<Vec<OsString>>();
                let config_args: Vec<OsString> = config_args.iter().map(|s| s.into()).collect();
                let all_args = cmd_args
                    .iter()
                    .take(1)
                    .chain(config_args.iter())
                    .chain(cmd_args.iter().skip(1));
                Args::try_parse_from(all_args)
            }
        };

        let args = match config_args {
            Ok(args) => args,
            Err(mut err) => {
                if let Some(config_args_keys) = config_args_keys {
                    err = style_config_error(err, config_args_keys);
                    error!("{}", err.to_string().replace("argument", "option"));
                    safe_exit(err.exit_code());
                } else {
                    err.exit()
                }
            }
        };

        args
    }
}

fn get_default_node_dirs() -> ProjectDirs {
    ProjectDirs::from("", "", "spaced").unwrap_or_else(|| {
        error!("error: could not retrieve default project directories from os");
        safe_exit(1);
    })
}

// from clap utilities
pub fn safe_exit(code: i32) -> ! {
    use std::io::Write;

    let _ = std::io::stdout().lock().flush();
    let _ = std::io::stderr().lock().flush();

    std::process::exit(code)
}

fn default_bitcoin_rpc_url(network: &ExtendedNetwork) -> &'static str {
    match network {
        ExtendedNetwork::Mainnet => "http://127.0.0.1:8332",
        ExtendedNetwork::Testnet4 => "http://127.0.0.1:48332",
        ExtendedNetwork::Signet => "http://127.0.0.1:38332",
        ExtendedNetwork::Testnet => "http://127.0.0.1:18332",
        ExtendedNetwork::Regtest => "http://127.0.0.1:18443",
    }
}

fn toml_value_to_string(value: Value) -> Option<String> {
    match value {
        Value::String(v) => Some(v),
        Value::Integer(i) => Some(i.to_string()),
        Value::Float(f) => Some(f.to_string()),
        Value::Boolean(b) => Some(b.to_string()),
        Value::Datetime(d) => Some(d.to_string()),
        Value::Array(_) => None,
        Value::Table(_) => None,
    }
}

fn load_args(path: Option<PathBuf>) -> Option<(Vec<String>, HashSet<String>)> {
    let path = match path {
        None => return None,
        Some(p) => p,
    };

    let mut config_args = HashSet::new();
    if let Ok(config_str) = fs::read_to_string(path.clone()) {
        let config: HashMap<String, toml::Value> = toml::from_str(&config_str).expect("parse");
        let mut args = Vec::new();
        for (key, value) in config {
            let value = match toml_value_to_string(value) {
                None => continue,
                Some(v) => v,
            };
            let arg = format!("--{}", key.replace('_', "-"));
            config_args.insert(arg.clone());
            args.push(arg);
            args.push(value);
        }
        return Some((args, config_args));
    }

    error!("could not read configuration at {}", path.to_str().unwrap());
    safe_exit(1);
}

fn maybe_style_arg(str: &str, set: &HashSet<String>) -> String {
    let arg_name = str.split_once(' ');
    if let Some((arg_name, _)) = arg_name {
        if set.contains(arg_name) {
            return str
                .replace("--", "config.")
                .replace('-', "_")
                .replace('<', "= <")
                .replace('>', ">");
        }
    }

    return str.to_string();
}

fn style_config_error(err: clap::Error, config_args: HashSet<String>) -> clap::Error {
    let mut new_error = clap::Error::new(err.kind());
    for (ck, cv) in err.context() {
        match ck {
            ContextKind::Usage
            | ContextKind::Suggested
            | ContextKind::SuggestedCommand
            | ContextKind::SuggestedSubcommand
            | ContextKind::Custom => {
                // skip
            }
            _ => {
                let new_cv = match cv {
                    ContextValue::String(str) => {
                        ContextValue::String(maybe_style_arg(str, &config_args))
                    }
                    ContextValue::Strings(strings) => {
                        let mut strs = strings.clone();
                        strs[0] = maybe_style_arg(&strs[0], &config_args);
                        ContextValue::Strings(strs)
                    }
                    _ => cv.clone(),
                };

                new_error.insert(ck, new_cv);
            }
        }
    }

    new_error
}

impl Display for ExtendedNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            ExtendedNetwork::Mainnet => "mainnet".to_string(),
            ExtendedNetwork::Testnet => "testnet".to_string(),
            ExtendedNetwork::Testnet4 => "testnet4".to_string(),
            ExtendedNetwork::Signet => "signet".to_string(),
            ExtendedNetwork::Regtest => "regtest".to_string(),
        };
        write!(f, "{}", str)
    }
}

pub fn default_spaces_rpc_port(chain: &ExtendedNetwork) -> u16 {
    match chain {
        ExtendedNetwork::Mainnet => 7225,
        ExtendedNetwork::Testnet4 => 7224,
        ExtendedNetwork::Testnet => 7223,
        ExtendedNetwork::Signet => 7221,
        ExtendedNetwork::Regtest => 7218,
    }
}
