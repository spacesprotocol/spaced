use anyhow::{anyhow, Result};
use assert_cmd::cargo::CommandCargoExt;
use bitcoind::{tempfile::tempdir, BitcoinD, Conf};
use log::{debug, error};
use std::{
    net::{Ipv4Addr, TcpListener},
    process::{Child, Command},
    thread,
    time::Duration,
};

#[derive(Debug)]
pub struct SpaceD {
    pub bitcoind: BitcoinD,
    process: Child,
    rpc_port: u16,
}

const LOCAL_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);

impl SpaceD {
    pub async fn new() -> Result<Self> {
        let mut conf: Conf = Conf::default();
        conf.args = vec!["-regtest", "-fallbackfee=0.0001", "-rpcauth=user:70dbb4f60ccc95e154da97a43b7a9d06$00c10a3849edf2f10173e80d0bdadbde793ad9a80e6e6f9f71f978fb5c797343"];
        let bitcoind = BitcoinD::from_downloaded_with_conf(&conf).unwrap();
        debug!("bitcoind running on port {}", bitcoind.rpc_url());
        let rpc_port = get_available_port()?;
        let mut process = Command::cargo_bin("spaced")?
            .arg("--chain")
            .arg("regtest")
            .arg("--bitcoin-rpc-url")
            .arg(bitcoind.rpc_url())
            .arg("--bitcoin-rpc-user")
            .arg("user")
            .arg("--bitcoin-rpc-password")
            .arg("password")
            .arg("--block-index")
            .arg("--data-dir")
            .arg(tempdir()?.path())
            .arg("--rpc-port")
            .arg(rpc_port.to_string())
            .spawn()?;
        if let Some(_) = process.try_wait()? {
            error!("spaced failed to obtain port {}", rpc_port);
            return Result::Err(anyhow!("Port unavailable"));
        }
        thread::sleep(Duration::from_millis(100));
        assert!(process.stderr.is_none());
        debug!("spaced running on port {}", rpc_port);
        Result::Ok(Self {
            bitcoind,
            process,
            rpc_port,
        })
    }

    pub fn spaced_rpc_url(&self) -> String {
        format!("http://{}:{}", LOCAL_IP, self.rpc_port)
    }
}

impl Drop for SpaceD {
    fn drop(&mut self) {
        debug!("killing spaced process");
        let _ = self.process.kill();
    }
}

/// Returns an unused local port if available.
///
/// The port may become unavailable after returning.
fn get_available_port() -> Result<u16> {
    // Binding with a port number of 0 will request that the OS assigns a port to this listener.
    let t = TcpListener::bind(("127.0.0.1", 0))?;
    Ok(t.local_addr().map(|s| s.port())?)
}
