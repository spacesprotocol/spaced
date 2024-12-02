use std::{net::Ipv4Addr, process::Child, time::Duration};
use std::process::Stdio;
use anyhow::Result;
use assert_cmd::cargo::CommandCargoExt;
use bitcoind::{anyhow, anyhow::anyhow, get_available_port, tempfile::tempdir};
use spaced::{
    jsonrpsee::{
        http_client::{HttpClient, HttpClientBuilder},
        tokio,
    },
    log::{debug, error},
    rpc::RpcClient,
};

const LOCAL_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);

/// Conf a similar structure to bitcoind crate configuration
#[non_exhaustive]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Conf<'a> {
    /// Spaced command line arguments e.g. `vec!["--chain", "regtest"]`
    /// note that `--rpc-port`, `--data-dir` are automatically initialized.
    pub args: Vec<&'a str>,
    pub view_stdout: bool,
}

#[derive(Debug)]
pub struct SpaceD {
    process: Child,
    pub client: HttpClient,
    rpc_port: u16,
}

impl SpaceD {
    pub async fn new(conf: Conf<'_>) -> Result<Self> {
        let rpc_port = get_available_port()?;

        let stdout = if conf.view_stdout {
            Stdio::inherit()
        } else {
            Stdio::null()
        };

        let args: Vec<_> = conf.args.into_iter().map(String::from).collect();
        let process = tokio::task::spawn_blocking(move || -> Result<Child> {
            Ok(std::process::Command::cargo_bin("spaced")?
                .args(args)
                .arg("--rpc-port")
                .arg(rpc_port.to_string())
                .arg("--data-dir")
                .arg(tempdir()?.path())
                .stdout(stdout)
                .spawn()?)
        })
        .await
        .expect("spawn blocking task")?;

        let client = HttpClientBuilder::default().build(rpc_url(rpc_port))?;

        let mut spaced = Self {
            process,
            rpc_port,
            client,
        };

        let mut i = 0;
        loop {
            if let Some(status) = spaced.process.try_wait()? {
                error!("early exit with: {:?}", status);
                return Err(anyhow!("Spaced exited with status {} ", status));
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
            assert!(spaced.process.stderr.is_none());

            if spaced.client.get_server_info().await.is_ok() {
                break;
            }

            debug!(
                "spaces client for process {} not ready ({})",
                spaced.process.id(),
                i
            );
            i += 1;
        }

        Ok(spaced)
    }

    pub fn rpc_url(&self) -> String {
        rpc_url(self.rpc_port)
    }
}

fn rpc_url(port: u16) -> String {
    format!("http://{}:{}", LOCAL_IP, port)
}

impl Drop for SpaceD {
    fn drop(&mut self) {
        debug!("killing spaced process");
        let _ = self.process.kill();
    }
}
