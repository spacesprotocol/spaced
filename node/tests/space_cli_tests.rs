#[cfg(test)]
mod test {
    use anyhow::{anyhow, Result};
    use assert_cmd::prelude::*;
    use bitcoind::bitcoincore_rpc::{Auth, RpcApi};
    use bitcoind::tempfile::tempdir;
    use bitcoind::{BitcoinD, Conf};
    use predicates::prelude::*;
    use serde_json::from_str;
    use spaced::config::ExtendedNetwork;
    use spaced::rpc::ServerInfo;
    use std::process::{Child, Command};
    use wallet::bitcoin::Network;

    async fn setup_bitcoind() -> Result<BitcoinD, Box<dyn std::error::Error>> {
        let mut conf: Conf = Conf::default();
        conf.args = vec!["-regtest", "-fallbackfee=0.0001", "-rpcauth=user:70dbb4f60ccc95e154da97a43b7a9d06$00c10a3849edf2f10173e80d0bdadbde793ad9a80e6e6f9f71f978fb5c797343"];
        let bitcoind = BitcoinD::from_downloaded_with_conf(&conf).unwrap();
        println!("bitcoind running on {}", bitcoind.rpc_url());
        Ok(bitcoind)
    }

    async fn setup_spaced(rpc_url: String, rpc_auth: Auth) -> Result<Child> {
        match rpc_auth {
            Auth::None => Err(anyhow!("No auth")),
            Auth::CookieFile(_) => Err(anyhow!("Cookie file auth not supported")),
            Auth::UserPass(user, password) => {
                let spaced_cmd = Command::cargo_bin("spaced")?
                    .arg("--chain")
                    .arg("regtest")
                    .arg("--bitcoin-rpc-url")
                    .arg(rpc_url)
                    .arg("--bitcoin-rpc-user")
                    .arg(user)
                    .arg("--bitcoin-rpc-password")
                    .arg(password)
                    .arg("--block-index")
                    .arg("--data-dir")
                    .arg(tempdir()?.path())
                    .spawn()?;
                Ok(spaced_cmd)
            }
        }
    }

    #[tokio::test]
    async fn test_get_server_info() -> Result<(), Box<dyn std::error::Error>> {
        env_logger::init();
        let bitcoind = setup_bitcoind().await?;
        let auth = Auth::UserPass("user".to_owned(), "password".to_owned());
        let address = bitcoind
            .client
            .get_new_address(None, None)?
            .require_network(Network::Regtest)?;
        println!("generated new address {}", address);
        bitcoind.client.generate_to_address(101, &address)?;
        let mut spaced = setup_spaced(bitcoind.rpc_url(), auth).await?;

        Command::cargo_bin("space-cli")?
            .arg("--chain")
            .arg("regtest")
            .arg("getserverinfo")
            .assert()
            .success()
            .stdout(predicate::function(|x: &str| {
                let info: ServerInfo = from_str(x).unwrap();
                return info.chain == ExtendedNetwork::Regtest;
            }));

        spaced.kill().expect("Couldn't kill spaced");
        Ok(())
    }
}
