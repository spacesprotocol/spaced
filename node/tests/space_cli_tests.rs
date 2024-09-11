pub mod utils;

#[cfg(test)]
mod tests {
    use crate::utils::SpaceD;
    use anyhow::Result;
    use assert_cmd::prelude::*;
    use predicates::prelude::*;
    use serde_json::from_str;
    use spaced::config::ExtendedNetwork;
    use spaced::rpc::ServerInfo;
    use std::process::Command;

    fn setup(spaced_rpc_url: String, args: &[&str]) -> Result<Command> {
        let mut space_cli = Command::cargo_bin("space-cli")?;
        space_cli
            .arg("--chain")
            .arg("regtest")
            .arg("--spaced-rpc-url")
            .arg(spaced_rpc_url);
        for arg in args {
            space_cli.arg(arg);
        }
        Ok(space_cli)
    }

    #[test]
    fn get_server_info_works() -> Result<()> {
        let spaced = SpaceD::new()?;
        let mut get_server_info = setup(spaced.spaced_rpc_url(), &["getserverinfo"])?;

        get_server_info
            .assert()
            .success()
            .stdout(predicate::function(|x: &str| {
                let info: ServerInfo = from_str(x).unwrap();
                return info.chain == ExtendedNetwork::Regtest;
            }));

        Ok(())
    }

    #[test]
    fn create_wallet_works() -> Result<()> {
        let spaced = SpaceD::new()?;
        let mut create_wallet = setup(spaced.spaced_rpc_url(), &["createwallet"])?;

        create_wallet
            .assert()
            .success()
            .stdout(predicate::str::is_empty());

        Ok(())
    }

    #[test]
    fn create_duplicate_wallet_fails() -> Result<()> {
        let spaced = SpaceD::new()?;
        let _ = setup(spaced.spaced_rpc_url(), &["createwallet"])?.status()?;
        let mut create_wallet_again = setup(spaced.spaced_rpc_url(), &["createwallet"])?;

        create_wallet_again
            .assert()
            .success()
            .stdout(predicate::str::contains("Wallet `default` already exists"));

        Ok(())
    }

}
