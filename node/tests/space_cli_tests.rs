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

    fn setup(args: &[&str]) -> Result<(SpaceD, Command)> {
        env_logger::init();
        let spaced = SpaceD::new()?;
        let mut space_cli = Command::cargo_bin("space-cli")?;
        space_cli
            .arg("--chain")
            .arg("regtest")
            .arg("--spaced-rpc-url")
            .arg(spaced.spaced_rpc_url());
        for arg in args {
            space_cli.arg(arg);
        }
        Ok((spaced, space_cli))
    }

    #[test]
    fn test_get_server_info() -> Result<()> {
        let (_spaced, mut space_cli) = setup(&["getserverinfo"])?;

        space_cli
            .assert()
            .success()
            .stdout(predicate::function(|x: &str| {
                let info: ServerInfo = from_str(x).unwrap();
                return info.chain == ExtendedNetwork::Regtest;
            }));

        Ok(())
    }
}
