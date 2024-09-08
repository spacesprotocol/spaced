mod spaced_utils;

#[cfg(test)]
mod tests {
    use crate::spaced_utils::SpaceD;
    use anyhow::Result;
    use assert_cmd::prelude::*;
    use predicates::prelude::*;
    use serde_json::from_str;
    use spaced::config::ExtendedNetwork;
    use spaced::rpc::ServerInfo;
    use std::process::Command;

    #[tokio::test]
    async fn test_get_server_info() -> Result<(), Box<dyn std::error::Error>> {
        env_logger::init();
        let spaced = SpaceD::new()?;

        Command::cargo_bin("space-cli")?
            .arg("--chain")
            .arg("regtest")
            .arg("--spaced-rpc-url")
            .arg(spaced.spaced_rpc_url())
            .arg("getserverinfo")
            .assert()
            .success()
            .stdout(predicate::function(|x: &str| {
                let info: ServerInfo = from_str(x).unwrap();
                return info.chain == ExtendedNetwork::Regtest;
            }));

        Ok(())
    }
}
