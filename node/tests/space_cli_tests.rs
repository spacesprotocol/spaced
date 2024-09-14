use std::process::Command;

use anyhow::Result;
use assert_cmd::prelude::*;
use predicates::prelude::*;
use serde_json::from_str;
use spaced::{config::ExtendedNetwork, rpc::ServerInfo};
use testutil::TestRig;

#[tokio::test]
async fn test_get_server_info() -> Result<()> {
    env_logger::init();
    let rig = TestRig::new().await?;

    Command::cargo_bin("space-cli")?
        .arg("--chain")
        .arg("regtest")
        .arg("--spaced-rpc-url")
        .arg(rig.spaced.rpc_url())
        .arg("getserverinfo")
        .assert()
        .success()
        .stdout(predicate::function(|x: &str| {
            let info: ServerInfo = from_str(x).unwrap();
            return info.chain == ExtendedNetwork::Regtest;
        }));

    Ok(())
}
