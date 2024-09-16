use std::str::FromStr;

use protocol::bitcoin::{Address, Amount};
use spaced::{rpc::RpcClient, wallets::AddressKind};
use testutil::TestRig;

async fn setup() -> anyhow::Result<TestRig> {
    // we need to mine at least 101 blocks
    let rig = TestRig::new().await?;
    rig.mine_blocks(101, None).await?;
    Ok(rig)
}

async fn it_should_create_and_fund_wallet(rig: &TestRig) -> anyhow::Result<()> {
    let name = "example".to_string();
    rig.spaced.client.wallet_create(name.clone()).await?;

    // get an address from the wallet to fund it
    let addr = Address::from_str(
        &rig.spaced
            .client
            .wallet_get_new_address(name.clone(), AddressKind::Coin)
            .await?,
    )?
    .assume_checked();
    // have the rig send some coins
    rig.send(&addr, Amount::from_sat(1000_000)).await?;
    // mine the transaction
    rig.mine_blocks(1, None).await?;
    // wait for the wallet to sync
    rig.wait_until_wallet_synced(&name).await?;

    let balance = rig.spaced.client.wallet_get_balance(name.clone()).await?;
    assert_eq!(
        balance.confirmed.total,
        Amount::from_sat(1000_000),
        "expected balance to match"
    );

    Ok(())
}

async fn it_should_handle_simple_reorg(rig: &TestRig) -> anyhow::Result<()> {
    // we mined the funding transaction on block 102
    // lets mark this block as invalid. This will
    // return any transactions that are still valid back
    // to the mempool. So lets re-mine two empty blocks
    // afterwards and see what the wallet thinks
    rig.invalidate_blocks(1).await?;
    rig.mine_empty_block().await?;
    rig.mine_empty_block().await?;
    assert_eq!(103, rig.get_block_count().await?);

    let name = "example".to_string();
    rig.wait_until_wallet_synced(&name).await?;

    let balance = rig.spaced.client.wallet_get_balance(name.clone()).await?;
    assert_eq!(
        balance.confirmed.total,
        Amount::from_sat(0),
        "expected balance to match"
    );

    // Now lets mine a block which will pull back our tx from mempool
    rig.mine_blocks(1, None).await?;
    rig.wait_until_wallet_synced(&name).await?;

    let balance = rig.spaced.client.wallet_get_balance(name.clone()).await?;
    assert_eq!(
        balance.confirmed.total,
        Amount::from_sat(1000_000),
        "expected balance to match"
    );
    Ok(())
}

#[tokio::test]
async fn run_wallet_tests() -> anyhow::Result<()> {
    let rig = setup().await?;
    it_should_create_and_fund_wallet(&rig).await?;
    it_should_handle_simple_reorg(&rig).await?;
    Ok(())
}
