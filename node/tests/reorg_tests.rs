use std::time::Duration;

use spaced::rpc::RpcClient;
use testutil::TestRig;

#[tokio::test]
async fn it_should_resync_after_reorg_at_same_height() -> anyhow::Result<()> {
    let rig = TestRig::new().await?;
    rig.mine_blocks(38, None).await?;
    rig.wait_until_synced().await?;

    let info = rig.spaced.client.get_server_info().await?;
    assert_eq!(info.tip.height, 38);
    assert_eq!(info.tip.hash, rig.get_best_block_hash().await?);

    let reorged = rig.reorg(1).await?;
    assert_eq!(reorged.len(), 1);

    rig.wait_until_tip(reorged[0], Duration::from_secs(2))
        .await?;
    Ok(())
}
