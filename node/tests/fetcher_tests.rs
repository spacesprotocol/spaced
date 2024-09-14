use std::{
    sync::mpsc::TryRecvError,
    time::{Duration, Instant},
};

use anyhow::Result;
use protocol::{bitcoin::BlockHash, constants::ChainAnchor};
use reqwest::blocking::Client;
use spaced::source::{BitcoinRpc, BitcoinRpcAuth, BlockEvent, BlockFetcher};
use testutil::TestRig;

async fn setup(blocks: u64) -> Result<(TestRig, u64, BlockHash)> {
    let rig = TestRig::new().await?;
    rig.mine_blocks(blocks as _, None).await?;
    let height = 0;
    let hash = rig.get_block_hash(height).await?;
    Ok((rig, height, hash))
}

#[test]
fn test_block_fetching_from_bitcoin_rpc() -> Result<()> {
    const GENERATED_BLOCKS: u64 = 10;

    let (rig, mut height, hash) = tokio::runtime::Runtime::new()?
        .block_on(setup(GENERATED_BLOCKS))?;
    let fetcher_rpc = BitcoinRpc::new(
        &rig.bitcoind.rpc_url(),
        BitcoinRpcAuth::UserPass("user".to_string(), "password".to_string()),
    );

    let client = Client::new();
    let (fetcher, receiver) = BlockFetcher::new(fetcher_rpc.clone(), client.clone(), 8);

    fetcher.start(ChainAnchor { hash, height: 0 });

    let timeout = Duration::from_secs(5);
    let start_time = Instant::now();

    loop {
        if start_time.elapsed() > timeout {
            panic!("Test timed out after {:?}", timeout);
        }
        match receiver.try_recv() {
            Ok(BlockEvent::Block(id, _)) => {
                height += 1;
                if id.height == GENERATED_BLOCKS as u32 {
                    break;
                }
            }
            Ok(BlockEvent::Error(e)) => panic!("Unexpected error: {}", e),
            Err(TryRecvError::Empty) => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(TryRecvError::Disconnected) => panic!("Disconnected unexpectedly"),
        }
    }

    assert_eq!(height, GENERATED_BLOCKS, "Not all blocks were received");
    Ok(())
}
