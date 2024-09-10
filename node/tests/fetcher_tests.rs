mod spaced_utils;

#[cfg(test)]
mod tests {
    use std::{
        sync::mpsc::TryRecvError,
        time::{Duration, Instant},
    };

    use crate::spaced_utils::SpaceD;
    use anyhow::Result;
    use bitcoind::bitcoincore_rpc::RpcApi;
    use protocol::constants::ChainAnchor;
    use reqwest::blocking::Client;
    use spaced::source::{BitcoinRpc, BitcoinRpcAuth, BlockEvent, BlockFetcher};
    use wallet::bitcoin::Network;

    #[test]
    fn test_block_fetching_from_bitcoin_rpc() -> Result<()> {
        let spaced = SpaceD::new()?;
        let fetcher_rpc = BitcoinRpc::new(
            &spaced.bitcoind.rpc_url(),
            BitcoinRpcAuth::UserPass("user".to_string(), "password".to_string()),
        );
        let miner_addr = spaced
            .bitcoind
            .client
            .get_new_address(None, None)?
            .require_network(Network::Regtest)?;
        const GENERATED_BLOCKS: u32 = 10;
        spaced
            .bitcoind
            .client
            .generate_to_address(GENERATED_BLOCKS as u64, &miner_addr)?;

        let client = Client::new();
        let (fetcher, receiver) = BlockFetcher::new(fetcher_rpc.clone(), client.clone(), 8);
        fetcher.start(ChainAnchor {
            hash: fetcher_rpc.send_json_blocking(&client, &fetcher_rpc.get_block_hash(0))?,
            height: 0,
        });

        let mut start_block = 0;
        let timeout = Duration::from_secs(5);
        let start_time = Instant::now();

        loop {
            if start_time.elapsed() > timeout {
                panic!("Test timed out after {:?}", timeout);
            }
            match receiver.try_recv() {
                Ok(BlockEvent::Block(id, _)) => {
                    start_block += 1;
                    if id.height == GENERATED_BLOCKS {
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
        assert_eq!(
            start_block, GENERATED_BLOCKS,
            "Not all blocks were received"
        );
        Ok(())
    }
}
