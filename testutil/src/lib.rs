pub extern crate bitcoind;
pub mod spaced;

use std::{fs, io, sync::Arc, time::Duration};
use std::path::{Path, PathBuf};
use ::spaced::{
    jsonrpsee::tokio,
    node::protocol::{
        bitcoin,
        bitcoin::{
            absolute, address::NetworkChecked, block, block::Header, hashes::Hash,
            key::rand::random, transaction, Address, Amount, Block, BlockHash, CompactTarget,
            OutPoint, ScriptBuf, ScriptHash, Sequence, Transaction, TxIn, TxMerkleNode, TxOut,
            Txid,
        },
    },
    rpc::RpcClient,
};
use anyhow::Result;
use bitcoind::{
    anyhow,
    anyhow::anyhow,
    bitcoincore_rpc::{
        bitcoincore_rpc_json::{GetBlockTemplateModes, GetBlockTemplateRules},
        RpcApi,
    },
    BitcoinD,
};
use bitcoind::anyhow::Context;
use bitcoind::tempfile::{tempdir, TempDir};
use crate::spaced::SpaceD;

// Path to the pre-created regtest testdata in build.rs
pub fn bitcoin_regtest_data_path() -> Result<String> {
    let mut path: PathBuf = env!("OUT_DIR").into();
    path.push("regtest_unpacked");
    path.push("bitcoin_core_regtest_data");
    Ok(format!("{}", path.display()))
}

#[derive(Debug)]
pub struct TestRig {
    pub bitcoind: Arc<BitcoinD>,
    pub spaced: SpaceD,
    pub test_data: Option<TempDir>,
}

impl TestRig {
    pub async fn new_with_regtest_preset() -> Result<TestRig> {
        let original_test_data = bitcoin_regtest_data_path()
            .context("could not get unpacked regtest testdata")?;
        let test_data = tempdir()?;
        copy_dir_all(original_test_data, test_data.path())?;

        let mut conf = bitcoind::Conf::default();
        conf.args = vec![
            "-regtest",
            "-rpcworkqueue=100",
            "-fallbackfee=0.0001",
            "-rpcauth=user:70dbb4f60ccc95e154da97a43b7a9d06$00c10a3849edf2f10173e80d0bdadbde793ad9a80e6e6f9f71f978fb5c797343"
        ];

        conf.staticdir = Some(test_data.path().join("bitcoind"));

        TestRig::new_with_bitcoin_conf(conf, Some(test_data)).await
    }

    pub async fn testdata_wallets_path(&self) -> PathBuf {
        self.test_data.as_ref().expect("created with regtest preset")
            .path().join("wallets")
    }

    pub async fn new() -> Result<TestRig> {
        let mut conf = bitcoind::Conf::default();
        // The RPC auth uses username "user" and password "password". If we
        // don't set this, bitcoind's RPC API becomes inaccessible to spaced due
        // to auth issues.
        conf.args = vec![
            "-regtest",
            "-fallbackfee=0.0001",
            "-rpcauth=user:70dbb4f60ccc95e154da97a43b7a9d06$00c10a3849edf2f10173e80d0bdadbde793ad9a80e6e6f9f71f978fb5c797343"
        ];

        Self::new_with_bitcoin_conf(conf, None).await
    }

    pub async fn new_with_bitcoin_conf(conf: bitcoind::Conf<'static>, test_data: Option<TempDir>) -> Result<Self> {
        let view_stdout = conf.view_stdout;
        let bitcoind =
            tokio::task::spawn_blocking(move || BitcoinD::from_downloaded_with_conf(&conf))
                .await
                .expect("handle")?;

        let rpc_url = bitcoind.rpc_url();
        let spaced_conf = spaced::Conf {
            args: vec![
                "--chain",
                "regtest",
                "--bitcoin-rpc-url",
                &rpc_url,
                "--bitcoin-rpc-user",
                "user",
                "--bitcoin-rpc-password",
                "password",
                "--block-index-full",
            ],
            view_stdout,
        };

        let spaced = SpaceD::new(spaced_conf).await?;
        Ok(TestRig {
            bitcoind: Arc::new(bitcoind),
            spaced,
            test_data,
        })
    }

    /// Waits until spaced tip == bitcoind tip
    pub async fn wait_until_synced(&self) -> anyhow::Result<()> {
        loop {
            let c = self.bitcoind.clone();
            let count = tokio::task::spawn_blocking(move || c.client.get_block_count())
                .await
                .expect("handle")? as u32;

            let info = self.spaced.client.get_server_info().await?;
            if count == info.tip.height {
                return Ok(());
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Waits until spaced tip == specified best_hash or specified time out
    pub async fn wait_until_tip(&self, tip: BlockHash, timeout: Duration) -> Result<()> {
        let start_time = tokio::time::Instant::now();

        loop {
            let info = self.spaced.client.get_server_info().await?;
            if info.tip.hash == tip {
                return Ok(());
            }
            if start_time.elapsed() >= timeout {
                return Err(anyhow!("Rimed out waiting for tip {:?}", tip));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Waits until named wallet tip == bitcoind tip
    pub async fn wait_until_wallet_synced(&self, wallet_name: &str) -> anyhow::Result<()> {
        loop {
            let c = self.bitcoind.clone();
            let count = tokio::task::spawn_blocking(move || c.client.get_block_count())
                .await
                .expect("handle")? as u32;

            let info = self.spaced.client.wallet_get_info(wallet_name).await?;
            if count == info.tip {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Mine a number of blocks of a given size `count`, which may be specified to a given coinbase
    /// `address`.
    ///
    /// An async verison of bdk's testenv mine_blocks:
    /// https://github.com/bitcoindevkit/bdk/blob/master/crates/testenv/src/lib.rs
    pub async fn mine_blocks(
        &self,
        count: usize,
        address: Option<Address>,
    ) -> Result<Vec<BlockHash>> {
        let coinbase_address = match address {
            Some(address) => address,
            None => {
                let c = self.bitcoind.clone();
                tokio::task::spawn_blocking(move || c.client.get_new_address(None, None))
                    .await
                    .expect("handle")?
                    .assume_checked()
            }
        };
        let block_hashes = self
            .bitcoind
            .client
            .generate_to_address(count as _, &coinbase_address)?;
        Ok(block_hashes)
    }

    /// Mine a block that is guaranteed to be empty even with transactions in the mempool.
    ///
    /// An async version of bdk's testenv mine_empty_block:
    /// https://github.com/bitcoindevkit/bdk/blob/master/crates/testenv/src/lib.rs
    pub async fn mine_empty_block(&self) -> anyhow::Result<(usize, BlockHash)> {
        let c = self.bitcoind.clone();
        let bt = tokio::task::spawn_blocking(move || {
            c.client.get_block_template(
                GetBlockTemplateModes::Template,
                &[GetBlockTemplateRules::SegWit],
                &[],
            )
        })
            .await
            .expect("handle")?;

        let txdata = vec![Transaction {
            version: transaction::Version::ONE,
            lock_time: absolute::LockTime::from_height(0)?,
            input: vec![TxIn {
                previous_output: OutPoint::default(),
                script_sig: ScriptBuf::builder()
                    .push_int(bt.height as _)
                    // random number so that re-mining creates unique block
                    .push_int(random())
                    .into_script(),
                sequence: Sequence::default(),
                witness: bitcoin::Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::new_p2sh(&ScriptHash::all_zeros()),
            }],
        }];

        let bits: [u8; 4] = bt
            .bits
            .clone()
            .try_into()
            .expect("rpc provided us with invalid bits");

        let mut block = Block {
            header: Header {
                version: block::Version::default(),
                prev_blockhash: bt.previous_block_hash,
                merkle_root: TxMerkleNode::all_zeros(),
                time: Ord::max(bt.min_time, std::time::UNIX_EPOCH.elapsed()?.as_secs()) as u32,
                bits: CompactTarget::from_consensus(u32::from_be_bytes(bits)),
                nonce: 0,
            },
            txdata,
        };

        block.header.merkle_root = block.compute_merkle_root().expect("must compute");

        for nonce in 0..=u32::MAX {
            block.header.nonce = nonce;
            if block.header.target().is_met_by(block.block_hash()) {
                break;
            }
        }

        let block_hash = block.header.block_hash();

        let c = self.bitcoind.clone();
        tokio::task::spawn_blocking(move || c.client.submit_block(&block))
            .await
            .expect("handle")?;

        Ok((bt.height as usize, block_hash))
    }

    /// Invalidate a number of blocks of a given size `count`.
    ///
    /// An async version of bdk's testenv invalidate_blocks:
    /// https://github.com/bitcoindevkit/bdk/blob/master/crates/testenv/src/lib.rs
    pub async fn invalidate_blocks(&self, count: usize) -> anyhow::Result<()> {
        let mut hash = self.get_best_block_hash().await?;

        for _ in 0..count {
            let prev_hash = self
                .bitcoind
                .client
                .get_block_info(&hash)?
                .previousblockhash;

            let c = self.bitcoind.clone();
            tokio::task::spawn_blocking(move || c.client.invalidate_block(&hash))
                .await
                .expect("handle")?;

            match prev_hash {
                Some(prev_hash) => hash = prev_hash,
                None => break,
            }
        }
        Ok(())
    }

    pub async fn get_block_count(&self) -> Result<u64> {
        let c = self.bitcoind.clone();
        Ok(
            tokio::task::spawn_blocking(move || c.client.get_block_count())
                .await
                .expect("handle")?,
        )
    }

    pub async fn get_best_block_hash(&self) -> Result<BlockHash> {
        let c = self.bitcoind.clone();
        Ok(
            tokio::task::spawn_blocking(move || c.client.get_best_block_hash())
                .await
                .expect("handle")?,
        )
    }

    pub async fn get_block_hash(&self, height: u64) -> Result<BlockHash> {
        let c = self.bitcoind.clone();
        Ok(
            tokio::task::spawn_blocking(move || c.client.get_block_hash(height))
                .await
                .expect("handle")?,
        )
    }

    pub async fn get_raw_transaction(&self, txid: &Txid) -> Result<Transaction> {
        let c = self.bitcoind.clone();
        let txid = txid.clone();
        Ok(
            tokio::task::spawn_blocking(move || c.client.get_raw_transaction(&txid, None))
                .await
                .expect("handle")?,
        )
    }

    /// Reorg a number of blocks of a given size `count`.
    /// Refer to [`SpaceD::mine_empty_block`] for more information.
    ///
    /// An async version of bdk's testenv reorg:
    /// https://github.com/bitcoindevkit/bdk/blob/master/crates/testenv/src/lib.rs
    pub async fn reorg(&self, count: usize) -> anyhow::Result<Vec<BlockHash>> {
        let start_height = self.get_block_count().await?;
        self.invalidate_blocks(count).await?;

        let res = self.mine_blocks(count, None).await?;
        assert_eq!(
            self.get_block_count().await?,
            start_height,
            "reorg should not result in height change"
        );
        Ok(res)
    }

    /// Reorg with a number of empty blocks of a given size `count`.
    ///
    /// An async version of bdk's testenv reorg_empty_blocks:
    /// https://github.com/bitcoindevkit/bdk/blob/master/crates/testenv/src/lib.rs
    pub async fn reorg_empty_blocks(&self, count: usize) -> Result<Vec<(usize, BlockHash)>> {
        let start_height = self.get_block_count().await?;
        self.invalidate_blocks(count).await?;

        let mut res = Vec::with_capacity(count);
        for _ in 0..count {
            res.push(self.mine_empty_block().await?);
        }
        assert_eq!(
            self.get_block_count().await?,
            start_height,
            "reorg should not result in height change"
        );
        Ok(res)
    }

    /// Send a tx of a given `amount` to a given `address`.
    ///
    /// An async version of bdk's testenv send:
    /// https://github.com/bitcoindevkit/bdk/blob/master/crates/testenv/src/lib.rs
    pub async fn send(&self, address: &Address<NetworkChecked>, amount: Amount) -> Result<Txid> {
        let c = self.bitcoind.clone();
        let addr = address.clone();
        let txid = tokio::task::spawn_blocking(move || {
            c.client
                .send_to_address(&addr, amount, None, None, None, None, None, None)
        })
            .await
            .expect("handle")?;
        Ok(txid)
    }
}

pub fn copy_dir_all(src: impl AsRef<Path>, dst: impl AsRef<Path>) -> io::Result<()> {
    fs::create_dir_all(&dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        if ty.is_dir() {
            copy_dir_all(entry.path(), dst.as_ref().join(entry.file_name()))?;
        } else {
            fs::copy(entry.path(), dst.as_ref().join(entry.file_name()))?;
        }
    }
    Ok(())
}
