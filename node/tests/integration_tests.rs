use std::path::{PathBuf};
use std::str::FromStr;
use protocol::bitcoin::{Amount, FeeRate};
use protocol::constants::RENEWAL_INTERVAL;
use protocol::{Covenant};
use protocol::script::SpaceScript;
use spaced::rpc::{BidParams, ExecuteParams, OpenParams, RegisterParams, RpcClient, RpcWalletRequest, RpcWalletTxBuilder, TransferSpacesParams};
use spaced::wallets::{AddressKind, WalletResponse};
use testutil::{TestRig};
use wallet::export::WalletExport;

const ALICE: &str = "wallet_99";
const BOB: &str = "wallet_98";
const EVE: &str = "wallet_93";

const TEST_SPACE: &str = "@example123";
const TEST_INITIAL_BID: u64 = 5000;


/// alice opens [TEST_SPACE] for auction
async fn it_should_open_a_space_for_auction(rig: &TestRig) -> anyhow::Result<()> {
    rig.wait_until_wallet_synced(ALICE).await?;
    let response = wallet_do(rig, ALICE, vec![
        RpcWalletRequest::Open(OpenParams {
            name: TEST_SPACE.to_string(),
            amount: TEST_INITIAL_BID,
        }),
    ], false).await.expect("send request");

    for tx_res in &response.result {
        assert!(tx_res.error.is_none(), "expect no errors for simple open");
    }
    assert_eq!(response.result.len(), 2, "must be 2 transactions");

    rig.mine_blocks(1, None).await?;
    rig.wait_until_synced().await?;

    let fullspaceout = rig.spaced.client.get_space(TEST_SPACE).await?;
    let fullspaceout = fullspaceout.expect("a fullspace out");
    let space = fullspaceout.spaceout.space.expect("a space");

    match space.covenant {
        Covenant::Bid { total_burned, burn_increment, claim_height, .. } => {
            assert!(claim_height.is_none(), "none for pre-auctions");
            assert_eq!(total_burned, burn_increment, "equal for initial bid");
            assert_eq!(total_burned, Amount::from_sat(TEST_INITIAL_BID), "must be equal to opened bid");
        }
        _ => panic!("expected a bid covenant")
    }

    Ok(())
}

/// Bob outbids alice by 1 sat
async fn it_should_allow_outbidding(rig: &TestRig) -> anyhow::Result<()> {
    // Bob outbids alice
    rig.wait_until_synced().await?;
    rig.wait_until_wallet_synced(BOB).await?;
    rig.wait_until_wallet_synced(ALICE).await?;
    let bobs_spaces = rig.spaced.client.wallet_list_spaces(BOB).await?;
    let alices_spaces = rig.spaced.client.wallet_list_spaces(ALICE).await?;
    let alices_balance = rig.spaced.client.wallet_get_balance(ALICE).await?;

    let result = wallet_do(
        rig, BOB,
        vec![
            RpcWalletRequest::Bid(BidParams {
                name: TEST_SPACE.to_string(),
                amount: TEST_INITIAL_BID + 1,
            }),
        ], false).await.expect("send request");

    println!("{}", serde_json::to_string_pretty(&result).unwrap());
    rig.mine_blocks(1, None).await?;

    rig.wait_until_synced().await?;
    rig.wait_until_wallet_synced(BOB).await?;
    rig.wait_until_wallet_synced(ALICE).await?;
    let bob_spaces_updated = rig.spaced.client.wallet_list_spaces(BOB).await?;
    let alice_spaces_updated = rig.spaced.client.wallet_list_spaces(ALICE).await?;
    let alices_balance_updated = rig.spaced.client.wallet_get_balance(ALICE).await?;

    assert_eq!(alices_spaces.len() - 1, alice_spaces_updated.len(), "alice must have one less space");
    assert_eq!(bobs_spaces.len() + 1, bob_spaces_updated.len(), "bob must have a new space");
    assert_eq!(alices_balance_updated.balance, alices_balance.balance +
        Amount::from_sat(TEST_INITIAL_BID + 662), "alice must be refunded this exact amount");

    let fullspaceout = rig.spaced.client.get_space(TEST_SPACE).await?;
    let fullspaceout = fullspaceout.expect("a fullspace out");
    let space = fullspaceout.spaceout.space.expect("a space");

    match space.covenant {
        Covenant::Bid { total_burned, burn_increment, claim_height, .. } => {
            assert!(claim_height.is_none(), "none for pre-auctions");
            assert_eq!(total_burned, Amount::from_sat(TEST_INITIAL_BID + 1), "total burned");
            assert_eq!(burn_increment, Amount::from_sat(1), "burn increment only 1 sat");
        }
        _ => panic!("expected a bid covenant")
    }

    Ok(())
}

/// Eve makes an invalid bid with a burn increment of 0 only refunding Bob's money
async fn it_should_only_accept_forced_zero_value_bid_increments_and_revoke(rig: &TestRig) -> anyhow::Result<()> {
    // Bob outbids alice
    rig.wait_until_wallet_synced(BOB).await?;
    rig.wait_until_wallet_synced(EVE).await?;
    let eve_spaces = rig.spaced.client.wallet_list_spaces(EVE).await?;
    let bob_spaces = rig.spaced.client.wallet_list_spaces(BOB).await?;
    let bob_balance = rig.spaced.client.wallet_get_balance(BOB).await?;

    let fullspaceout = rig.spaced.client.get_space(TEST_SPACE).await?.expect("exists");
    let space = fullspaceout.spaceout.space.expect("a space");
    let last_bid = match space.covenant {
        Covenant::Bid { total_burned, .. } => total_burned,
        _ => panic!("expected a bid")
    };

    assert!(wallet_do(
        rig, EVE,
        vec![
            RpcWalletRequest::Bid(BidParams {
                name: TEST_SPACE.to_string(),
                amount: last_bid.to_sat(),
            }),
        ],
        false).await.is_err(), "shouldn't be able to bid with same value unless forced");

    // force only
    assert!(rig.spaced.client.wallet_send_request(
        EVE,
        RpcWalletTxBuilder {
            bidouts: None,
            requests: vec![
                RpcWalletRequest::Bid(BidParams {
                    name: TEST_SPACE.to_string(),
                    amount: last_bid.to_sat(),
                }),
            ],
            fee_rate: Some(FeeRate::from_sat_per_vb(1).expect("fee")),
            dust: None,
            force: true,
            confirmed_only: false,
            skip_tx_check: false,
        },
    ).await.is_err(), "should require skip tx check");

    // force & skip tx check
    let result = rig.spaced.client.wallet_send_request(
        EVE,
        RpcWalletTxBuilder {
            bidouts: None,
            requests: vec![
                RpcWalletRequest::Bid(BidParams {
                    name: TEST_SPACE.to_string(),
                    amount: last_bid.to_sat(),
                }),
            ],
            fee_rate: Some(FeeRate::from_sat_per_vb(1).expect("fee")),
            dust: None,
            force: true,
            confirmed_only: false,
            skip_tx_check: true,
        },
    ).await?;

    println!("{}", serde_json::to_string_pretty(&result).unwrap());
    rig.mine_blocks(1, None).await?;

    rig.wait_until_synced().await?;
    rig.wait_until_wallet_synced(BOB).await?;
    rig.wait_until_wallet_synced(ALICE).await?;
    let bob_spaces_updated = rig.spaced.client.wallet_list_spaces(BOB).await?;
    let bob_balance_updated = rig.spaced.client.wallet_get_balance(BOB).await?;
    let eve_spaces_updated = rig.spaced.client.wallet_list_spaces(EVE).await?;

    assert_eq!(bob_spaces.len() - 1, bob_spaces_updated.len(), "bob must have one less space");
    assert_eq!(bob_balance_updated.balance, bob_balance.balance +
        Amount::from_sat(last_bid.to_sat() + 662), "alice must be refunded this exact amount");
    assert_eq!(eve_spaces_updated.len(), eve_spaces.len(), "eve must have the same number of spaces");

    let fullspaceout = rig.spaced.client.get_space(TEST_SPACE).await?;
    assert!(fullspaceout.is_none(), "must be revoked");
    Ok(())
}

async fn it_should_allow_claim_on_or_after_claim_height(rig: &TestRig) -> anyhow::Result<()> {
    let wallet = EVE;
    let claimable_space = "@test9880";
    let space = rig.spaced.client.get_space(claimable_space).await?
        .expect(claimable_space);
    let space = space.spaceout.space.expect(claimable_space);

    let current_height = rig.get_block_count().await?;
    let claim_height = space.claim_height().expect("height") as u64;
    rig.mine_blocks((claim_height - current_height) as _, None).await?;

    assert_eq!(claim_height, rig.get_block_count().await?, "heights must match");

    rig.wait_until_wallet_synced(wallet).await?;
    let all_spaces = rig.spaced.client.wallet_list_spaces(wallet).await?;

    let result = wallet_do(rig, wallet, vec![
        RpcWalletRequest::Register(RegisterParams {
            name: claimable_space.to_string(),
            to: None,
        }),
    ], false).await.expect("send request");

    println!("{}", serde_json::to_string_pretty(&result).unwrap());
    rig.mine_blocks(1, None).await?;

    rig.wait_until_synced().await?;
    rig.wait_until_wallet_synced(wallet).await?;
    let all_spaces_2 = rig.spaced.client.wallet_list_spaces(wallet).await?;

    assert_eq!(all_spaces.len(), all_spaces_2.len(), "must be equal");

    let space = rig.spaced.client.get_space(claimable_space).await?
        .expect(claimable_space);
    let space = space.spaceout.space.expect(claimable_space);

    match space.covenant {
        Covenant::Transfer { .. } => {}
        _ => panic!("covenant is not transfer"),
    }
    Ok(())
}

async fn it_should_allow_batch_transfers_refreshing_expire_height(rig: &TestRig) -> anyhow::Result<()> {
    rig.wait_until_wallet_synced(ALICE).await?;
    rig.wait_until_synced().await?;
    let all_spaces = rig.spaced.client.wallet_list_spaces(ALICE).await?;
    let registered_spaces: Vec<_> = all_spaces.iter().filter_map(|s| {
        let space = s.space.as_ref().expect("space");
        match space.covenant {
            Covenant::Transfer { .. } => Some(space.name.to_string()),
            _ => None,
        }
    }).collect();

    let space_address = rig.spaced.client.wallet_get_new_address(ALICE, AddressKind::Space).await?;

    let result = wallet_do(rig, ALICE, vec![
        RpcWalletRequest::Transfer(TransferSpacesParams {
            spaces: registered_spaces.clone(),
            to: space_address,
        }),
    ], false).await.expect("send request");

    println!("{}", serde_json::to_string_pretty(&result).unwrap());

    rig.mine_blocks(1, None).await?;
    let expected_expire_height = rig.get_block_count().await? as u32 + RENEWAL_INTERVAL;

    rig.wait_until_synced().await?;
    rig.wait_until_wallet_synced(ALICE).await?;
    let all_spaces_2 = rig.spaced.client.wallet_list_spaces(ALICE).await?;

    assert_eq!(all_spaces.len(), all_spaces_2.len(), "must be equal");

    let mut count = 0;
    all_spaces_2.iter().for_each(|s| {
        let space = s.space.as_ref().expect("space");
        match space.covenant {
            Covenant::Transfer { expire_height, .. } => {
                count += 1;
                assert_eq!(expire_height, expected_expire_height, "must refresh expire height");
            }
            _ => {}
        }
    });
    assert_eq!(count, registered_spaces.len(), "must keep the exact number of registered spaces");
    assert_eq!(all_spaces.len(), all_spaces_2.len(), "shouldn't change number of held spaces");

    Ok(())
}

async fn it_should_allow_applying_script_in_batch(rig: &TestRig) -> anyhow::Result<()> {
    rig.wait_until_wallet_synced(ALICE).await?;
    rig.wait_until_synced().await?;
    let all_spaces = rig.spaced.client.wallet_list_spaces(ALICE).await?;
    let registered_spaces: Vec<_> = all_spaces.iter().filter_map(|s| {
        let space = s.space.as_ref().expect("space");
        match space.covenant {
            Covenant::Transfer { .. } => Some(space.name.to_string()),
            _ => None,
        }
    }).collect();

    let result = wallet_do(rig, ALICE, vec![
        RpcWalletRequest::Execute(ExecuteParams {
            context: registered_spaces.clone(),
            space_script: SpaceScript::create_set_fallback(&[0xDE, 0xAD, 0xBE, 0xEF]),
        }),
    ], false).await.expect("send request");

    println!("{}", serde_json::to_string_pretty(&result).unwrap());

    rig.mine_blocks(1, None).await?;
    let expected_expire_height = rig.get_block_count().await? as u32 + RENEWAL_INTERVAL;

    rig.wait_until_synced().await?;
    rig.wait_until_wallet_synced(ALICE).await?;
    let all_spaces_2 = rig.spaced.client.wallet_list_spaces(ALICE).await?;

    assert_eq!(all_spaces.len(), all_spaces_2.len(), "must be equal");

    let mut count = 0;
    all_spaces_2.iter().for_each(|s| {
        let space = s.space.as_ref().expect("space");
        match &space.covenant {
            Covenant::Transfer { expire_height, data } => {
                count += 1;
                assert_eq!(*expire_height, expected_expire_height, "must refresh expire height");
                assert!(data.is_some(), "must be data set");
                assert_eq!(data.clone().unwrap().to_vec(), vec![0xDE, 0xAD, 0xBE, 0xEF], "must set correct data");
            }
            _ => {}
        }
    });
    assert_eq!(count, registered_spaces.len(), "must keep the exact number of registered spaces");
    assert_eq!(all_spaces.len(), all_spaces_2.len(), "shouldn't change number of held spaces");

    Ok(())
}



// Alice places an unconfirmed bid on @test2.
// Bob attempts to replace it but fails due to a lack of confirmed bid & funding utxos.
// Eve, with confirmed bid outputs/funds, successfully replaces the bid.
async fn it_should_replace_mempool_bids(rig: &TestRig) -> anyhow::Result<()> {
    // create some confirmed bid outs for Eve
    rig.spaced.client.wallet_send_request(
        EVE,
        RpcWalletTxBuilder {
            bidouts: Some(2),
            requests: vec![],
            fee_rate: Some(FeeRate::from_sat_per_vb(2).expect("fee")),
            dust: None,
            force: false,
            confirmed_only: false,
            skip_tx_check: false,
        },
    ).await?;
    rig.mine_blocks(1, None).await?;

    rig.wait_until_wallet_synced(ALICE).await?;
    rig.wait_until_wallet_synced(BOB).await?;
    rig.wait_until_wallet_synced(EVE).await?;

    let response = wallet_do(rig, ALICE, vec![
        RpcWalletRequest::Bid(BidParams {
            name: "@test2".to_string(),
            amount: 1000,
        })], false).await?;

    let response = serde_json::to_string_pretty(&response).unwrap();
    println!("{}", response);

    let response = wallet_do(rig, BOB, vec![
        RpcWalletRequest::Bid(BidParams {
            name: "@test2".to_string(),
            amount: 1000,
        })], false).await?;

    let response = serde_json::to_string_pretty(&response).unwrap();

    println!("{}", response);

    assert!(response.contains("hint"), "should have a hint about replacement errors");

    let replacement = rig.spaced.client.wallet_send_request(
        BOB,
        RpcWalletTxBuilder {
            bidouts: None,
            requests: vec![
                RpcWalletRequest::Bid(BidParams {
                    name: "@test2".to_string(),
                    amount: 1000,
                })],
            fee_rate: Some(FeeRate::from_sat_per_vb(2).expect("fee")),
            dust: None,
            force: false,
            confirmed_only: false,
            skip_tx_check: false,
        },
    ).await?;

    let response = serde_json::to_string_pretty(&replacement).unwrap();
    println!("{}", response);

    assert!(response.contains("hint"), "should have a hint about confirmed only");
    assert!(response.contains("replacement-adds-unconfirmed"), "expected a replacement-adds-unconfirmed in the message");

    // now let Eve try a replacement since she has confirmed outputs
    let replacement = rig.spaced.client.wallet_send_request(
        EVE,
        RpcWalletTxBuilder {
            bidouts: None,
            requests: vec![
                RpcWalletRequest::Bid(BidParams {
                    name: "@test2".to_string(),
                    amount: 1000,
                })],
            fee_rate: Some(FeeRate::from_sat_per_vb(2).expect("fee")),
            dust: None,
            force: false,
            confirmed_only: false,
            skip_tx_check: false,
        },
    ).await?;

    let response = serde_json::to_string_pretty(&replacement).unwrap();
    println!("{}", response);

    for tx_res in replacement.result {
        assert!(tx_res.error.is_none(), "Eve should have no problem replacing")
    }

    // Alice won't be able to build off other transactions from the double spent bid
    // even when Eve bid gets confirmed. Wallet must remove double spent tx.
    rig.mine_blocks(1, None).await?;
    rig.wait_until_wallet_synced(ALICE).await?;
    let txs = rig.spaced.client.wallet_list_transactions(
        ALICE,
        1000, 0
    ).await?;
    let unconfirmed : Vec<_> = txs.iter().filter(|tx| !tx.confirmed).collect();
    assert_eq!(unconfirmed.len(), 0, "there should be no stuck unconfirmed transactions");
    Ok(())
}

async fn it_should_maintain_locktime_when_fee_bumping(rig: &TestRig) -> anyhow::Result<()> {
    rig.wait_until_wallet_synced(ALICE).await?;

    let response = rig.spaced.client.wallet_send_request(
        ALICE,
        RpcWalletTxBuilder {
            bidouts: Some(2),
            requests: vec![],
            fee_rate: Some(FeeRate::from_sat_per_vb(1).expect("fee")),
            dust: None,
            force: false,
            confirmed_only: false,
            skip_tx_check: false
        },
    ).await?;

    println!("{}",  serde_json::to_string_pretty(&response).unwrap());

    let txid = response.result[0].txid;
    for tx_res in response.result{
        assert!(tx_res.error.is_none(), "should not be error");
    }

    let tx = rig.get_raw_transaction(&txid).await?;

    let bump = rig.spaced.client.wallet_bump_fee(
        ALICE, txid, FeeRate::from_sat_per_vb(4).expect("fee"), false
    ).await?;
    assert_eq!(bump.len(), 1, "should only be 1 tx");
    assert!(bump[0].error.is_none(), "should be no errors");

    let replacement = rig.get_raw_transaction(&bump[0].txid).await?;

    assert_eq!(tx.lock_time, replacement.lock_time, "locktimes must not change");
    Ok(())
}

#[tokio::test]
async fn run_auction_tests() -> anyhow::Result<()> {
    let rig = TestRig::new_with_regtest_preset().await?;
    let wallets_path = rig.testdata_wallets_path().await;

    let count = rig.get_block_count().await? as u32;
    assert!(count > 3000, "expected an initialized test set");

    rig.wait_until_synced().await?;
    load_wallet(&rig, wallets_path.clone(), ALICE).await?;
    load_wallet(&rig, wallets_path.clone(), BOB).await?;
    load_wallet(&rig, wallets_path, EVE).await?;

    it_should_open_a_space_for_auction(&rig).await?;
    it_should_allow_outbidding(&rig).await?;
    it_should_only_accept_forced_zero_value_bid_increments_and_revoke(&rig).await?;
    it_should_allow_claim_on_or_after_claim_height(&rig).await?;
    it_should_allow_batch_transfers_refreshing_expire_height(&rig).await?;
    it_should_allow_applying_script_in_batch(&rig).await?;
    it_should_replace_mempool_bids(&rig).await?;
    it_should_maintain_locktime_when_fee_bumping(&rig).await?;

    Ok(())
}

async fn wallet_do(rig: &TestRig, wallet: &str, requests: Vec<RpcWalletRequest>, force: bool) -> anyhow::Result<WalletResponse> {
    let res = rig.spaced.client.wallet_send_request(
        wallet,
        RpcWalletTxBuilder {
            bidouts: None,
            requests,
            fee_rate: Some(FeeRate::from_sat_per_vb(1).expect("fee")),
            dust: None,
            force,
            confirmed_only: false,
            skip_tx_check: false,
        },
    ).await?;
    Ok(res)
}

pub async fn load_wallet(rig: &TestRig, wallets_dir: PathBuf, name: &str) -> anyhow::Result<()> {
    let wallet_path = wallets_dir.join(format!("{name}.json"));
    let json = std::fs::read_to_string(wallet_path)?;
    let export = WalletExport::from_str(&json)?;
    rig.spaced.client.wallet_import(export).await?;
    Ok(())
}
