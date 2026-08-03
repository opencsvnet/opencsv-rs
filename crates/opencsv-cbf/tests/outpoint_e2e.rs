//! Real-regtest receipt for authoritative fee/stock outpoint revalidation.
//!
//! RPC supplies only the claim under test. The verdict path is P2P,
//! PoW-header checked, BIP158 directed, and full-block merkle checked.

mod common;

use std::time::Duration;

use common::{bitcoind_path, Node};
use opencsv_cbf::block::OutPoint;
use opencsv_cbf::hash::{from_hex, hash_from_display};
use opencsv_cbf::{CbfClient, Config, Network, OutpointVerdict};
use serde_json::{json, Map, Value};

#[test]
fn confirmed_outpoint_transitions_from_unspent_to_recently_spent() {
    let Some(bitcoind) = bitcoind_path() else {
        eprintln!(
            "skipping confirmed_outpoint_transitions_from_unspent_to_recently_spent: bitcoind not found"
        );
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let node = Node::start(&bitcoind, tmp.path().join("node"));
    node.create_wallet_and_mine(101);
    node.wait_for_filter_index();

    let wallet = node.rpc(Some("test"));
    let mut unspent = wallet
        .call("listunspent", json!([1]))
        .unwrap()
        .as_array()
        .unwrap()
        .clone();
    unspent.sort_by_key(|entry| std::cmp::Reverse(entry["confirmations"].as_u64().unwrap()));
    let selected = unspent
        .into_iter()
        .find(|entry| entry["spendable"].as_bool() == Some(true))
        .expect("a mature regtest coinbase output");
    let txid_display = selected["txid"].as_str().unwrap();
    let vout = selected["vout"].as_u64().unwrap() as u32;
    let confirmations = selected["confirmations"].as_u64().unwrap();
    let birth_height = 101 - confirmations + 1;
    let expected_value = (selected["amount"].as_f64().unwrap() * 100_000_000.0).round() as u64;
    let expected_script = from_hex(selected["scriptPubKey"].as_str().unwrap()).unwrap();
    let outpoint = OutPoint {
        txid: hash_from_display(txid_display).unwrap(),
        vout,
    };

    let config = Config {
        network: Network::Regtest,
        peers: vec![format!("127.0.0.1:{}", node.p2p_port)],
        cache_dir: tmp.path().join("cbf"),
        timeout: Duration::from_secs(30),
    };
    let mut client = CbfClient::connect(&config).unwrap();
    let verdict = client
        .verify_outpoint_unspent(
            outpoint,
            expected_value,
            &expected_script,
            birth_height,
            200,
        )
        .unwrap();
    assert!(matches!(
        verdict,
        OutpointVerdict::Unspent {
            creation_height,
            checked_through: 101,
            ..
        } if creation_height == birth_height
    ));

    let destination = wallet
        .call("getnewaddress", json!([]))
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned();
    let mut output = Map::new();
    output.insert(
        destination,
        json!(selected["amount"].as_f64().unwrap() - 0.0001),
    );
    let raw = wallet
        .call(
            "createrawtransaction",
            json!([[{"txid": txid_display, "vout": vout}], [Value::Object(output)]]),
        )
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned();
    let signed = wallet
        .call("signrawtransactionwithwallet", json!([raw]))
        .unwrap();
    assert_eq!(signed["complete"].as_bool(), Some(true));
    let spending_txid_display = wallet
        .call("sendrawtransaction", json!([signed["hex"]]))
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned();
    let mining_address = wallet
        .call("getnewaddress", json!([]))
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned();
    wallet
        .call("generatetoaddress", json!([1, mining_address]))
        .unwrap();
    node.wait_for_filter_index();
    client.sync().unwrap();

    let verdict = client
        .verify_outpoint_unspent(
            outpoint,
            expected_value,
            &expected_script,
            birth_height,
            201,
        )
        .unwrap();
    assert_eq!(
        verdict,
        OutpointVerdict::Spent {
            creation_height: birth_height,
            spend_height: 102,
            spending_txid: hash_from_display(&spending_txid_display).unwrap(),
        }
    );
}
