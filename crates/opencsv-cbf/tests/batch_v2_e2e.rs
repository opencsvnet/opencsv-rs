//! Real multi-party batching-v2 regtest: independently keyed stock and
//! participant UTXOs, canonical co-funding, adversarial output mutation,
//! unanimous RBF, mining, BIP158 discovery, and per-payload occurrence.

mod common;

use std::str::FromStr;
use std::time::Duration;

use bitcoin::consensus::encode::serialize_hex;
use bitcoin::hashes::Hash as _;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin::{Amount, BlockHash, OutPoint, ScriptBuf, TxOut, Txid};
use common::{bitcoind_path, Node};
use opencsv_bitcoin::batch_v2::{
    p2wpkh_script, Manifest, ParticipantCommitment, Proposal, RejectionReason,
};
use opencsv_cbf::{CbfClient, Config, ScanIndex};
use opencsv_core::{binding, BatchVersion, Digest};
use serde_json::{json, Value};

fn secret(seed: u8) -> SecretKey {
    SecretKey::from_slice(&[seed; 32]).expect("nonzero deterministic secret")
}

fn public(secret: &SecretKey) -> PublicKey {
    PublicKey::from_secret_key(&Secp256k1::new(), secret)
}

fn sats(value: &Value) -> u64 {
    let text = value.to_string();
    let (whole, fraction) = text.split_once('.').unwrap_or((&text, ""));
    let mut fraction = fraction.to_string();
    assert!(fraction.len() <= 8, "BTC amount has sub-satoshi precision");
    fraction.extend(std::iter::repeat_n('0', 8 - fraction.len()));
    whole.parse::<u64>().unwrap() * 100_000_000 + fraction.parse::<u64>().unwrap_or(0)
}

fn address_for(script: &ScriptBuf) -> String {
    bitcoin::Address::from_script(script, bitcoin::Network::Regtest)
        .expect("standard regtest script")
        .to_string()
}

fn fund(
    wallet: &opencsv_bitcoin::rpc::RpcClient<opencsv_bitcoin::rpc::HttpTransport>,
    address: &str,
) -> Txid {
    let txid = wallet
        .call("sendtoaddress", json!([address, 0.001]))
        .expect("fund protocol-controlled address");
    Txid::from_str(txid.as_str().unwrap()).unwrap()
}

fn mine(wallet: &opencsv_bitcoin::rpc::RpcClient<opencsv_bitcoin::rpc::HttpTransport>, count: u64) {
    let address = wallet
        .call("getnewaddress", json!([]))
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();
    wallet
        .call("generatetoaddress", json!([count, address]))
        .unwrap();
}

fn utxo(node: &Node, txid: Txid, script_pubkey: ScriptBuf) -> (OutPoint, TxOut) {
    let transaction = node
        .rpc(None)
        .call("getrawtransaction", json!([txid.to_string(), true]))
        .unwrap();
    let script_hex: String = script_pubkey
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let entry = transaction["vout"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| {
            sats(&entry["value"]) == 100_000
                && entry["scriptPubKey"]["hex"].as_str() == Some(script_hex.as_str())
        })
        .expect("100,000-sat funding output");
    let vout = entry["n"].as_u64().unwrap() as u32;
    (
        OutPoint::new(txid, vout),
        TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey,
        },
    )
}

fn mempool_allowed(node: &Node, transaction: &bitcoin::Transaction) -> (bool, Option<String>) {
    let result = node
        .rpc(None)
        .call("testmempoolaccept", json!([[serialize_hex(transaction)]]))
        .unwrap();
    let result = &result.as_array().unwrap()[0];
    (
        result["allowed"].as_bool().unwrap_or(false),
        result["reject-reason"].as_str().map(str::to_string),
    )
}

#[test]
fn cofunded_batch_v2_regtest() {
    let Some(bitcoind) = bitcoind_path() else {
        eprintln!("skipping cofunded_batch_v2_regtest: bitcoind not found");
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let node = Node::start(&bitcoind, tmp.path().join("node"));
    node.create_wallet_and_mine(101);
    let wallet = node.rpc(Some("test"));

    let stock_secret = secret(3);
    let participant_secrets = [secret(4), secret(5)];
    let change_secrets = [secret(14), secret(15)];

    // The stock script depends only on owner key and participant count.
    // A temporary proposal supplies the exact constructor before the
    // stock outpoint exists; the final proposal below commits that outpoint.
    let placeholder = Proposal::new(
        [1u8; 32],
        OutPoint::new(Txid::from_byte_array([1u8; 32]), 0),
        100_000,
        public(&stock_secret),
        2,
        [1u8; 32],
        100,
        120,
        2,
        10,
    )
    .unwrap();
    let stock_spk = placeholder.stock_script_pubkey();
    let participant_spks = participant_secrets.map(|key| p2wpkh_script(public(&key)));
    let stock_address = address_for(&stock_spk);
    let participant_addresses = participant_spks.each_ref().map(address_for);

    let stock_funding_txid = fund(&wallet, &stock_address);
    let participant_funding_txids = [
        fund(&wallet, &participant_addresses[0]),
        fund(&wallet, &participant_addresses[1]),
    ];

    let (stock_outpoint, stock_prevout) = utxo(&node, stock_funding_txid, stock_spk.clone());
    let participant_utxos = [
        utxo(
            &node,
            participant_funding_txids[0],
            participant_spks[0].clone(),
        ),
        utxo(
            &node,
            participant_funding_txids[1],
            participant_spks[1].clone(),
        ),
    ];
    mine(&wallet, 1);
    assert_eq!(stock_prevout.value.to_sat(), 100_000);

    let genesis = node.rpc(None).call("getblockhash", json!([0])).unwrap();
    let chain_id = BlockHash::from_str(genesis.as_str().unwrap())
        .unwrap()
        .to_byte_array();
    let height = node
        .rpc(None)
        .call("getblockcount", json!([]))
        .unwrap()
        .as_u64()
        .unwrap() as u32;
    let proposal = Proposal::new(
        chain_id,
        stock_outpoint,
        100_000,
        public(&stock_secret),
        2,
        [9u8; 32],
        height,
        height + 20,
        2,
        10,
    )
    .unwrap();
    proposal.validate_at(chain_id, height).unwrap();
    assert_eq!(proposal.stock_script_pubkey(), stock_prevout.script_pubkey);
    assert_eq!(
        proposal
            .validate_at([0x55; 32], height)
            .unwrap_err()
            .reason(),
        RejectionReason::WrongChain
    );

    let raw_nullifiers = [
        Digest::from_bytes([41u8; 32]),
        Digest::from_bytes([42u8; 32]),
    ];
    let commitments: Vec<_> = (0..2)
        .map(|index| {
            ParticipantCommitment::new(
                &proposal,
                [(index + 1) as u8; 32],
                [(index + 11) as u8; 32],
                binding(&raw_nullifiers[index], &proposal.context()).to_anchor(),
                participant_utxos[index].0,
                participant_utxos[index].1.clone(),
                public(&participant_secrets[index]),
                p2wpkh_script(public(&change_secrets[index])),
                10_000,
            )
            .unwrap()
        })
        .collect();
    let manifest = Manifest::build(&proposal, commitments).unwrap();
    let stock_signature = manifest.sign_stock(&proposal, &stock_secret).unwrap();
    let participant_signatures: Vec<_> = (0..2)
        .map(|index| {
            let expected = manifest.participant_fee_pubkey(index).unwrap();
            let key = participant_secrets
                .iter()
                .find(|key| public(key) == expected)
                .unwrap();
            manifest.sign_participant(&proposal, index, key).unwrap()
        })
        .collect();
    let initial = manifest
        .finalize(&proposal, &stock_signature, &participant_signatures)
        .unwrap();

    // A coordinator-mutated marker/output is rejected by participant
    // SIGHASH_ALL signatures before the honest transaction is broadcast.
    let mut mutated = initial.clone();
    mutated.output[1].value += Amount::from_sat(1);
    let (allowed, reason) = mempool_allowed(&node, &mutated);
    assert!(!allowed, "mutated output accepted: {reason:?}");
    assert!(mempool_allowed(&node, &initial).0);
    let initial_txid = node
        .rpc(None)
        .call("sendrawtransaction", json!([serialize_hex(&initial)]))
        .unwrap();
    assert_eq!(
        initial_txid.as_str().unwrap(),
        initial.compute_txid().to_string()
    );

    // Unanimous protocol-safe replacement: same inputs, header, marker,
    // stock, scripts, and positions; only participant charges rise.
    let replacement_manifest = manifest.replacement(&proposal, 3).unwrap();
    let replacement_stock_signature = replacement_manifest
        .sign_stock(&proposal, &stock_secret)
        .unwrap();
    let replacement_participant_signatures: Vec<_> = (0..2)
        .map(|index| {
            let expected = replacement_manifest.participant_fee_pubkey(index).unwrap();
            let key = participant_secrets
                .iter()
                .find(|key| public(key) == expected)
                .unwrap();
            replacement_manifest
                .sign_participant(&proposal, index, key)
                .unwrap()
        })
        .collect();
    let replacement = replacement_manifest
        .finalize(
            &proposal,
            &replacement_stock_signature,
            &replacement_participant_signatures,
        )
        .unwrap();
    let (allowed, reason) = mempool_allowed(&node, &replacement);
    assert!(allowed, "conforming replacement rejected: {reason:?}");
    let replacement_txid = node
        .rpc(None)
        .call("sendrawtransaction", json!([serialize_hex(&replacement)]))
        .unwrap();
    assert_eq!(
        replacement_txid.as_str().unwrap(),
        replacement.compute_txid().to_string()
    );
    assert!(
        node.rpc(None)
            .call(
                "getmempoolentry",
                json!([initial.compute_txid().to_string()])
            )
            .is_err(),
        "replaced transaction remained in mempool"
    );
    mine(&wallet, 1);

    // The marker discovers the block; v2 decoding indexes both payloads
    // under the batch-v2 domain and exact input-0 context.
    node.wait_for_filter_index();
    let config = Config {
        network: opencsv_bitcoin::Network::Regtest,
        peers: vec![format!("127.0.0.1:{}", node.p2p_port)],
        cache_dir: tmp.path().join("cbf"),
        timeout: Duration::from_secs(30),
    };
    let mut client = CbfClient::connect(&config).unwrap();
    let tip = client.tip_height();
    let mut index =
        ScanIndex::open(tmp.path().join("scan"), opencsv_bitcoin::Network::Regtest).unwrap();
    index.scan_sync(&mut client, height as u64).unwrap();
    let txid = replacement.compute_txid().to_byte_array();
    let entries: Vec<_> = index
        .occurrences()
        .iter()
        .filter(|entry| entry.txid == txid)
        .collect();
    assert_eq!(entries.len(), 2);
    assert!(entries.iter().all(|entry| {
        entry.ctx == proposal.context()
            && entry
                .batch
                .as_ref()
                .is_some_and(|batch| batch.version == BatchVersion::V2)
    }));
    for raw_nullifier in &raw_nullifiers {
        assert!(index
            .scan_check(raw_nullifier, height as u64, tip)
            .is_some());
    }
    drop(index);
    let reopened =
        ScanIndex::open(tmp.path().join("scan"), opencsv_bitcoin::Network::Regtest).unwrap();
    assert_eq!(
        reopened
            .occurrences()
            .iter()
            .filter(|entry| {
                entry.txid == txid
                    && entry
                        .batch
                        .as_ref()
                        .is_some_and(|batch| batch.version == BatchVersion::V2)
            })
            .count(),
        2,
        "persisted scan index lost the v2 witness version"
    );
    for raw_nullifier in &raw_nullifiers {
        assert!(reopened
            .scan_check(raw_nullifier, height as u64, tip)
            .is_some());
    }

    println!(
        "batch-v2 regtest receipt: initial={} replacement={} fee={}sat weight={}WU payloads=2",
        initial.compute_txid(),
        replacement.compute_txid(),
        replacement_manifest.miner_fee(),
        replacement.weight().to_wu(),
    );
}
