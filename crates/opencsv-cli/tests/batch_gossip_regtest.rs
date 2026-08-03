//! Acceptance receipt: three independently keyed C2 peers author, gossip,
//! verify, reserve, sign, persist, and broadcast one real regtest batch.
//!
//! Setting `OPENCSV_BITCOIND` makes node startup and every subsequent failure
//! fatal. Without an available binary the receipt is explicitly skipped.

#[path = "../../opencsv-cbf/tests/common/mod.rs"]
mod common;

use std::str::FromStr;
use std::time::Duration;

use bitcoin::consensus::encode::serialize_hex;
use bitcoin::hashes::Hash as _;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin::{Amount, BlockHash, OutPoint, ScriptBuf, TxOut, Txid};
use common::{bitcoind_path, Node};
use opencsv_bitcoin::batch_v2::{p2wpkh_script, ParticipantCommitment, Proposal};
use opencsv_cbf::{
    BatchInputBirthHeights, CbfClient, CommitmentInputBirthHeights, Config, ScanIndex,
};
use opencsv_cli::batch_gossip::{
    relay_next, relay_once, send_frame, IngestOutcome, ProtocolPhase, RelayAttempt, Session,
    SessionPolicy,
};
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
    script: &ScriptBuf,
) -> Txid {
    let txid = wallet
        .call("sendtoaddress", json!([address_for(script), 0.001]))
        .expect("fund protocol-controlled address");
    Txid::from_str(txid.as_str().unwrap()).unwrap()
}

fn funded_output(node: &Node, txid: Txid, script: ScriptBuf) -> (OutPoint, TxOut) {
    let transaction = node
        .rpc(None)
        .call("getrawtransaction", json!([txid.to_string(), true]))
        .unwrap();
    let script_hex: String = script
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
        .expect("100,000-sat protocol output");
    (
        OutPoint::new(txid, entry["n"].as_u64().unwrap() as u32),
        TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: script,
        },
    )
}

fn mine(wallet: &opencsv_bitcoin::rpc::RpcClient<opencsv_bitcoin::rpc::HttpTransport>, count: u64) {
    let address = wallet
        .call("getnewaddress", json!([]))
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned();
    wallet
        .call("generatetoaddress", json!([count, address]))
        .unwrap();
}

fn client(node: &Node, cache: std::path::PathBuf) -> CbfClient {
    CbfClient::connect(&Config {
        network: opencsv_bitcoin::Network::Regtest,
        peers: vec![format!("127.0.0.1:{}", node.p2p_port)],
        cache_dir: cache,
        timeout: Duration::from_secs(30),
    })
    .unwrap()
}

fn gossip(receiver: &mut Session, wire: &[u8]) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    std::thread::scope(|scope| {
        let relay = scope.spawn(|| relay_once(&listener, receiver, &[]).unwrap());
        send_frame(address, wire).unwrap();
        assert_eq!(relay.join().unwrap().outcome, IngestOutcome::Accepted);
    });
}

fn reject_malformed_then_gossip(receiver: &mut Session, wire: &[u8]) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    std::thread::scope(|scope| {
        let relay = scope.spawn(|| {
            let rejected = relay_next(&listener, receiver, &[]).unwrap();
            let accepted = relay_next(&listener, receiver, &[]).unwrap();
            (rejected, accepted)
        });
        send_frame(address, b"malformed-before-honest-frame").unwrap();
        send_frame(address, wire).unwrap();
        let (rejected, accepted) = relay.join().unwrap();
        assert!(matches!(rejected, RelayAttempt::Rejected { .. }));
        assert!(matches!(
            accepted,
            RelayAttempt::Processed(report) if report.outcome == IngestOutcome::Accepted
        ));
    });
}

fn gossip_to_other_peers(sessions: &mut [Session], author: usize, wire: &[u8]) {
    for (index, session) in sessions.iter_mut().enumerate() {
        if index != author {
            gossip(session, wire);
        }
    }
}

#[test]
fn three_peer_authoring_gossip_and_real_broadcast() {
    let Some(bitcoind) = bitcoind_path() else {
        eprintln!("skipping three_peer_authoring_gossip_and_real_broadcast: bitcoind not found");
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let node = Node::start(&bitcoind, tmp.path().join("node"));
    node.create_wallet_and_mine(101);
    let wallet = node.rpc(Some("test"));

    let stock_key = secret(3);
    let fee_keys = [secret(4), secret(5)];
    let change_keys = [secret(14), secret(15)];
    let placeholder = Proposal::new(
        [1; 32],
        OutPoint::new(Txid::from_byte_array([1; 32]), 0),
        100_000,
        public(&stock_key),
        2,
        [2; 32],
        1,
        2,
        2,
        10,
    )
    .unwrap();
    let stock_script = placeholder.stock_script_pubkey();
    let fee_scripts = fee_keys.each_ref().map(|key| p2wpkh_script(public(key)));
    let stock_txid = fund(&wallet, &stock_script);
    let fee_txids = [
        fund(&wallet, &fee_scripts[0]),
        fund(&wallet, &fee_scripts[1]),
    ];
    let (stock_outpoint, stock_prevout) = funded_output(&node, stock_txid, stock_script);
    let fee_prevouts = [
        funded_output(&node, fee_txids[0], fee_scripts[0].clone()),
        funded_output(&node, fee_txids[1], fee_scripts[1].clone()),
    ];
    mine(&wallet, 1);
    node.wait_for_filter_index();
    let birth_height = 102u64;
    let height = node
        .rpc(None)
        .call("getblockcount", json!([]))
        .unwrap()
        .as_u64()
        .unwrap() as u32;
    assert_eq!(height, birth_height as u32);
    let genesis = node.rpc(None).call("getblockhash", json!([0])).unwrap();
    let chain_id = BlockHash::from_str(genesis.as_str().unwrap())
        .unwrap()
        .to_byte_array();
    let policy = SessionPolicy {
        chain_id,
        current_height: height,
    };
    let roots: Vec<_> = (0..3).map(|_| tempfile::tempdir().unwrap()).collect();
    let mut sessions: Vec<_> = roots
        .iter()
        .map(|root| Session::init(root.path(), policy).unwrap())
        .collect();

    let proposal = Proposal::new(
        chain_id,
        stock_outpoint,
        stock_prevout.value.to_sat(),
        public(&stock_key),
        2,
        [9; 32],
        height,
        height + 20,
        2,
        10,
    )
    .unwrap();
    sessions[0]
        .reserve_local_input(proposal.batch_id(), stock_outpoint)
        .unwrap();
    let proposal_frame = sessions[0]
        .publish_proposal(proposal.wire_bytes(), &stock_key)
        .unwrap();
    gossip(&mut sessions[1], &proposal_frame);
    reject_malformed_then_gossip(&mut sessions[2], &proposal_frame);

    let raw_nullifiers = [Digest::from_bytes([41; 32]), Digest::from_bytes([42; 32])];
    let commitments: Vec<_> = (0..2)
        .map(|index| {
            ParticipantCommitment::new(
                &proposal,
                [(index + 1) as u8; 32],
                [(index + 11) as u8; 32],
                binding(&raw_nullifiers[index], &proposal.context()).to_anchor(),
                fee_prevouts[index].0,
                fee_prevouts[index].1.clone(),
                public(&fee_keys[index]),
                p2wpkh_script(public(&change_keys[index])),
                10_000,
            )
            .unwrap()
        })
        .collect();
    let mut commitment_frames = Vec::new();
    for index in 0..2 {
        let author = index + 1;
        let mut verifier = client(&node, tmp.path().join(format!("commit-cbf-{index}")));
        let verified = verifier
            .verify_commitment_inputs(
                &proposal,
                &commitments[index],
                CommitmentInputBirthHeights {
                    stock: birth_height,
                    fee: birth_height,
                },
                16,
            )
            .unwrap();
        let reservation = sessions[author]
            .reserve_local_input(
                commitments[index].operation_id(),
                commitments[index].fee_outpoint(),
            )
            .unwrap();
        let frame = sessions[author]
            .publish_verified_commitment(
                commitments[index].wire_bytes(),
                &fee_keys[index],
                &verified,
                &reservation,
                Duration::from_secs(30),
            )
            .unwrap();
        gossip_to_other_peers(&mut sessions, author, &frame);
        commitment_frames.push(frame);
    }

    // Manifest omission is not a degraded mode: deterministic source
    // reconstruction fails until every authorized participant is present.
    let omitted_root = tempfile::tempdir().unwrap();
    let mut omitted = Session::init(omitted_root.path(), policy).unwrap();
    omitted.ingest(&proposal_frame).unwrap();
    omitted.ingest(&commitment_frames[0]).unwrap();
    assert!(omitted.author_manifest().is_err());

    let manifest_frame = sessions[0].author_manifest().unwrap();
    gossip_to_other_peers(&mut sessions, 0, &manifest_frame);
    let initial_manifest = sessions[0].latest_manifest().unwrap();
    let births = BatchInputBirthHeights {
        stock: birth_height,
        participants: vec![birth_height; 2],
    };

    // Participant 1 signs the initial epoch and disappears. A later
    // replacement is announced with no latest-epoch shares; abort must still
    // fail because the earlier signature may be held by any peer.
    let vanished = 1usize;
    let vanished_pubkey = public(&fee_keys[vanished - 1]);
    let vanished_input = initial_manifest
        .commitments()
        .iter()
        .position(|commitment| commitment.fee_pubkey() == vanished_pubkey)
        .unwrap() as u16
        + 1;
    let vanished_operation =
        initial_manifest.commitments()[usize::from(vanished_input) - 1].operation_id();
    let vanished_reservation = sessions[vanished]
        .local_reservation(vanished_operation)
        .unwrap();
    let mut vanished_verifier = client(&node, tmp.path().join("sign-cbf-initial-vanished"));
    let vanished_verified = vanished_verifier
        .verify_batch_inputs(&proposal, &initial_manifest, &births, 16)
        .unwrap();
    let vanished_frame = sessions[vanished]
        .sign_and_publish(
            initial_manifest.manifest_id(),
            vanished_input,
            &fee_keys[vanished - 1],
            &vanished_verified,
            &vanished_reservation,
            Duration::from_secs(30),
        )
        .unwrap();
    gossip_to_other_peers(&mut sessions, vanished, &vanished_frame);

    let replacement_frame = sessions[0].author_replacement(3).unwrap();
    gossip_to_other_peers(&mut sessions, 0, &replacement_frame);
    let replacement_manifest = sessions[0].latest_manifest().unwrap();
    assert_ne!(
        replacement_manifest.manifest_id(),
        initial_manifest.manifest_id()
    );
    assert!(sessions[2]
        .mark_phase(
            ProtocolPhase::AbortedBeforeSignature,
            "latest epoch is unsigned but an earlier share escaped",
        )
        .is_err());
    sessions[vanished] = Session::open(roots[vanished].path()).unwrap();
    assert_eq!(
        sessions[vanished]
            .local_reservation(vanished_operation)
            .unwrap()
            .phase(),
        opencsv_bitcoin::batch_v2::ReservationPhase::SignatureReleased
    );

    // The two remaining peers complete the earlier epoch without the vanished
    // peer. Every node can recover and finalize that non-latest manifest.
    for signer in [0usize, 2usize] {
        let (input_index, key) = if signer == 0 {
            (0, &stock_key)
        } else {
            let wanted = public(&fee_keys[signer - 1]);
            let participant_index = initial_manifest
                .commitments()
                .iter()
                .position(|commitment| commitment.fee_pubkey() == wanted)
                .unwrap();
            (participant_index as u16 + 1, &fee_keys[signer - 1])
        };
        let operation_id = if input_index == 0 {
            proposal.batch_id()
        } else {
            initial_manifest.commitments()[usize::from(input_index) - 1].operation_id()
        };
        let reservation = sessions[signer].local_reservation(operation_id).unwrap();
        let mut verifier = client(&node, tmp.path().join(format!("sign-cbf-initial-{signer}")));
        let verified = verifier
            .verify_batch_inputs(&proposal, &initial_manifest, &births, 16)
            .unwrap();
        let frame = sessions[signer]
            .sign_and_publish(
                initial_manifest.manifest_id(),
                input_index,
                key,
                &verified,
                &reservation,
                Duration::from_secs(30),
            )
            .unwrap();
        gossip_to_other_peers(&mut sessions, signer, &frame);
    }

    let initial = sessions[0]
        .finalize_manifest(initial_manifest.manifest_id())
        .unwrap();
    for session in sessions.iter_mut().skip(1) {
        assert_eq!(
            session
                .finalize_manifest(initial_manifest.manifest_id())
                .unwrap(),
            initial
        );
    }
    sessions[0]
        .mark_phase(
            ProtocolPhase::Broadcast,
            &format!("attempt={}", initial.compute_txid()),
        )
        .unwrap();
    let accepted = node
        .rpc(None)
        .call("testmempoolaccept", json!([[serialize_hex(&initial)]]))
        .unwrap();
    assert_eq!(accepted[0]["allowed"].as_bool(), Some(true), "{accepted}");
    let initial_txid = node
        .rpc(None)
        .call("sendrawtransaction", json!([serialize_hex(&initial)]))
        .unwrap();
    assert_eq!(
        initial_txid.as_str(),
        Some(initial.compute_txid().to_string().as_str())
    );
    sessions[0]
        .mark_phase(
            ProtocolPhase::Mempool,
            &format!("txid={}", initial.compute_txid()),
        )
        .unwrap();

    // All three peers now authorize the already-announced replacement. CBF
    // deliberately verifies confirmed state; the known post-check mempool
    // race remains a liveness risk, and Core enforces the actual BIP125 swap.
    for signer in 0..3 {
        let (input_index, key) = if signer == 0 {
            (0, &stock_key)
        } else {
            let wanted = public(&fee_keys[signer - 1]);
            let participant_index = replacement_manifest
                .commitments()
                .iter()
                .position(|commitment| commitment.fee_pubkey() == wanted)
                .unwrap();
            (participant_index as u16 + 1, &fee_keys[signer - 1])
        };
        let operation_id = if input_index == 0 {
            proposal.batch_id()
        } else {
            replacement_manifest.commitments()[usize::from(input_index) - 1].operation_id()
        };
        let reservation = sessions[signer].local_reservation(operation_id).unwrap();
        let mut verifier = client(
            &node,
            tmp.path().join(format!("sign-cbf-replacement-{signer}")),
        );
        let verified = verifier
            .verify_batch_inputs(&proposal, &replacement_manifest, &births, 16)
            .unwrap();
        let frame = sessions[signer]
            .sign_and_publish(
                replacement_manifest.manifest_id(),
                input_index,
                key,
                &verified,
                &reservation,
                Duration::from_secs(30),
            )
            .unwrap();
        gossip_to_other_peers(&mut sessions, signer, &frame);
    }
    let replacement = sessions[0]
        .finalize_manifest(replacement_manifest.manifest_id())
        .unwrap();
    for session in sessions.iter_mut().skip(1) {
        assert_eq!(
            session
                .finalize_manifest(replacement_manifest.manifest_id())
                .unwrap(),
            replacement
        );
    }
    let accepted = node
        .rpc(None)
        .call("testmempoolaccept", json!([[serialize_hex(&replacement)]]))
        .unwrap();
    assert_eq!(accepted[0]["allowed"].as_bool(), Some(true), "{accepted}");
    let replacement_txid = node
        .rpc(None)
        .call("sendrawtransaction", json!([serialize_hex(&replacement)]))
        .unwrap();
    assert_eq!(
        replacement_txid.as_str(),
        Some(replacement.compute_txid().to_string().as_str())
    );
    assert!(node
        .rpc(None)
        .call(
            "getmempoolentry",
            json!([initial.compute_txid().to_string()])
        )
        .is_err());
    sessions[0]
        .mark_phase(
            ProtocolPhase::Mempool,
            &format!("replacement={}", replacement.compute_txid()),
        )
        .unwrap();
    mine(&wallet, 1);
    node.wait_for_filter_index();
    sessions[0]
        .mark_phase(ProtocolPhase::Confirmed, "height=103")
        .unwrap();

    let mut discovery = client(&node, tmp.path().join("discovery-cbf"));
    let mut index = ScanIndex::open(
        tmp.path().join("discovery-index"),
        opencsv_bitcoin::Network::Regtest,
    )
    .unwrap();
    index.scan_sync(&mut discovery, birth_height).unwrap();
    let discovered: Vec<_> = index
        .occurrences()
        .iter()
        .filter(|entry| entry.txid == replacement.compute_txid().to_byte_array())
        .collect();
    assert_eq!(discovered.len(), 2);
    assert!(discovered.iter().all(|entry| {
        entry
            .batch
            .as_ref()
            .is_some_and(|batch| batch.version == BatchVersion::V2)
    }));

    // A fresh authoritative recheck sees the recently spent stock input and
    // cannot mint a new signing capability for either old manifest.
    let mut after = client(&node, tmp.path().join("post-confirmation-cbf"));
    let error = after
        .verify_batch_inputs(&proposal, &replacement_manifest, &births, 32)
        .unwrap_err();
    assert!(error.to_string().contains("spent at height 103"), "{error}");
    assert_eq!(
        sessions[0].status().unwrap().phase,
        ProtocolPhase::Confirmed
    );
    let reopened = Session::open(roots[0].path()).unwrap();
    let signed_ids = reopened.signed_manifest_ids().unwrap();
    assert_eq!(signed_ids.len(), 2);
    assert!(signed_ids.contains(&initial_manifest.manifest_id()));
    assert!(signed_ids.contains(&replacement_manifest.manifest_id()));
    assert_eq!(
        reopened
            .signed_transaction(initial_manifest.manifest_id())
            .unwrap(),
        initial
    );
    assert_eq!(
        reopened
            .signed_transaction(replacement_manifest.manifest_id())
            .unwrap(),
        replacement
    );
    println!(
        "ACCEPTANCE three-peer authoring->TCP gossip->sign-disappear recovery->initial {}->unanimous replacement {}->BIP158 discovery->confirmed height=103",
        initial.compute_txid(),
        replacement.compute_txid()
    );
}
