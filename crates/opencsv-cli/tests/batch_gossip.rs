use std::net::TcpListener;
use std::thread;

use bitcoin::hashes::Hash as _;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin::{Amount, OutPoint, TxOut, Txid};
use opencsv_bitcoin::batch_v2::{
    p2wpkh_script, Manifest, ParticipantCommitment, Proposal, SignatureShare,
};
use opencsv_cli::batch_gossip::{
    relay_next, relay_once, send_frame, IngestOutcome, MessageKind, ProtocolPhase, RelayAttempt,
    RelayPolicy, Session, SessionPolicy, SignedFrame,
};
use opencsv_core::{binding, Digest};

fn secret(seed: u8) -> SecretKey {
    SecretKey::from_slice(&[seed; 32]).unwrap()
}

fn public(secret: &SecretKey) -> PublicKey {
    PublicKey::from_secret_key(&Secp256k1::new(), secret)
}

fn outpoint(seed: u8, vout: u32) -> OutPoint {
    OutPoint::new(Txid::from_byte_array([seed; 32]), vout)
}

struct Fixture {
    policy: SessionPolicy,
    stock_secret: SecretKey,
    participant_secrets: Vec<SecretKey>,
    proposal: Proposal,
    commitments: Vec<ParticipantCommitment>,
    manifest: Manifest,
    shares: Vec<SignatureShare>,
}

fn fixture() -> Fixture {
    let stock_secret = secret(3);
    let policy = SessionPolicy {
        chain_id: [9; 32],
        current_height: 100,
    };
    let proposal = Proposal::new(
        policy.chain_id,
        outpoint(7, 1),
        100_000,
        public(&stock_secret),
        2,
        [8; 32],
        100,
        110,
        2,
        20,
    )
    .unwrap();
    let participant_secrets = vec![secret(5), secret(4)];
    let commitments: Vec<_> = participant_secrets
        .iter()
        .enumerate()
        .map(|(index, key)| {
            let raw = Digest::from_bytes([(index + 1) as u8; 32]);
            ParticipantCommitment::new(
                &proposal,
                [(index + 1) as u8; 32],
                [(index + 11) as u8; 32],
                binding(&raw, &proposal.context()).to_anchor(),
                outpoint((20 - index) as u8, index as u32),
                TxOut {
                    value: Amount::from_sat(20_000),
                    script_pubkey: p2wpkh_script(public(key)),
                },
                public(key),
                p2wpkh_script(public(&secret((30 + index) as u8))),
                10_000,
            )
            .unwrap()
        })
        .collect();
    let manifest = Manifest::build(&proposal, commitments.clone()).unwrap();
    let mut shares = vec![SignatureShare::new(
        manifest.manifest_id(),
        0,
        proposal.stock_owner_pubkey(),
        manifest.sign_stock(&proposal, &stock_secret).unwrap(),
    )
    .unwrap()];
    for index in 0..2 {
        let expected = manifest.participant_fee_pubkey(index).unwrap();
        let key = participant_secrets
            .iter()
            .find(|key| public(key) == expected)
            .unwrap();
        shares.push(
            SignatureShare::new(
                manifest.manifest_id(),
                (index + 1) as u16,
                expected,
                manifest.sign_participant(&proposal, index, key).unwrap(),
            )
            .unwrap(),
        );
    }
    Fixture {
        policy,
        stock_secret,
        participant_secrets,
        proposal,
        commitments,
        manifest,
        shares,
    }
}

#[test]
fn complete_two_round_session_recovers_and_rejects_tampering() {
    let fixture = fixture();
    let roots: Vec<_> = (0..3).map(|_| tempfile::tempdir().unwrap()).collect();
    let mut sessions: Vec<_> = roots
        .iter()
        .map(|root| Session::init(root.path(), fixture.policy).unwrap())
        .collect();

    let proposal_wire = sessions[0]
        .publish_proposal(fixture.proposal.wire_bytes(), &fixture.stock_secret)
        .unwrap();
    for session in sessions.iter_mut().skip(1) {
        assert_eq!(
            session.ingest(&proposal_wire).unwrap(),
            IngestOutcome::Accepted
        );
    }
    assert_eq!(
        sessions[1].ingest(&proposal_wire).unwrap(),
        IngestOutcome::Duplicate
    );
    let same_body_other_relay = SignedFrame::sign_proposal(
        fixture.proposal.wire_bytes(),
        &secret(77),
        &fixture.stock_secret,
    )
    .unwrap();
    assert_eq!(
        sessions[1]
            .ingest(&same_body_other_relay.to_wire())
            .unwrap(),
        IngestOutcome::Duplicate
    );
    assert_eq!(
        std::fs::read_dir(roots[1].path().join("frames"))
            .unwrap()
            .count(),
        1
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(roots[0].path().join("identity.key"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0);
    }

    let commitment_0 = sessions[1]
        .publish_commitment(
            fixture.commitments[0].wire_bytes(),
            &fixture.participant_secrets[0],
        )
        .unwrap();
    for (index, session) in sessions.iter_mut().enumerate() {
        if index != 1 {
            assert_eq!(
                session.ingest(&commitment_0).unwrap(),
                IngestOutcome::Accepted
            );
        }
    }
    assert!(sessions[0]
        .publish(MessageKind::Manifest, fixture.manifest.wire_bytes())
        .is_err());

    let commitment_1 = sessions[2]
        .publish_commitment(
            fixture.commitments[1].wire_bytes(),
            &fixture.participant_secrets[1],
        )
        .unwrap();
    for session in sessions.iter_mut().take(2) {
        assert_eq!(
            session.ingest(&commitment_1).unwrap(),
            IngestOutcome::Accepted
        );
    }

    let manifest_wire = sessions[0]
        .publish(MessageKind::Manifest, fixture.manifest.wire_bytes())
        .unwrap();
    for session in sessions.iter_mut().skip(1) {
        assert_eq!(
            session.ingest(&manifest_wire).unwrap(),
            IngestOutcome::Accepted
        );
    }

    for (publisher, share) in fixture.shares.iter().enumerate() {
        let share_wire = sessions[publisher]
            .publish(MessageKind::Signature, share.wire_bytes())
            .unwrap();
        for (index, session) in sessions.iter_mut().enumerate() {
            if index != publisher {
                assert_eq!(
                    session.ingest(&share_wire).unwrap(),
                    IngestOutcome::Accepted
                );
            }
        }
        if publisher == 0 {
            assert!(sessions[0]
                .mark_phase(
                    ProtocolPhase::AbortedBeforeSignature,
                    "partial signatures exist"
                )
                .is_err());
        }
    }

    let expected = sessions[0].finalize_latest().unwrap();
    for session in &mut sessions[1..] {
        assert_eq!(session.finalize_latest().unwrap(), expected);
        let status = session.status().unwrap();
        assert_eq!(status.phase, ProtocolPhase::SignedPersisted);
        assert_eq!(status.signature_shares, 3);
        assert_eq!(status.required_signatures, 3);
    }

    drop(sessions);
    let mut reopened = Session::open(roots[2].path()).unwrap();
    assert_eq!(reopened.latest_signed_transaction().unwrap(), expected);
    assert!(reopened
        .mark_phase(ProtocolPhase::AbortedBeforeSignature, "late abort")
        .is_err());
    reopened
        .mark_phase(
            ProtocolPhase::Broadcast,
            &expected.compute_txid().to_string(),
        )
        .unwrap();
    reopened
        .mark_phase(ProtocolPhase::Mempool, "testmempoolaccept=true")
        .unwrap();
    assert_eq!(reopened.finalize_latest().unwrap(), expected);
    assert_eq!(reopened.status().unwrap().phase, ProtocolPhase::Mempool);
    reopened
        .mark_phase(ProtocolPhase::Confirmed, "height=101")
        .unwrap();
    reopened
        .mark_phase(ProtocolPhase::PayloadDelivered, "receipt=peer")
        .unwrap();
    assert_eq!(
        reopened.status().unwrap().phase,
        ProtocolPhase::PayloadDelivered
    );

    let replacement = fixture.manifest.replacement(&fixture.proposal, 3).unwrap();
    let replacement_frame =
        SignedFrame::sign(MessageKind::Manifest, replacement.wire_bytes(), &secret(78)).unwrap();
    assert!(reopened.ingest(&replacement_frame.to_wire()).is_err());

    let mut tampered = proposal_wire.clone();
    tampered[50] ^= 1;
    assert!(reopened.ingest(&tampered).is_err());

    let wrong_chain_root = tempfile::tempdir().unwrap();
    let mut wrong_chain = Session::init(
        wrong_chain_root.path(),
        SessionPolicy {
            chain_id: [0x55; 32],
            current_height: 100,
        },
    )
    .unwrap();
    let external = SignedFrame::sign_proposal(
        fixture.proposal.wire_bytes(),
        &secret(77),
        &fixture.stock_secret,
    )
    .unwrap();
    assert!(wrong_chain.ingest(&external.to_wire()).is_err());

    let abort_root = tempfile::tempdir().unwrap();
    let mut aborted = Session::init(abort_root.path(), fixture.policy).unwrap();
    assert_eq!(
        aborted.ingest(&proposal_wire).unwrap(),
        IngestOutcome::Accepted
    );
    aborted
        .mark_phase(
            ProtocolPhase::AbortedBeforeSignature,
            "participant declined",
        )
        .unwrap();
    assert!(aborted.ingest(&commitment_0).is_err());
}

#[test]
fn tcp_relay_persists_before_reporting_forward_success() {
    let fixture = fixture();
    let sender_root = tempfile::tempdir().unwrap();
    let receiver_root = tempfile::tempdir().unwrap();
    let mut sender = Session::init(sender_root.path(), fixture.policy).unwrap();
    let receiver = Session::init(receiver_root.path(), fixture.policy).unwrap();
    let wire = sender
        .publish_proposal(fixture.proposal.wire_bytes(), &fixture.stock_secret)
        .unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let joined = thread::spawn(move || {
        let mut receiver = receiver;
        let report = relay_once(&listener, &mut receiver, &[]).unwrap();
        (report, receiver.status().unwrap())
    });
    send_frame(address, &wire).unwrap();
    let (report, status) = joined.join().unwrap();
    assert_eq!(report.outcome, IngestOutcome::Accepted);
    assert_eq!(report.forwarded, 0);
    assert_eq!(status.phase, ProtocolPhase::Proposed);
    assert_eq!(
        Session::open(receiver_root.path())
            .unwrap()
            .status()
            .unwrap(),
        status
    );
}

#[test]
fn malformed_connection_is_rejected_without_stopping_relay() {
    let fixture = fixture();
    let sender_root = tempfile::tempdir().unwrap();
    let receiver_root = tempfile::tempdir().unwrap();
    let mut sender = Session::init(sender_root.path(), fixture.policy).unwrap();
    let receiver = Session::init(receiver_root.path(), fixture.policy).unwrap();
    let valid = sender
        .publish_proposal(fixture.proposal.wire_bytes(), &fixture.stock_secret)
        .unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let joined = thread::spawn(move || {
        let mut receiver = receiver;
        let rejected = relay_next(&listener, &mut receiver, &[]).unwrap();
        let processed = relay_next(&listener, &mut receiver, &[]).unwrap();
        (rejected, processed, receiver.status().unwrap())
    });
    send_frame(address, b"not-a-canonical-frame").unwrap();
    send_frame(address, &valid).unwrap();
    let (rejected, processed, status) = joined.join().unwrap();
    assert!(matches!(rejected, RelayAttempt::Rejected { .. }));
    assert!(matches!(
        processed,
        RelayAttempt::Processed(report) if report.outcome == IngestOutcome::Accepted
    ));
    assert_eq!(status.phase, ProtocolPhase::Proposed);
}

#[test]
fn local_commitment_quota_and_authorized_identities_are_enforced() {
    let fixture = fixture();
    let root = tempfile::tempdir().unwrap();
    let mut session = Session::init_with_relay_policy(
        root.path(),
        fixture.policy,
        RelayPolicy {
            max_commitments: 1,
            ..RelayPolicy::default()
        },
    )
    .unwrap();
    session
        .publish_proposal(fixture.proposal.wire_bytes(), &fixture.stock_secret)
        .unwrap();
    session
        .publish_commitment(
            fixture.commitments[0].wire_bytes(),
            &fixture.participant_secrets[0],
        )
        .unwrap();
    let error = session
        .publish_commitment(
            fixture.commitments[1].wire_bytes(),
            &fixture.participant_secrets[1],
        )
        .unwrap_err();
    assert!(error.to_string().contains("commitment quota"));
    assert_eq!(
        Session::open(root.path())
            .unwrap()
            .status()
            .unwrap()
            .commitments,
        1
    );
}

#[test]
fn proposal_reannouncement_is_idempotent_but_conflict_is_rejected() {
    let fixture = fixture();
    let root = tempfile::tempdir().unwrap();
    let mut session = Session::init(root.path(), fixture.policy).unwrap();
    let first = session
        .publish_proposal(fixture.proposal.wire_bytes(), &fixture.stock_secret)
        .unwrap();
    assert_eq!(session.ingest(&first).unwrap(), IngestOutcome::Duplicate);

    let conflicting = Proposal::new(
        fixture.policy.chain_id,
        fixture.proposal.stock_outpoint(),
        fixture.proposal.stock_value(),
        fixture.proposal.stock_owner_pubkey(),
        2,
        [0x91; 32],
        100,
        110,
        2,
        20,
    )
    .unwrap();
    let frame =
        SignedFrame::sign_proposal(conflicting.wire_bytes(), &secret(92), &fixture.stock_secret)
            .unwrap();
    let error = session.ingest(&frame.to_wire()).unwrap_err();
    assert!(error.to_string().contains("different proposal body"));
}

#[test]
fn earlier_epoch_signature_blocks_sign_and_disappear_abort() {
    let fixture = fixture();
    let root = tempfile::tempdir().unwrap();
    let mut session = Session::init(root.path(), fixture.policy).unwrap();
    session
        .publish_proposal(fixture.proposal.wire_bytes(), &fixture.stock_secret)
        .unwrap();
    for (index, (commitment, key)) in fixture
        .commitments
        .iter()
        .zip(&fixture.participant_secrets)
        .enumerate()
    {
        let frame = SignedFrame::sign_commitment(
            &fixture.proposal,
            commitment.wire_bytes(),
            &secret(100 + index as u8),
            key,
        )
        .unwrap();
        session.ingest(&frame.to_wire()).unwrap();
    }
    session
        .publish(MessageKind::Manifest, fixture.manifest.wire_bytes())
        .unwrap();
    session
        .publish(MessageKind::Signature, fixture.shares[0].wire_bytes())
        .unwrap();

    let replacement = fixture.manifest.replacement(&fixture.proposal, 3).unwrap();
    session
        .publish(MessageKind::Manifest, replacement.wire_bytes())
        .unwrap();
    let error = session
        .mark_phase(
            ProtocolPhase::AbortedBeforeSignature,
            "latest epoch unsigned but prior signature escaped",
        )
        .unwrap_err();
    assert!(error.to_string().contains("illegal batch phase transition"));
}
