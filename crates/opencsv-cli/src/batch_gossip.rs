//! Authenticated, durable, all-peer relay for batching v2.
//!
//! C1 defines the canonical proposal, commitment, manifest, and signature
//! bodies. This module adds only C2 transport and crash semantics: signed
//! bounded frames, content-addressed deduplication, validation before relay,
//! an append-only event receipt, deterministic session reconstruction, and
//! persistence of the fully signed transaction before broadcast.

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1, SecretKey};
use bitcoin::Transaction;
use opencsv_bitcoin::batch_v2::{
    Manifest, ParticipantCommitment, Proposal, ReservationPhase, SignatureShare,
};
use opencsv_cbf::{VerifiedBatchInputs, VerifiedChainTip, VerifiedCommitmentInputs};
use rand::RngExt;
use sha2::{Digest, Sha256};

use crate::error::{io_err, Error};

const FRAME_MAGIC: [u8; 8] = *b"OCSVG2\0\0";
const POLICY_MAGIC: [u8; 8] = *b"OCSVP2\0\0";
const RELAY_POLICY_MAGIC: [u8; 8] = *b"OCSVRP3\0";
const RESERVATION_MAGIC: [u8; 8] = *b"OCSVRSV2";
const FRAME_VERSION: u16 = 3;
const MAX_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;
const MAX_FRAME_BYTES: usize = MAX_PAYLOAD_BYTES + 256;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Deployment-local relay limits. These bounds are not C1 protocol constants;
/// operators may tighten them without changing transcript validity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelayPolicy {
    /// Maximum stored participant commitments, additionally capped by the
    /// proposal participant count.
    pub max_commitments: u32,
    /// Maximum stored manifest epochs in one local session.
    pub max_replacement_epochs: u32,
    /// Maximum bytes across accepted frame files.
    pub max_session_bytes: u64,
    /// Maximum active event-log size before one bounded rotation.
    pub max_event_bytes: u64,
}

impl Default for RelayPolicy {
    fn default() -> Self {
        Self {
            max_commitments: 64,
            max_replacement_epochs: 16,
            max_session_bytes: 32 * 1024 * 1024,
            max_event_bytes: 1024 * 1024,
        }
    }
}

impl RelayPolicy {
    fn validate(self) -> Result<Self, Error> {
        if !(1..=64).contains(&self.max_commitments)
            || self.max_replacement_epochs == 0
            || self.max_session_bytes < 4096
            || self.max_event_bytes < 4096
        {
            return Err(protocol_error("invalid local relay policy"));
        }
        Ok(self)
    }
}

/// Typed C2 relay payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageKind {
    /// Round 0 proposal.
    Proposal,
    /// Round 1 participant commitment.
    Commitment,
    /// Round 1 source-complete canonical manifest.
    Manifest,
    /// Round 2 input-specific signature share.
    Signature,
}

impl MessageKind {
    fn to_byte(self) -> u8 {
        match self {
            Self::Proposal => 1,
            Self::Commitment => 2,
            Self::Manifest => 3,
            Self::Signature => 4,
        }
    }

    fn from_byte(byte: u8) -> Result<Self, Error> {
        match byte {
            1 => Ok(Self::Proposal),
            2 => Ok(Self::Commitment),
            3 => Ok(Self::Manifest),
            4 => Ok(Self::Signature),
            _ => Err(protocol_error(format!("unknown gossip kind {byte}"))),
        }
    }

    /// Stable CLI/journal name.
    pub fn name(self) -> &'static str {
        match self {
            Self::Proposal => "proposal",
            Self::Commitment => "commitment",
            Self::Manifest => "manifest",
            Self::Signature => "signature",
        }
    }
}

/// Authenticated C2 frame. The relay identity is separate from Bitcoin input
/// keys; canonical C1 bodies and input signatures are still validated at the
/// protocol layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedFrame {
    kind: MessageKind,
    sender: PublicKey,
    payload: Vec<u8>,
    origin_signature: Option<Signature>,
    signature: Signature,
}

impl SignedFrame {
    /// Sign a manifest or signature-share body with a relay identity.
    /// Proposal and commitment frames require origin-key authorization and
    /// must use [`Self::sign_proposal`] or [`Self::sign_commitment`].
    pub fn sign(kind: MessageKind, payload: Vec<u8>, identity: &SecretKey) -> Result<Self, Error> {
        if matches!(kind, MessageKind::Proposal | MessageKind::Commitment) {
            return Err(protocol_error(
                "proposal/commitment frames require Bitcoin-key origin authorization",
            ));
        }
        Self::sign_parts(kind, payload, identity, None)
    }

    /// Sign a proposal frame with both the separate relay identity and the
    /// stock key committed by the unchanged C1 proposal body.
    pub fn sign_proposal(
        payload: Vec<u8>,
        identity: &SecretKey,
        stock_key: &SecretKey,
    ) -> Result<Self, Error> {
        let proposal = Proposal::from_wire(&payload).map_err(batch_error)?;
        require_origin_key(stock_key, proposal.stock_owner_pubkey(), "stock")?;
        Self::sign_parts(MessageKind::Proposal, payload, identity, Some(stock_key))
    }

    /// Sign a commitment frame with both the separate relay identity and the
    /// fee key committed by the unchanged C1 commitment body.
    pub fn sign_commitment(
        proposal: &Proposal,
        payload: Vec<u8>,
        identity: &SecretKey,
        fee_key: &SecretKey,
    ) -> Result<Self, Error> {
        let commitment =
            ParticipantCommitment::from_wire(proposal, &payload).map_err(batch_error)?;
        require_origin_key(fee_key, commitment.fee_pubkey(), "fee")?;
        Self::sign_parts(MessageKind::Commitment, payload, identity, Some(fee_key))
    }

    fn sign_parts(
        kind: MessageKind,
        payload: Vec<u8>,
        identity: &SecretKey,
        origin_key: Option<&SecretKey>,
    ) -> Result<Self, Error> {
        if payload.len() > MAX_PAYLOAD_BYTES {
            return Err(protocol_error("gossip payload exceeds 4 MiB"));
        }
        let secp = Secp256k1::new();
        let sender = PublicKey::from_secret_key(&secp, identity);
        let origin_signature = origin_key.map(|key| {
            secp.sign_ecdsa(
                &Message::from_digest(origin_digest(kind, sender, &payload)),
                key,
            )
        });
        let digest = frame_digest(kind, sender, &payload, origin_signature.as_ref());
        let signature = secp.sign_ecdsa(&Message::from_digest(digest), identity);
        Ok(Self {
            kind,
            sender,
            payload,
            origin_signature,
            signature,
        })
    }

    /// Parse, canonicalize, and authenticate a frame.
    pub fn from_wire(wire: &[u8]) -> Result<Self, Error> {
        if wire.len() > MAX_FRAME_BYTES || wire.len() < 60 {
            return Err(protocol_error("gossip frame length is outside policy"));
        }
        if wire[..8] != FRAME_MAGIC {
            return Err(protocol_error("gossip frame magic mismatch"));
        }
        let version = u16::from_le_bytes([wire[8], wire[9]]);
        if version != FRAME_VERSION {
            return Err(protocol_error(format!(
                "unsupported gossip frame version {version}"
            )));
        }
        let kind = MessageKind::from_byte(wire[10])?;
        let sender = PublicKey::from_slice(&wire[11..44])
            .map_err(|error| protocol_error(format!("relay public key: {error}")))?;
        let payload_len =
            u32::from_le_bytes(wire[44..48].try_into().expect("fixed slice")) as usize;
        if payload_len > MAX_PAYLOAD_BYTES {
            return Err(protocol_error("gossip payload exceeds 4 MiB"));
        }
        let payload_end = 48usize
            .checked_add(payload_len)
            .ok_or_else(|| protocol_error("gossip length overflow"))?;
        let origin_len_end = payload_end
            .checked_add(2)
            .ok_or_else(|| protocol_error("gossip length overflow"))?;
        if origin_len_end > wire.len() {
            return Err(protocol_error("truncated gossip payload"));
        }
        let origin_len = u16::from_le_bytes(
            wire[payload_end..origin_len_end]
                .try_into()
                .expect("fixed slice"),
        ) as usize;
        if origin_len != 0 && !(8..=72).contains(&origin_len) {
            return Err(protocol_error("invalid origin signature length"));
        }
        let origin_end = origin_len_end
            .checked_add(origin_len)
            .ok_or_else(|| protocol_error("gossip length overflow"))?;
        let signature_len_end = origin_end
            .checked_add(2)
            .ok_or_else(|| protocol_error("gossip length overflow"))?;
        if signature_len_end > wire.len() {
            return Err(protocol_error("truncated origin authorization"));
        }
        let origin_signature = if origin_len == 0 {
            None
        } else {
            Some(parse_low_s_signature(
                &wire[origin_len_end..origin_end],
                "origin",
            )?)
        };
        let signature_len = u16::from_le_bytes(
            wire[origin_end..signature_len_end]
                .try_into()
                .expect("fixed slice"),
        ) as usize;
        if !(8..=72).contains(&signature_len) || signature_len_end + signature_len != wire.len() {
            return Err(protocol_error(
                "invalid gossip signature length/trailing bytes",
            ));
        }
        let signature = parse_low_s_signature(&wire[signature_len_end..], "relay")?;
        let payload = wire[48..payload_end].to_vec();
        Secp256k1::verification_only()
            .verify_ecdsa(
                &Message::from_digest(frame_digest(
                    kind,
                    sender,
                    &payload,
                    origin_signature.as_ref(),
                )),
                &signature,
                &sender,
            )
            .map_err(|error| protocol_error(format!("relay authentication: {error}")))?;
        let frame = Self {
            kind,
            sender,
            payload,
            origin_signature,
            signature,
        };
        if frame.to_wire() != wire {
            return Err(protocol_error("non-canonical gossip frame"));
        }
        Ok(frame)
    }

    /// Canonical frame bytes.
    pub fn to_wire(&self) -> Vec<u8> {
        let origin_signature = self.origin_signature.as_ref().map(Signature::serialize_der);
        let signature = self.signature.serialize_der();
        let origin_len = origin_signature
            .as_ref()
            .map_or(0, bitcoin::secp256k1::ecdsa::SerializedSignature::len);
        let mut wire = Vec::with_capacity(52 + self.payload.len() + origin_len + signature.len());
        wire.extend_from_slice(&FRAME_MAGIC);
        wire.extend_from_slice(&FRAME_VERSION.to_le_bytes());
        wire.push(self.kind.to_byte());
        wire.extend_from_slice(&self.sender.serialize());
        wire.extend_from_slice(&(self.payload.len() as u32).to_le_bytes());
        wire.extend_from_slice(&self.payload);
        wire.extend_from_slice(&(origin_len as u16).to_le_bytes());
        if let Some(origin_signature) = origin_signature {
            wire.extend_from_slice(&origin_signature);
        }
        wire.extend_from_slice(&(signature.len() as u16).to_le_bytes());
        wire.extend_from_slice(&signature);
        wire
    }

    /// Typed payload kind.
    pub fn kind(&self) -> MessageKind {
        self.kind
    }

    /// Authenticated relay identity.
    pub fn sender(&self) -> PublicKey {
        self.sender
    }

    /// Canonical C1 body bytes.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Bitcoin-key origin authorization for proposal/commitment frames.
    pub fn origin_signature(&self) -> Option<Signature> {
        self.origin_signature
    }

    /// Content-addressed frame identifier.
    pub fn id(&self) -> [u8; 32] {
        Sha256::digest(self.to_wire()).into()
    }
}

/// Independently verified chain snapshot used when accepting round 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionPolicy {
    /// Genesis block hash in internal byte order.
    pub chain_id: [u8; 32],
    /// Verified height at session creation/update.
    pub current_height: u32,
}

/// Result of durable frame ingestion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IngestOutcome {
    /// New authenticated frame persisted and eligible for forwarding.
    Accepted,
    /// Exact frame was already persisted; do not relay it again.
    Duplicate,
}

/// Durable protocol phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtocolPhase {
    /// Session exists but has no proposal.
    Ready,
    /// Round 0 proposal validated.
    Proposed,
    /// One or more round 1 commitments validated.
    Committed,
    /// A source-complete manifest and any partial signatures are present.
    ManifestReady,
    /// Complete signed transaction persisted before broadcast.
    SignedPersisted,
    /// First broadcast attempt recorded.
    Broadcast,
    /// Node/mempool acceptance recorded.
    Mempool,
    /// Confirmation-policy completion recorded.
    Confirmed,
    /// Payload/consignment delivery recorded.
    PayloadDelivered,
    /// Unsigned session aborted.
    AbortedBeforeSignature,
    /// A confirmed conflict invalidated the operation.
    InvalidatedOnChain,
    /// Unsigned proposal expired.
    ExpiredUnsigned,
}

impl ProtocolPhase {
    /// Stable journal/config spelling.
    pub fn name(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Proposed => "proposed",
            Self::Committed => "committed",
            Self::ManifestReady => "manifest_ready",
            Self::SignedPersisted => "signed_persisted",
            Self::Broadcast => "broadcast",
            Self::Mempool => "mempool",
            Self::Confirmed => "confirmed",
            Self::PayloadDelivered => "payload_delivered",
            Self::AbortedBeforeSignature => "aborted_before_signature",
            Self::InvalidatedOnChain => "invalidated_on_chain",
            Self::ExpiredUnsigned => "expired_unsigned",
        }
    }

    /// Parse the stable spelling.
    pub fn parse(value: &str) -> Result<Self, Error> {
        match value {
            "ready" => Ok(Self::Ready),
            "proposed" => Ok(Self::Proposed),
            "committed" => Ok(Self::Committed),
            "manifest_ready" => Ok(Self::ManifestReady),
            "signed_persisted" => Ok(Self::SignedPersisted),
            "broadcast" => Ok(Self::Broadcast),
            "mempool" => Ok(Self::Mempool),
            "confirmed" => Ok(Self::Confirmed),
            "payload_delivered" => Ok(Self::PayloadDelivered),
            "aborted_before_signature" => Ok(Self::AbortedBeforeSignature),
            "invalidated_on_chain" => Ok(Self::InvalidatedOnChain),
            "expired_unsigned" => Ok(Self::ExpiredUnsigned),
            _ => Err(protocol_error(format!("unknown batch phase `{value}`"))),
        }
    }

    fn rejects_new_protocol_messages(self) -> bool {
        matches!(
            self,
            Self::Confirmed
                | Self::PayloadDelivered
                | Self::AbortedBeforeSignature
                | Self::InvalidatedOnChain
                | Self::ExpiredUnsigned
        )
    }
}

/// Reconstructed durable session status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionStatus {
    /// Current phase.
    pub phase: ProtocolPhase,
    /// Proposal ID when round 0 exists.
    pub batch_id: Option<[u8; 32]>,
    /// Number of distinct commitment bodies stored.
    pub commitments: usize,
    /// Number of manifest epochs stored.
    pub manifests: usize,
    /// Latest manifest ID.
    pub latest_manifest_id: Option<[u8; 32]>,
    /// Verified signature shares for the latest manifest.
    pub signature_shares: usize,
    /// Number of signatures required by the latest manifest.
    pub required_signatures: usize,
}

/// Durable signer-local reservation capability. Fields are private; a session
/// creates or reloads it only after checking every persisted reservation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalReservation {
    operation_id: [u8; 32],
    outpoint: bitcoin::OutPoint,
    phase: ReservationPhase,
}

impl LocalReservation {
    /// Wallet operation bound to this reservation.
    pub fn operation_id(&self) -> [u8; 32] {
        self.operation_id
    }

    /// Exact locally locked Bitcoin input.
    pub fn outpoint(&self) -> bitcoin::OutPoint {
        self.outpoint
    }

    /// Persisted abort/withholding phase.
    pub fn phase(&self) -> ReservationPhase {
        self.phase
    }
}

/// Durable C2 session. One process owns a session directory at a time; relay
/// threads share it behind a mutex.
pub struct Session {
    root: PathBuf,
    policy: SessionPolicy,
    relay_policy: RelayPolicy,
    identity: SecretKey,
    commitments: Vec<ParticipantCommitment>,
    commitment_senders: HashSet<[u8; 33]>,
    stored_frame_bytes: u64,
}

impl Session {
    /// Create a new session or open an existing session with the same chain
    /// policy. Identity material is generated once and stored mode 0600.
    pub fn init(root: impl AsRef<Path>, policy: SessionPolicy) -> Result<Self, Error> {
        Self::init_with_relay_policy(root, policy, RelayPolicy::default())
    }

    /// Create/open a session with explicit deployment-local relay bounds.
    pub fn init_with_relay_policy(
        root: impl AsRef<Path>,
        policy: SessionPolicy,
        relay_policy: RelayPolicy,
    ) -> Result<Self, Error> {
        let relay_policy = relay_policy.validate()?;
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root).map_err(io_err(&root))?;
        set_private_directory(&root)?;
        for name in [
            "frames",
            "commitments",
            "manifests",
            "signatures",
            "signed",
            "reservations",
        ] {
            let path = root.join(name);
            fs::create_dir_all(&path).map_err(io_err(&path))?;
            set_private_directory(&path)?;
        }
        let policy_path = root.join("policy.bin");
        let policy_bytes = encode_policy(policy);
        if policy_path.exists() {
            let existing = read_limited(&policy_path, 64)?;
            if existing != policy_bytes {
                return Err(protocol_error("session chain policy mismatch"));
            }
        } else {
            atomic_write(&policy_path, &policy_bytes)?;
        }
        let relay_policy_path = root.join("relay-policy.bin");
        let relay_policy_bytes = encode_relay_policy(relay_policy);
        if relay_policy_path.exists() {
            let existing = read_limited(&relay_policy_path, 64)?;
            if existing != relay_policy_bytes {
                return Err(protocol_error("session relay policy mismatch"));
            }
        } else {
            atomic_write(&relay_policy_path, &relay_policy_bytes)?;
        }
        let identity = load_or_create_identity(&root.join("identity.key"))?;
        let (commitments, commitment_senders, stored_frame_bytes) =
            rebuild_session_index(&root, relay_policy)?;
        Ok(Self {
            root,
            policy,
            relay_policy,
            identity,
            commitments,
            commitment_senders,
            stored_frame_bytes,
        })
    }

    /// Open an initialized session.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, Error> {
        let root = root.as_ref().to_path_buf();
        require_private_directory(&root)?;
        let reservations = root.join("reservations");
        fs::create_dir_all(&reservations).map_err(io_err(&reservations))?;
        set_private_directory(&reservations)?;
        let policy_path = root.join("policy.bin");
        let policy = decode_policy(&read_limited(&policy_path, 64)?)?;
        let relay_policy_path = root.join("relay-policy.bin");
        let relay_policy = if relay_policy_path.exists() {
            decode_relay_policy(&read_limited(&relay_policy_path, 64)?)?
        } else {
            let policy = RelayPolicy::default();
            atomic_write(&relay_policy_path, &encode_relay_policy(policy))?;
            policy
        };
        let identity = load_identity(&root.join("identity.key"))?;
        let (commitments, commitment_senders, stored_frame_bytes) =
            rebuild_session_index(&root, relay_policy)?;
        Ok(Self {
            root,
            policy,
            relay_policy,
            identity,
            commitments,
            commitment_senders,
            stored_frame_bytes,
        })
    }

    /// Relay identity public key.
    pub fn identity_pubkey(&self) -> PublicKey {
        PublicKey::from_secret_key(&Secp256k1::new(), &self.identity)
    }

    /// Independently verified chain policy currently bound to this session.
    pub fn session_policy(&self) -> SessionPolicy {
        self.policy
    }

    /// Refresh expiry-sensitive session height from a fresh, independently
    /// agreed CBF tip receipt. The receipt type has no public constructor.
    pub fn refresh_verified_tip(
        &mut self,
        tip: &VerifiedChainTip,
        max_age: Duration,
    ) -> Result<(), Error> {
        tip.require_fresh(max_age)
            .map_err(|error| protocol_error(error.to_string()))?;
        if tip.chain_id() != self.policy.chain_id {
            return Err(protocol_error("verified tip belongs to another chain"));
        }
        let height = u32::try_from(tip.height())
            .map_err(|_| protocol_error("verified tip height exceeds u32"))?;
        self.policy.current_height = height;
        atomic_write(&self.root.join("policy.bin"), &encode_policy(self.policy))?;
        self.append_event(format!("verified_tip {} {}", height, hex(&tip.hash())))
    }

    /// Load the canonical proposal currently bound to this session.
    pub fn proposal(&self) -> Result<Proposal, Error> {
        self.load_proposal()?
            .ok_or_else(|| protocol_error("session has no proposal"))
    }

    /// Reconstruct the latest canonical manifest from the authorized pool.
    pub fn latest_manifest(&self) -> Result<Manifest, Error> {
        let proposal = self.proposal()?;
        let commitments = self.load_commitments(Some(&proposal))?;
        self.load_manifests(Some(&proposal), &commitments)?
            .last()
            .cloned()
            .ok_or_else(|| protocol_error("session has no manifest"))
    }

    /// Reconstruct one exact canonical manifest epoch by identifier.
    pub fn manifest(&self, manifest_id: [u8; 32]) -> Result<Manifest, Error> {
        let proposal = self.proposal()?;
        let commitments = self.load_commitments(Some(&proposal))?;
        self.load_manifests(Some(&proposal), &commitments)?
            .into_iter()
            .find(|manifest| manifest.manifest_id() == manifest_id)
            .ok_or_else(|| protocol_error("session has no named manifest"))
    }

    /// Durably reserve one local input for one operation. Another participant
    /// cannot prove this private wallet lock; each signer must enforce its own.
    pub fn reserve_local_input(
        &self,
        operation_id: [u8; 32],
        outpoint: bitcoin::OutPoint,
    ) -> Result<LocalReservation, Error> {
        for path in read_paths_with_extension(&self.root.join("reservations"), "bin")? {
            let existing = decode_reservation(&read_limited(&path, 128)?)?;
            if existing.operation_id == operation_id {
                if existing.outpoint == outpoint {
                    return Ok(existing);
                }
                return Err(protocol_error(
                    "operation already reserves another Bitcoin input",
                ));
            }
            if existing.outpoint == outpoint && !existing.phase.is_releasable() {
                return Err(protocol_error(
                    "Bitcoin input is reserved by another local operation",
                ));
            }
        }
        let reservation = LocalReservation {
            operation_id,
            outpoint,
            phase: ReservationPhase::CommittedUnsigned,
        };
        self.persist_reservation(&reservation)?;
        Ok(reservation)
    }

    /// Reload one signer-local reservation after a crash/restart.
    pub fn local_reservation(&self, operation_id: [u8; 32]) -> Result<LocalReservation, Error> {
        decode_reservation(&read_limited(&self.reservation_path(operation_id), 128)?)
    }

    /// Publish a commitment only after authoritative stock/fee verification
    /// and an exact signer-local fee reservation.
    pub fn publish_verified_commitment(
        &mut self,
        payload: Vec<u8>,
        fee_key: &SecretKey,
        verified: &VerifiedCommitmentInputs,
        reservation: &LocalReservation,
        max_age: Duration,
    ) -> Result<Vec<u8>, Error> {
        let proposal = self.proposal()?;
        let commitment =
            ParticipantCommitment::from_wire(&proposal, &payload).map_err(batch_error)?;
        verified
            .require_fresh_for(&proposal, &commitment, max_age)
            .map_err(|error| protocol_error(error.to_string()))?;
        self.require_reservation(
            reservation,
            commitment.operation_id(),
            commitment.fee_outpoint(),
        )?;
        self.publish_commitment(payload, fee_key)
    }

    /// Deterministically author and publish the source-complete initial
    /// manifest from the authorized commitment index.
    pub fn author_manifest(&mut self) -> Result<Vec<u8>, Error> {
        let proposal = self.proposal()?;
        let manifest = Manifest::build(&proposal, self.commitments.clone()).map_err(batch_error)?;
        self.publish(MessageKind::Manifest, manifest.wire_bytes())
    }

    /// Deterministically author and publish the next invariant-preserving
    /// replacement manifest.
    pub fn author_replacement(&mut self, feerate_sat_vb: u32) -> Result<Vec<u8>, Error> {
        let proposal = self.proposal()?;
        let previous = self.latest_manifest()?;
        let replacement = previous
            .replacement(&proposal, feerate_sat_vb)
            .map_err(batch_error)?;
        self.publish(MessageKind::Manifest, replacement.wire_bytes())
    }

    /// Release one signature only after fresh authoritative verification and
    /// a durable signer-local reservation. The reservation is advanced before
    /// the share becomes eligible for peer publication, so a crash can never
    /// make a released signature look abortable.
    pub fn sign_and_publish(
        &mut self,
        manifest_id: [u8; 32],
        input_index: u16,
        signing_key: &SecretKey,
        verified: &VerifiedBatchInputs,
        reservation: &LocalReservation,
        max_age: Duration,
    ) -> Result<Vec<u8>, Error> {
        let proposal = self.proposal()?;
        let commitments = self.load_commitments(Some(&proposal))?;
        let manifests = self.load_manifests(Some(&proposal), &commitments)?;
        let manifest = manifests
            .iter()
            .find(|candidate| candidate.manifest_id() == manifest_id)
            .ok_or_else(|| protocol_error("cannot sign an unavailable manifest"))?;
        verified
            .require_fresh_for(&proposal, manifest, max_age)
            .map_err(|error| protocol_error(error.to_string()))?;

        let (operation_id, outpoint, signer_pubkey, signature) = if input_index == 0 {
            (
                proposal.batch_id(),
                proposal.stock_outpoint(),
                proposal.stock_owner_pubkey(),
                manifest
                    .sign_stock(&proposal, signing_key)
                    .map_err(batch_error)?,
            )
        } else {
            let participant_index = usize::from(input_index) - 1;
            let commitment = manifest
                .commitments()
                .get(participant_index)
                .ok_or_else(|| protocol_error("signature input index is outside the manifest"))?;
            (
                commitment.operation_id(),
                commitment.fee_outpoint(),
                commitment.fee_pubkey(),
                manifest
                    .sign_participant(&proposal, participant_index, signing_key)
                    .map_err(batch_error)?,
            )
        };
        self.require_reservation(reservation, operation_id, outpoint)?;

        let released = LocalReservation {
            operation_id,
            outpoint,
            phase: reservation
                .phase
                .signature_released()
                .map_err(batch_error)?,
        };
        self.persist_reservation(&released)?;
        let share = SignatureShare::new(manifest_id, input_index, signer_pubkey, signature)
            .map_err(batch_error)?;
        self.publish(MessageKind::Signature, share.wire_bytes())
    }

    /// Sign, durably ingest, and return a typed frame for peer publication.
    pub fn publish(&mut self, kind: MessageKind, payload: Vec<u8>) -> Result<Vec<u8>, Error> {
        let frame = SignedFrame::sign(kind, payload, &self.identity)?;
        let wire = frame.to_wire();
        self.ingest(&wire)?;
        Ok(wire)
    }

    /// Authorize and publish a round-0 proposal with the C1 stock key while
    /// retaining a separate relay identity.
    pub fn publish_proposal(
        &mut self,
        payload: Vec<u8>,
        stock_key: &SecretKey,
    ) -> Result<Vec<u8>, Error> {
        let frame = SignedFrame::sign_proposal(payload, &self.identity, stock_key)?;
        let wire = frame.to_wire();
        self.ingest(&wire)?;
        Ok(wire)
    }

    /// Authorize and publish a round-1 commitment with its fee key while
    /// retaining a separate relay identity.
    pub fn publish_commitment(
        &mut self,
        payload: Vec<u8>,
        fee_key: &SecretKey,
    ) -> Result<Vec<u8>, Error> {
        let proposal = self
            .load_proposal()?
            .ok_or_else(|| protocol_error("commitment arrived before proposal"))?;
        let frame = SignedFrame::sign_commitment(&proposal, payload, &self.identity, fee_key)?;
        let wire = frame.to_wire();
        self.ingest(&wire)?;
        Ok(wire)
    }

    /// Authenticate, protocol-validate, and persist one frame before it is
    /// eligible for forwarding.
    pub fn ingest(&mut self, wire: &[u8]) -> Result<IngestOutcome, Error> {
        let frame = SignedFrame::from_wire(wire)?;
        self.verify_origin_authorization(&frame)?;
        let frame_path = self
            .root
            .join("frames")
            .join(format!("{}.frame", hex(&semantic_frame_id(&frame))));
        if frame_path.exists() {
            let existing = read_limited(&frame_path, MAX_FRAME_BYTES)?;
            let existing = SignedFrame::from_wire(&existing)?;
            if existing.kind != frame.kind || existing.payload != frame.payload {
                return Err(protocol_error("semantic frame-id collision"));
            }
            return Ok(IngestOutcome::Duplicate);
        }
        if self
            .load_phase()?
            .is_some_and(ProtocolPhase::rejects_new_protocol_messages)
        {
            return Err(protocol_error(
                "terminal/confirmed session rejects new protocol messages",
            ));
        }
        self.enforce_frame_policy(&frame, wire.len())?;
        self.persist_semantic(&frame)?;
        atomic_write(&frame_path, wire)?;
        self.stored_frame_bytes = self
            .stored_frame_bytes
            .checked_add(wire.len() as u64)
            .ok_or_else(|| protocol_error("stored frame-byte counter overflow"))?;
        self.append_event(format!(
            "accepted {} {} {}",
            frame.kind.name(),
            hex(&frame.id()),
            hex(&frame.sender.serialize())
        ))?;
        Ok(IngestOutcome::Accepted)
    }

    fn enforce_frame_policy(&self, frame: &SignedFrame, wire_len: usize) -> Result<(), Error> {
        let projected = self
            .stored_frame_bytes
            .checked_add(wire_len as u64)
            .ok_or_else(|| protocol_error("stored frame-byte counter overflow"))?;
        if projected > self.relay_policy.max_session_bytes {
            return Err(protocol_error("session frame-byte quota exceeded"));
        }
        match frame.kind {
            MessageKind::Proposal => {
                if let Some(existing) = self.load_proposal()? {
                    if existing.wire_bytes() != frame.payload {
                        return Err(protocol_error(
                            "different proposal body in an initialized session",
                        ));
                    }
                }
            }
            MessageKind::Commitment => {
                let proposal = self
                    .load_proposal()?
                    .ok_or_else(|| protocol_error("commitment arrived before proposal"))?;
                let commitment = ParticipantCommitment::from_wire(&proposal, &frame.payload)
                    .map_err(batch_error)?;
                if self
                    .commitments
                    .iter()
                    .any(|existing| existing.commitment_id() == commitment.commitment_id())
                {
                    return Ok(());
                }
                let cap = usize::try_from(self.relay_policy.max_commitments)
                    .expect("u32 fits usize")
                    .min(proposal.participant_count());
                if self.commitments.len() >= cap {
                    return Err(protocol_error("authorized commitment quota exceeded"));
                }
                if self.commitment_senders.contains(&frame.sender.serialize()) {
                    return Err(protocol_error(
                        "relay identity already authorized another commitment",
                    ));
                }
                if self.commitments.iter().any(|existing| {
                    existing.fee_pubkey() == commitment.fee_pubkey()
                        || existing.fee_outpoint() == commitment.fee_outpoint()
                        || existing.operation_id() == commitment.operation_id()
                        || existing.payload() == commitment.payload()
                }) {
                    return Err(protocol_error(
                        "authorized commitment identity/outpoint/operation/payload quota exceeded",
                    ));
                }
            }
            MessageKind::Manifest => {
                let proposal = self
                    .load_proposal()?
                    .ok_or_else(|| protocol_error("manifest arrived before proposal"))?;
                let manifest =
                    Manifest::from_wire_pool(&proposal, &self.commitments, &frame.payload)
                        .map_err(batch_error)?;
                if manifest.replacement_epoch() >= self.relay_policy.max_replacement_epochs {
                    return Err(protocol_error("local replacement-epoch quota exceeded"));
                }
            }
            MessageKind::Signature => {}
        }
        Ok(())
    }

    fn verify_origin_authorization(&self, frame: &SignedFrame) -> Result<(), Error> {
        let expected_key = match frame.kind {
            MessageKind::Proposal => {
                let proposal = Proposal::from_wire(&frame.payload).map_err(batch_error)?;
                proposal.stock_owner_pubkey()
            }
            MessageKind::Commitment => {
                let proposal = self
                    .load_proposal()?
                    .ok_or_else(|| protocol_error("commitment arrived before proposal"))?;
                ParticipantCommitment::from_wire(&proposal, &frame.payload)
                    .map_err(batch_error)?
                    .fee_pubkey()
            }
            MessageKind::Manifest | MessageKind::Signature => {
                if frame.origin_signature.is_some() {
                    return Err(protocol_error(
                        "manifest/signature frames must not carry origin authorization",
                    ));
                }
                return Ok(());
            }
        };
        verify_origin_signature(frame, expected_key)
    }

    /// Reconstruct session status from canonical bodies and persisted phase.
    pub fn status(&self) -> Result<SessionStatus, Error> {
        let proposal = self.load_proposal()?;
        let commitments = self.load_commitments(proposal.as_ref())?;
        let manifests = self.load_manifests(proposal.as_ref(), &commitments)?;
        let latest = manifests.last();
        let signature_shares = match latest {
            Some(manifest) => self
                .load_signatures(manifest, proposal.as_ref().expect("manifest has proposal"))?
                .len(),
            None => 0,
        };
        let required_signatures = latest
            .map(|manifest| manifest.commitment_ids().len() + 1)
            .unwrap_or(0);
        let derived = if proposal.is_none() {
            ProtocolPhase::Ready
        } else if latest.is_some() {
            if self
                .signed_path(latest.expect("checked").manifest_id())
                .exists()
            {
                ProtocolPhase::SignedPersisted
            } else {
                ProtocolPhase::ManifestReady
            }
        } else if commitments.is_empty() {
            ProtocolPhase::Proposed
        } else {
            ProtocolPhase::Committed
        };
        let phase = self.load_phase()?.unwrap_or(derived);
        Ok(SessionStatus {
            phase,
            batch_id: proposal.as_ref().map(Proposal::batch_id),
            commitments: commitments.len(),
            manifests: manifests.len(),
            latest_manifest_id: latest.map(Manifest::manifest_id),
            signature_shares,
            required_signatures,
        })
    }

    /// Verify all latest-epoch shares, finalize the transaction, and atomically
    /// persist its consensus bytes before returning them.
    pub fn finalize_latest(&mut self) -> Result<Transaction, Error> {
        let proposal = self
            .load_proposal()?
            .ok_or_else(|| protocol_error("cannot finalize without a proposal"))?;
        let commitments = self.load_commitments(Some(&proposal))?;
        let manifests = self.load_manifests(Some(&proposal), &commitments)?;
        let manifest_id = manifests
            .last()
            .ok_or_else(|| protocol_error("cannot finalize without a manifest"))?
            .manifest_id();
        self.finalize_manifest(manifest_id)
    }

    /// Finalize and persist one exact manifest epoch. Earlier signed epochs
    /// remain recoverable after later replacement manifests arrive.
    pub fn finalize_manifest(&mut self, manifest_id: [u8; 32]) -> Result<Transaction, Error> {
        let proposal = self
            .load_proposal()?
            .ok_or_else(|| protocol_error("cannot finalize without a proposal"))?;
        let commitments = self.load_commitments(Some(&proposal))?;
        let manifests = self.load_manifests(Some(&proposal), &commitments)?;
        let manifest = manifests
            .iter()
            .find(|manifest| manifest.manifest_id() == manifest_id)
            .ok_or_else(|| protocol_error("cannot finalize an unavailable manifest"))?;
        let signed_path = self.signed_path(manifest_id);
        if signed_path.exists() {
            return self.signed_transaction(manifest_id);
        }
        if self.status()?.phase.rejects_new_protocol_messages() {
            return Err(protocol_error(
                "terminal/confirmed session cannot finalize a new manifest",
            ));
        }
        let shares = self.load_signatures(manifest, &proposal)?;
        let transaction = manifest
            .finalize_shares(&proposal, &shares)
            .map_err(batch_error)?;
        let bytes = serialize(&transaction);
        atomic_write(&signed_path, &bytes)?;
        if matches!(
            self.status()?.phase,
            ProtocolPhase::Ready
                | ProtocolPhase::Proposed
                | ProtocolPhase::Committed
                | ProtocolPhase::ManifestReady
                | ProtocolPhase::SignedPersisted
        ) {
            self.persist_phase(ProtocolPhase::SignedPersisted, &hex(&manifest_id))?;
        } else {
            self.append_event(format!("signed_persisted {}", hex(&manifest_id)))?;
        }
        Ok(transaction)
    }

    /// Load the latest complete signed transaction, verifying canonical
    /// consensus encoding and transaction identity.
    pub fn latest_signed_transaction(&self) -> Result<Transaction, Error> {
        let proposal = self
            .load_proposal()?
            .ok_or_else(|| protocol_error("session has no proposal"))?;
        let commitments = self.load_commitments(Some(&proposal))?;
        let manifests = self.load_manifests(Some(&proposal), &commitments)?;
        let manifest_id = manifests
            .last()
            .ok_or_else(|| protocol_error("session has no manifest"))?
            .manifest_id();
        self.signed_transaction(manifest_id)
    }

    /// Load and verify the persisted signed transaction for one exact epoch.
    pub fn signed_transaction(&self, manifest_id: [u8; 32]) -> Result<Transaction, Error> {
        let proposal = self
            .load_proposal()?
            .ok_or_else(|| protocol_error("session has no proposal"))?;
        let commitments = self.load_commitments(Some(&proposal))?;
        let manifests = self.load_manifests(Some(&proposal), &commitments)?;
        let manifest = manifests
            .iter()
            .find(|manifest| manifest.manifest_id() == manifest_id)
            .ok_or_else(|| protocol_error("session has no named manifest"))?;
        let path = self.signed_path(manifest_id);
        let bytes = read_limited(&path, MAX_PAYLOAD_BYTES)?;
        let transaction: Transaction = deserialize(&bytes)
            .map_err(|error| protocol_error(format!("signed transaction: {error}")))?;
        if serialize(&transaction) != bytes {
            return Err(protocol_error("non-canonical signed transaction encoding"));
        }
        let shares = self.load_signatures(manifest, &proposal)?;
        let expected = manifest
            .finalize_shares(&proposal, &shares)
            .map_err(batch_error)?;
        if expected != transaction {
            return Err(protocol_error(
                "persisted transaction differs from verified shares",
            ));
        }
        Ok(transaction)
    }

    /// Manifest IDs for every durably persisted signed epoch.
    pub fn signed_manifest_ids(&self) -> Result<Vec<[u8; 32]>, Error> {
        let mut ids = Vec::new();
        for path in read_paths_with_extension(&self.root.join("signed"), "tx")? {
            let name = path
                .file_stem()
                .and_then(|value| value.to_str())
                .ok_or_else(|| protocol_error("invalid signed manifest filename"))?;
            ids.push(parse_hex_32(name)?);
        }
        Ok(ids)
    }

    /// Persist a post-assembly phase transition with one-line evidence.
    pub fn mark_phase(&mut self, next: ProtocolPhase, evidence: &str) -> Result<(), Error> {
        if evidence.contains(['\n', '\r']) {
            return Err(protocol_error("phase evidence must be one line"));
        }
        let status = self.status()?;
        let current = status.phase;
        let allowed = match next {
            ProtocolPhase::Broadcast => current == ProtocolPhase::SignedPersisted,
            ProtocolPhase::Mempool => {
                matches!(current, ProtocolPhase::Broadcast | ProtocolPhase::Mempool)
            }
            ProtocolPhase::Confirmed => matches!(
                current,
                ProtocolPhase::Broadcast | ProtocolPhase::Mempool | ProtocolPhase::Confirmed
            ),
            ProtocolPhase::PayloadDelivered => matches!(
                current,
                ProtocolPhase::Confirmed | ProtocolPhase::PayloadDelivered
            ),
            ProtocolPhase::AbortedBeforeSignature | ProtocolPhase::ExpiredUnsigned => {
                !self.has_any_signature_share()?
                    && matches!(
                        current,
                        ProtocolPhase::Proposed
                            | ProtocolPhase::Committed
                            | ProtocolPhase::ManifestReady
                    )
            }
            ProtocolPhase::InvalidatedOnChain => status.manifests > 0,
            ProtocolPhase::Ready
            | ProtocolPhase::Proposed
            | ProtocolPhase::Committed
            | ProtocolPhase::ManifestReady
            | ProtocolPhase::SignedPersisted => false,
        };
        if !allowed {
            return Err(protocol_error(format!(
                "illegal batch phase transition {} -> {}",
                current.name(),
                next.name()
            )));
        }
        self.persist_phase(next, evidence)
    }

    fn has_any_signature_share(&self) -> Result<bool, Error> {
        let Some(proposal) = self.load_proposal()? else {
            return Ok(false);
        };
        let commitments = self.load_commitments(Some(&proposal))?;
        for manifest in self.load_manifests(Some(&proposal), &commitments)? {
            if !self.load_signatures(&manifest, &proposal)?.is_empty() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn reservation_path(&self, operation_id: [u8; 32]) -> PathBuf {
        self.root
            .join("reservations")
            .join(format!("{}.bin", hex(&operation_id)))
    }

    fn persist_reservation(&self, reservation: &LocalReservation) -> Result<(), Error> {
        atomic_write(
            &self.reservation_path(reservation.operation_id),
            &encode_reservation(reservation),
        )
    }

    fn require_reservation(
        &self,
        supplied: &LocalReservation,
        expected_operation_id: [u8; 32],
        expected_outpoint: bitcoin::OutPoint,
    ) -> Result<(), Error> {
        if supplied.operation_id != expected_operation_id || supplied.outpoint != expected_outpoint
        {
            return Err(protocol_error(
                "local reservation does not match this operation and input",
            ));
        }
        let persisted = self.local_reservation(expected_operation_id)?;
        if persisted != *supplied {
            return Err(protocol_error("local reservation capability is stale"));
        }
        if persisted.phase.is_releasable() {
            return Err(protocol_error("local reservation is no longer signable"));
        }
        Ok(())
    }

    fn persist_semantic(&mut self, frame: &SignedFrame) -> Result<(), Error> {
        match frame.kind {
            MessageKind::Proposal => {
                let proposal = Proposal::from_wire(&frame.payload).map_err(batch_error)?;
                proposal
                    .validate_at(self.policy.chain_id, self.policy.current_height)
                    .map_err(batch_error)?;
                semantic_write(&self.root.join("proposal.bin"), &frame.payload)?;
            }
            MessageKind::Commitment => {
                let proposal = self
                    .load_proposal()?
                    .ok_or_else(|| protocol_error("commitment arrived before proposal"))?;
                let commitment = ParticipantCommitment::from_wire(&proposal, &frame.payload)
                    .map_err(batch_error)?;
                semantic_write(
                    &self
                        .root
                        .join("commitments")
                        .join(format!("{}.bin", hex(&commitment.commitment_id()))),
                    &frame.payload,
                )?;
                if !self
                    .commitments
                    .iter()
                    .any(|existing| existing.commitment_id() == commitment.commitment_id())
                {
                    self.commitments.push(commitment);
                    self.commitment_senders.insert(frame.sender.serialize());
                }
            }
            MessageKind::Manifest => {
                let proposal = self
                    .load_proposal()?
                    .ok_or_else(|| protocol_error("manifest arrived before proposal"))?;
                let commitments = self.load_commitments(Some(&proposal))?;
                let manifest = Manifest::from_wire_pool(&proposal, &commitments, &frame.payload)
                    .map_err(batch_error)?;
                let existing = self.load_manifests(Some(&proposal), &commitments)?;
                if let Some(same_epoch) = existing
                    .iter()
                    .find(|candidate| candidate.replacement_epoch() == manifest.replacement_epoch())
                {
                    if same_epoch != &manifest {
                        return Err(protocol_error("manifest equivocation at one epoch"));
                    }
                } else if manifest.replacement_epoch() == 0 {
                    if !existing.is_empty() {
                        return Err(protocol_error("late epoch-zero manifest"));
                    }
                } else {
                    let previous = existing
                        .iter()
                        .find(|candidate| {
                            candidate.replacement_epoch() + 1 == manifest.replacement_epoch()
                        })
                        .ok_or_else(|| protocol_error("replacement manifest skipped an epoch"))?;
                    let expected = previous
                        .replacement(&proposal, manifest.feerate_sat_vb())
                        .map_err(batch_error)?;
                    if expected != manifest {
                        return Err(protocol_error(
                            "replacement manifest violates C1 invariants",
                        ));
                    }
                }
                semantic_write(
                    &self.root.join("manifests").join(format!(
                        "{:010}-{}.bin",
                        manifest.replacement_epoch(),
                        hex(&manifest.manifest_id())
                    )),
                    &frame.payload,
                )?;
            }
            MessageKind::Signature => {
                let proposal = self
                    .load_proposal()?
                    .ok_or_else(|| protocol_error("signature arrived before proposal"))?;
                let commitments = self.load_commitments(Some(&proposal))?;
                let manifests = self.load_manifests(Some(&proposal), &commitments)?;
                let share = SignatureShare::from_wire(&frame.payload).map_err(batch_error)?;
                let manifest = manifests
                    .iter()
                    .find(|candidate| candidate.manifest_id() == share.manifest_id())
                    .ok_or_else(|| protocol_error("signature names an unavailable manifest"))?;
                manifest
                    .verify_signature_share(&proposal, &share)
                    .map_err(batch_error)?;
                semantic_write(
                    &self.root.join("signatures").join(format!(
                        "{}-{:05}.bin",
                        hex(&share.manifest_id()),
                        share.input_index()
                    )),
                    &frame.payload,
                )?;
            }
        }
        Ok(())
    }

    fn load_proposal(&self) -> Result<Option<Proposal>, Error> {
        let path = self.root.join("proposal.bin");
        if !path.exists() {
            return Ok(None);
        }
        let wire = read_limited(&path, MAX_PAYLOAD_BYTES)?;
        let proposal = Proposal::from_wire(&wire).map_err(batch_error)?;
        proposal
            .validate_at(self.policy.chain_id, self.policy.current_height)
            .map_err(batch_error)?;
        Ok(Some(proposal))
    }

    fn load_commitments(
        &self,
        proposal: Option<&Proposal>,
    ) -> Result<Vec<ParticipantCommitment>, Error> {
        let Some(_proposal) = proposal else {
            return Ok(Vec::new());
        };
        Ok(self.commitments.clone())
    }

    fn load_manifests(
        &self,
        proposal: Option<&Proposal>,
        commitments: &[ParticipantCommitment],
    ) -> Result<Vec<Manifest>, Error> {
        let Some(proposal) = proposal else {
            return Ok(Vec::new());
        };
        let mut manifests: Vec<_> = read_sorted(&self.root.join("manifests"))?
            .into_iter()
            .map(|path| {
                Manifest::from_wire_pool(
                    proposal,
                    commitments,
                    &read_limited(&path, MAX_PAYLOAD_BYTES)?,
                )
                .map_err(batch_error)
            })
            .collect::<Result<_, _>>()?;
        manifests.sort_by_key(Manifest::replacement_epoch);
        for pair in manifests.windows(2) {
            if pair[0].replacement_epoch() + 1 != pair[1].replacement_epoch() {
                return Err(protocol_error("persisted manifests skip/repeat an epoch"));
            }
            let expected = pair[0]
                .replacement(proposal, pair[1].feerate_sat_vb())
                .map_err(batch_error)?;
            if expected != pair[1] {
                return Err(protocol_error(
                    "persisted replacement violates C1 invariants",
                ));
            }
        }
        Ok(manifests)
    }

    fn load_signatures(
        &self,
        manifest: &Manifest,
        proposal: &Proposal,
    ) -> Result<Vec<SignatureShare>, Error> {
        let prefix = format!("{}-", hex(&manifest.manifest_id()));
        let mut shares = Vec::new();
        for path in read_sorted(&self.root.join("signatures"))? {
            let matches = path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(&prefix));
            if !matches {
                continue;
            }
            let share = SignatureShare::from_wire(&read_limited(&path, MAX_PAYLOAD_BYTES)?)
                .map_err(batch_error)?;
            manifest
                .verify_signature_share(proposal, &share)
                .map_err(batch_error)?;
            shares.push(share);
        }
        shares.sort_by_key(SignatureShare::input_index);
        Ok(shares)
    }

    fn signed_path(&self, manifest_id: [u8; 32]) -> PathBuf {
        self.root
            .join("signed")
            .join(format!("{}.tx", hex(&manifest_id)))
    }

    fn append_event(&self, event: String) -> Result<(), Error> {
        let path = self.root.join("events.log");
        if event.len() > 1024 || event.contains(['\n', '\r']) {
            return Err(protocol_error("event receipt exceeds one-line bound"));
        }
        if fs::metadata(&path)
            .map(|metadata| metadata.len() >= self.relay_policy.max_event_bytes)
            .unwrap_or(false)
        {
            let rotated = self.root.join("events.log.1");
            if rotated.exists() {
                fs::remove_file(&rotated).map_err(io_err(&rotated))?;
            }
            fs::rename(&path, &rotated).map_err(io_err(&path))?;
        }
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&path).map_err(io_err(&path))?;
        writeln!(file, "{event}").map_err(io_err(&path))?;
        file.sync_all().map_err(io_err(&path))
    }

    fn persist_phase(&self, phase: ProtocolPhase, evidence: &str) -> Result<(), Error> {
        let body = format!("{}\n{}\n", phase.name(), evidence);
        atomic_write(&self.root.join("phase"), body.as_bytes())?;
        self.append_event(format!("phase {} {evidence}", phase.name()))
    }

    fn load_phase(&self) -> Result<Option<ProtocolPhase>, Error> {
        let path = self.root.join("phase");
        if !path.exists() {
            return Ok(None);
        }
        let bytes = read_limited(&path, 4096)?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|error| protocol_error(format!("phase utf8: {error}")))?;
        let name = text
            .lines()
            .next()
            .ok_or_else(|| protocol_error("empty phase file"))?;
        ProtocolPhase::parse(name).map(Some)
    }
}

/// Result from one accepted TCP connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayReport {
    /// Ingest result.
    pub outcome: IngestOutcome,
    /// Number of peers that received a newly accepted frame.
    pub forwarded: usize,
    /// Peer delivery failures; local persistence still succeeded.
    pub failed_peers: Vec<String>,
}

/// One listener iteration. Invalid peer input is a bounded rejection rather
/// than a relay-process failure; listener and durable-storage failures remain
/// fatal errors from [`relay_next`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RelayAttempt {
    /// A valid frame was accepted or deduplicated.
    Processed(RelayReport),
    /// One remote connection supplied an invalid or incomplete frame.
    Rejected {
        /// Remote TCP peer.
        remote: SocketAddr,
        /// One-line bounded rejection receipt.
        reason: String,
    },
}

/// Send one persisted frame to a peer using a bounded length prefix.
pub fn send_frame(peer: SocketAddr, wire: &[u8]) -> Result<(), Error> {
    if wire.len() > MAX_FRAME_BYTES {
        return Err(protocol_error("frame exceeds relay bound"));
    }
    let mut stream = TcpStream::connect_timeout(&peer, CONNECT_TIMEOUT)
        .map_err(|error| protocol_error(format!("connect {peer}: {error}")))?;
    stream
        .set_write_timeout(Some(CONNECT_TIMEOUT))
        .map_err(|error| protocol_error(format!("set timeout {peer}: {error}")))?;
    stream
        .write_all(&(wire.len() as u32).to_le_bytes())
        .and_then(|_| stream.write_all(wire))
        .and_then(|_| stream.flush())
        .map_err(|error| protocol_error(format!("send {peer}: {error}")))
}

/// Accept, validate, persist, and (only when new) forward one frame.
pub fn relay_once(
    listener: &TcpListener,
    session: &mut Session,
    peers: &[SocketAddr],
) -> Result<RelayReport, Error> {
    let (stream, _remote) = listener
        .accept()
        .map_err(|error| protocol_error(format!("accept: {error}")))?;
    process_stream(stream, session, peers)
}

/// Accept one connection while containing malformed-frame failures. This is
/// the Internet-facing listener primitive used by the CLI relay loop.
pub fn relay_next(
    listener: &TcpListener,
    session: &mut Session,
    peers: &[SocketAddr],
) -> Result<RelayAttempt, Error> {
    relay_next_with_refresh(listener, session, peers, |_| Ok(()))
}

/// Accept one connection, refresh expiry-sensitive verified state, then
/// process the frame. Refresh failure is fatal and happens after `accept`, so
/// a relay that was idle cannot ingest against a receipt obtained before the
/// idle period.
pub fn relay_next_with_refresh(
    listener: &TcpListener,
    session: &mut Session,
    peers: &[SocketAddr],
    refresh: impl FnOnce(&mut Session) -> Result<(), Error>,
) -> Result<RelayAttempt, Error> {
    let (stream, remote) = listener
        .accept()
        .map_err(|error| protocol_error(format!("accept: {error}")))?;
    refresh(session)?;
    match process_stream(stream, session, peers) {
        Ok(report) => Ok(RelayAttempt::Processed(report)),
        Err(error @ (Error::Io { .. } | Error::Decode { .. })) => Err(error),
        Err(error) => {
            let reason = bounded_one_line(&error.to_string(), 512);
            session.append_event(format!("rejected {remote} {reason}"))?;
            Ok(RelayAttempt::Rejected { remote, reason })
        }
    }
}

fn process_stream(
    mut stream: TcpStream,
    session: &mut Session,
    peers: &[SocketAddr],
) -> Result<RelayReport, Error> {
    stream
        .set_read_timeout(Some(CONNECT_TIMEOUT))
        .map_err(|error| protocol_error(format!("set read timeout: {error}")))?;
    let mut length = [0u8; 4];
    stream
        .read_exact(&mut length)
        .map_err(|error| protocol_error(format!("read frame length: {error}")))?;
    let length = u32::from_le_bytes(length) as usize;
    if length > MAX_FRAME_BYTES {
        return Err(protocol_error("incoming frame exceeds relay bound"));
    }
    let mut wire = vec![0u8; length];
    stream
        .read_exact(&mut wire)
        .map_err(|error| protocol_error(format!("read frame: {error}")))?;
    let outcome = session.ingest(&wire)?;
    let mut forwarded = 0;
    let mut failed_peers = Vec::new();
    if outcome == IngestOutcome::Accepted {
        for peer in peers {
            match send_frame(*peer, &wire) {
                Ok(()) => forwarded += 1,
                Err(error) => failed_peers.push(format!("{peer}: {error}")),
            }
        }
    }
    Ok(RelayReport {
        outcome,
        forwarded,
        failed_peers,
    })
}

fn bounded_one_line(message: &str, limit: usize) -> String {
    let mut output = String::with_capacity(message.len().min(limit));
    for character in message.chars() {
        if output.len() >= limit {
            break;
        }
        output.push(if matches!(character, '\n' | '\r') {
            ' '
        } else {
            character
        });
    }
    output
}

fn frame_digest(
    kind: MessageKind,
    sender: PublicKey,
    payload: &[u8],
    origin_signature: Option<&Signature>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"OpenCSV/batch-v2/gossip-v3");
    hasher.update([0]);
    hasher.update(FRAME_MAGIC);
    hasher.update(FRAME_VERSION.to_le_bytes());
    hasher.update([kind.to_byte()]);
    hasher.update(sender.serialize());
    hasher.update((payload.len() as u32).to_le_bytes());
    hasher.update(payload);
    if let Some(signature) = origin_signature {
        let signature = signature.serialize_der();
        hasher.update((signature.len() as u16).to_le_bytes());
        hasher.update(signature);
    } else {
        hasher.update(0u16.to_le_bytes());
    }
    hasher.finalize().into()
}

fn origin_digest(kind: MessageKind, sender: PublicKey, payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"OpenCSV/batch-v2/origin-authorization-v1");
    hasher.update([0]);
    hasher.update([kind.to_byte()]);
    hasher.update(sender.serialize());
    hasher.update(Sha256::digest(payload));
    hasher.finalize().into()
}

fn parse_low_s_signature(bytes: &[u8], role: &str) -> Result<Signature, Error> {
    let signature = Signature::from_der(bytes)
        .map_err(|error| protocol_error(format!("{role} signature: {error}")))?;
    let mut normalized = signature;
    normalized.normalize_s();
    if normalized != signature {
        return Err(protocol_error(format!("{role} signature is not low-S")));
    }
    Ok(signature)
}

fn require_origin_key(
    secret_key: &SecretKey,
    expected: PublicKey,
    role: &str,
) -> Result<(), Error> {
    let actual = PublicKey::from_secret_key(&Secp256k1::new(), secret_key);
    if actual != expected {
        return Err(protocol_error(format!(
            "{role} origin key does not match the C1 body"
        )));
    }
    Ok(())
}

fn verify_origin_signature(frame: &SignedFrame, expected_key: PublicKey) -> Result<(), Error> {
    let signature = frame.origin_signature.ok_or_else(|| {
        protocol_error("proposal/commitment frame lacks Bitcoin-key origin authorization")
    })?;
    Secp256k1::verification_only()
        .verify_ecdsa(
            &Message::from_digest(origin_digest(frame.kind, frame.sender, &frame.payload)),
            &signature,
            &expected_key,
        )
        .map_err(|error| protocol_error(format!("origin authorization: {error}")))
}

fn semantic_frame_id(frame: &SignedFrame) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"OpenCSV/batch-v2/gossip-body");
    hasher.update([0]);
    hasher.update([frame.kind.to_byte()]);
    hasher.update((frame.payload.len() as u32).to_le_bytes());
    hasher.update(&frame.payload);
    hasher.finalize().into()
}

fn protocol_error(message: impl Into<String>) -> Error {
    Error::Transport(format!("batch v2: {}", message.into()))
}

fn batch_error(error: opencsv_bitcoin::batch_v2::ProtocolError) -> Error {
    protocol_error(error.to_string())
}

fn encode_policy(policy: SessionPolicy) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(44);
    bytes.extend_from_slice(&POLICY_MAGIC);
    bytes.extend_from_slice(&policy.chain_id);
    bytes.extend_from_slice(&policy.current_height.to_le_bytes());
    bytes
}

fn decode_policy(bytes: &[u8]) -> Result<SessionPolicy, Error> {
    if bytes.len() != 44 || bytes[..8] != POLICY_MAGIC {
        return Err(protocol_error("invalid session policy"));
    }
    Ok(SessionPolicy {
        chain_id: bytes[8..40].try_into().expect("length checked"),
        current_height: u32::from_le_bytes(bytes[40..44].try_into().expect("length checked")),
    })
}

fn encode_relay_policy(policy: RelayPolicy) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(32);
    bytes.extend_from_slice(&RELAY_POLICY_MAGIC);
    bytes.extend_from_slice(&policy.max_commitments.to_le_bytes());
    bytes.extend_from_slice(&policy.max_replacement_epochs.to_le_bytes());
    bytes.extend_from_slice(&policy.max_session_bytes.to_le_bytes());
    bytes.extend_from_slice(&policy.max_event_bytes.to_le_bytes());
    bytes
}

fn decode_relay_policy(bytes: &[u8]) -> Result<RelayPolicy, Error> {
    if bytes.len() != 32 || bytes[..8] != RELAY_POLICY_MAGIC {
        return Err(protocol_error("invalid local relay policy encoding"));
    }
    RelayPolicy {
        max_commitments: u32::from_le_bytes(bytes[8..12].try_into().expect("length checked")),
        max_replacement_epochs: u32::from_le_bytes(
            bytes[12..16].try_into().expect("length checked"),
        ),
        max_session_bytes: u64::from_le_bytes(bytes[16..24].try_into().expect("length checked")),
        max_event_bytes: u64::from_le_bytes(bytes[24..32].try_into().expect("length checked")),
    }
    .validate()
}

fn encode_reservation(reservation: &LocalReservation) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(77);
    bytes.extend_from_slice(&RESERVATION_MAGIC);
    bytes.extend_from_slice(&reservation.operation_id);
    bytes.extend_from_slice(&serialize(&reservation.outpoint));
    bytes.push(reservation.phase.to_byte());
    bytes
}

fn decode_reservation(bytes: &[u8]) -> Result<LocalReservation, Error> {
    if bytes.len() != 77 || bytes[..8] != RESERVATION_MAGIC {
        return Err(protocol_error("invalid local reservation encoding"));
    }
    let outpoint = deserialize(&bytes[40..76])
        .map_err(|error| protocol_error(format!("local reservation outpoint: {error}")))?;
    let reservation = LocalReservation {
        operation_id: bytes[8..40].try_into().expect("length checked"),
        outpoint,
        phase: ReservationPhase::from_byte(bytes[76]).map_err(batch_error)?,
    };
    if encode_reservation(&reservation) != bytes {
        return Err(protocol_error("non-canonical local reservation encoding"));
    }
    Ok(reservation)
}

type RebuiltSessionIndex = (Vec<ParticipantCommitment>, HashSet<[u8; 33]>, u64);

fn rebuild_session_index(
    root: &Path,
    relay_policy: RelayPolicy,
) -> Result<RebuiltSessionIndex, Error> {
    let proposal_path = root.join("proposal.bin");
    let proposal = if proposal_path.exists() {
        Some(
            Proposal::from_wire(&read_limited(&proposal_path, MAX_PAYLOAD_BYTES)?)
                .map_err(batch_error)?,
        )
    } else {
        None
    };
    let commitment_paths = read_paths_with_extension(&root.join("commitments"), "bin")?;
    let mut commitments = Vec::with_capacity(commitment_paths.len());
    for path in commitment_paths {
        let proposal = proposal
            .as_ref()
            .ok_or_else(|| protocol_error("stored commitment has no proposal"))?;
        let commitment =
            ParticipantCommitment::from_wire(proposal, &read_limited(&path, MAX_PAYLOAD_BYTES)?)
                .map_err(batch_error)?;
        if commitments.iter().any(|existing: &ParticipantCommitment| {
            existing.fee_pubkey() == commitment.fee_pubkey()
                || existing.fee_outpoint() == commitment.fee_outpoint()
                || existing.operation_id() == commitment.operation_id()
                || existing.payload() == commitment.payload()
        }) {
            return Err(protocol_error(
                "stored commitment pool violates authorized identity quotas",
            ));
        }
        commitments.push(commitment);
    }
    let participant_cap = proposal
        .as_ref()
        .map(Proposal::participant_count)
        .unwrap_or(0);
    let policy_cap = usize::try_from(relay_policy.max_commitments).expect("u32 fits usize");
    if commitments.len() > participant_cap.min(policy_cap) {
        return Err(protocol_error("stored commitment pool exceeds local quota"));
    }

    let mut stored_frame_bytes = 0u64;
    let mut commitment_senders = HashSet::new();
    let mut authorized_commitments = HashSet::new();
    let frame_paths = read_paths_with_extension(&root.join("frames"), "frame")?;
    for path in frame_paths {
        let length = fs::metadata(&path).map_err(io_err(&path))?.len();
        stored_frame_bytes = stored_frame_bytes
            .checked_add(length)
            .ok_or_else(|| protocol_error("stored frame-byte counter overflow"))?;
        if stored_frame_bytes > relay_policy.max_session_bytes {
            return Err(protocol_error("stored frames exceed local byte quota"));
        }
        let frame = SignedFrame::from_wire(&read_limited(&path, MAX_FRAME_BYTES)?)?;
        match frame.kind {
            MessageKind::Proposal => {
                let proposal = Proposal::from_wire(&frame.payload).map_err(batch_error)?;
                verify_origin_signature(&frame, proposal.stock_owner_pubkey())?;
            }
            MessageKind::Commitment => {
                let proposal = proposal
                    .as_ref()
                    .ok_or_else(|| protocol_error("commitment frame has no proposal"))?;
                let commitment = ParticipantCommitment::from_wire(proposal, &frame.payload)
                    .map_err(batch_error)?;
                verify_origin_signature(&frame, commitment.fee_pubkey())?;
                if !commitment_senders.insert(frame.sender.serialize()) {
                    return Err(protocol_error(
                        "stored relay identity authorized multiple commitments",
                    ));
                }
                authorized_commitments.insert(commitment.commitment_id());
            }
            MessageKind::Manifest | MessageKind::Signature => {
                if frame.origin_signature.is_some() {
                    return Err(protocol_error(
                        "stored manifest/signature has unexpected origin authorization",
                    ));
                }
            }
        }
    }
    if commitments
        .iter()
        .any(|commitment| !authorized_commitments.contains(&commitment.commitment_id()))
    {
        return Err(protocol_error(
            "stored commitment lacks its authorized relay frame",
        ));
    }
    Ok((commitments, commitment_senders, stored_frame_bytes))
}

fn load_or_create_identity(path: &Path) -> Result<SecretKey, Error> {
    if path.exists() {
        return load_identity(path);
    }
    let secret = loop {
        let candidate: [u8; 32] = rand::rng().random();
        if let Ok(secret) = SecretKey::from_slice(&candidate) {
            break secret;
        }
    };
    atomic_write(path, &secret.secret_bytes())?;
    Ok(secret)
}

fn load_identity(path: &Path) -> Result<SecretKey, Error> {
    require_private_file(path)?;
    let bytes = read_limited(path, 32)?;
    if bytes.len() != 32 {
        return Err(protocol_error("relay identity is not 32 bytes"));
    }
    SecretKey::from_slice(&bytes)
        .map_err(|error| protocol_error(format!("relay identity: {error}")))
}

fn semantic_write(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    if path.exists() {
        let existing = read_limited(path, MAX_PAYLOAD_BYTES)?;
        if existing == bytes {
            return Ok(());
        }
        return Err(protocol_error(format!(
            "semantic equivocation at {}",
            path.display()
        )));
    }
    atomic_write(path, bytes)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    let parent = path
        .parent()
        .ok_or_else(|| protocol_error("path has no parent"))?;
    fs::create_dir_all(parent).map_err(io_err(parent))?;
    let suffix: u64 = rand::rng().random();
    let temp = parent.join(format!(".opencsv-{suffix:016x}.tmp"));
    let result = (|| {
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temp).map_err(io_err(&temp))?;
        file.write_all(bytes).map_err(io_err(&temp))?;
        file.sync_all().map_err(io_err(&temp))?;
        fs::rename(&temp, path).map_err(io_err(path))?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(io_err(parent))
    })();
    if result.is_err() && temp.exists() {
        let _ = fs::remove_file(&temp);
    }
    result
}

fn set_private_directory(path: &Path) -> Result<(), Error> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(io_err(path))?;
    }
    Ok(())
}

fn require_private_directory(path: &Path) -> Result<(), Error> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(path)
            .map_err(io_err(path))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            return Err(protocol_error(format!(
                "session directory {} must not be group/world accessible",
                path.display()
            )));
        }
    }
    Ok(())
}

fn require_private_file(path: &Path) -> Result<(), Error> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(path)
            .map_err(io_err(path))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            return Err(protocol_error(format!(
                "relay identity {} must be mode 0600 or stricter",
                path.display()
            )));
        }
    }
    Ok(())
}

fn read_limited(path: &Path, limit: usize) -> Result<Vec<u8>, Error> {
    let file = File::open(path).map_err(io_err(path))?;
    let mut bytes = Vec::with_capacity(limit.min(64 * 1024));
    file.take((limit as u64).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(io_err(path))?;
    if bytes.len() > limit {
        return Err(protocol_error(format!(
            "{} exceeds size policy",
            path.display()
        )));
    }
    Ok(bytes)
}

fn read_sorted(directory: &Path) -> Result<Vec<PathBuf>, Error> {
    read_paths_with_extension(directory, "bin")
}

fn read_paths_with_extension(directory: &Path, extension: &str) -> Result<Vec<PathBuf>, Error> {
    if !directory.exists() {
        return Ok(Vec::new());
    }
    let mut paths = fs::read_dir(directory)
        .map_err(io_err(directory))?
        .map(|entry| entry.map(|entry| entry.path()).map_err(io_err(directory)))
        .collect::<Result<Vec<_>, _>>()?;
    paths.retain(|path| path.extension().and_then(|value| value.to_str()) == Some(extension));
    paths.sort();
    Ok(paths)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn parse_hex_32(value: &str) -> Result<[u8; 32], Error> {
    if value.len() != 64 {
        return Err(protocol_error("32-byte hex value has wrong length"));
    }
    let mut output = [0u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(chunk)
            .map_err(|error| protocol_error(format!("hex utf8: {error}")))?;
        output[index] =
            u8::from_str_radix(text, 16).map_err(|_| protocol_error("invalid hex value"))?;
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::Hash as _;
    use bitcoin::{OutPoint, Txid};

    use super::*;

    fn secret(seed: u8) -> SecretKey {
        SecretKey::from_slice(&[seed; 32]).unwrap()
    }

    fn proposal(nonce: u8, stock_key: &SecretKey) -> Proposal {
        Proposal::new(
            [9; 32],
            OutPoint::new(Txid::from_byte_array([7; 32]), 1),
            100_000,
            PublicKey::from_secret_key(&Secp256k1::new(), stock_key),
            1,
            [nonce; 32],
            100,
            110,
            2,
            20,
        )
        .unwrap()
    }

    #[test]
    fn cross_batch_origin_replay_and_relay_substitution_fail() {
        let stock_key = secret(3);
        let relay_key = secret(4);
        let first = proposal(8, &stock_key);
        let second = proposal(9, &stock_key);
        let authorized =
            SignedFrame::sign_proposal(first.wire_bytes(), &relay_key, &stock_key).unwrap();

        let payload = second.wire_bytes();
        let origin_signature = authorized.origin_signature;
        let signature = Secp256k1::new().sign_ecdsa(
            &Message::from_digest(frame_digest(
                MessageKind::Proposal,
                authorized.sender,
                &payload,
                origin_signature.as_ref(),
            )),
            &relay_key,
        );
        let replay = SignedFrame {
            kind: MessageKind::Proposal,
            sender: authorized.sender,
            payload,
            origin_signature,
            signature,
        };
        let root = tempfile::tempdir().unwrap();
        let mut session = Session::init(
            root.path(),
            SessionPolicy {
                chain_id: [9; 32],
                current_height: 100,
            },
        )
        .unwrap();
        assert!(session.ingest(&replay.to_wire()).is_err());

        let substituted_key = secret(5);
        let substituted_sender = PublicKey::from_secret_key(&Secp256k1::new(), &substituted_key);
        let signature = Secp256k1::new().sign_ecdsa(
            &Message::from_digest(frame_digest(
                MessageKind::Proposal,
                substituted_sender,
                authorized.payload(),
                authorized.origin_signature.as_ref(),
            )),
            &substituted_key,
        );
        let substituted = SignedFrame {
            kind: MessageKind::Proposal,
            sender: substituted_sender,
            payload: authorized.payload.clone(),
            origin_signature: authorized.origin_signature,
            signature,
        };
        assert!(session.ingest(&substituted.to_wire()).is_err());
        assert!(SignedFrame::sign_proposal(first.wire_bytes(), &relay_key, &secret(6)).is_err());
    }

    #[test]
    fn local_reservations_are_durable_idempotent_and_exclusive() {
        let root = tempfile::tempdir().unwrap();
        let session = Session::init(
            root.path(),
            SessionPolicy {
                chain_id: [9; 32],
                current_height: 100,
            },
        )
        .unwrap();
        let operation = [0x31; 32];
        let reserved = OutPoint::new(Txid::from_byte_array([0x41; 32]), 2);
        let reservation = session.reserve_local_input(operation, reserved).unwrap();
        assert_eq!(
            session.reserve_local_input(operation, reserved).unwrap(),
            reservation
        );
        assert!(session
            .reserve_local_input([0x32; 32], reserved)
            .unwrap_err()
            .to_string()
            .contains("another local operation"));
        assert!(session
            .reserve_local_input(
                operation,
                OutPoint::new(Txid::from_byte_array([0x42; 32]), 3),
            )
            .unwrap_err()
            .to_string()
            .contains("another Bitcoin input"));

        drop(session);
        let reopened = Session::open(root.path()).unwrap();
        assert_eq!(reopened.local_reservation(operation).unwrap(), reservation);
    }
}
