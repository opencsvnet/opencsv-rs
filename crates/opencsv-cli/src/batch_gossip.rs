//! Authenticated, durable, all-peer relay for batching v2.
//!
//! C1 defines the canonical proposal, commitment, manifest, and signature
//! bodies. This module adds only C2 transport and crash semantics: signed
//! bounded frames, content-addressed deduplication, validation before relay,
//! an append-only event receipt, deterministic session reconstruction, and
//! persistence of the fully signed transaction before broadcast.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1, SecretKey};
use bitcoin::Transaction;
use opencsv_bitcoin::batch_v2::{Manifest, ParticipantCommitment, Proposal, SignatureShare};
use rand::RngExt;
use sha2::{Digest, Sha256};

use crate::error::{io_err, Error};

const FRAME_MAGIC: [u8; 8] = *b"OCSVG2\0\0";
const POLICY_MAGIC: [u8; 8] = *b"OCSVP2\0\0";
const FRAME_VERSION: u16 = 2;
const MAX_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;
const MAX_FRAME_BYTES: usize = MAX_PAYLOAD_BYTES + 128;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

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
    signature: Signature,
}

impl SignedFrame {
    /// Sign a typed canonical body with a relay identity.
    pub fn sign(kind: MessageKind, payload: Vec<u8>, identity: &SecretKey) -> Result<Self, Error> {
        if payload.len() > MAX_PAYLOAD_BYTES {
            return Err(protocol_error("gossip payload exceeds 4 MiB"));
        }
        let secp = Secp256k1::new();
        let sender = PublicKey::from_secret_key(&secp, identity);
        let digest = frame_digest(kind, sender, &payload);
        let signature = secp.sign_ecdsa(&Message::from_digest(digest), identity);
        Ok(Self {
            kind,
            sender,
            payload,
            signature,
        })
    }

    /// Parse, canonicalize, and authenticate a frame.
    pub fn from_wire(wire: &[u8]) -> Result<Self, Error> {
        if wire.len() > MAX_FRAME_BYTES || wire.len() < 58 {
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
        let signature_len_end = payload_end
            .checked_add(2)
            .ok_or_else(|| protocol_error("gossip length overflow"))?;
        if signature_len_end > wire.len() {
            return Err(protocol_error("truncated gossip payload"));
        }
        let signature_len = u16::from_le_bytes(
            wire[payload_end..signature_len_end]
                .try_into()
                .expect("fixed slice"),
        ) as usize;
        if !(8..=72).contains(&signature_len) || signature_len_end + signature_len != wire.len() {
            return Err(protocol_error(
                "invalid gossip signature length/trailing bytes",
            ));
        }
        let signature = Signature::from_der(&wire[signature_len_end..])
            .map_err(|error| protocol_error(format!("relay signature: {error}")))?;
        let mut normalized = signature;
        normalized.normalize_s();
        if normalized != signature {
            return Err(protocol_error("relay signature is not low-S"));
        }
        let payload = wire[48..payload_end].to_vec();
        Secp256k1::verification_only()
            .verify_ecdsa(
                &Message::from_digest(frame_digest(kind, sender, &payload)),
                &signature,
                &sender,
            )
            .map_err(|error| protocol_error(format!("relay authentication: {error}")))?;
        let frame = Self {
            kind,
            sender,
            payload,
            signature,
        };
        if frame.to_wire() != wire {
            return Err(protocol_error("non-canonical gossip frame"));
        }
        Ok(frame)
    }

    /// Canonical frame bytes.
    pub fn to_wire(&self) -> Vec<u8> {
        let signature = self.signature.serialize_der();
        let mut wire = Vec::with_capacity(50 + self.payload.len() + signature.len());
        wire.extend_from_slice(&FRAME_MAGIC);
        wire.extend_from_slice(&FRAME_VERSION.to_le_bytes());
        wire.push(self.kind.to_byte());
        wire.extend_from_slice(&self.sender.serialize());
        wire.extend_from_slice(&(self.payload.len() as u32).to_le_bytes());
        wire.extend_from_slice(&self.payload);
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

/// Durable C2 session. One process owns a session directory at a time; relay
/// threads share it behind a mutex.
pub struct Session {
    root: PathBuf,
    policy: SessionPolicy,
    identity: SecretKey,
}

impl Session {
    /// Create a new session or open an existing session with the same chain
    /// policy. Identity material is generated once and stored mode 0600.
    pub fn init(root: impl AsRef<Path>, policy: SessionPolicy) -> Result<Self, Error> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root).map_err(io_err(&root))?;
        set_private_directory(&root)?;
        for name in ["frames", "commitments", "manifests", "signatures", "signed"] {
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
        let identity = load_or_create_identity(&root.join("identity.key"))?;
        Ok(Self {
            root,
            policy,
            identity,
        })
    }

    /// Open an initialized session.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, Error> {
        let root = root.as_ref().to_path_buf();
        require_private_directory(&root)?;
        let policy_path = root.join("policy.bin");
        let policy = decode_policy(&read_limited(&policy_path, 64)?)?;
        let identity = load_identity(&root.join("identity.key"))?;
        Ok(Self {
            root,
            policy,
            identity,
        })
    }

    /// Relay identity public key.
    pub fn identity_pubkey(&self) -> PublicKey {
        PublicKey::from_secret_key(&Secp256k1::new(), &self.identity)
    }

    /// Sign, durably ingest, and return a typed frame for peer publication.
    pub fn publish(&mut self, kind: MessageKind, payload: Vec<u8>) -> Result<Vec<u8>, Error> {
        let frame = SignedFrame::sign(kind, payload, &self.identity)?;
        let wire = frame.to_wire();
        self.ingest(&wire)?;
        Ok(wire)
    }

    /// Authenticate, protocol-validate, and persist one frame before it is
    /// eligible for forwarding.
    pub fn ingest(&mut self, wire: &[u8]) -> Result<IngestOutcome, Error> {
        let frame = SignedFrame::from_wire(wire)?;
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
        self.persist_semantic(&frame)?;
        atomic_write(&frame_path, wire)?;
        self.append_event(format!(
            "accepted {} {} {}",
            frame.kind.name(),
            hex(&frame.id()),
            hex(&frame.sender.serialize())
        ))?;
        Ok(IngestOutcome::Accepted)
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
        let manifest = manifests
            .last()
            .ok_or_else(|| protocol_error("cannot finalize without a manifest"))?;
        let signed_path = self.signed_path(manifest.manifest_id());
        if signed_path.exists() {
            return self.latest_signed_transaction();
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
        self.persist_phase(
            ProtocolPhase::SignedPersisted,
            &hex(&manifest.manifest_id()),
        )?;
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
        let manifest = manifests
            .last()
            .ok_or_else(|| protocol_error("session has no manifest"))?;
        let path = self.signed_path(manifest.manifest_id());
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
                status.signature_shares == 0
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

    fn persist_semantic(&self, frame: &SignedFrame) -> Result<(), Error> {
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
        let Some(proposal) = proposal else {
            return Ok(Vec::new());
        };
        read_sorted(&self.root.join("commitments"))?
            .into_iter()
            .map(|path| {
                ParticipantCommitment::from_wire(proposal, &read_limited(&path, MAX_PAYLOAD_BYTES)?)
                    .map_err(batch_error)
            })
            .collect()
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
    let (mut stream, _remote) = listener
        .accept()
        .map_err(|error| protocol_error(format!("accept: {error}")))?;
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

fn frame_digest(kind: MessageKind, sender: PublicKey, payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"OpenCSV/batch-v2/gossip");
    hasher.update([0]);
    hasher.update(FRAME_MAGIC);
    hasher.update(FRAME_VERSION.to_le_bytes());
    hasher.update([kind.to_byte()]);
    hasher.update(sender.serialize());
    hasher.update((payload.len() as u32).to_le_bytes());
    hasher.update(payload);
    hasher.finalize().into()
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
    let metadata = fs::metadata(path).map_err(io_err(path))?;
    if metadata.len() > limit as u64 {
        return Err(protocol_error(format!(
            "{} exceeds size policy",
            path.display()
        )));
    }
    fs::read(path).map_err(io_err(path))
}

fn read_sorted(directory: &Path) -> Result<Vec<PathBuf>, Error> {
    if !directory.exists() {
        return Ok(Vec::new());
    }
    let mut paths = fs::read_dir(directory)
        .map_err(io_err(directory))?
        .map(|entry| entry.map(|entry| entry.path()).map_err(io_err(directory)))
        .collect::<Result<Vec<_>, _>>()?;
    paths.retain(|path| path.extension().and_then(|value| value.to_str()) == Some("bin"));
    paths.sort();
    Ok(paths)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
