//! Signed, co-funded OpenCSV batching v2.
//!
//! This module implements C1 from the normative repository-root
//! `BATCHING_V2.md`: canonical proposals, participant commitments,
//! manifests, exact fee allocation, signed P2WSH input-0 stock,
//! P2WPKH participant inputs, detached signatures, PSBT material, and
//! fail-closed finalization. Networking and CLI gossip are C2.

use std::collections::HashSet;

use bitcoin::absolute;
use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::hashes::Hash as _;
use bitcoin::opcodes::all::{OP_CHECKSIGVERIFY, OP_DROP};
use bitcoin::opcodes::OP_TRUE;
use bitcoin::psbt::{Psbt, PsbtSighashType};
use bitcoin::script::{Builder, PushBytesBuf};
use bitcoin::secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use bitcoin::sighash::SighashCache;
use bitcoin::transaction;
use bitcoin::{
    Address, Amount, CompressedPublicKey, EcdsaSighashType, Network as BitcoinNetwork, OutPoint,
    ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use opencsv_core::{envelope_v2_encode, AnchorRecord, TruncatedDigest, MAX_BATCH_V2_PARTICIPANTS};
use sha2::{Digest as _, Sha256};

use crate::{funding_ctx, MARKER_DUST_SATS, MARKER_SPK};

/// Batching-v2 transcript version.
pub const VERSION: u16 = 2;
/// First eight bytes of every batching-v2 transcript message.
pub const MESSAGE_MAGIC: [u8; 8] = *b"OCSVB2\0\0";
/// Initial/RBF transaction version.
pub const TX_VERSION: transaction::Version = transaction::Version::TWO;
/// Every v2 input opts into replacement without a relative lock.
pub const INPUT_SEQUENCE: Sequence = Sequence::ENABLE_RBF_NO_LOCKTIME;
/// Conservative reusable-stock and participant-change floor.
pub const MIN_OUTPUT_SATS: u64 = 546;

const PROPOSAL_KIND: u8 = 0x01;
const COMMITMENT_KIND: u8 = 0x02;
const MANIFEST_KIND: u8 = 0x03;
const SIGNATURE_KIND: u8 = 0x04;

/// Stable machine-readable rejection categories frozen by C0.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejectionReason {
    /// Unsupported protocol version.
    InvalidVersion,
    /// Transcript belongs to another Bitcoin network.
    WrongChain,
    /// Bytes are malformed or non-canonical.
    InvalidSerialization,
    /// Input-0 stock does not match the signed-stock contract.
    InvalidStock,
    /// Chain data is stale or inconsistent.
    StaleChainState,
    /// Proposal has passed its expiry height.
    ExpiredProposal,
    /// Participant commitment is invalid.
    InvalidCommitment,
    /// A manifest repeats a commitment, operation, input, payload, or change.
    DuplicateCommitment,
    /// An operation or reserved input conflicts with another operation.
    ConflictingOperation,
    /// A required participant fee input is unavailable.
    UnavailableFeeInput,
    /// Participant inputs are not in canonical outpoint order.
    NoncanonicalOrder,
    /// A payload is not bound to input 0's context.
    PayloadContextMismatch,
    /// Header and witness payload commitment differ.
    HeaderMismatch,
    /// Inputs, outputs, values, scripts, or positions violate v2.
    ProtocolLayoutViolation,
    /// Feerate, charge, or maximum-fee policy is violated.
    FeePolicyViolation,
    /// A participant change output would be below the v2 floor.
    InsufficientChange,
    /// Checked integer arithmetic overflowed.
    ArithmeticOverflow,
    /// A non-ALL signature policy was requested or supplied.
    SignaturePolicyViolation,
    /// A Bitcoin signature is missing, wrong-key, or invalid.
    InvalidSignature,
    /// A replacement changes an invariant or is not fee-monotone.
    ReplacementViolation,
    /// Durable state could not be persisted or recovered.
    StorageFailure,
}

/// A protocol rejection with stable category and diagnostic detail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtocolError {
    reason: RejectionReason,
    detail: String,
}

impl ProtocolError {
    fn new(reason: RejectionReason, detail: impl Into<String>) -> Self {
        Self {
            reason,
            detail: detail.into(),
        }
    }

    /// Stable machine-readable rejection category.
    pub fn reason(&self) -> RejectionReason {
        self.reason
    }
}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.reason, self.detail)
    }
}

impl std::error::Error for ProtocolError {}

/// Persistable fee-input reservation phase for abort/withholding safety.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReservationPhase {
    /// Commitment sent, but no Bitcoin signature has left the wallet.
    CommittedUnsigned,
    /// A signature may be held by another peer; timeout cannot unlock.
    SignatureReleased,
    /// The batch/replacement met the wallet's confirmation policy.
    Confirmed,
    /// Another confirmed spend permanently invalidated the batch.
    InvalidatedOnChain,
    /// Unsigned operation was aborted and its reservation released.
    ReleasedBeforeSignature,
}

impl ReservationPhase {
    /// Stable one-byte journal encoding.
    pub fn to_byte(self) -> u8 {
        match self {
            Self::CommittedUnsigned => 0,
            Self::SignatureReleased => 1,
            Self::Confirmed => 2,
            Self::InvalidatedOnChain => 3,
            Self::ReleasedBeforeSignature => 4,
        }
    }

    /// Decode the stable journal byte, rejecting unknown future states.
    pub fn from_byte(byte: u8) -> Result<Self, ProtocolError> {
        match byte {
            0 => Ok(Self::CommittedUnsigned),
            1 => Ok(Self::SignatureReleased),
            2 => Ok(Self::Confirmed),
            3 => Ok(Self::InvalidatedOnChain),
            4 => Ok(Self::ReleasedBeforeSignature),
            _ => Err(ProtocolError::new(
                RejectionReason::InvalidSerialization,
                format!("unknown reservation phase {byte}"),
            )),
        }
    }

    /// Record that a signature was released to another peer.
    pub fn signature_released(self) -> Result<Self, ProtocolError> {
        match self {
            Self::CommittedUnsigned | Self::SignatureReleased => Ok(Self::SignatureReleased),
            _ => Err(ProtocolError::new(
                RejectionReason::ConflictingOperation,
                "cannot release a signature from a terminal reservation",
            )),
        }
    }

    /// Apply a timeout abort. This is legal only before any signature release.
    pub fn timeout_abort(self) -> Result<Self, ProtocolError> {
        match self {
            Self::CommittedUnsigned => Ok(Self::ReleasedBeforeSignature),
            Self::SignatureReleased => Err(ProtocolError::new(
                RejectionReason::ConflictingOperation,
                "timeout cannot unlock an input after signature release",
            )),
            state => Ok(state),
        }
    }

    /// Record a confirmation-policy-complete batch or replacement.
    pub fn confirmed(self) -> Self {
        Self::Confirmed
    }

    /// Record a confirmation-policy-complete conflicting cancellation.
    pub fn invalidated_on_chain(self) -> Self {
        Self::InvalidatedOnChain
    }

    /// Whether wallet policy may release/retire the fee-input reservation.
    pub fn is_releasable(self) -> bool {
        matches!(
            self,
            Self::Confirmed | Self::InvalidatedOnChain | Self::ReleasedBeforeSignature
        )
    }
}

/// A validated proposal fixing input 0, network, membership count, and fee bounds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proposal {
    chain_id: [u8; 32],
    stock_outpoint: OutPoint,
    stock_value: u64,
    stock_owner_pubkey: PublicKey,
    participant_count: u8,
    proposal_nonce: [u8; 32],
    observed_tip_height: u32,
    expiry_height: u32,
    target_feerate_sat_vb: u32,
    max_feerate_sat_vb: u32,
}

impl Proposal {
    /// Construct and validate a batching-v2 proposal.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id: [u8; 32],
        stock_outpoint: OutPoint,
        stock_value: u64,
        stock_owner_pubkey: PublicKey,
        participant_count: u8,
        proposal_nonce: [u8; 32],
        observed_tip_height: u32,
        expiry_height: u32,
        target_feerate_sat_vb: u32,
        max_feerate_sat_vb: u32,
    ) -> Result<Self, ProtocolError> {
        let proposal = Self {
            chain_id,
            stock_outpoint,
            stock_value,
            stock_owner_pubkey,
            participant_count,
            proposal_nonce,
            observed_tip_height,
            expiry_height,
            target_feerate_sat_vb,
            max_feerate_sat_vb,
        };
        proposal.validate()?;
        Ok(proposal)
    }

    /// Domain-separated proposal identifier.
    pub fn batch_id(&self) -> [u8; 32] {
        domain_hash("OpenCSV/batch-v2/proposal", &self.body())
    }

    /// Complete canonical proposal wire message.
    pub fn wire_bytes(&self) -> Vec<u8> {
        wire_message(PROPOSAL_KIND, &self.body())
    }

    /// Parse a canonical proposal wire message and reject ambiguity/trailing bytes.
    pub fn from_wire(wire: &[u8]) -> Result<Self, ProtocolError> {
        let body = wire_body(wire, PROPOSAL_KIND)?;
        let mut reader = Reader::new(body);
        let version = reader.u16()?;
        if version != VERSION {
            return Err(ProtocolError::new(
                RejectionReason::InvalidVersion,
                format!("proposal version {version}"),
            ));
        }
        let chain_id = reader.array()?;
        let stock_outpoint = reader.outpoint()?;
        let stock_value = reader.u64()?;
        let stock_owner_pubkey = reader.public_key()?;
        let participant_count = reader.u8()?;
        let proposal_nonce = reader.array()?;
        let observed_tip_height = reader.u32()?;
        let expiry_height = reader.u32()?;
        let target_feerate_sat_vb = reader.u32()?;
        let max_feerate_sat_vb = reader.u32()?;
        reader.finish()?;
        let proposal = Self::new(
            chain_id,
            stock_outpoint,
            stock_value,
            stock_owner_pubkey,
            participant_count,
            proposal_nonce,
            observed_tip_height,
            expiry_height,
            target_feerate_sat_vb,
            max_feerate_sat_vb,
        )?;
        require_canonical_wire(wire, &proposal.wire_bytes())?;
        Ok(proposal)
    }

    /// Input-0 OpenCSV context.
    pub fn context(&self) -> [u8; 32] {
        funding_ctx(
            &self.stock_outpoint.txid.to_byte_array(),
            self.stock_outpoint.vout,
        )
    }

    /// Count-specific signed stock witness script.
    pub fn stock_witness_script(&self) -> ScriptBuf {
        stock_witness_script(self.stock_owner_pubkey, self.participant_count as usize)
    }

    /// Count-specific native P2WSH stock scriptPubKey.
    pub fn stock_script_pubkey(&self) -> ScriptBuf {
        self.stock_witness_script().to_p2wsh()
    }

    /// Number of participant payload/input/change triplets.
    pub fn participant_count(&self) -> usize {
        self.participant_count as usize
    }

    /// Compressed public key controlling the signed input-0 stock.
    pub fn stock_owner_pubkey(&self) -> PublicKey {
        self.stock_owner_pubkey
    }

    /// Validate network replay and expiry against independently observed chain state.
    pub fn validate_at(
        &self,
        expected_chain_id: [u8; 32],
        current_height: u32,
    ) -> Result<(), ProtocolError> {
        self.validate()?;
        if self.chain_id != expected_chain_id {
            return Err(ProtocolError::new(
                RejectionReason::WrongChain,
                "proposal chain id differs from the verified chain",
            ));
        }
        if current_height >= self.expiry_height {
            return Err(ProtocolError::new(
                RejectionReason::ExpiredProposal,
                "proposal expired at the verified height",
            ));
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), ProtocolError> {
        let count = self.participant_count as usize;
        if !(1..=MAX_BATCH_V2_PARTICIPANTS).contains(&count) {
            return Err(ProtocolError::new(
                RejectionReason::InvalidStock,
                format!("participant count {count} is outside 1..=64"),
            ));
        }
        if self.chain_id == [0u8; 32] {
            return Err(ProtocolError::new(
                RejectionReason::WrongChain,
                "zero chain id",
            ));
        }
        if self.stock_outpoint.is_null() || self.stock_value < MIN_OUTPUT_SATS {
            return Err(ProtocolError::new(
                RejectionReason::InvalidStock,
                "null outpoint or sub-floor stock value",
            ));
        }
        if self.expiry_height <= self.observed_tip_height {
            return Err(ProtocolError::new(
                RejectionReason::ExpiredProposal,
                "expiry must be above observed tip",
            ));
        }
        if self.target_feerate_sat_vb == 0 || self.max_feerate_sat_vb < self.target_feerate_sat_vb {
            return Err(ProtocolError::new(
                RejectionReason::FeePolicyViolation,
                "invalid target/max feerate",
            ));
        }
        Ok(())
    }

    fn body(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(164);
        out.extend_from_slice(&VERSION.to_le_bytes());
        out.extend_from_slice(&self.chain_id);
        out.extend_from_slice(&serialize(&self.stock_outpoint));
        out.extend_from_slice(&self.stock_value.to_le_bytes());
        out.extend_from_slice(&self.stock_owner_pubkey.serialize());
        out.push(self.participant_count);
        out.extend_from_slice(&self.proposal_nonce);
        out.extend_from_slice(&self.observed_tip_height.to_le_bytes());
        out.extend_from_slice(&self.expiry_height.to_le_bytes());
        out.extend_from_slice(&self.target_feerate_sat_vb.to_le_bytes());
        out.extend_from_slice(&self.max_feerate_sat_vb.to_le_bytes());
        out
    }
}

/// One participant's payload, fee input, change, and maximum-charge commitment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParticipantCommitment {
    batch_id: [u8; 32],
    operation_id: [u8; 32],
    commit_nonce: [u8; 32],
    payload: TruncatedDigest,
    fee_outpoint: OutPoint,
    fee_prevout: TxOut,
    fee_pubkey: PublicKey,
    change_spk: ScriptBuf,
    max_charge: u64,
}

impl ParticipantCommitment {
    /// Construct and validate one participant commitment.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        proposal: &Proposal,
        operation_id: [u8; 32],
        commit_nonce: [u8; 32],
        payload: TruncatedDigest,
        fee_outpoint: OutPoint,
        fee_prevout: TxOut,
        fee_pubkey: PublicKey,
        change_spk: ScriptBuf,
        max_charge: u64,
    ) -> Result<Self, ProtocolError> {
        let commitment = Self {
            batch_id: proposal.batch_id(),
            operation_id,
            commit_nonce,
            payload,
            fee_outpoint,
            fee_prevout,
            fee_pubkey,
            change_spk,
            max_charge,
        };
        commitment.validate(proposal)?;
        Ok(commitment)
    }

    /// Domain-separated participant commitment identifier.
    pub fn commitment_id(&self) -> [u8; 32] {
        domain_hash("OpenCSV/batch-v2/commitment", &self.body())
    }

    /// Complete canonical participant-commitment wire message.
    pub fn wire_bytes(&self) -> Vec<u8> {
        wire_message(COMMITMENT_KIND, &self.body())
    }

    /// Parse one canonical participant commitment for `proposal`.
    pub fn from_wire(proposal: &Proposal, wire: &[u8]) -> Result<Self, ProtocolError> {
        let body = wire_body(wire, COMMITMENT_KIND)?;
        let mut reader = Reader::new(body);
        let batch_id = reader.array()?;
        let operation_id = reader.array()?;
        let commit_nonce = reader.array()?;
        let payload = TruncatedDigest(reader.array()?);
        let fee_outpoint = reader.outpoint()?;
        let fee_value = reader.u64()?;
        let fee_pubkey = reader.public_key()?;
        let fee_prevout_spk = reader.script()?;
        let change_spk = reader.script()?;
        let max_charge = reader.u64()?;
        reader.finish()?;
        let commitment = Self {
            batch_id,
            operation_id,
            commit_nonce,
            payload,
            fee_outpoint,
            fee_prevout: TxOut {
                value: Amount::from_sat(fee_value),
                script_pubkey: fee_prevout_spk,
            },
            fee_pubkey,
            change_spk,
            max_charge,
        };
        commitment.validate(proposal)?;
        require_canonical_wire(wire, &commitment.wire_bytes())?;
        Ok(commitment)
    }

    /// Participant's context-bound on-chain payload.
    pub fn payload(&self) -> TruncatedDigest {
        self.payload
    }

    /// Participant's reserved fee outpoint.
    pub fn fee_outpoint(&self) -> OutPoint {
        self.fee_outpoint
    }

    fn validate(&self, proposal: &Proposal) -> Result<(), ProtocolError> {
        if self.batch_id != proposal.batch_id()
            || self.fee_outpoint.is_null()
            || self.max_charge == 0
        {
            return Err(ProtocolError::new(
                RejectionReason::InvalidCommitment,
                "batch id, outpoint, or maximum charge is invalid",
            ));
        }
        if self.fee_prevout.script_pubkey != p2wpkh_script(self.fee_pubkey) {
            return Err(ProtocolError::new(
                RejectionReason::InvalidCommitment,
                "fee prevout is not P2WPKH for the committed key",
            ));
        }
        if !is_canonical_p2wpkh(&self.change_spk) {
            return Err(ProtocolError::new(
                RejectionReason::InvalidCommitment,
                "change is not canonical P2WPKH",
            ));
        }
        Ok(())
    }

    fn body(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(230);
        out.extend_from_slice(&self.batch_id);
        out.extend_from_slice(&self.operation_id);
        out.extend_from_slice(&self.commit_nonce);
        out.extend_from_slice(self.payload.as_bytes());
        out.extend_from_slice(&serialize(&self.fee_outpoint));
        out.extend_from_slice(&self.fee_prevout.value.to_sat().to_le_bytes());
        out.extend_from_slice(&self.fee_pubkey.serialize());
        encode_script(&mut out, &self.fee_prevout.script_pubkey);
        encode_script(&mut out, &self.change_spk);
        out.extend_from_slice(&self.max_charge.to_le_bytes());
        out
    }
}

/// Canonical C1 manifest and exact unsigned Bitcoin transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    batch_id: [u8; 32],
    replacement_epoch: u32,
    feerate_sat_vb: u32,
    max_weight: u32,
    miner_fee: u64,
    total_charge: u64,
    charges: Vec<u64>,
    commitments: Vec<ParticipantCommitment>,
    unsigned_tx: Transaction,
}

impl Manifest {
    /// Build the canonical initial manifest, sorting commitments by outpoint.
    pub fn build(
        proposal: &Proposal,
        commitments: Vec<ParticipantCommitment>,
    ) -> Result<Self, ProtocolError> {
        Self::build_at(proposal, commitments, 0, proposal.target_feerate_sat_vb)
    }

    fn build_at(
        proposal: &Proposal,
        mut commitments: Vec<ParticipantCommitment>,
        replacement_epoch: u32,
        feerate_sat_vb: u32,
    ) -> Result<Self, ProtocolError> {
        proposal.validate()?;
        if commitments.len() != proposal.participant_count() {
            return Err(ProtocolError::new(
                RejectionReason::InvalidCommitment,
                "commitment count does not match proposal",
            ));
        }
        if feerate_sat_vb < proposal.target_feerate_sat_vb
            || feerate_sat_vb > proposal.max_feerate_sat_vb
        {
            return Err(ProtocolError::new(
                RejectionReason::FeePolicyViolation,
                "manifest feerate is outside proposal bounds",
            ));
        }
        for commitment in &commitments {
            commitment.validate(proposal)?;
        }
        commitments.sort_by_key(|commitment| serialize(&commitment.fee_outpoint));
        reject_duplicates(&commitments)?;

        let count = commitments.len();
        let max_weight_u64 = max_signed_weight(count)?;
        let max_weight = u32::try_from(max_weight_u64).map_err(|_| {
            ProtocolError::new(RejectionReason::ArithmeticOverflow, "weight exceeds u32")
        })?;
        let max_vbytes = max_weight_u64.div_ceil(4);
        let miner_fee = u64::from(feerate_sat_vb)
            .checked_mul(max_vbytes)
            .ok_or_else(|| {
                ProtocolError::new(RejectionReason::ArithmeticOverflow, "miner fee overflow")
            })?;
        let total_charge = miner_fee.checked_add(MARKER_DUST_SATS).ok_or_else(|| {
            ProtocolError::new(RejectionReason::ArithmeticOverflow, "total charge overflow")
        })?;
        let base = total_charge / count as u64;
        let remainder = total_charge % count as u64;
        let mut charges = Vec::with_capacity(count);
        let mut changes = Vec::with_capacity(count);
        for (index, commitment) in commitments.iter().enumerate() {
            let charge = base + u64::from((index as u64) < remainder);
            if charge > commitment.max_charge {
                return Err(ProtocolError::new(
                    RejectionReason::FeePolicyViolation,
                    format!("participant {index} charge exceeds committed maximum"),
                ));
            }
            let change = commitment
                .fee_prevout
                .value
                .to_sat()
                .checked_sub(charge)
                .ok_or_else(|| {
                    ProtocolError::new(
                        RejectionReason::InsufficientChange,
                        format!("participant {index} cannot cover charge"),
                    )
                })?;
            if change < MIN_OUTPUT_SATS {
                return Err(ProtocolError::new(
                    RejectionReason::InsufficientChange,
                    format!("participant {index} change is below v2 floor"),
                ));
            }
            charges.push(charge);
            changes.push(change);
        }

        let payloads: Vec<_> = commitments.iter().map(|c| c.payload).collect();
        let record = AnchorRecord::batch_header_v2(&payloads, &proposal.context());
        let push = PushBytesBuf::try_from(record.to_bytes().to_vec()).map_err(|error| {
            ProtocolError::new(
                RejectionReason::InvalidSerialization,
                format!("batch header push: {error}"),
            )
        })?;
        let mut inputs = Vec::with_capacity(count + 1);
        inputs.push(TxIn {
            previous_output: proposal.stock_outpoint,
            script_sig: ScriptBuf::new(),
            sequence: INPUT_SEQUENCE,
            witness: Witness::new(),
        });
        inputs.extend(commitments.iter().map(|commitment| TxIn {
            previous_output: commitment.fee_outpoint,
            script_sig: ScriptBuf::new(),
            sequence: INPUT_SEQUENCE,
            witness: Witness::new(),
        }));
        let mut outputs = Vec::with_capacity(count + 3);
        outputs.push(TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::new_op_return(push),
        });
        outputs.push(TxOut {
            value: Amount::from_sat(MARKER_DUST_SATS),
            script_pubkey: ScriptBuf::from_bytes(MARKER_SPK.to_vec()),
        });
        outputs.push(TxOut {
            value: Amount::from_sat(proposal.stock_value),
            script_pubkey: proposal.stock_script_pubkey(),
        });
        outputs.extend(
            commitments
                .iter()
                .zip(changes)
                .map(|(commitment, value)| TxOut {
                    value: Amount::from_sat(value),
                    script_pubkey: commitment.change_spk.clone(),
                }),
        );
        let unsigned_tx = Transaction {
            version: TX_VERSION,
            lock_time: absolute::LockTime::ZERO,
            input: inputs,
            output: outputs,
        };
        let manifest = Self {
            batch_id: proposal.batch_id(),
            replacement_epoch,
            feerate_sat_vb,
            max_weight,
            miner_fee,
            total_charge,
            charges,
            commitments,
            unsigned_tx,
        };
        manifest.check_layout(proposal)?;
        Ok(manifest)
    }

    /// Domain-separated manifest identifier.
    pub fn manifest_id(&self) -> [u8; 32] {
        domain_hash("OpenCSV/batch-v2/manifest", &self.body())
    }

    /// Complete canonical manifest wire message.
    pub fn wire_bytes(&self) -> Vec<u8> {
        wire_message(MANIFEST_KIND, &self.body())
    }

    /// Parse and fully reconstruct a canonical manifest from committed source bodies.
    pub fn from_wire(
        proposal: &Proposal,
        mut commitments: Vec<ParticipantCommitment>,
        wire: &[u8],
    ) -> Result<Self, ProtocolError> {
        let body = wire_body(wire, MANIFEST_KIND)?;
        let mut reader = Reader::new(body);
        let batch_id = reader.array()?;
        let replacement_epoch = reader.u32()?;
        let participant_count = reader.u8()? as usize;
        if participant_count != proposal.participant_count()
            || commitments.len() != participant_count
        {
            return Err(ProtocolError::new(
                RejectionReason::InvalidCommitment,
                "manifest count differs from proposal/source commitments",
            ));
        }
        let mut commitment_ids = Vec::with_capacity(participant_count);
        for _ in 0..participant_count {
            commitment_ids.push(reader.array()?);
        }
        let max_weight = reader.u32()?;
        let feerate_sat_vb = reader.u32()?;
        let miner_fee = reader.u64()?;
        let total_charge = reader.u64()?;
        let mut charges = Vec::with_capacity(participant_count);
        for _ in 0..participant_count {
            charges.push(reader.u64()?);
        }
        let transaction_length = reader.u32()? as usize;
        let transaction_bytes = reader.bytes(transaction_length)?;
        let unsigned_tx: Transaction = deserialize(transaction_bytes).map_err(|error| {
            ProtocolError::new(
                RejectionReason::InvalidSerialization,
                format!("unsigned transaction: {error}"),
            )
        })?;
        if serialize(&unsigned_tx) != transaction_bytes {
            return Err(ProtocolError::new(
                RejectionReason::InvalidSerialization,
                "non-canonical unsigned transaction encoding",
            ));
        }
        reader.finish()?;
        commitments.sort_by_key(|commitment| serialize(&commitment.fee_outpoint));
        reject_duplicates(&commitments)?;
        if commitments
            .iter()
            .map(ParticipantCommitment::commitment_id)
            .ne(commitment_ids)
        {
            return Err(ProtocolError::new(
                RejectionReason::NoncanonicalOrder,
                "manifest commitment IDs do not match canonical outpoint order",
            ));
        }
        let manifest = Self {
            batch_id,
            replacement_epoch,
            feerate_sat_vb,
            max_weight,
            miner_fee,
            total_charge,
            charges,
            commitments,
            unsigned_tx,
        };
        manifest.validate(proposal)?;
        require_canonical_wire(wire, &manifest.wire_bytes())?;
        Ok(manifest)
    }

    /// Parse a manifest by selecting its ordered commitment IDs from an
    /// unordered pool of independently validated commitment bodies.
    /// Extra pool entries are ignored; missing or repeated selected IDs
    /// fail closed.
    pub fn from_wire_pool(
        proposal: &Proposal,
        commitment_pool: &[ParticipantCommitment],
        wire: &[u8],
    ) -> Result<Self, ProtocolError> {
        let body = wire_body(wire, MANIFEST_KIND)?;
        let mut reader = Reader::new(body);
        let batch_id: [u8; 32] = reader.array()?;
        let _replacement_epoch = reader.u32()?;
        let participant_count = reader.u8()? as usize;
        if batch_id != proposal.batch_id() || participant_count != proposal.participant_count() {
            return Err(ProtocolError::new(
                RejectionReason::InvalidCommitment,
                "manifest identity/count differs from proposal",
            ));
        }
        let mut selected = Vec::with_capacity(participant_count);
        let mut seen = HashSet::with_capacity(participant_count);
        for _ in 0..participant_count {
            let commitment_id: [u8; 32] = reader.array()?;
            if !seen.insert(commitment_id) {
                return Err(ProtocolError::new(
                    RejectionReason::DuplicateCommitment,
                    "manifest repeats a commitment id",
                ));
            }
            let commitment = commitment_pool
                .iter()
                .find(|candidate| candidate.commitment_id() == commitment_id)
                .ok_or_else(|| {
                    ProtocolError::new(
                        RejectionReason::InvalidCommitment,
                        "manifest source commitment is unavailable",
                    )
                })?;
            selected.push(commitment.clone());
        }
        Self::from_wire(proposal, selected, wire)
    }

    /// Exact unsigned transaction every signer must reconstruct.
    pub fn unsigned_transaction(&self) -> &Transaction {
        &self.unsigned_tx
    }

    /// Canonically ordered per-participant charges.
    pub fn charges(&self) -> &[u64] {
        &self.charges
    }

    /// Pessimistic signed weight in weight units.
    pub fn max_weight(&self) -> u32 {
        self.max_weight
    }

    /// Exact miner fee in satoshis.
    pub fn miner_fee(&self) -> u64 {
        self.miner_fee
    }

    /// Replacement epoch committed by this manifest.
    pub fn replacement_epoch(&self) -> u32 {
        self.replacement_epoch
    }

    /// Feerate selected for this manifest epoch.
    pub fn feerate_sat_vb(&self) -> u32 {
        self.feerate_sat_vb
    }

    /// Domain-separated IDs of the selected source commitments, in
    /// canonical participant order.
    pub fn commitment_ids(&self) -> Vec<[u8; 32]> {
        self.commitments
            .iter()
            .map(ParticipantCommitment::commitment_id)
            .collect()
    }

    /// Canonically ordered participant signing key at `index`.
    pub fn participant_fee_pubkey(&self, index: usize) -> Option<PublicKey> {
        self.commitments
            .get(index)
            .map(|commitment| commitment.fee_pubkey)
    }

    /// Create PSBT-v0 signer material with every independently verified prevout.
    pub fn psbt(&self, proposal: &Proposal) -> Result<Psbt, ProtocolError> {
        self.validate(proposal)?;
        let mut psbt = Psbt::from_unsigned_tx(self.unsigned_tx.clone()).map_err(|error| {
            ProtocolError::new(
                RejectionReason::InvalidSerialization,
                format!("PSBT: {error}"),
            )
        })?;
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(proposal.stock_value),
            script_pubkey: proposal.stock_script_pubkey(),
        });
        psbt.inputs[0].witness_script = Some(proposal.stock_witness_script());
        psbt.inputs[0].sighash_type = Some(PsbtSighashType::from(EcdsaSighashType::All));
        for (input, commitment) in psbt.inputs[1..].iter_mut().zip(&self.commitments) {
            input.witness_utxo = Some(commitment.fee_prevout.clone());
            input.sighash_type = Some(PsbtSighashType::from(EcdsaSighashType::All));
        }
        Ok(psbt)
    }

    /// Sign input 0 after validating the complete manifest.
    pub fn sign_stock(
        &self,
        proposal: &Proposal,
        secret_key: &SecretKey,
    ) -> Result<bitcoin::ecdsa::Signature, ProtocolError> {
        self.validate(proposal)?;
        require_key(secret_key, proposal.stock_owner_pubkey)?;
        let sighash = SighashCache::new(&self.unsigned_tx)
            .p2wsh_signature_hash(
                0,
                &proposal.stock_witness_script(),
                Amount::from_sat(proposal.stock_value),
                EcdsaSighashType::All,
            )
            .map_err(|error| {
                ProtocolError::new(
                    RejectionReason::SignaturePolicyViolation,
                    format!("stock sighash: {error}"),
                )
            })?;
        Ok(sign_digest(secret_key, sighash.to_byte_array()))
    }

    /// Sign one participant input by canonical participant index.
    pub fn sign_participant(
        &self,
        proposal: &Proposal,
        participant_index: usize,
        secret_key: &SecretKey,
    ) -> Result<bitcoin::ecdsa::Signature, ProtocolError> {
        self.validate(proposal)?;
        let commitment = self.commitments.get(participant_index).ok_or_else(|| {
            ProtocolError::new(
                RejectionReason::InvalidCommitment,
                "participant index out of range",
            )
        })?;
        require_key(secret_key, commitment.fee_pubkey)?;
        let sighash = SighashCache::new(&self.unsigned_tx)
            .p2wpkh_signature_hash(
                participant_index + 1,
                &commitment.fee_prevout.script_pubkey,
                commitment.fee_prevout.value,
                EcdsaSighashType::All,
            )
            .map_err(|error| {
                ProtocolError::new(
                    RejectionReason::SignaturePolicyViolation,
                    format!("participant sighash: {error}"),
                )
            })?;
        Ok(sign_digest(secret_key, sighash.to_byte_array()))
    }

    /// Verify all signatures and construct the complete standard witness transaction.
    pub fn finalize(
        &self,
        proposal: &Proposal,
        stock_signature: &bitcoin::ecdsa::Signature,
        participant_signatures: &[bitcoin::ecdsa::Signature],
    ) -> Result<Transaction, ProtocolError> {
        self.validate(proposal)?;
        if participant_signatures.len() != self.commitments.len() {
            return Err(ProtocolError::new(
                RejectionReason::InvalidSignature,
                "participant signature count mismatch",
            ));
        }
        verify_stock_signature(self, proposal, stock_signature)?;
        for (index, signature) in participant_signatures.iter().enumerate() {
            verify_participant_signature(self, index, signature)?;
        }

        let mut tx = self.unsigned_tx.clone();
        let payloads: Vec<_> = self.commitments.iter().map(|c| c.payload).collect();
        let mut stock_items = envelope_v2_encode(&payloads).expect("validated 1..=64 payloads");
        stock_items.push(stock_signature.serialize().to_vec());
        stock_items.push(proposal.stock_witness_script().into_bytes());
        tx.input[0].witness = Witness::from_slice(&stock_items);
        for ((input, signature), commitment) in tx.input[1..]
            .iter_mut()
            .zip(participant_signatures)
            .zip(&self.commitments)
        {
            input.witness = Witness::p2wpkh(signature, &commitment.fee_pubkey);
        }
        if tx.weight().to_wu() > u64::from(self.max_weight) {
            return Err(ProtocolError::new(
                RejectionReason::ProtocolLayoutViolation,
                "signed transaction exceeds pessimistic weight",
            ));
        }
        Ok(tx)
    }

    /// Verify one detached share against its manifest ID, exact input
    /// index, expected signing key, and `SIGHASH_ALL` digest.
    pub fn verify_signature_share(
        &self,
        proposal: &Proposal,
        share: &SignatureShare,
    ) -> Result<(), ProtocolError> {
        self.validate(proposal)?;
        if share.manifest_id != self.manifest_id() {
            return Err(ProtocolError::new(
                RejectionReason::InvalidSignature,
                "signature share names another manifest",
            ));
        }
        let input_index = usize::from(share.input_index);
        if input_index == 0 {
            if share.signer_pubkey != proposal.stock_owner_pubkey {
                return Err(ProtocolError::new(
                    RejectionReason::InvalidSignature,
                    "input 0 share is not from the stock owner",
                ));
            }
            return verify_stock_signature(self, proposal, &share.signature);
        }
        let participant_index = input_index - 1;
        let commitment = self.commitments.get(participant_index).ok_or_else(|| {
            ProtocolError::new(
                RejectionReason::InvalidSignature,
                "signature share input index is outside the manifest",
            )
        })?;
        if share.signer_pubkey != commitment.fee_pubkey {
            return Err(ProtocolError::new(
                RejectionReason::InvalidSignature,
                "participant share key does not match the ordered input",
            ));
        }
        verify_participant_signature(self, participant_index, &share.signature)
    }

    /// Verify, deduplicate, order, and finalize a complete all-peer share
    /// set. Exact duplicate shares are idempotent; conflicting shares for
    /// one input are rejected.
    pub fn finalize_shares(
        &self,
        proposal: &Proposal,
        shares: &[SignatureShare],
    ) -> Result<Transaction, ProtocolError> {
        let mut ordered = vec![None; self.commitments.len() + 1];
        for share in shares {
            self.verify_signature_share(proposal, share)?;
            let index = usize::from(share.input_index);
            match ordered[index] {
                Some(existing) if existing == share.signature => {}
                Some(_) => {
                    return Err(ProtocolError::new(
                        RejectionReason::ConflictingOperation,
                        "conflicting signature shares for one input",
                    ));
                }
                None => ordered[index] = Some(share.signature),
            }
        }
        let mut signatures = ordered.into_iter();
        let stock = signatures.next().flatten().ok_or_else(|| {
            ProtocolError::new(
                RejectionReason::InvalidSignature,
                "stock signature share is missing",
            )
        })?;
        let participants: Vec<_> = signatures
            .map(|signature| {
                signature.ok_or_else(|| {
                    ProtocolError::new(
                        RejectionReason::InvalidSignature,
                        "participant signature share is missing",
                    )
                })
            })
            .collect::<Result<_, _>>()?;
        self.finalize(proposal, &stock, &participants)
    }

    /// Build the next unanimous, invariant-preserving replacement epoch.
    pub fn replacement(
        &self,
        proposal: &Proposal,
        new_feerate_sat_vb: u32,
    ) -> Result<Self, ProtocolError> {
        if new_feerate_sat_vb <= self.feerate_sat_vb {
            return Err(ProtocolError::new(
                RejectionReason::ReplacementViolation,
                "replacement feerate must increase",
            ));
        }
        let replacement = Self::build_at(
            proposal,
            self.commitments.clone(),
            self.replacement_epoch.checked_add(1).ok_or_else(|| {
                ProtocolError::new(
                    RejectionReason::ArithmeticOverflow,
                    "replacement epoch overflow",
                )
            })?,
            new_feerate_sat_vb,
        )?;
        if self.unsigned_tx.input != replacement.unsigned_tx.input
            || self.unsigned_tx.output[..3] != replacement.unsigned_tx.output[..3]
            || self
                .unsigned_tx
                .output
                .iter()
                .skip(3)
                .map(|output| &output.script_pubkey)
                .ne(replacement
                    .unsigned_tx
                    .output
                    .iter()
                    .skip(3)
                    .map(|output| &output.script_pubkey))
        {
            return Err(ProtocolError::new(
                RejectionReason::ReplacementViolation,
                "replacement changed a protected invariant",
            ));
        }
        Ok(replacement)
    }

    /// Recompute the canonical manifest and reject any mutation.
    pub fn validate(&self, proposal: &Proposal) -> Result<(), ProtocolError> {
        let expected = Self::build_at(
            proposal,
            self.commitments.clone(),
            self.replacement_epoch,
            self.feerate_sat_vb,
        )?;
        if self != &expected {
            return Err(ProtocolError::new(
                RejectionReason::ProtocolLayoutViolation,
                "manifest differs from canonical reconstruction",
            ));
        }
        Ok(())
    }

    fn check_layout(&self, proposal: &Proposal) -> Result<(), ProtocolError> {
        if self.batch_id != proposal.batch_id()
            || self.unsigned_tx.version != TX_VERSION
            || self.unsigned_tx.lock_time != absolute::LockTime::ZERO
            || self.unsigned_tx.input.len() != self.commitments.len() + 1
            || self.unsigned_tx.output.len() != self.commitments.len() + 3
            || self
                .unsigned_tx
                .input
                .iter()
                .any(|input| input.sequence != INPUT_SEQUENCE || !input.script_sig.is_empty())
        {
            return Err(ProtocolError::new(
                RejectionReason::ProtocolLayoutViolation,
                "transaction framing is not canonical v2",
            ));
        }
        Ok(())
    }

    fn body(&self) -> Vec<u8> {
        let tx = serialize(&self.unsigned_tx);
        let mut out = Vec::new();
        out.extend_from_slice(&self.batch_id);
        out.extend_from_slice(&self.replacement_epoch.to_le_bytes());
        out.push(self.commitments.len() as u8);
        for commitment in &self.commitments {
            out.extend_from_slice(&commitment.commitment_id());
        }
        out.extend_from_slice(&self.max_weight.to_le_bytes());
        out.extend_from_slice(&self.feerate_sat_vb.to_le_bytes());
        out.extend_from_slice(&self.miner_fee.to_le_bytes());
        out.extend_from_slice(&self.total_charge.to_le_bytes());
        for charge in &self.charges {
            out.extend_from_slice(&charge.to_le_bytes());
        }
        out.extend_from_slice(&(tx.len() as u32).to_le_bytes());
        out.extend_from_slice(&tx);
        out
    }
}

/// A canonical P2WPKH script for a compressed secp256k1 public key.
pub fn p2wpkh_script(public_key: PublicKey) -> ScriptBuf {
    Address::p2wpkh(&CompressedPublicKey(public_key), BitcoinNetwork::Bitcoin).script_pubkey()
}

/// The exact count-specific signed input-0 witness script.
pub fn stock_witness_script(public_key: PublicKey, participant_count: usize) -> ScriptBuf {
    let mut builder = Builder::new()
        .push_key(&bitcoin::PublicKey::new(public_key))
        .push_opcode(OP_CHECKSIGVERIFY);
    for _ in 0..=participant_count {
        builder = builder.push_opcode(OP_DROP);
    }
    builder.push_opcode(OP_TRUE).into_script()
}

/// Frozen pessimistic signed weight `968 + 423*N` in weight units.
pub fn max_signed_weight(participant_count: usize) -> Result<u64, ProtocolError> {
    if !(1..=MAX_BATCH_V2_PARTICIPANTS).contains(&participant_count) {
        return Err(ProtocolError::new(
            RejectionReason::InvalidCommitment,
            "participant count outside 1..=64",
        ));
    }
    423u64
        .checked_mul(participant_count as u64)
        .and_then(|value| value.checked_add(968))
        .ok_or_else(|| ProtocolError::new(RejectionReason::ArithmeticOverflow, "weight overflow"))
}

fn reject_duplicates(commitments: &[ParticipantCommitment]) -> Result<(), ProtocolError> {
    let mut ids = HashSet::new();
    let mut operations = HashSet::new();
    let mut outpoints = HashSet::new();
    let mut payloads = HashSet::new();
    let mut changes = HashSet::new();
    for commitment in commitments {
        if !ids.insert(commitment.commitment_id())
            || !operations.insert(commitment.operation_id)
            || !outpoints.insert(commitment.fee_outpoint)
            || !payloads.insert(commitment.payload)
            || !changes.insert(commitment.change_spk.clone())
        {
            return Err(ProtocolError::new(
                RejectionReason::DuplicateCommitment,
                "duplicate participant material",
            ));
        }
    }
    Ok(())
}

fn verify_stock_signature(
    manifest: &Manifest,
    proposal: &Proposal,
    signature: &bitcoin::ecdsa::Signature,
) -> Result<(), ProtocolError> {
    require_all(signature)?;
    let sighash = SighashCache::new(&manifest.unsigned_tx)
        .p2wsh_signature_hash(
            0,
            &proposal.stock_witness_script(),
            Amount::from_sat(proposal.stock_value),
            EcdsaSighashType::All,
        )
        .map_err(|error| {
            ProtocolError::new(
                RejectionReason::InvalidSignature,
                format!("stock sighash: {error}"),
            )
        })?;
    verify_digest(
        signature,
        proposal.stock_owner_pubkey,
        sighash.to_byte_array(),
    )
}

fn verify_participant_signature(
    manifest: &Manifest,
    index: usize,
    signature: &bitcoin::ecdsa::Signature,
) -> Result<(), ProtocolError> {
    require_all(signature)?;
    let commitment = &manifest.commitments[index];
    let sighash = SighashCache::new(&manifest.unsigned_tx)
        .p2wpkh_signature_hash(
            index + 1,
            &commitment.fee_prevout.script_pubkey,
            commitment.fee_prevout.value,
            EcdsaSighashType::All,
        )
        .map_err(|error| {
            ProtocolError::new(
                RejectionReason::InvalidSignature,
                format!("participant sighash: {error}"),
            )
        })?;
    verify_digest(signature, commitment.fee_pubkey, sighash.to_byte_array())
}

fn require_key(secret_key: &SecretKey, expected: PublicKey) -> Result<(), ProtocolError> {
    let actual = PublicKey::from_secret_key(&Secp256k1::new(), secret_key);
    if actual != expected {
        return Err(ProtocolError::new(
            RejectionReason::InvalidSignature,
            "secret key does not control the committed input",
        ));
    }
    Ok(())
}

fn require_all(signature: &bitcoin::ecdsa::Signature) -> Result<(), ProtocolError> {
    if signature.sighash_type != EcdsaSighashType::All {
        return Err(ProtocolError::new(
            RejectionReason::SignaturePolicyViolation,
            "only SIGHASH_ALL is permitted",
        ));
    }
    let mut normalized = signature.signature;
    normalized.normalize_s();
    if normalized != signature.signature {
        return Err(ProtocolError::new(
            RejectionReason::InvalidSignature,
            "only low-S ECDSA signatures are permitted",
        ));
    }
    Ok(())
}

fn sign_digest(secret_key: &SecretKey, digest: [u8; 32]) -> bitcoin::ecdsa::Signature {
    let secp = Secp256k1::signing_only();
    bitcoin::ecdsa::Signature {
        signature: secp.sign_ecdsa(&Message::from_digest(digest), secret_key),
        sighash_type: EcdsaSighashType::All,
    }
}

fn verify_digest(
    signature: &bitcoin::ecdsa::Signature,
    public_key: PublicKey,
    digest: [u8; 32],
) -> Result<(), ProtocolError> {
    Secp256k1::verification_only()
        .verify_ecdsa(
            &Message::from_digest(digest),
            &signature.signature,
            &public_key,
        )
        .map_err(|error| {
            ProtocolError::new(
                RejectionReason::InvalidSignature,
                format!("signature verification: {error}"),
            )
        })
}

fn is_canonical_p2wpkh(script: &ScriptBuf) -> bool {
    let bytes = script.as_bytes();
    bytes.len() == 22 && bytes[0] == 0x00 && bytes[1] == 0x14
}

fn encode_script(out: &mut Vec<u8>, script: &ScriptBuf) {
    let len = u16::try_from(script.len()).expect("C1 scripts are at most 101 bytes");
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(script.as_bytes());
}

fn domain_hash(domain: &str, body: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update([0]);
    hasher.update(body);
    hasher.finalize().into()
}

fn wire_message(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(13 + body.len());
    out.extend_from_slice(&MESSAGE_MAGIC);
    out.push(kind);
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(body);
    out
}

fn wire_body(wire: &[u8], expected_kind: u8) -> Result<&[u8], ProtocolError> {
    if wire.len() < 13 || wire[..8] != MESSAGE_MAGIC {
        return Err(ProtocolError::new(
            RejectionReason::InvalidSerialization,
            "missing batching-v2 message magic/header",
        ));
    }
    if wire[8] != expected_kind {
        return Err(ProtocolError::new(
            RejectionReason::InvalidSerialization,
            format!("unexpected message kind 0x{:02x}", wire[8]),
        ));
    }
    let declared = u32::from_le_bytes(wire[9..13].try_into().expect("length checked")) as usize;
    if declared != wire.len() - 13 {
        return Err(ProtocolError::new(
            RejectionReason::InvalidSerialization,
            "body length mismatch or trailing bytes",
        ));
    }
    Ok(&wire[13..])
}

fn require_canonical_wire(actual: &[u8], canonical: &[u8]) -> Result<(), ProtocolError> {
    if actual != canonical {
        return Err(ProtocolError::new(
            RejectionReason::InvalidSerialization,
            "message is not its canonical re-encoding",
        ));
    }
    Ok(())
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn bytes(&mut self, len: usize) -> Result<&'a [u8], ProtocolError> {
        let end = self.position.checked_add(len).ok_or_else(|| {
            ProtocolError::new(
                RejectionReason::ArithmeticOverflow,
                "message cursor overflow",
            )
        })?;
        let value = self.bytes.get(self.position..end).ok_or_else(|| {
            ProtocolError::new(
                RejectionReason::InvalidSerialization,
                "truncated canonical message",
            )
        })?;
        self.position = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ProtocolError> {
        self.bytes(N)
            .map(|bytes| bytes.try_into().expect("length checked"))
    }

    fn u8(&mut self) -> Result<u8, ProtocolError> {
        Ok(self.bytes(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, ProtocolError> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, ProtocolError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, ProtocolError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn outpoint(&mut self) -> Result<OutPoint, ProtocolError> {
        deserialize(self.bytes(36)?).map_err(|error| {
            ProtocolError::new(
                RejectionReason::InvalidSerialization,
                format!("outpoint: {error}"),
            )
        })
    }

    fn public_key(&mut self) -> Result<PublicKey, ProtocolError> {
        PublicKey::from_slice(self.bytes(33)?).map_err(|error| {
            ProtocolError::new(
                RejectionReason::InvalidSerialization,
                format!("compressed public key: {error}"),
            )
        })
    }

    fn script(&mut self) -> Result<ScriptBuf, ProtocolError> {
        let len = self.u16()? as usize;
        Ok(ScriptBuf::from_bytes(self.bytes(len)?.to_vec()))
    }

    fn finish(&self) -> Result<(), ProtocolError> {
        if self.position != self.bytes.len() {
            return Err(ProtocolError::new(
                RejectionReason::InvalidSerialization,
                "trailing canonical body bytes",
            ));
        }
        Ok(())
    }
}

/// Canonical detached signature share for C2 all-peer relay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignatureShare {
    manifest_id: [u8; 32],
    input_index: u16,
    signer_pubkey: PublicKey,
    signature: bitcoin::ecdsa::Signature,
}

impl SignatureShare {
    /// Construct a canonical SIGHASH_ALL signature share.
    pub fn new(
        manifest_id: [u8; 32],
        input_index: u16,
        signer_pubkey: PublicKey,
        signature: bitcoin::ecdsa::Signature,
    ) -> Result<Self, ProtocolError> {
        require_all(&signature)?;
        Ok(Self {
            manifest_id,
            input_index,
            signer_pubkey,
            signature,
        })
    }

    /// Complete canonical signature-share wire message.
    pub fn wire_bytes(&self) -> Vec<u8> {
        let signature = self.signature.serialize();
        let mut body = Vec::with_capacity(140);
        body.extend_from_slice(&self.manifest_id);
        body.extend_from_slice(&self.input_index.to_le_bytes());
        body.extend_from_slice(&self.signer_pubkey.serialize());
        body.extend_from_slice(&(signature.len() as u16).to_le_bytes());
        body.extend_from_slice(&signature);
        wire_message(SIGNATURE_KIND, &body)
    }

    /// Parse a canonical signature-share message.
    pub fn from_wire(wire: &[u8]) -> Result<Self, ProtocolError> {
        let body = wire_body(wire, SIGNATURE_KIND)?;
        let mut reader = Reader::new(body);
        let manifest_id = reader.array()?;
        let input_index = reader.u16()?;
        let signer_pubkey = reader.public_key()?;
        let signature_len = reader.u16()? as usize;
        if signature_len > 73 {
            return Err(ProtocolError::new(
                RejectionReason::InvalidSerialization,
                "signature share exceeds 73 bytes",
            ));
        }
        let signature = bitcoin::ecdsa::Signature::from_slice(reader.bytes(signature_len)?)
            .map_err(|error| {
                ProtocolError::new(
                    RejectionReason::InvalidSerialization,
                    format!("signature share: {error}"),
                )
            })?;
        reader.finish()?;
        let share = Self::new(manifest_id, input_index, signer_pubkey, signature)?;
        require_canonical_wire(wire, &share.wire_bytes())?;
        Ok(share)
    }

    /// Manifest identifier this share signs.
    pub fn manifest_id(&self) -> [u8; 32] {
        self.manifest_id
    }

    /// Bitcoin input index this share satisfies.
    pub fn input_index(&self) -> u16 {
        self.input_index
    }

    /// Compressed signing public key.
    pub fn signer_pubkey(&self) -> PublicKey {
        self.signer_pubkey
    }

    /// Detached Bitcoin signature.
    pub fn signature(&self) -> bitcoin::ecdsa::Signature {
        self.signature
    }
}

/// Canonical signature-share wire message for C2 relay.
pub fn signature_share_wire(
    manifest_id: [u8; 32],
    input_index: u16,
    signer_pubkey: PublicKey,
    signature: &bitcoin::ecdsa::Signature,
) -> Result<Vec<u8>, ProtocolError> {
    SignatureShare::new(manifest_id, input_index, signer_pubkey, *signature)
        .map(|share| share.wire_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::Txid;
    use opencsv_core::{binding, BatchVersion, Digest};

    fn secret(seed: u8) -> SecretKey {
        SecretKey::from_slice(&[seed; 32]).unwrap()
    }

    fn public(secret: &SecretKey) -> PublicKey {
        PublicKey::from_secret_key(&Secp256k1::new(), secret)
    }

    fn outpoint(seed: u8, vout: u32) -> OutPoint {
        OutPoint::new(Txid::from_byte_array([seed; 32]), vout)
    }

    fn fixture() -> (
        Proposal,
        Vec<ParticipantCommitment>,
        Vec<SecretKey>,
        SecretKey,
    ) {
        let stock_secret = secret(3);
        let proposal = Proposal::new(
            [9u8; 32],
            outpoint(7, 1),
            100_000,
            public(&stock_secret),
            2,
            [8u8; 32],
            100,
            110,
            2,
            20,
        )
        .unwrap();
        let participant_secrets = vec![secret(5), secret(4)];
        let commitments = participant_secrets
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
        (proposal, commitments, participant_secrets, stock_secret)
    }

    #[test]
    fn signed_stock_script_and_weight_boundaries_are_exact() {
        let key = public(&secret(1));
        let one = stock_witness_script(key, 1);
        let max = stock_witness_script(key, 64);
        assert_eq!(one.len(), 38);
        assert_eq!(max.len(), 101);
        assert_eq!(max_signed_weight(1).unwrap(), 1_391);
        assert_eq!(max_signed_weight(64).unwrap(), 28_040);
        assert!(max_signed_weight(0).is_err());
        assert!(max_signed_weight(65).is_err());
    }

    #[test]
    fn manifest_orders_allocates_signs_and_finalizes() {
        let (proposal, commitments, participant_secrets, stock_secret) = fixture();
        let manifest = Manifest::build(&proposal, commitments).unwrap();
        manifest.validate(&proposal).unwrap();
        assert!(
            manifest.commitments[0].fee_outpoint < manifest.commitments[1].fee_outpoint,
            "fixture arrives reverse-sorted and must canonicalize"
        );
        assert_eq!(manifest.max_weight(), 1_814);
        assert_eq!(manifest.miner_fee(), 908);
        assert_eq!(manifest.charges(), &[727, 727]);
        let tx = manifest.unsigned_transaction();
        assert_eq!(tx.input.len(), 3);
        assert_eq!(tx.output.len(), 5);
        assert_eq!(tx.output[0].value, Amount::ZERO);
        assert_eq!(tx.output[1].value.to_sat(), MARKER_DUST_SATS);
        assert_eq!(tx.output[2].value.to_sat(), 100_000);

        let stock_signature = manifest.sign_stock(&proposal, &stock_secret).unwrap();
        // Secrets must follow canonical commitment order, not arrival order.
        let participant_signatures: Vec<_> = manifest
            .commitments
            .iter()
            .map(|commitment| {
                let key = participant_secrets
                    .iter()
                    .find(|key| public(key) == commitment.fee_pubkey)
                    .unwrap();
                manifest
                    .sign_participant(
                        &proposal,
                        manifest
                            .commitments
                            .iter()
                            .position(|candidate| candidate == commitment)
                            .unwrap(),
                        key,
                    )
                    .unwrap()
            })
            .collect();
        let signed = manifest
            .finalize(&proposal, &stock_signature, &participant_signatures)
            .unwrap();
        assert!(signed.weight().to_wu() <= u64::from(manifest.max_weight()));
        let witness: Vec<Vec<u8>> = signed.input[0].witness.iter().map(<[u8]>::to_vec).collect();
        let (version, payloads) = opencsv_core::witness_envelope_decode(&witness).unwrap();
        assert_eq!(version, BatchVersion::V2);
        assert_eq!(payloads.len(), 2);
        assert_eq!(manifest.psbt(&proposal).unwrap().inputs.len(), 3);
    }

    #[test]
    fn wrong_keys_duplicates_and_output_mutations_fail_closed() {
        let (proposal, commitments, _, stock_secret) = fixture();
        let duplicate = vec![commitments[0].clone(), commitments[0].clone()];
        assert_eq!(
            Manifest::build(&proposal, duplicate).unwrap_err().reason(),
            RejectionReason::DuplicateCommitment
        );

        let manifest = Manifest::build(&proposal, commitments).unwrap();
        assert_eq!(
            manifest
                .sign_participant(&proposal, 0, &stock_secret)
                .unwrap_err()
                .reason(),
            RejectionReason::InvalidSignature
        );
        let stock_all = manifest.sign_stock(&proposal, &stock_secret).unwrap();
        let stock_none = bitcoin::ecdsa::Signature {
            signature: stock_all.signature,
            sighash_type: EcdsaSighashType::None,
        };
        assert_eq!(
            signature_share_wire(
                manifest.manifest_id(),
                0,
                proposal.stock_owner_pubkey,
                &stock_none,
            )
            .unwrap_err()
            .reason(),
            RejectionReason::SignaturePolicyViolation
        );
        for output in 0..manifest.unsigned_tx.output.len() {
            let mut mutated = manifest.clone();
            mutated.unsigned_tx.output[output].value += Amount::from_sat(1);
            assert_eq!(
                mutated.validate(&proposal).unwrap_err().reason(),
                RejectionReason::ProtocolLayoutViolation,
                "output {output} mutation accepted"
            );
        }

        for input in 0..manifest.unsigned_tx.input.len() {
            let mut mutated = manifest.clone();
            mutated.unsigned_tx.input[input].sequence = Sequence::MAX;
            assert_eq!(
                mutated.validate(&proposal).unwrap_err().reason(),
                RejectionReason::ProtocolLayoutViolation,
                "input {input} sequence mutation accepted"
            );
        }
        let mut reordered = manifest.clone();
        reordered.unsigned_tx.input.swap(0, 1);
        assert_eq!(
            reordered.validate(&proposal).unwrap_err().reason(),
            RejectionReason::ProtocolLayoutViolation
        );
        let mut charge_mutated = manifest.clone();
        charge_mutated.charges[0] += 1;
        assert_eq!(
            charge_mutated.validate(&proposal).unwrap_err().reason(),
            RejectionReason::ProtocolLayoutViolation
        );
        let mut script_mutated = manifest.clone();
        script_mutated.unsigned_tx.output[1].script_pubkey = ScriptBuf::new();
        assert_eq!(
            script_mutated.validate(&proposal).unwrap_err().reason(),
            RejectionReason::ProtocolLayoutViolation
        );
        let mut commitment_order_mutated = manifest.clone();
        commitment_order_mutated.commitments.swap(0, 1);
        assert_eq!(
            commitment_order_mutated
                .validate(&proposal)
                .unwrap_err()
                .reason(),
            RejectionReason::ProtocolLayoutViolation
        );

        let wrong_participant_signatures = vec![stock_all; manifest.commitments.len()];
        assert_eq!(
            manifest
                .finalize(&proposal, &stock_all, &wrong_participant_signatures)
                .unwrap_err()
                .reason(),
            RejectionReason::InvalidSignature
        );
    }

    #[test]
    fn replacement_is_unanimous_and_invariant_preserving() {
        let (proposal, commitments, _, _) = fixture();
        let initial = Manifest::build(&proposal, commitments).unwrap();
        assert_eq!(
            initial.replacement(&proposal, 2).unwrap_err().reason(),
            RejectionReason::ReplacementViolation
        );
        let replacement = initial.replacement(&proposal, 3).unwrap();
        assert_eq!(replacement.replacement_epoch, 1);
        assert!(replacement.miner_fee > initial.miner_fee);
        assert_eq!(replacement.unsigned_tx.input, initial.unsigned_tx.input);
        assert_eq!(
            replacement.unsigned_tx.output[..3],
            initial.unsigned_tx.output[..3]
        );
        for (old, new) in initial.unsigned_tx.output[3..]
            .iter()
            .zip(&replacement.unsigned_tx.output[3..])
        {
            assert_eq!(old.script_pubkey, new.script_pubkey);
            assert!(new.value < old.value);
        }
    }

    #[test]
    fn abort_and_withholding_keep_signed_inputs_safe() {
        let unsigned = ReservationPhase::CommittedUnsigned;
        assert_eq!(
            unsigned.timeout_abort().unwrap(),
            ReservationPhase::ReleasedBeforeSignature
        );
        let signed = unsigned.signature_released().unwrap();
        assert_eq!(
            signed.timeout_abort().unwrap_err().reason(),
            RejectionReason::ConflictingOperation
        );
        assert!(
            !signed.is_releasable(),
            "coordinator withholding cannot unlock"
        );
        assert!(signed.confirmed().is_releasable());
        assert!(signed.invalidated_on_chain().is_releasable());
        for byte in 0..=4 {
            assert_eq!(ReservationPhase::from_byte(byte).unwrap().to_byte(), byte);
        }
        assert_eq!(
            ReservationPhase::from_byte(5).unwrap_err().reason(),
            RejectionReason::InvalidSerialization
        );
    }

    #[test]
    fn maximum_batch_constructs_signs_and_decodes_within_policy_margin() {
        let stock_secret = secret(200);
        let proposal = Proposal::new(
            [0x33; 32],
            outpoint(250, 0),
            100_000,
            public(&stock_secret),
            64,
            [0x44; 32],
            1_000,
            1_010,
            1,
            2,
        )
        .unwrap();
        let participant_secrets: Vec<_> = (1..=64).map(secret).collect();
        let commitments: Vec<_> = participant_secrets
            .iter()
            .enumerate()
            .map(|(index, key)| {
                let raw = Digest::from_bytes([(index + 1) as u8; 32]);
                ParticipantCommitment::new(
                    &proposal,
                    [(index + 1) as u8; 32],
                    [(index + 65) as u8; 32],
                    binding(&raw, &proposal.context()).to_anchor(),
                    outpoint((index + 1) as u8, index as u32),
                    TxOut {
                        value: Amount::from_sat(10_000),
                        script_pubkey: p2wpkh_script(public(key)),
                    },
                    public(key),
                    p2wpkh_script(public(&secret((index + 100) as u8))),
                    1_000,
                )
                .unwrap()
            })
            .collect();
        let manifest = Manifest::build(&proposal, commitments).unwrap();
        assert_eq!(manifest.max_weight(), 28_040);
        assert_eq!(manifest.unsigned_tx.input.len(), 65);
        assert_eq!(manifest.unsigned_tx.output.len(), 67);
        let stock_signature = manifest.sign_stock(&proposal, &stock_secret).unwrap();
        let signatures: Vec<_> = (0..64)
            .map(|index| {
                let expected = manifest.participant_fee_pubkey(index).unwrap();
                let key = participant_secrets
                    .iter()
                    .find(|key| public(key) == expected)
                    .unwrap();
                manifest.sign_participant(&proposal, index, key).unwrap()
            })
            .collect();
        let transaction = manifest
            .finalize(&proposal, &stock_signature, &signatures)
            .unwrap();
        assert_eq!(proposal.stock_witness_script().len(), 101);
        assert_eq!(transaction.input[0].witness.len(), 67);
        assert!(transaction.weight().to_wu() <= 28_040);
        let witness: Vec<Vec<u8>> = transaction.input[0]
            .witness
            .iter()
            .map(<[u8]>::to_vec)
            .collect();
        assert_eq!(
            opencsv_core::witness_envelope_decode(&witness)
                .unwrap()
                .1
                .len(),
            64
        );
    }

    #[test]
    fn transcript_wire_messages_are_typed_and_deterministic() {
        let (proposal, commitments, _, stock_secret) = fixture();
        let proposal_wire = proposal.wire_bytes();
        assert_eq!(&proposal_wire[..8], &MESSAGE_MAGIC);
        assert_eq!(proposal_wire[8], PROPOSAL_KIND);
        assert_eq!(proposal.batch_id(), proposal.batch_id());
        assert_eq!(commitments[0].wire_bytes()[8], COMMITMENT_KIND);
        let source_commitments = commitments.clone();
        let manifest = Manifest::build(&proposal, commitments).unwrap();
        assert_eq!(manifest.wire_bytes()[8], MANIFEST_KIND);
        assert_ne!(proposal.batch_id(), manifest.manifest_id());
        let stock_signature = manifest.sign_stock(&proposal, &stock_secret).unwrap();
        let signature_wire = signature_share_wire(
            manifest.manifest_id(),
            0,
            proposal.stock_owner_pubkey,
            &stock_signature,
        )
        .unwrap();
        let commitment_wire = manifest.commitments[0].wire_bytes();
        let manifest_wire = manifest.wire_bytes();
        for (name, bytes, expected_len, expected_sha256) in [
            (
                "proposal",
                proposal_wire.as_slice(),
                173,
                "27ee90ba463dfb07874e9aa87b74d80c4bf018d5260270737edd8609ca8c0e98",
            ),
            (
                "commitment",
                commitment_wire.as_slice(),
                266,
                "2fc72ba89f1c80ad4a55f83372eccec2f5954113d48bc7d3d8c3195844cff010",
            ),
            (
                "manifest",
                manifest_wire.as_slice(),
                514,
                "9c426fea03d7ec47013e932429fd379dcdfd05e95436d1ba6a407deeed580776",
            ),
            (
                "signature",
                signature_wire.as_slice(),
                153,
                "ea9058cfe1a6ab94b367fa016cff89d3ff7f97a24478f09ed7e9adda50c2056e",
            ),
        ] {
            assert_eq!(bytes.len(), expected_len, "{name} wire length changed");
            assert_eq!(
                format!("{:x}", sha2::Sha256::digest(bytes)),
                expected_sha256,
                "{name} golden bytes changed"
            );
        }
        assert_eq!(
            proposal.batch_id(),
            [
                0x18, 0x51, 0x98, 0x60, 0xc0, 0x0a, 0xaa, 0xa4, 0xb9, 0x02, 0x0d, 0x91, 0x58, 0x2f,
                0xef, 0xbb, 0xe7, 0xe7, 0x39, 0xf5, 0x09, 0x45, 0xd2, 0x8b, 0xe1, 0x9e, 0x0e, 0x56,
                0xeb, 0xdf, 0x3d, 0x13,
            ]
        );
        assert_eq!(
            manifest.manifest_id(),
            [
                0xa2, 0x69, 0x19, 0x2a, 0x9b, 0x61, 0xde, 0x5d, 0x57, 0x49, 0x79, 0x07, 0x49, 0x1e,
                0x91, 0x80, 0x66, 0xdd, 0x0b, 0x87, 0xf9, 0x8e, 0xd7, 0x86, 0xb8, 0x70, 0x4e, 0xc8,
                0x45, 0xf8, 0x8e, 0x14,
            ]
        );

        assert_eq!(Proposal::from_wire(&proposal_wire).unwrap(), proposal);
        assert_eq!(
            ParticipantCommitment::from_wire(&proposal, &commitment_wire).unwrap(),
            manifest.commitments[0]
        );
        assert_eq!(
            Manifest::from_wire(&proposal, source_commitments, &manifest_wire).unwrap(),
            manifest
        );
        let decoded_share = SignatureShare::from_wire(&signature_wire).unwrap();
        assert_eq!(decoded_share.manifest_id(), manifest.manifest_id());
        assert_eq!(decoded_share.input_index(), 0);
        assert_eq!(decoded_share.signer_pubkey(), proposal.stock_owner_pubkey);
        assert_eq!(decoded_share.signature(), stock_signature);

        for mut malformed in [
            proposal_wire.clone(),
            commitment_wire.clone(),
            manifest_wire,
        ] {
            malformed.push(0);
            let reason = match malformed[8] {
                PROPOSAL_KIND => Proposal::from_wire(&malformed).unwrap_err().reason(),
                COMMITMENT_KIND => ParticipantCommitment::from_wire(&proposal, &malformed)
                    .unwrap_err()
                    .reason(),
                MANIFEST_KIND => Manifest::from_wire(&proposal, fixture().1, &malformed)
                    .unwrap_err()
                    .reason(),
                _ => unreachable!(),
            };
            assert_eq!(reason, RejectionReason::InvalidSerialization);
        }

        let mut wrong_magic = proposal_wire;
        wrong_magic[0] ^= 1;
        assert_eq!(
            Proposal::from_wire(&wrong_magic).unwrap_err().reason(),
            RejectionReason::InvalidSerialization
        );
        assert_eq!(
            proposal
                .validate_at([0x55; 32], proposal.observed_tip_height)
                .unwrap_err()
                .reason(),
            RejectionReason::WrongChain
        );
        assert_eq!(
            proposal
                .validate_at(proposal.chain_id, proposal.expiry_height)
                .unwrap_err()
                .reason(),
            RejectionReason::ExpiredProposal
        );
    }

    #[test]
    fn peer_pool_reconstruction_and_share_finalization_are_idempotent() {
        let (proposal, commitments, participant_secrets, stock_secret) = fixture();
        let manifest = Manifest::build(&proposal, commitments.clone()).unwrap();
        let mut pool = commitments;
        let mut extra = pool[0].clone();
        extra.operation_id = [99; 32];
        extra.commit_nonce = [98; 32];
        extra.fee_outpoint = outpoint(99, 9);
        extra.payload = TruncatedDigest([97; 24]);
        extra.change_spk = p2wpkh_script(public(&secret(96)));
        pool.push(extra);
        assert_eq!(
            Manifest::from_wire_pool(&proposal, &pool, &manifest.wire_bytes()).unwrap(),
            manifest
        );

        let stock_signature = manifest.sign_stock(&proposal, &stock_secret).unwrap();
        let mut shares = vec![SignatureShare::new(
            manifest.manifest_id(),
            0,
            proposal.stock_owner_pubkey(),
            stock_signature,
        )
        .unwrap()];
        for index in 0..manifest.commitments.len() {
            let expected = manifest.participant_fee_pubkey(index).unwrap();
            let key = participant_secrets
                .iter()
                .find(|key| public(key) == expected)
                .unwrap();
            let signature = manifest.sign_participant(&proposal, index, key).unwrap();
            shares.push(
                SignatureShare::new(
                    manifest.manifest_id(),
                    (index + 1) as u16,
                    expected,
                    signature,
                )
                .unwrap(),
            );
        }
        let expected = manifest
            .finalize(
                &proposal,
                &shares[0].signature(),
                &shares[1..]
                    .iter()
                    .map(SignatureShare::signature)
                    .collect::<Vec<_>>(),
            )
            .unwrap();
        let mut duplicated = shares.clone();
        duplicated.push(shares[1].clone());
        assert_eq!(
            manifest.finalize_shares(&proposal, &duplicated).unwrap(),
            expected
        );

        let wrong_manifest = SignatureShare::new(
            [0x55; 32],
            0,
            proposal.stock_owner_pubkey(),
            shares[0].signature(),
        )
        .unwrap();
        assert_eq!(
            manifest
                .verify_signature_share(&proposal, &wrong_manifest)
                .unwrap_err()
                .reason(),
            RejectionReason::InvalidSignature
        );
    }
}
