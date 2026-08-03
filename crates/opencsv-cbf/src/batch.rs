//! Authoritative batching-v2 prevout verification capabilities.
//!
//! Candidate heights may come from an explorer or wallet, but acceptance is
//! based only on the CBF clients independently agreed PoW/header view,
//! BIP158-directed full-block downloads, and merkle-checked exact outpoints.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bitcoin::hashes::Hash as _;
use opencsv_bitcoin::batch_v2::{Manifest, ParticipantCommitment, Proposal};

use crate::block::OutPoint;
use crate::{CbfClient, Error, OutpointVerdict};

/// Search hints for the stock creation and every canonical participant input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchInputBirthHeights {
    /// Claimed creation height of input-0 stock.
    pub stock: u64,
    /// Claimed creation heights in canonical manifest commitment order.
    pub participants: Vec<u64>,
}

/// Search hints for proposal stock and one participant fee input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommitmentInputBirthHeights {
    /// Claimed creation height of input-0 stock.
    pub stock: u64,
    /// Claimed creation height of this participant fee input.
    pub fee: u64,
}

/// Independently agreed chain tip with a bounded wall-clock receipt time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedChainTip {
    chain_id: [u8; 32],
    height: u64,
    hash: [u8; 32],
    verified_at_unix_seconds: u64,
}

impl VerifiedChainTip {
    /// Network genesis hash, internal byte order.
    pub fn chain_id(&self) -> [u8; 32] {
        self.chain_id
    }

    /// Independently agreed tip height.
    pub fn height(&self) -> u64 {
        self.height
    }

    /// Independently agreed tip hash, internal byte order.
    pub fn hash(&self) -> [u8; 32] {
        self.hash
    }

    /// Wall-clock receipt time used only for maximum-age policy.
    pub fn verified_at_unix_seconds(&self) -> u64 {
        self.verified_at_unix_seconds
    }

    /// Reject a stale or future-dated tip receipt.
    pub fn require_fresh(&self, max_age: Duration) -> Result<(), Error> {
        require_fresh_timestamp(self.verified_at_unix_seconds, max_age)
    }
}

/// One exact output whose existence and unspent state were independently checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedBatchOutpoint {
    outpoint: bitcoin::OutPoint,
    creation_height: u64,
    checked_through: u64,
    matched_blocks: u64,
}

impl VerifiedBatchOutpoint {
    /// Exact verified Bitcoin outpoint.
    pub fn outpoint(&self) -> bitcoin::OutPoint {
        self.outpoint
    }

    /// Merkle-checked block that created the output.
    pub fn creation_height(&self) -> u64 {
        self.creation_height
    }

    /// Independently agreed tip through which spends were checked.
    pub fn checked_through(&self) -> u64 {
        self.checked_through
    }

    /// Number of filter matches that required full-block inspection.
    pub fn matched_blocks(&self) -> u64 {
        self.matched_blocks
    }
}

/// Unforgeable product-path capability binding one exact manifest to a fresh,
/// independently verified set of public Bitcoin inputs.
///
/// Fields are private and there is no public constructor. The only production
/// constructor is [`CbfClient::verify_batch_inputs`]. A separate durable local
/// reservation guard remains mandatory for the signing wallet: another
/// participant cannot prove its private wallet lock, so every signer enforces
/// its own reservation and independently rechecks all public outpoints.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedBatchInputs {
    batch_id: [u8; 32],
    manifest_id: [u8; 32],
    verified_tip_height: u64,
    verified_tip_hash: [u8; 32],
    verified_at_unix_seconds: u64,
    stock: VerifiedBatchOutpoint,
    participants: Vec<VerifiedBatchOutpoint>,
}

/// Unforgeable capability binding one commitment to independently verified
/// stock and fee inputs before that commitment is published.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedCommitmentInputs {
    batch_id: [u8; 32],
    commitment_id: [u8; 32],
    verified_at_unix_seconds: u64,
    stock: VerifiedBatchOutpoint,
    fee: VerifiedBatchOutpoint,
}

impl VerifiedCommitmentInputs {
    /// Require this capability to name the exact proposal/commitment and meet
    /// the maximum-age policy at publication time.
    pub fn require_fresh_for(
        &self,
        proposal: &Proposal,
        commitment: &ParticipantCommitment,
        max_age: Duration,
    ) -> Result<(), Error> {
        if self.batch_id != proposal.batch_id() || self.commitment_id != commitment.commitment_id()
        {
            return Err(Error::InvalidInput(
                "verified commitment inputs belong to another operation".into(),
            ));
        }
        require_fresh_timestamp(self.verified_at_unix_seconds, max_age)
    }

    /// Verified stock receipt.
    pub fn stock(&self) -> &VerifiedBatchOutpoint {
        &self.stock
    }

    /// Verified participant fee receipt.
    pub fn fee(&self) -> &VerifiedBatchOutpoint {
        &self.fee
    }
}

impl VerifiedBatchInputs {
    /// Proposal identifier bound by this capability.
    pub fn batch_id(&self) -> [u8; 32] {
        self.batch_id
    }

    /// Manifest identifier bound by this capability.
    pub fn manifest_id(&self) -> [u8; 32] {
        self.manifest_id
    }

    /// Independently agreed tip height at verification time.
    pub fn verified_tip_height(&self) -> u64 {
        self.verified_tip_height
    }

    /// Independently agreed tip hash at verification time, internal byte order.
    pub fn verified_tip_hash(&self) -> [u8; 32] {
        self.verified_tip_hash
    }

    /// Wall-clock receipt time used only to enforce a maximum signing age.
    pub fn verified_at_unix_seconds(&self) -> u64 {
        self.verified_at_unix_seconds
    }

    /// Verified input-0 stock receipt.
    pub fn stock(&self) -> &VerifiedBatchOutpoint {
        &self.stock
    }

    /// Verified participant receipts in canonical manifest order.
    pub fn participants(&self) -> &[VerifiedBatchOutpoint] {
        &self.participants
    }

    /// Require that this capability names the exact proposal/manifest and is
    /// no older than `max_age` at the moment a signature is released.
    pub fn require_fresh_for(
        &self,
        proposal: &Proposal,
        manifest: &Manifest,
        max_age: Duration,
    ) -> Result<(), Error> {
        if self.batch_id != proposal.batch_id() || self.manifest_id != manifest.manifest_id() {
            return Err(Error::InvalidInput(
                "verified batch inputs belong to another proposal or manifest".into(),
            ));
        }
        require_fresh_timestamp(self.verified_at_unix_seconds, max_age)
    }
}

impl CbfClient {
    /// Capture the current all-peer-agreed tip as a maximum-age-capable
    /// receipt for expiry-sensitive relay decisions.
    pub fn verified_tip_receipt(&self) -> Result<VerifiedChainTip, Error> {
        let height = self.tip_height();
        let hash = self
            .block_hash(height)
            .ok_or_else(|| Error::Consensus("verified tip hash is unavailable".into()))?;
        Ok(VerifiedChainTip {
            chain_id: self.params().genesis_hash,
            height,
            hash,
            verified_at_unix_seconds: unix_time()?,
        })
    }

    /// Verify proposal stock and one participant fee input before publishing
    /// the participant commitment.
    pub fn verify_commitment_inputs(
        &mut self,
        proposal: &Proposal,
        commitment: &ParticipantCommitment,
        birth_heights: CommitmentInputBirthHeights,
        max_blocks: u64,
    ) -> Result<VerifiedCommitmentInputs, Error> {
        let stock = verify_expected(
            self,
            proposal.stock_outpoint(),
            proposal.stock_value(),
            proposal.stock_script_pubkey().as_bytes(),
            birth_heights.stock,
            max_blocks,
            "stock",
        )?;
        let fee = verify_expected(
            self,
            commitment.fee_outpoint(),
            commitment.fee_prevout().value.to_sat(),
            commitment.fee_prevout().script_pubkey.as_bytes(),
            birth_heights.fee,
            max_blocks,
            "participant fee",
        )?;
        if stock.checked_through != fee.checked_through {
            return Err(Error::DivergentPeers(
                "commitment inputs were not checked through one common tip".into(),
            ));
        }
        Ok(VerifiedCommitmentInputs {
            batch_id: proposal.batch_id(),
            commitment_id: commitment.commitment_id(),
            verified_at_unix_seconds: unix_time()?,
            stock,
            fee,
        })
    }

    /// Independently verify the exact public inputs of one source-complete
    /// canonical manifest and return the capability required by product
    /// signing paths.
    pub fn verify_batch_inputs(
        &mut self,
        proposal: &Proposal,
        manifest: &Manifest,
        birth_heights: &BatchInputBirthHeights,
        max_blocks: u64,
    ) -> Result<VerifiedBatchInputs, Error> {
        manifest
            .psbt(proposal)
            .map_err(|error| Error::InvalidInput(format!("batch manifest: {error}")))?;
        if birth_heights.participants.len() != manifest.commitments().len() {
            return Err(Error::InvalidInput(
                "participant birth-height count differs from canonical manifest".into(),
            ));
        }

        let stock = verify_expected(
            self,
            proposal.stock_outpoint(),
            proposal.stock_value(),
            proposal.stock_script_pubkey().as_bytes(),
            birth_heights.stock,
            max_blocks,
            "stock",
        )?;
        let mut participants = Vec::with_capacity(manifest.commitments().len());
        for (index, (commitment, birth_height)) in manifest
            .commitments()
            .iter()
            .zip(&birth_heights.participants)
            .enumerate()
        {
            participants.push(verify_expected(
                self,
                commitment.fee_outpoint(),
                commitment.fee_prevout().value.to_sat(),
                commitment.fee_prevout().script_pubkey.as_bytes(),
                *birth_height,
                max_blocks,
                &format!("participant {index}"),
            )?);
        }

        let verified_tip_height = self.tip_height();
        if stock.checked_through != verified_tip_height
            || participants
                .iter()
                .any(|receipt| receipt.checked_through != verified_tip_height)
        {
            return Err(Error::DivergentPeers(
                "batch inputs were not checked through one common tip".into(),
            ));
        }
        let verified_tip_hash = self
            .block_hash(verified_tip_height)
            .ok_or_else(|| Error::Consensus("verified tip hash is unavailable".into()))?;

        Ok(VerifiedBatchInputs {
            batch_id: proposal.batch_id(),
            manifest_id: manifest.manifest_id(),
            verified_tip_height,
            verified_tip_hash,
            verified_at_unix_seconds: unix_time()?,
            stock,
            participants,
        })
    }
}

fn verify_expected(
    client: &mut CbfClient,
    outpoint: bitcoin::OutPoint,
    expected_value: u64,
    expected_script: &[u8],
    birth_height: u64,
    max_blocks: u64,
    role: &str,
) -> Result<VerifiedBatchOutpoint, Error> {
    let verdict = client.verify_outpoint_unspent(
        OutPoint {
            txid: outpoint.txid.to_byte_array(),
            vout: outpoint.vout,
        },
        expected_value,
        expected_script,
        birth_height,
        max_blocks,
    )?;
    match verdict {
        OutpointVerdict::Unspent {
            creation_height,
            checked_through,
            matched_blocks,
        } => Ok(VerifiedBatchOutpoint {
            outpoint,
            creation_height,
            checked_through,
            matched_blocks,
        }),
        OutpointVerdict::Spent {
            spend_height,
            spending_txid,
            ..
        } => Err(Error::InvalidInput(format!(
            "{role} outpoint was spent at height {spend_height} by {}",
            crate::hash::hash_to_display(&spending_txid)
        ))),
        OutpointVerdict::NotFound { .. } => Err(Error::InvalidInput(format!(
            "{role} outpoint was not found in independently verified blocks"
        ))),
        OutpointVerdict::OutputMismatch { creation_height } => Err(Error::InvalidInput(format!(
            "{role} outpoint value/script differs at height {creation_height}"
        ))),
    }
}

fn unix_time() -> Result<u64, Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| Error::InvalidInput(format!("system clock before Unix epoch: {error}")))
}

fn require_fresh_timestamp(timestamp: u64, max_age: Duration) -> Result<(), Error> {
    if max_age.is_zero() {
        return Err(Error::InvalidInput(
            "verified-tip maximum age must be positive".into(),
        ));
    }
    let now = unix_time()?;
    let age = now
        .checked_sub(timestamp)
        .ok_or_else(|| Error::InvalidInput("verified-tip receipt time is in the future".into()))?;
    if age > max_age.as_secs() {
        return Err(Error::InvalidInput(format!(
            "verified-tip receipt age {age}s exceeds signing limit {}s",
            max_age.as_secs()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verified_tip_receipt_has_an_enforced_maximum_age() {
        let stale = VerifiedChainTip {
            chain_id: [1; 32],
            height: 100,
            hash: [2; 32],
            verified_at_unix_seconds: 1,
        };
        assert!(stale.require_fresh(Duration::from_secs(60)).is_err());

        let fresh = VerifiedChainTip {
            chain_id: [1; 32],
            height: 100,
            hash: [2; 32],
            verified_at_unix_seconds: unix_time().unwrap(),
        };
        fresh.require_fresh(Duration::from_secs(60)).unwrap();
        assert!(fresh.require_fresh(Duration::ZERO).is_err());
    }
}
