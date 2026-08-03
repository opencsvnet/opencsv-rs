//! Conservative fee and marker-cost comparison for solo anchors and
//! batching v2.
//!
//! The model uses the frozen batching-v2 maximum signed weight and a
//! constructed maximum-size P2WPKH solo anchor. Values are transaction
//! costs, not quotes: the reusable batching stock setup transaction is
//! deliberately excluded and feerates must come from an explicit
//! caller policy or a measured fee source.

use bitcoin::absolute;
use bitcoin::script::PushBytesBuf;
use bitcoin::transaction;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

use crate::batch_v2::max_signed_weight;
use crate::{MARKER_DUST_SATS, MARKER_SPK};

/// A rejected fee-model request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeeModelError {
    /// Participant count is outside batching v2's frozen `1..=64` range.
    InvalidParticipantCount,
    /// A zero feerate is not an actionable Bitcoin fee policy.
    ZeroFeerate,
    /// Checked fee arithmetic overflowed.
    ArithmeticOverflow,
}

impl std::fmt::Display for FeeModelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidParticipantCount => f.write_str("participant count must be in 1..=64"),
            Self::ZeroFeerate => f.write_str("feerate must be at least 1 sat/vB"),
            Self::ArithmeticOverflow => f.write_str("fee arithmetic overflow"),
        }
    }
}

impl std::error::Error for FeeModelError {}

/// Conservative comparison of separate solo anchors and one batching-v2
/// transaction at a caller-supplied feerate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeeEstimate {
    /// Number of OpenCSV operations being compared.
    pub participants: usize,
    /// Caller-supplied feerate in satoshis per virtual byte.
    pub feerate_sat_vb: u32,
    /// Maximum signed size of one solo P2WPKH-funded anchor.
    pub solo_max_vbytes: u64,
    /// Frozen maximum signed size of the batching-v2 transaction.
    pub batch_max_vbytes: u64,
    /// Protocol marker value paid once per transaction.
    pub marker_sats_per_transaction: u64,
    /// Miner fees for `participants` separate solo anchors.
    pub solo_miner_fee_total: u64,
    /// Miner fee for one batching-v2 transaction.
    pub batch_miner_fee: u64,
    /// Miner fees plus one marker per solo anchor.
    pub solo_total_charge: u64,
    /// Miner fee plus the batching transaction's single marker.
    pub batch_total_charge: u64,
    /// `solo_total_charge - batch_total_charge`; negative means batching
    /// is more expensive for this participant count and feerate.
    pub solo_minus_batch_sats: i128,
    /// Lowest per-participant batching charge under exact remainder
    /// allocation.
    pub batch_charge_floor: u64,
    /// Highest per-participant batching charge under exact remainder
    /// allocation.
    pub batch_charge_ceiling: u64,
}

/// Maximum signed weight of a solo anchor funded by one P2WPKH input,
/// with the record, marker, and P2WPKH change outputs.
pub fn solo_max_signed_weight() -> u64 {
    let payload = PushBytesBuf::try_from(vec![0u8; 64]).expect("64 bytes are pushable");
    let mut witness = Witness::new();
    witness.push([0u8; 73]);
    witness.push([0u8; 33]);
    let transaction = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness,
        }],
        output: vec![
            TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::new_op_return(payload),
            },
            TxOut {
                value: Amount::from_sat(MARKER_DUST_SATS),
                script_pubkey: ScriptBuf::from_bytes(MARKER_SPK.to_vec()),
            },
            TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::from_bytes([vec![0x00, 0x14], vec![0u8; 20]].concat()),
            },
        ],
    };
    transaction.weight().to_wu()
}

/// Compare solo and batching-v2 costs using pessimistic signed sizes.
pub fn estimate(participants: usize, feerate_sat_vb: u32) -> Result<FeeEstimate, FeeModelError> {
    if feerate_sat_vb == 0 {
        return Err(FeeModelError::ZeroFeerate);
    }
    let batch_weight =
        max_signed_weight(participants).map_err(|_| FeeModelError::InvalidParticipantCount)?;
    let solo_max_vbytes = solo_max_signed_weight().div_ceil(4);
    let batch_max_vbytes = batch_weight.div_ceil(4);
    let rate = u64::from(feerate_sat_vb);
    let solo_miner_fee_each = solo_max_vbytes
        .checked_mul(rate)
        .ok_or(FeeModelError::ArithmeticOverflow)?;
    let solo_miner_fee_total = solo_miner_fee_each
        .checked_mul(participants as u64)
        .ok_or(FeeModelError::ArithmeticOverflow)?;
    let batch_miner_fee = batch_max_vbytes
        .checked_mul(rate)
        .ok_or(FeeModelError::ArithmeticOverflow)?;
    let solo_total_each = solo_miner_fee_each
        .checked_add(MARKER_DUST_SATS)
        .ok_or(FeeModelError::ArithmeticOverflow)?;
    let solo_total_charge = solo_total_each
        .checked_mul(participants as u64)
        .ok_or(FeeModelError::ArithmeticOverflow)?;
    let batch_total_charge = batch_miner_fee
        .checked_add(MARKER_DUST_SATS)
        .ok_or(FeeModelError::ArithmeticOverflow)?;
    let participant_count = participants as u64;

    Ok(FeeEstimate {
        participants,
        feerate_sat_vb,
        solo_max_vbytes,
        batch_max_vbytes,
        marker_sats_per_transaction: MARKER_DUST_SATS,
        solo_miner_fee_total,
        batch_miner_fee,
        solo_total_charge,
        batch_total_charge,
        solo_minus_batch_sats: i128::from(solo_total_charge) - i128::from(batch_total_charge),
        batch_charge_floor: batch_total_charge / participant_count,
        batch_charge_ceiling: batch_total_charge.div_ceil(participant_count),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn solo_weight_is_constructed_and_frozen() {
        assert_eq!(solo_max_signed_weight(), 911);
        assert_eq!(solo_max_signed_weight().div_ceil(4), 228);
    }

    #[test]
    fn exact_costs_include_marker_once_per_transaction() {
        let one = estimate(1, 3).unwrap();
        assert_eq!(one.solo_total_charge, 1_230);
        assert_eq!(one.batch_max_vbytes, 348);
        assert_eq!(one.batch_total_charge, 1_590);
        assert_eq!(one.solo_minus_batch_sats, -360);

        let four = estimate(4, 3).unwrap();
        assert_eq!(four.batch_max_vbytes, 665);
        assert_eq!(four.solo_total_charge, 4_920);
        assert_eq!(four.batch_total_charge, 2_541);
        assert_eq!(four.solo_minus_batch_sats, 2_379);
        assert_eq!(four.batch_charge_floor, 635);
        assert_eq!(four.batch_charge_ceiling, 636);
    }

    #[test]
    fn participant_bounds_and_zero_feerate_are_rejected() {
        assert_eq!(estimate(0, 1), Err(FeeModelError::InvalidParticipantCount));
        assert_eq!(estimate(65, 1), Err(FeeModelError::InvalidParticipantCount));
        assert_eq!(estimate(1, 0), Err(FeeModelError::ZeroFeerate));
    }

    #[test]
    fn batch_cost_and_savings_are_monotone() {
        let mut previous_cost = 0;
        let mut previous_savings = i128::MIN;
        for participants in 1..=64 {
            let estimate = estimate(participants, 10).unwrap();
            assert!(estimate.batch_total_charge > previous_cost);
            assert!(estimate.solo_minus_batch_sats > previous_savings);
            previous_cost = estimate.batch_total_charge;
            previous_savings = estimate.solo_minus_batch_sats;
        }
    }
}
