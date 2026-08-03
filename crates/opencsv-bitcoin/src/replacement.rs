//! Fail-closed validation for solo-anchor fee replacements.
//!
//! Bitcoin Core's generic `bumpfee` RPC is not protocol-aware: when the
//! available change is small it may remove the change output. OpenCSV must
//! instead preserve the funding inputs and the exact record/marker/change
//! positions. This module is the pure validation boundary used before a
//! replacement is signed or broadcast.

use bitcoin::{Sequence, Transaction};

use crate::{MARKER_DUST_SATS, MARKER_SPK};

/// Stable reason that a proposed solo-anchor replacement was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SoloReplacementRejection {
    /// The original is not the canonical three-output OpenCSV layout.
    OriginalLayout,
    /// The replacement is not the canonical three-output OpenCSV layout.
    ReplacementLayout,
    /// Transaction version, lock time, or funding inputs changed.
    FundingInputsChanged,
    /// The transaction is not explicitly replaceable with the canonical
    /// OpenCSV sequence.
    NotReplaceable,
    /// The bound 64-byte record at output zero changed.
    RecordChanged,
    /// The unspendable marker at output one changed.
    MarkerChanged,
    /// The change destination at output two changed.
    ChangeScriptChanged,
    /// The replacement removed change or reduced it below relay dust.
    ChangeRemovedOrDust,
    /// The replacement did not pay a strictly higher miner fee.
    FeeNotIncreased,
}

impl SoloReplacementRejection {
    /// Stable machine-readable rejection code for FFI and journals.
    pub const fn code(self) -> &'static str {
        match self {
            Self::OriginalLayout => "original_layout",
            Self::ReplacementLayout => "replacement_layout",
            Self::FundingInputsChanged => "funding_inputs_changed",
            Self::NotReplaceable => "not_replaceable",
            Self::RecordChanged => "record_changed",
            Self::MarkerChanged => "marker_changed",
            Self::ChangeScriptChanged => "change_script_changed",
            Self::ChangeRemovedOrDust => "change_removed_or_dust",
            Self::FeeNotIncreased => "fee_not_increased",
        }
    }
}

impl std::fmt::Display for SoloReplacementRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for SoloReplacementRejection {}

/// Successful solo-anchor replacement validation receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SoloReplacementReceipt {
    /// Satoshis removed from change and therefore added to the miner fee.
    pub fee_increment_sats: u64,
    /// Change value that remains after the bump.
    pub replacement_change_sats: u64,
}

/// Validate a protocol-safe replacement of one OpenCSV solo anchor.
///
/// The original and replacement must both have exactly three outputs:
/// the zero-value 64-byte record, the current unspendable marker, and one
/// non-dust change output. Funding outpoints and their order are immutable,
/// as the first one defines the OpenCSV transaction context. Witnesses may
/// change when the replacement is signed; all other protected structure is
/// fixed. With identical inputs, a strict reduction in change is a strict fee
/// increase.
pub fn validate_solo_anchor_replacement(
    original: &Transaction,
    replacement: &Transaction,
) -> Result<SoloReplacementReceipt, SoloReplacementRejection> {
    validate_layout(original).map_err(|_| SoloReplacementRejection::OriginalLayout)?;
    validate_layout(replacement).map_err(|_| SoloReplacementRejection::ReplacementLayout)?;

    if original.version != replacement.version
        || original.lock_time != replacement.lock_time
        || original.input.len() != replacement.input.len()
        || original
            .input
            .iter()
            .zip(&replacement.input)
            .any(|(old, new)| {
                old.previous_output != new.previous_output
                    || old.sequence != new.sequence
                    || old.script_sig != new.script_sig
            })
    {
        return Err(SoloReplacementRejection::FundingInputsChanged);
    }
    if original
        .input
        .iter()
        .chain(&replacement.input)
        .any(|input| input.sequence != Sequence::ENABLE_RBF_NO_LOCKTIME)
    {
        return Err(SoloReplacementRejection::NotReplaceable);
    }
    if original.output[0] != replacement.output[0] {
        return Err(SoloReplacementRejection::RecordChanged);
    }
    if original.output[1] != replacement.output[1] {
        return Err(SoloReplacementRejection::MarkerChanged);
    }
    if original.output[2].script_pubkey != replacement.output[2].script_pubkey {
        return Err(SoloReplacementRejection::ChangeScriptChanged);
    }

    let old_change = original.output[2].value.to_sat();
    let new_change = replacement.output[2].value.to_sat();
    if new_change
        < replacement.output[2]
            .script_pubkey
            .minimal_non_dust()
            .to_sat()
    {
        return Err(SoloReplacementRejection::ChangeRemovedOrDust);
    }
    let fee_increment_sats = old_change
        .checked_sub(new_change)
        .filter(|increment| *increment > 0)
        .ok_or(SoloReplacementRejection::FeeNotIncreased)?;

    Ok(SoloReplacementReceipt {
        fee_increment_sats,
        replacement_change_sats: new_change,
    })
}

fn validate_layout(transaction: &Transaction) -> Result<(), ()> {
    if transaction.input.is_empty() || transaction.output.len() != 3 {
        return Err(());
    }
    let record = &transaction.output[0];
    let record_script = record.script_pubkey.as_bytes();
    if record.value.to_sat() != 0
        || record_script.len() != 66
        || record_script[0] != 0x6a
        || record_script[1] != 0x40
    {
        return Err(());
    }
    let marker = &transaction.output[1];
    if marker.value.to_sat() != MARKER_DUST_SATS || marker.script_pubkey.as_bytes() != MARKER_SPK {
        return Err(());
    }
    if transaction.output[2].script_pubkey.is_op_return() {
        return Err(());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use bitcoin::absolute;
    use bitcoin::script::PushBytesBuf;
    use bitcoin::transaction;
    use bitcoin::{Amount, OutPoint, ScriptBuf, TxIn, TxOut, Witness};

    use super::*;

    fn anchor(change: u64) -> Transaction {
        let payload = PushBytesBuf::try_from(vec![7u8; 64]).unwrap();
        Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
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
                    value: Amount::from_sat(change),
                    script_pubkey: ScriptBuf::from_bytes(
                        [vec![0x00, 0x14], vec![3u8; 20]].concat(),
                    ),
                },
            ],
        }
    }

    #[test]
    fn accepts_change_only_fee_bump() {
        let receipt = validate_solo_anchor_replacement(&anchor(2_298), &anchor(1_500)).unwrap();
        assert_eq!(receipt.fee_increment_sats, 798);
        assert_eq!(receipt.replacement_change_sats, 1_500);
    }

    #[test]
    fn rejects_core_style_change_removal() {
        let original = anchor(2_298);
        let mut replacement = anchor(1_500);
        replacement.output.pop();
        assert_eq!(
            validate_solo_anchor_replacement(&original, &replacement),
            Err(SoloReplacementRejection::ReplacementLayout)
        );
    }

    #[test]
    fn rejects_every_protected_mutation() {
        let original = anchor(2_298);

        let mut replacement = anchor(1_500);
        replacement.input[0].previous_output.vout = 1;
        assert_eq!(
            validate_solo_anchor_replacement(&original, &replacement),
            Err(SoloReplacementRejection::FundingInputsChanged)
        );

        let mut replacement = anchor(1_500);
        replacement.output[0].script_pubkey =
            ScriptBuf::new_op_return(PushBytesBuf::try_from(vec![8u8; 64]).unwrap());
        assert_eq!(
            validate_solo_anchor_replacement(&original, &replacement),
            Err(SoloReplacementRejection::RecordChanged)
        );

        let mut replacement = anchor(1_500);
        replacement.output[1].value = Amount::from_sat(MARKER_DUST_SATS + 1);
        assert_eq!(
            validate_solo_anchor_replacement(&original, &replacement),
            Err(SoloReplacementRejection::ReplacementLayout)
        );

        let mut replacement = anchor(1_500);
        replacement.output[2].script_pubkey =
            ScriptBuf::from_bytes([vec![0x00, 0x14], vec![4u8; 20]].concat());
        assert_eq!(
            validate_solo_anchor_replacement(&original, &replacement),
            Err(SoloReplacementRejection::ChangeScriptChanged)
        );

        assert_eq!(
            validate_solo_anchor_replacement(&original, &anchor(2_298)),
            Err(SoloReplacementRejection::FeeNotIncreased)
        );

        assert_eq!(
            validate_solo_anchor_replacement(&original, &anchor(200)),
            Err(SoloReplacementRejection::ChangeRemovedOrDust)
        );
    }

    #[test]
    fn rejection_codes_are_stable() {
        assert_eq!(
            SoloReplacementRejection::ChangeRemovedOrDust.code(),
            "change_removed_or_dust"
        );
        assert_eq!(
            SoloReplacementRejection::FundingInputsChanged.code(),
            "funding_inputs_changed"
        );
    }
}
