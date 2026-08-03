//! Pure receiver accept decision. All networking, chain reads, proof
//! verification, key derivation and storage stay in the host driver; this
//! module receives only explicit observations and deterministically chooses
//! accept or a stable rejection reason.

use crate::types::{Location, Payload};

/// Result of validating the consignment's asset/genesis relationship.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssetObservation {
    /// Every opening names a pinned asset, or a supplied genesis matches all
    /// openings.
    Valid,
    /// Supplied genesis data does not identify every opening's asset.
    GenesisMismatch,
    /// At least one opening names an unpinned asset and no genesis was supplied.
    UnknownAsset,
}

/// The first-occurrence observation for one nullifier occurrence key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OccurrenceObservation {
    /// Truncated occurrence key included in stable conflict evidence.
    pub nullifier: Payload,
    /// First canonical occurrence, or `None` when the chain view cannot find it.
    pub first: Option<Location>,
}

/// Observed state of the referenced anchor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AnchorObservation {
    /// Record, context or canonical location lookup failed.
    Missing,
    /// All anchor-dependent facts observed by the host driver.
    Present {
        /// Canonical anchor location.
        location: Location,
        /// Confirmation depth at the observed chain tip.
        confirmations: u64,
        /// Whether the record binds exactly the consignment's nullifiers.
        binds_nullifiers: bool,
        /// First-occurrence observations in consignment order.
        occurrences: Vec<OccurrenceObservation>,
    },
}

/// Complete, explicit input to [`decide`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptInput {
    /// Whether the consignment carries at least one coin opening.
    pub has_openings: bool,
    /// Asset/genesis validation result.
    pub asset: AssetObservation,
    /// Referenced anchor and chain observations.
    pub anchor: AnchorObservation,
    /// Result already returned by the configured proof verifier.
    pub proof_valid: bool,
    /// Confirmation policy supplied by the host.
    pub required_confirmations: u64,
    /// Whether at least one opening belongs to the recipient.
    pub has_owned_output: bool,
}

/// Stable reason codes returned by [`decide`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejectReason {
    /// The consignment carries no coin openings.
    EmptyConsignment,
    /// Supplied genesis does not match the openings.
    GenesisMismatch,
    /// An opening names an unpinned asset without genesis data.
    UnknownAsset,
    /// Record, context, location or required occurrence lookup failed.
    AnchorNotFound,
    /// The anchor has insufficient confirmation depth.
    InsufficientConfirmations {
        /// Observed confirmation depth.
        have: u64,
        /// Required confirmation depth.
        required: u64,
    },
    /// A nullifier's first occurrence is not the referenced anchor.
    NullifierConflict {
        /// Truncated occurrence key.
        nullifier: Payload,
        /// First canonical occurrence.
        first: Location,
    },
    /// The record does not bind exactly the supplied nullifiers.
    IllFormedAnchor,
    /// The configured proof verifier rejected the proof.
    InvalidProof,
    /// No opening belongs to the recipient.
    NoOwnedOutput,
}

impl RejectReason {
    /// Stable machine-readable code for logs, FFI and persistence.
    pub const fn code(self) -> &'static str {
        match self {
            Self::EmptyConsignment => "empty_consignment",
            Self::GenesisMismatch => "genesis_mismatch",
            Self::UnknownAsset => "unknown_asset",
            Self::AnchorNotFound => "anchor_not_found",
            Self::InsufficientConfirmations { .. } => "insufficient_confirmations",
            Self::NullifierConflict { .. } => "nullifier_conflict",
            Self::IllFormedAnchor => "ill_formed_anchor",
            Self::InvalidProof => "invalid_proof",
            Self::NoOwnedOutput => "no_owned_output",
        }
    }
}

/// Deterministic accept result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcceptDecision {
    /// All checks passed for the referenced canonical anchor.
    Accept {
        /// Canonical accepted anchor location.
        anchor: Location,
    },
    /// A stable protocol/policy rejection.
    Reject(RejectReason),
}

/// Evaluate checks that precede all chain and proof work.
pub fn preflight_rejection(has_openings: bool, asset: AssetObservation) -> Option<RejectReason> {
    if !has_openings {
        return Some(RejectReason::EmptyConsignment);
    }
    match asset {
        AssetObservation::Valid => None,
        AssetObservation::GenesisMismatch => Some(RejectReason::GenesisMismatch),
        AssetObservation::UnknownAsset => Some(RejectReason::UnknownAsset),
    }
}

/// Evaluate anchor presence before proof verification.
pub fn anchor_rejection(anchor_present: bool) -> Option<RejectReason> {
    if anchor_present {
        None
    } else {
        Some(RejectReason::AnchorNotFound)
    }
}

/// Evaluate the externally verified proof result.
pub fn proof_rejection(proof_valid: bool) -> Option<RejectReason> {
    if proof_valid {
        None
    } else {
        Some(RejectReason::InvalidProof)
    }
}

/// Evaluate confirmation depth and exact record/nullifier binding.
pub fn chain_prefix_rejection(
    confirmations: u64,
    required_confirmations: u64,
    binds_nullifiers: bool,
) -> Option<RejectReason> {
    if confirmations < required_confirmations {
        return Some(RejectReason::InsufficientConfirmations {
            have: confirmations,
            required: required_confirmations,
        });
    }
    if binds_nullifiers {
        None
    } else {
        Some(RejectReason::IllFormedAnchor)
    }
}

/// Evaluate first-occurrence observations in their canonical input order.
pub fn occurrence_rejection(
    anchor: Location,
    occurrences: &[OccurrenceObservation],
) -> Option<RejectReason> {
    let mut index = 0usize;
    while index < occurrences.len() {
        let occurrence = occurrences[index];
        let Some(first) = occurrence.first else {
            return Some(RejectReason::AnchorNotFound);
        };
        if first != anchor {
            return Some(RejectReason::NullifierConflict {
                nullifier: occurrence.nullifier,
                first,
            });
        }
        index += 1;
    }
    None
}

/// Pure accept/reject boundary. Checks retain the historical driver order so
/// multiple simultaneous failures always select the same stable reason.
pub fn decide(input: &AcceptInput) -> AcceptDecision {
    if let Some(reason) = preflight_rejection(input.has_openings, input.asset) {
        return AcceptDecision::Reject(reason);
    }
    let AnchorObservation::Present {
        location,
        confirmations,
        binds_nullifiers,
        occurrences,
    } = &input.anchor
    else {
        return AcceptDecision::Reject(RejectReason::AnchorNotFound);
    };
    if let Some(reason) = proof_rejection(input.proof_valid) {
        return AcceptDecision::Reject(reason);
    }
    if let Some(reason) = chain_prefix_rejection(
        *confirmations,
        input.required_confirmations,
        *binds_nullifiers,
    ) {
        return AcceptDecision::Reject(reason);
    }
    if let Some(reason) = occurrence_rejection(*location, occurrences) {
        return AcceptDecision::Reject(reason);
    }
    if !input.has_owned_output {
        return AcceptDecision::Reject(RejectReason::NoOwnedOutput);
    }
    AcceptDecision::Accept { anchor: *location }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn location(height: u64, position: u32) -> Location {
        Location { height, position }
    }

    fn accepted_input() -> AcceptInput {
        let anchor = location(10, 2);
        AcceptInput {
            has_openings: true,
            asset: AssetObservation::Valid,
            anchor: AnchorObservation::Present {
                location: anchor,
                confirmations: 6,
                binds_nullifiers: true,
                occurrences: vec![OccurrenceObservation {
                    nullifier: [7u8; 24],
                    first: Some(anchor),
                }],
            },
            proof_valid: true,
            required_confirmations: 6,
            has_owned_output: true,
        }
    }

    #[test]
    fn accepts_complete_valid_observations() {
        assert_eq!(
            decide(&accepted_input()),
            AcceptDecision::Accept {
                anchor: location(10, 2)
            }
        );
    }

    #[test]
    fn rejection_precedence_is_stable() {
        let mut input = accepted_input();
        input.has_openings = false;
        input.asset = AssetObservation::GenesisMismatch;
        input.anchor = AnchorObservation::Missing;
        input.proof_valid = false;
        input.has_owned_output = false;
        assert_eq!(
            decide(&input),
            AcceptDecision::Reject(RejectReason::EmptyConsignment)
        );

        input.has_openings = true;
        assert_eq!(
            decide(&input),
            AcceptDecision::Reject(RejectReason::GenesisMismatch)
        );

        input.asset = AssetObservation::Valid;
        assert_eq!(
            decide(&input),
            AcceptDecision::Reject(RejectReason::AnchorNotFound)
        );
    }

    #[test]
    fn confirmation_binding_occurrence_and_ownership_order_is_stable() {
        let anchor = location(10, 2);
        let conflict = location(9, 1);
        let mut input = accepted_input();
        input.proof_valid = false;
        input.anchor = AnchorObservation::Present {
            location: anchor,
            confirmations: 1,
            binds_nullifiers: false,
            occurrences: vec![OccurrenceObservation {
                nullifier: [4u8; 24],
                first: Some(conflict),
            }],
        };
        input.has_owned_output = false;
        assert_eq!(
            decide(&input),
            AcceptDecision::Reject(RejectReason::InvalidProof)
        );

        input.proof_valid = true;
        assert_eq!(
            decide(&input),
            AcceptDecision::Reject(RejectReason::InsufficientConfirmations {
                have: 1,
                required: 6,
            })
        );

        if let AnchorObservation::Present { confirmations, .. } = &mut input.anchor {
            *confirmations = 6;
        }
        assert_eq!(
            decide(&input),
            AcceptDecision::Reject(RejectReason::IllFormedAnchor)
        );
        if let AnchorObservation::Present {
            binds_nullifiers, ..
        } = &mut input.anchor
        {
            *binds_nullifiers = true;
        }
        assert_eq!(
            decide(&input),
            AcceptDecision::Reject(RejectReason::NullifierConflict {
                nullifier: [4u8; 24],
                first: conflict,
            })
        );

        if let AnchorObservation::Present { occurrences, .. } = &mut input.anchor {
            occurrences[0].first = Some(anchor);
        }
        assert_eq!(
            decide(&input),
            AcceptDecision::Reject(RejectReason::NoOwnedOutput)
        );
    }

    #[test]
    fn missing_occurrence_is_anchor_not_found() {
        let mut input = accepted_input();
        if let AnchorObservation::Present { occurrences, .. } = &mut input.anchor {
            occurrences[0].first = None;
        }
        assert_eq!(
            decide(&input),
            AcceptDecision::Reject(RejectReason::AnchorNotFound)
        );
    }

    #[test]
    fn rejection_codes_are_unique_and_stable() {
        let reasons = [
            RejectReason::EmptyConsignment,
            RejectReason::GenesisMismatch,
            RejectReason::UnknownAsset,
            RejectReason::AnchorNotFound,
            RejectReason::InsufficientConfirmations {
                have: 0,
                required: 1,
            },
            RejectReason::NullifierConflict {
                nullifier: [0u8; 24],
                first: location(0, 0),
            },
            RejectReason::IllFormedAnchor,
            RejectReason::InvalidProof,
            RejectReason::NoOwnedOutput,
        ];
        let mut codes: Vec<_> = reasons.iter().map(|reason| reason.code()).collect();
        let original_len = codes.len();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), original_len);
    }
}
