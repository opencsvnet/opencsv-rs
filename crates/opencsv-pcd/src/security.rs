//! Security accounting for the frozen authenticated v3/v4 FRI profile.
//!
//! The Plonky3 calculator reports a per-instance round-by-round bound. A
//! coin proof batches several AIR instances, so this module additionally
//! subtracts conservative union-bound margins for protocol components and
//! the number of batch instances. Verification fails closed if a proof's
//! actual trace degrees fall below the published deployment floor.

use p3_uni_stark::{ConjecturedSecurity, ProvenSecurity, StarkSecurityParams};

use crate::node::{CoinProof, NodeError, LEGACY_COIN_PROOF_VERSION};
use crate::recursion_config::CoinFriParams;

/// Stable identifier for the current proof-lineage-v4 production profile.
pub const COIN_PROOF_PROFILE_ID: &str =
    "opencsv-pcd-v4-babybear4-fri-b3-a4-q64-cpow16-qpow16-final4-pack1x3-horner4";
/// Stable identifier for the authenticated legacy-v3 compatibility profile.
pub const LEGACY_COIN_PROOF_PROFILE_ID: &str =
    "opencsv-pcd-v3-babybear4-fri-b3-a4-q64-cpow16-qpow16-final4-pack1x3-horner4";
/// Accept-driver tag for the v4 verifier with explicit v3 compatibility.
pub const COIN_VK_TAG: &[u8] = b"opencsv-pcd-coin-v4-with-v3-fri94";

/// Conservative floor(log2(|BabyBear^4|)).
const CHALLENGE_FIELD_BITS: usize = 123;
/// Poseidon2 commitment collision-resistance target.
const COMMITMENT_COLLISION_BITS: usize = 128;
/// Lookup-expanded constraint budget across every AIR in one batch.
pub(crate) const MAX_BATCH_CONSTRAINTS: usize = 1024;
/// Maximum lookup-expanded AIR constraint degree admitted by this profile.
pub(crate) const MAX_AIR_CONSTRAINT_DEGREE: usize = 3;
/// Standard local/next out-of-domain opening combination.
const MAX_COMBO: usize = 2;
/// Conservative margin for the round components omitted by the calculator's
/// `min` aggregation. The calculator has four soundness components (ALI,
/// DEEP, FRI commit, FRI query), so a conservative max-to-sum conversion is
/// `ceil(log2(4)) = 2` bits.
const COMPONENT_UNION_BITS: usize = 2;

/// Minimum union-adjusted proven-security estimate accepted at runtime.
pub const PRODUCTION_SECURITY_TARGET_BITS: usize = 94;

/// Security receipt for one concrete batch proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofSecurityReport {
    /// Exact profile identifier.
    pub profile_id: &'static str,
    /// Random-words conjectured estimate, capped by the challenge field.
    pub conjectured_bits: usize,
    /// Minimum proven per-instance estimate across the proof's actual traces.
    pub proven_bits: usize,
    /// Conservative batch/component union-bound margin.
    pub union_bound_bits: usize,
    /// `proven_bits - union_bound_bits`.
    pub union_adjusted_bits: usize,
    /// Actual extended trace degree bits carried by the proof.
    pub degree_bits: Vec<usize>,
}

fn security_params() -> StarkSecurityParams {
    let fp = CoinFriParams::production();
    StarkSecurityParams {
        fri_log_blowup: fp.log_blowup,
        fri_log_final_poly_len: fp.log_final_poly_len,
        fri_max_log_arity: fp.max_log_arity,
        fri_num_queries: fp.num_queries,
        fri_commit_proof_of_work_bits: fp.commit_proof_of_work_bits,
        fri_query_proof_of_work_bits: fp.query_proof_of_work_bits,
        num_modulus_bits: CHALLENGE_FIELD_BITS,
        collision_resistance: COMMITMENT_COLLISION_BITS,
        num_constraints: MAX_BATCH_CONSTRAINTS,
        air_max_constraint_degree: MAX_AIR_CONSTRAINT_DEGREE,
        max_combo: MAX_COMBO,
    }
}

fn ceil_log2(value: usize) -> usize {
    if value <= 1 {
        0
    } else {
        usize::BITS as usize - (value - 1).leading_zeros() as usize
    }
}

/// Calculate the frozen profile's conservative security receipt against a
/// proof's actual extended trace degrees.
pub fn proof_security_report(proof: &CoinProof) -> ProofSecurityReport {
    let params = security_params();
    let conjectured_bits = ConjecturedSecurity::compute_from_params(&params).security_bits;
    let degree_bits = proof.proof.proof.degree_bits.clone();
    let proven_bits = degree_bits
        .iter()
        .map(|&degree| ProvenSecurity::compute_from_proof(degree, &params).security_bits())
        .min()
        .unwrap_or(0);
    let union_bound_bits = COMPONENT_UNION_BITS + ceil_log2(degree_bits.len());
    ProofSecurityReport {
        profile_id: if proof.version == LEGACY_COIN_PROOF_VERSION {
            LEGACY_COIN_PROOF_PROFILE_ID
        } else {
            COIN_PROOF_PROFILE_ID
        },
        conjectured_bits,
        proven_bits,
        union_bound_bits,
        union_adjusted_bits: proven_bits.saturating_sub(union_bound_bits),
        degree_bits,
    }
}

/// Fail closed when proof growth moves the concrete batch below the frozen
/// production security floor.
pub(crate) fn validate_proof_security(proof: &CoinProof) -> Result<(), NodeError> {
    let report = proof_security_report(proof);
    if report.union_adjusted_bits < PRODUCTION_SECURITY_TARGET_BITS {
        return Err(NodeError::InsufficientProofSecurity {
            actual: report.union_adjusted_bits,
            required: PRODUCTION_SECURITY_TARGET_BITS,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_profile_values_are_explicit() {
        let fp = CoinFriParams::production();
        assert_eq!(fp.log_blowup, 3);
        assert_eq!(fp.max_log_arity, 2);
        assert_eq!(fp.log_final_poly_len, 2);
        assert_eq!(fp.num_queries, 64);
        assert_eq!(fp.commit_proof_of_work_bits, 16);
        assert_eq!(fp.query_proof_of_work_bits, 16);
        assert_eq!(
            ConjecturedSecurity::compute_from_params(&security_params()).security_bits,
            123
        );
    }

    #[test]
    fn trace_growth_crosses_the_fail_closed_floor() {
        let params = security_params();
        let at_limit = ProvenSecurity::compute_from_proof(18, &params).security_bits();
        let beyond_limit = ProvenSecurity::compute_from_proof(19, &params).security_bits();
        let batch_margin = COMPONENT_UNION_BITS + ceil_log2(7);
        assert_eq!(at_limit.saturating_sub(batch_margin), 94);
        assert!(beyond_limit.saturating_sub(batch_margin) < PRODUCTION_SECURITY_TARGET_BITS);
    }
}
