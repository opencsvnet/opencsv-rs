//! Public supply audit (paper §4.9).
//!
//! ```text
//! supply(asset_id, h) =  Σ V  over MINT anchors with this asset_id up to h
//!                      − Σ V  over REDEEM anchors with this asset_id up to h
//! ```
//!
//! Anyone with chain data computes this with a linear scan — no proofs, no
//! issuer cooperation. Conservation (paper §4.5 item 2) guarantees shielded
//! transfers neither create nor destroy value, so they are ignored here.
//!
//! Anchor records are copyable bytes, so identical MINT anchors are
//! **deduplicated**: each distinct `mint_commit` counts once per asset (a
//! byte-copied mint must not double-count; `mint_commit` binds
//! `asset_id ∥ V ∥ mint_nonce`, so a genuine second mint of the same asset
//! has a fresh nonce and a fresh commitment).

use std::collections::HashSet;

use crate::anchor::AnchorRecord;
use crate::asset::AssetId;
use crate::chain::AnchorChain;
use crate::digest::TruncatedDigest;

/// Failure modes of [`supply`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SupplyError {
    /// Redemptions exceed mints at the requested height — the anchored stream
    /// is inconsistent (only possible on an adversarial/corrupt chain view).
    NegativeSupply,
}

impl std::fmt::Display for SupplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NegativeSupply => write!(f, "redemptions exceed mints at requested height"),
        }
    }
}

impl std::error::Error for SupplyError {}

/// Compute the public per-asset supply at `height` (paper §4.9).
pub fn supply<C: AnchorChain>(
    chain: &C,
    asset_id: &AssetId,
    height: u64,
) -> Result<u64, SupplyError> {
    let target = asset_id.to_anchor();
    let mut seen_mints: HashSet<TruncatedDigest> = HashSet::new();
    let mut total: i128 = 0;
    for (_, record) in chain.anchors_up_to(height) {
        match record {
            AnchorRecord::Mint {
                asset_id,
                value,
                mint_commit,
            } if asset_id == target && seen_mints.insert(mint_commit) => {
                total += i128::from(value);
            }
            AnchorRecord::Redeem {
                asset_id, value, ..
            } if asset_id == target => total -= i128::from(value),
            _ => {}
        }
    }
    u64::try_from(total).map_err(|_| SupplyError::NegativeSupply)
}
