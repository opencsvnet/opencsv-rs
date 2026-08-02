//! Public supply audit (mirror of `opencsv-core::audit::supply`, paper
//! §4.9):
//!
//! ```text
//! supply(asset_id, h) =  Σ V  over MINT anchors with this asset_id up to h
//!                      − Σ V  over REDEEM anchors with this asset_id up to h
//! ```
//!
//! Anchor records are copyable bytes, so identical MINT anchors are
//! **deduplicated**: each distinct `mint_commit` counts once per asset.

use crate::record::Record;
use crate::types::{AssetId24, Location, MintCommit};

/// Failure modes of [`supply`] (mirror of `audit::SupplyError`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SupplyError {
    /// Redemptions exceed mints at the requested height — the anchored
    /// stream is inconsistent (only possible on an adversarial/corrupt
    /// chain view).
    NegativeSupply,
}

/// Does `seen` already contain `commit`? (Linear scan — no `HashSet` in
/// the verification surface.)
fn seen_contains(seen: &[MintCommit], commit: &MintCommit) -> bool {
    let mut i = 0usize;
    while i < seen.len() {
        if seen[i] == *commit {
            return true;
        }
        i += 1;
    }
    false
}

/// Compute the public per-asset supply at `height` (paper §4.9), over the
/// anchor records with location at or below `height`, in canonical order.
///
/// Mirror of `audit::supply`: MINT records with a matching asset count
/// once per distinct `mint_commit`; REDEEM records with a matching asset
/// subtract; everything else is ignored. Fails with
/// [`SupplyError::NegativeSupply`] if redemptions exceed mints.
pub fn supply(
    anchors: &[(Location, Record)],
    asset_id: &AssetId24,
    height: u64,
) -> Result<u64, SupplyError> {
    let mut seen_mints: Vec<MintCommit> = Vec::new();
    let mut total: i128 = 0;
    let mut i = 0usize;
    while i < anchors.len() {
        let (location, record) = &anchors[i];
        if location.height <= height {
            // Note: match by value (Aeneas chokes on by-reference matches
            // inside loops); `Record` is `Copy`, so this is free.
            match *record {
                Record::Mint {
                    asset_id: record_asset,
                    value,
                    mint_commit,
                } => {
                    if record_asset == *asset_id && !seen_contains(&seen_mints, &mint_commit) {
                        seen_mints.push(mint_commit);
                        total += i128::from(value);
                    }
                }
                Record::Redeem {
                    asset_id: record_asset,
                    value,
                    ..
                } => {
                    if record_asset == *asset_id {
                        total -= i128::from(value);
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }
    if total < 0 || total > i128::from(u64::MAX) {
        Err(SupplyError::NegativeSupply)
    } else {
        Ok(total as u64)
    }
}
