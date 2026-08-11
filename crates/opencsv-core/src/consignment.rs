//! The consignment — the off-chain sender→recipient message (paper §4.8).

use serde::{Deserialize, Serialize};

use crate::asset::AssetGenesis;
use crate::asset::AssetId;
use crate::chain::AnchorRef;
use crate::coin::{Coin, Commitment, Owner};
use crate::digest::Digest;

/// The opening of one recipient output coin: `(asset_id, v_i, owner_i, r_i)`
/// (paper §4.8).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoinOpening {
    /// Asset of this output.
    pub asset_id: AssetId,
    /// Value in base units.
    pub value: u64,
    /// Owner public key of the recipient.
    pub owner: Owner,
    /// Hiding randomness.
    pub randomness: Digest,
}

impl CoinOpening {
    /// Reconstruct the coin from its opening.
    pub fn to_coin(&self) -> Coin {
        Coin {
            asset_id: self.asset_id,
            value: self.value,
            owner: self.owner,
            randomness: self.randomness,
        }
    }

    /// The coin's commitment `C` (paper §4.3).
    pub fn commitment(&self) -> Commitment {
        self.to_coin().commitment()
    }

    /// Canonical byte encoding used in proof public inputs:
    /// `asset_id(32) ∥ v(8 LE) ∥ owner(32) ∥ r(32)`.
    pub fn to_public_input_bytes(&self) -> [u8; 104] {
        let mut out = [0u8; 104];
        out[0..32].copy_from_slice(self.asset_id.as_bytes());
        out[32..40].copy_from_slice(&self.value.to_le_bytes());
        out[40..72].copy_from_slice(self.owner.as_bytes());
        out[72..104].copy_from_slice(self.randomness.as_bytes());
        out
    }
}

/// A consignment: the off-chain message delivering coins to a recipient
/// (paper §4.8).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Consignment {
    /// Openings of the recipient's output coins.
    pub coin_openings: Vec<CoinOpening>,
    /// Raw nullifiers of the consumed coins (empty for mints; for
    /// compressed transfers, the full list the anchor's bound commitment
    /// hashes). These travel **only** off-chain — on-chain records carry
    /// bound payloads `H("bind" ∥ nf ∥ ctx)` — and let the recipient
    /// recognize occurrences of its nullifiers (see `crate::chain`).
    pub nullifiers: Vec<Digest>,
    /// Opaque PCD proof bytes `π` for the transaction.
    pub proof: Vec<u8>,
    /// Where the transaction's anchor sits on the L1.
    pub anchor_ref: AnchorRef,
    /// Genesis parameters, present iff the asset may be unknown to the
    /// recipient (paper §4.8 `aux`).
    pub aux: Option<AssetGenesis>,
}

/// Error decoding a serialized consignment.
#[derive(Debug)]
pub struct ConsignmentError(String);

impl std::fmt::Display for ConsignmentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid consignment encoding: {}", self.0)
    }
}

impl std::error::Error for ConsignmentError {}

impl Consignment {
    /// Serialize with bincode (serde data model).
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serde::encode_to_vec(self, bincode::config::standard())
            .expect("consignment serialization is infallible")
    }

    /// Parse a consignment produced by [`Consignment::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ConsignmentError> {
        let (consignment, read) =
            bincode::serde::decode_from_slice(bytes, bincode::config::standard())
                .map_err(|e| ConsignmentError(e.to_string()))?;
        if read != bytes.len() {
            return Err(ConsignmentError("trailing bytes".into()));
        }
        Ok(consignment)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::AnchorLocation;
    use crate::digest::BABY_BEAR_P;

    fn consignment_with_nullifiers(nullifiers: Vec<Digest>) -> Consignment {
        Consignment {
            coin_openings: vec![],
            nullifiers,
            proof: vec![],
            anchor_ref: AnchorRef {
                txid: [0u8; 32],
                location: AnchorLocation {
                    height: 1,
                    position: 0,
                },
            },
            aux: None,
        }
    }

    /// A nullifier digest with one limb bumped by `p` is a non-canonical
    /// twin encoding of another field element: decoding must reject it.
    #[test]
    fn from_bytes_rejects_non_canonical_nullifier_limb() {
        let mut twin = [7u8; 32];
        let bumped = u32::from_le_bytes(twin[0..4].try_into().unwrap()) + BABY_BEAR_P;
        twin[0..4].copy_from_slice(&bumped.to_le_bytes());
        let forged = consignment_with_nullifiers(vec![Digest::from_bytes(twin)]);
        assert!(Consignment::from_bytes(&forged.to_bytes()).is_err());

        // The canonical encoding of the same consignment still decodes.
        let canonical = consignment_with_nullifiers(vec![Digest::from_bytes([7u8; 32])]);
        let bytes = canonical.to_bytes();
        assert_eq!(Consignment::from_bytes(&bytes).unwrap(), canonical);
    }
}
