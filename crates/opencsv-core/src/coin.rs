//! Coins, commitments, nullifiers, and owner keys (paper §4.3).

use serde::{Deserialize, Deserializer, Serialize};

use crate::asset::AssetId;
use crate::digest::Digest;
use crate::field::{bytes_to_felts, hash_felts, u64_to_felts};

/// A coin commitment: `C = H("coin" ∥ asset_id ∥ v ∥ owner ∥ r)`.
pub type Commitment = Digest;
/// A coin nullifier: `nf = H("null" ∥ osk ∥ C)`. Publishing `nf` is the spend.
pub type Nullifier = Digest;
/// An owner's public key: `owner = H(osk)`.
pub type Owner = Digest;

/// Owner secret key. 32 bytes of entropy; the corresponding public key is
/// `owner = H(osk)` (paper §4.3).
#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
pub struct OwnerSecret(pub Digest);

impl<'de> Deserialize<'de> for OwnerSecret {
    /// Same wire format as the inner digest, but without `Digest`'s
    /// canonical-limb rejection: an osk is local secret entropy, never an
    /// untrusted encoding, and existing key files predate the canonicality
    /// rule. Identity-bearing digests must keep the strict `Digest` path.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Self(Digest::from_bytes(<[u8; 32]>::deserialize(
            deserializer,
        )?)))
    }
}

impl OwnerSecret {
    /// Wrap 32 bytes of secret entropy.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Digest::from_bytes(bytes))
    }

    /// `owner = H(osk)` (paper §4.3; note the paper specifies no domain tag
    /// here — the hash input is the secret alone).
    pub fn owner(&self) -> Owner {
        hash_felts("", &[&bytes_to_felts(self.0.as_bytes())])
    }
}

impl std::fmt::Debug for OwnerSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OwnerSecret(<redacted>)")
    }
}

/// A coin: `coin = (asset_id, v, owner, r)` (paper §4.3).
///
/// Note on `r`: the paper writes `r ←$ 𝔽` (a single field element). A single
/// BabyBear element carries only ~31 bits, far too little to make the
/// commitment hiding, so this implementation draws `r` as a full 32-byte
/// digest (8 field elements). To be reconciled with the paper.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Coin {
    /// Asset this coin is denominated in.
    pub asset_id: AssetId,
    /// Value in the asset's base units, `0 ≤ v < 2^64`.
    pub value: u64,
    /// Owner public key, `owner = H(osk)`.
    pub owner: Owner,
    /// Hiding randomness (see type-level note).
    pub randomness: Digest,
}

impl Coin {
    /// `C := H("coin" ∥ asset_id ∥ v ∥ owner ∥ r)` (paper §4.3).
    pub fn commitment(&self) -> Commitment {
        hash_felts(
            "coin",
            &[
                &self.asset_id.to_elems(),
                &u64_to_felts(self.value),
                &self.owner.to_elems(),
                &self.randomness.to_elems(),
            ],
        )
    }

    /// `nf := H("null" ∥ osk ∥ C)` (paper §4.3). Computable only by whoever
    /// knows `osk` for the `owner` committed in `C`.
    pub fn nullifier(&self, osk: &OwnerSecret) -> Nullifier {
        nullifier(osk, &self.commitment())
    }
}

/// `nf := H("null" ∥ osk ∥ C)` from a secret key and a commitment.
pub fn nullifier(osk: &OwnerSecret, commitment: &Commitment) -> Nullifier {
    hash_felts(
        "null",
        &[&bytes_to_felts(osk.0.as_bytes()), &commitment.to_elems()],
    )
}
