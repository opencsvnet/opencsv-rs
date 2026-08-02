//! Asset genesis parameters and asset identifiers (paper §4.2).

use serde::{Deserialize, Serialize};

use crate::digest::Digest;
use crate::field::{bytes_to_felts, hash_felts, u64_to_felts};

/// An asset identifier: `asset_id = H("OpenCSV-asset" ∥ G)`.
pub type AssetId = Digest;

/// Genesis parameters of an asset, published out-of-band by the issuer and
/// pinned into clients trust-on-first-use (paper §4.2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetGenesis {
    /// Poseidon2 commitment to the issuer seed for new assets. Legacy
    /// prototype records may contain an Ed25519 public key and are read-only.
    pub issuer_pk: [u8; 32],
    /// ISO-4217-style currency code, e.g. `b"USD"`.
    pub currency_code: [u8; 3],
    /// Hash of the asset's human/legal terms (redemption policy, fees, …).
    pub terms_hash: Digest,
    /// Domain separation across assets sharing `(issuer_pk, currency_code)`.
    pub nonce: u64,
}

impl AssetGenesis {
    /// `asset_id := H("OpenCSV-asset" ∥ G)` (paper §4.2).
    pub fn asset_id(&self) -> AssetId {
        hash_felts(
            "OpenCSV-asset",
            &[
                &bytes_to_felts(&self.issuer_pk),
                &bytes_to_felts(&self.currency_code),
                &self.terms_hash.to_elems(),
                &u64_to_felts(self.nonce),
            ],
        )
    }
}
