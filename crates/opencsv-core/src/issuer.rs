//! Issuer authorization (paper §4.1, §4.4).
//!
//! New assets use [`PoseidonIssuerAuthorization`]: the public key is a
//! domain-separated Poseidon2 commitment to a 32-byte issuer seed. The mint
//! PCD circuit proves knowledge of that seed, binds the derived key through
//! [`crate::AssetGenesis`] to the asset id, and constrains the exact mint
//! statement in the same proof. The resulting non-interactive PCD proof is
//! the transferable signature-of-knowledge; no reusable secret material or
//! standalone signature bytes are disclosed.
//!
//! [`Ed25519IssuerSignature`] remains solely for recognizing/exporting legacy
//! prototype records. New mint paths do not use it, because the old signature
//! was never carried in consignments and therefore could not authorize a mint
//! at the receiver's verification boundary.

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

use crate::asset::AssetId;
use crate::digest::Digest;
use crate::field::{bytes_to_felts, hash_felts};

/// Domain separation for the Poseidon issuer-key commitment.
pub const POSEIDON_ISSUER_KEY_DOMAIN: &str = "issuer-key-v1";

/// AIR-native issuer authorization for version-2 mint proofs.
///
/// This type creates the long-lived key commitment. Verification of a mint
/// authorization is performed by the PCD circuit as a proof of knowledge,
/// not by a standalone `verify(pk, msg, sig)` function.
pub struct PoseidonIssuerAuthorization;

impl PoseidonIssuerAuthorization {
    /// Derive `(secret_seed, public_key)` from a 32-byte seed.
    pub fn keypair_from_seed(seed: [u8; 32]) -> ([u8; 32], [u8; 32]) {
        (seed, Self::public_key(&seed))
    }

    /// Derive the public key committed to by a version-2 mint circuit.
    pub fn public_key(seed: &[u8; 32]) -> [u8; 32] {
        *hash_felts(POSEIDON_ISSUER_KEY_DOMAIN, &[&bytes_to_felts(seed)]).as_bytes()
    }

    /// Return whether a stored seed controls `public_key` under this scheme.
    pub fn controls(seed: &[u8; 32], public_key: &[u8; 32]) -> bool {
        Self::public_key(seed) == *public_key
    }
}

/// An issuer signature scheme `Σ` with interface
/// `Σ.Verify(ipk, m, σ) ∈ {0,1}` (paper §4.1).
pub trait IssuerSignature {
    /// Issuer public key (`ipk`).
    type PublicKey;
    /// Issuer secret key (`isk`).
    type SecretKey;
    /// Signature (`σ`).
    type Signature;

    /// Sign a message with the issuer's secret key.
    fn sign(sk: &Self::SecretKey, msg: &[u8]) -> Self::Signature;
    /// Verify a signature against the issuer's public key.
    fn verify(pk: &Self::PublicKey, msg: &[u8], sig: &Self::Signature) -> bool;
}

/// Ed25519 issuer signatures — **legacy prototype records only**.
///
/// This scheme is not accepted by version-2 mint proving. See module docs.
#[deprecated(note = "legacy only; use PoseidonIssuerAuthorization for new assets")]
pub struct Ed25519IssuerSignature;

#[allow(deprecated)]
impl Ed25519IssuerSignature {
    /// Derive the keypair for a 32-byte secret seed.
    pub fn keypair_from_seed(seed: [u8; 32]) -> ([u8; 32], [u8; 32]) {
        let sk = SigningKey::from_bytes(&seed);
        (sk.to_bytes(), sk.verifying_key().to_bytes())
    }
}

#[allow(deprecated)]
impl IssuerSignature for Ed25519IssuerSignature {
    type PublicKey = [u8; 32];
    type SecretKey = [u8; 32];
    type Signature = [u8; 64];

    fn sign(sk: &Self::SecretKey, msg: &[u8]) -> Self::Signature {
        SigningKey::from_bytes(sk).sign(msg).to_bytes()
    }

    fn verify(pk: &Self::PublicKey, msg: &[u8], sig: &Self::Signature) -> bool {
        let Ok(vk) = VerifyingKey::from_bytes(pk) else {
            return false;
        };
        vk.verify_strict(msg, &ed25519_dalek::Signature::from_bytes(sig))
            .is_ok()
    }
}

/// The message signed by the issuer to authorize a mint:
/// `"OpenCSV-mint" ∥ asset_id ∥ V ∥ mint_nonce` (paper §4.4 item 1; the mint
/// AIR checks `Σ.Verify(ipk, (asset_id, V, mint_nonce), σ) = 1`).
pub fn mint_signing_message(asset_id: &AssetId, value: u64, mint_nonce: &Digest) -> Vec<u8> {
    let mut msg = Vec::with_capacity(11 + 32 + 8 + 32);
    msg.extend_from_slice(b"OpenCSV-mint");
    msg.extend_from_slice(asset_id.as_bytes());
    msg.extend_from_slice(&value.to_le_bytes());
    msg.extend_from_slice(mint_nonce.as_bytes());
    msg
}
