//! Digest types produced by the scheme's Poseidon2 hash.
//!
//! A full [`Digest`] is 8 BabyBear elements serialized as canonical
//! little-endian `u32`s (32 bytes, ~248 bits). Because the on-chain anchor
//! budget is exactly 64 bytes (paper §4.4–4.6) and a `MINT`/`REDEEM` record
//! must carry *two* digests plus an 8-byte amount and a tag byte, anchors
//! carry a 24-byte prefix, [`TruncatedDigest`] (~186 bits, ~93-bit collision
//! resistance at the anchor layer). The full 32-byte digest is used for all
//! off-chain hashing (commitments, nullifiers, asset IDs). This is a
//! deviation from the paper, which both fixes the anchor at 64 bytes and
//! describes nullifiers as "64 pseudorandom bytes"; see the crate docs.

use p3_baby_bear::BabyBear;
use rand::RngExt as _;
use serde::{Deserialize, Deserializer, Serialize};

use crate::field::{elems_to_canonical_u32s, felt, DIGEST_ELEMS};

/// Byte length of a full [`Digest`].
pub const DIGEST_BYTES: usize = 32;
/// Byte length of a [`TruncatedDigest`] as carried in anchor records.
pub const TRUNCATED_DIGEST_BYTES: usize = 24;

/// The BabyBear prime `p = 2^31 − 2^27 + 1`. A digest limb is canonical iff
/// it is `< p`; since `2p < 2^32`, every canonical limb `c < 2^32 − p` has a
/// non-canonical *twin* encoding `c + p` that reduces to the same field
/// element. Twins are equal under [`Digest::to_elems`] but differ as byte
/// strings, so untrusted encodings must be rejected (see
/// [`Digest::is_canonical`]).
pub const BABY_BEAR_P: u32 = 0x7800_0001;

/// A 32-byte Poseidon2 digest (8 BabyBear elements, canonical LE `u32`s).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub struct Digest(pub [u8; DIGEST_BYTES]);

impl<'de> Deserialize<'de> for Digest {
    /// Same wire format as the derived impl — the newtype wrapper is
    /// transparent to both bincode and postcard, so the inner `[u8; 32]`
    /// is all that is on the wire — but rejects non-canonical limbs
    /// (`>= p`): a twin encoding of another field element must not cross
    /// a deserialization boundary.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let digest = Self(<[u8; DIGEST_BYTES]>::deserialize(deserializer)?);
        if !digest.is_canonical() {
            return Err(serde::de::Error::custom(
                "non-canonical digest: a little-endian u32 limb is >= BabyBear p",
            ));
        }
        Ok(digest)
    }
}

/// The 24-byte prefix of a [`Digest`] carried inside 64-byte anchor records.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TruncatedDigest(pub [u8; TRUNCATED_DIGEST_BYTES]);

impl Digest {
    /// Draw eight independent, uniformly distributed canonical BabyBear
    /// limbs. Rejection sampling avoids the bias introduced by reducing a
    /// uniform `u32` modulo `p` (because `p` does not divide `2^32`).
    pub fn random_canonical() -> Self {
        let mut bytes = [0u8; DIGEST_BYTES];
        let mut rng = rand::rng();
        for limb in bytes.chunks_exact_mut(4) {
            let canonical = loop {
                let candidate: u32 = rng.random();
                if candidate < BABY_BEAR_P {
                    break candidate;
                }
            };
            limb.copy_from_slice(&canonical.to_le_bytes());
        }
        Self(bytes)
    }

    /// Wrap raw bytes.
    ///
    /// Infallible and unchecked: the limbs may be non-canonical. Bytes
    /// from an untrusted source must be validated with
    /// [`Digest::is_canonical`] (serde deserialization already rejects
    /// non-canonical limbs).
    pub fn from_bytes(bytes: [u8; DIGEST_BYTES]) -> Self {
        Self(bytes)
    }

    /// `true` iff every little-endian `u32` limb is canonical (`< p`,
    /// see [`BABY_BEAR_P`]). Digests produced by this crate are always
    /// canonical; a non-canonical limb is a twin encoding of a smaller
    /// field element.
    pub fn is_canonical(&self) -> bool {
        self.0
            .chunks_exact(4)
            .all(|chunk| u32::from_le_bytes(chunk.try_into().expect("4-byte chunk")) < BABY_BEAR_P)
    }

    /// The digest as a byte string.
    pub fn as_bytes(&self) -> &[u8; DIGEST_BYTES] {
        &self.0
    }

    /// View the digest as 8 field elements (each `u32` limb reduced mod p).
    pub fn to_elems(&self) -> [BabyBear; DIGEST_ELEMS] {
        let mut out = [BabyBear::default(); DIGEST_ELEMS];
        for (i, chunk) in self.0.chunks_exact(4).enumerate() {
            out[i] = felt(u32::from_le_bytes(chunk.try_into().expect("4-byte chunk")));
        }
        out
    }

    pub(crate) fn from_elems(elems: &[BabyBear; DIGEST_ELEMS]) -> Self {
        let mut bytes = [0u8; DIGEST_BYTES];
        for (chunk, x) in bytes
            .chunks_exact_mut(4)
            .zip(elems_to_canonical_u32s(elems))
        {
            chunk.copy_from_slice(&x.to_le_bytes());
        }
        Self(bytes)
    }

    /// The 24-byte anchor-carrying prefix of this digest.
    pub fn to_anchor(&self) -> TruncatedDigest {
        let mut out = [0u8; TRUNCATED_DIGEST_BYTES];
        out.copy_from_slice(&self.0[..TRUNCATED_DIGEST_BYTES]);
        TruncatedDigest(out)
    }
}

impl TruncatedDigest {
    /// The digest prefix as a byte string.
    pub fn as_bytes(&self) -> &[u8; TRUNCATED_DIGEST_BYTES] {
        &self.0
    }
}

impl std::fmt::Debug for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Digest(0x{})", hex(&self.0))
    }
}

impl std::fmt::Debug for TruncatedDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TruncatedDigest(0x{})", hex(&self.0))
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The digest with every limb set to `c`, plus its non-canonical twin
    /// with limb 0 bumped by `p` (the same field element, a different byte
    /// string).
    fn twin_pair(c: u8) -> (Digest, Digest) {
        let canonical = Digest::from_bytes([c; DIGEST_BYTES]);
        let mut twin = *canonical.as_bytes();
        let bumped = u32::from_le_bytes(twin[0..4].try_into().unwrap()) + BABY_BEAR_P;
        twin[0..4].copy_from_slice(&bumped.to_le_bytes());
        (canonical, Digest::from_bytes(twin))
    }

    #[test]
    fn canonicality_tracks_limbs_against_p() {
        let (canonical, twin) = twin_pair(7);
        assert!(canonical.is_canonical());
        assert!(!twin.is_canonical());
        // The twin is a different byte string for the same field elements.
        assert_ne!(canonical, twin);
        assert_eq!(canonical.to_elems(), twin.to_elems());
        // Boundary: `p - 1` is canonical, `p` itself is not.
        let mut limb = [0u8; DIGEST_BYTES];
        limb[0..4].copy_from_slice(&(BABY_BEAR_P - 1).to_le_bytes());
        assert!(Digest::from_bytes(limb).is_canonical());
        limb[0..4].copy_from_slice(&BABY_BEAR_P.to_le_bytes());
        assert!(!Digest::from_bytes(limb).is_canonical());
    }

    #[test]
    fn bincode_round_trip_rejects_non_canonical_limbs() {
        let (canonical, twin) = twin_pair(7);
        let bytes = bincode::serde::encode_to_vec(canonical, bincode::config::standard()).unwrap();
        let (decoded, read): (Digest, usize) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        assert_eq!(decoded, canonical);
        assert_eq!(read, bytes.len());

        // The twin encoding of the same field elements fails deserialization.
        let twin: Result<(Digest, usize), _> =
            bincode::serde::decode_from_slice(twin.as_bytes(), bincode::config::standard());
        assert!(twin.is_err());
    }

    #[test]
    fn random_canonical_is_always_strictly_serializable() {
        for _ in 0..1024 {
            let digest = Digest::random_canonical();
            assert!(digest.is_canonical());
            let bytes = bincode::serde::encode_to_vec(digest, bincode::config::standard()).unwrap();
            let (decoded, read): (Digest, usize) =
                bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
            assert_eq!(decoded, digest);
            assert_eq!(read, bytes.len());
        }
    }
}
