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
use serde::{Deserialize, Serialize};

use crate::field::{elems_to_canonical_u32s, felt, DIGEST_ELEMS};

/// Byte length of a full [`Digest`].
pub const DIGEST_BYTES: usize = 32;
/// Byte length of a [`TruncatedDigest`] as carried in anchor records.
pub const TRUNCATED_DIGEST_BYTES: usize = 24;

/// A 32-byte Poseidon2 digest (8 BabyBear elements, canonical LE `u32`s).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Digest(pub [u8; DIGEST_BYTES]);

/// The 24-byte prefix of a [`Digest`] carried inside 64-byte anchor records.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TruncatedDigest(pub [u8; TRUNCATED_DIGEST_BYTES]);

impl Digest {
    /// Wrap raw bytes.
    pub fn from_bytes(bytes: [u8; DIGEST_BYTES]) -> Self {
        Self(bytes)
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
