//! BabyBear field arithmetic and Poseidon2 hashing (paper §4.1).
//!
//! The paper specifies "Poseidon over 𝔽"; we instantiate this with **Poseidon2**
//! over BabyBear (`p = 2^31 − 2^27 + 1`) using the Plonky3 parameter set
//! (width 16, rate 8, `RF = 8`, `RP = 13`, constants shipped with `p3-baby-bear`).
//! The width-16/rate-8 configuration gives a 248-bit capacity and is the
//! standard Plonky3 deployment targeting 128-bit security.
//!
//! # Domain separation
//!
//! Every hash in the scheme is computed as
//!
//! ```text
//! H(domain ∥ parts…) = Sponge( [N] ∥ domain_felts ∥ parts_felts… )
//! ```
//!
//! where `domain` is an ASCII tag (e.g. `"coin"`, `"null"`), encoded three
//! bytes per field element, and `N` is the total number of field elements
//! absorbed after the length prefix itself. The length prefix plus distinct
//! domains make cross-domain and cross-length collisions infeasible, which
//! matters because the underlying `PaddingFreeSponge` is only collision
//! resistant for fixed-length inputs otherwise.
//!
//! # Encodings
//!
//! - bytes → field elements: little-endian chunks of 3 bytes (each < 2^24 < p);
//! - `u64` → 3 field elements: little-endian 24-bit limbs;
//! - [`Digest`] → 8 field elements: little-endian `u32` limbs reduced mod p
//!   (digests produced by this crate are always canonical, i.e. < p).

use p3_baby_bear::{default_babybear_poseidon2_16, BabyBear, Poseidon2BabyBear};
use p3_field::PrimeField32;
use p3_symmetric::{CryptographicHasher, PaddingFreeSponge};
use std::sync::OnceLock;

use crate::digest::Digest;

/// Poseidon2 state width.
pub const POSEIDON2_WIDTH: usize = 16;
/// Sponge rate (elements absorbed/squeezed per permutation call).
pub const POSEIDON2_RATE: usize = 8;
/// Number of field elements in a full digest.
pub const DIGEST_ELEMS: usize = 8;

/// The Poseidon2 permutation over BabyBear used throughout the scheme.
pub type Perm = Poseidon2BabyBear<POSEIDON2_WIDTH>;
/// The sponge hasher built on [`Perm`].
pub type Sponge = PaddingFreeSponge<Perm, POSEIDON2_WIDTH, POSEIDON2_RATE, DIGEST_ELEMS>;

fn sponge() -> &'static Sponge {
    static SPONGE: OnceLock<Sponge> = OnceLock::new();
    SPONGE.get_or_init(|| Sponge::new(default_babybear_poseidon2_16()))
}

/// Reduce a `u32` into BabyBear (canonical on output).
pub(crate) fn felt(x: u32) -> BabyBear {
    BabyBear::new(x)
}

/// Encode bytes as field elements, three bytes per element (little-endian).
pub(crate) fn bytes_to_felts(bytes: &[u8]) -> Vec<BabyBear> {
    bytes
        .chunks(3)
        .map(|chunk| {
            let mut buf = [0u8; 4];
            buf[..chunk.len()].copy_from_slice(chunk);
            felt(u32::from_le_bytes(buf))
        })
        .collect()
}

/// Encode a `u64` as three little-endian 24-bit limbs.
pub(crate) fn u64_to_felts(v: u64) -> [BabyBear; 3] {
    [
        felt((v & 0xFF_FFFF) as u32),
        felt(((v >> 24) & 0xFF_FFFF) as u32),
        felt((v >> 48) as u32),
    ]
}

/// Domain-separated Poseidon2 hash: `H(domain ∥ parts…)` as described in the
/// module docs. Public so that `opencsv-pcd` can reproduce identical hashes
/// in-circuit.
pub fn hash_felts(domain: &str, parts: &[&[BabyBear]]) -> Digest {
    let domain_felts = bytes_to_felts(domain.as_bytes());
    let n = domain_felts.len() + parts.iter().map(|p| p.len()).sum::<usize>();
    let input = std::iter::once(felt(n as u32))
        .chain(domain_felts)
        .chain(parts.iter().flat_map(|p| p.iter().copied()));
    Digest::from_elems(&sponge().hash_iter(input))
}

pub(crate) fn elems_to_canonical_u32s(elems: &[BabyBear]) -> impl Iterator<Item = u32> + '_ {
    elems.iter().map(|e| e.as_canonical_u32())
}
