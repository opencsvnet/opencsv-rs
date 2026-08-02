//! The cryptographic boundary of the kernel. For the Aeneas translation
//! these functions are opaque: Lean reasons about their binding properties,
//! while Rust evaluates the same Poseidon2 construction as `opencsv-core`.
//!
//! Keeping this boundary self-contained makes the dependency direction
//! explicit: production core code may call the verified kernel without a
//! package cycle.

use std::sync::OnceLock;

use p3_baby_bear::{default_babybear_poseidon2_16, BabyBear, Poseidon2BabyBear};
use p3_field::PrimeField32;
use p3_symmetric::{CryptographicHasher, PaddingFreeSponge};

use crate::types::{Ctx, Payload, RawNf};

const WIDTH: usize = 16;
const RATE: usize = 8;
const DIGEST_ELEMS: usize = 8;

type Permutation = Poseidon2BabyBear<WIDTH>;
type Sponge = PaddingFreeSponge<Permutation, WIDTH, RATE, DIGEST_ELEMS>;

fn sponge() -> &'static Sponge {
    static SPONGE: OnceLock<Sponge> = OnceLock::new();
    SPONGE.get_or_init(|| Sponge::new(default_babybear_poseidon2_16()))
}

fn felt(value: u32) -> BabyBear {
    BabyBear::new(value)
}

fn bytes_to_felts(bytes: &[u8]) -> Vec<BabyBear> {
    let mut result = Vec::with_capacity(bytes.len().div_ceil(3));
    let mut offset = 0usize;
    while offset < bytes.len() {
        let end = usize::min(offset + 3, bytes.len());
        let mut word = [0u8; 4];
        word[..end - offset].copy_from_slice(&bytes[offset..end]);
        result.push(felt(u32::from_le_bytes(word)));
        offset = end;
    }
    result
}

fn digest_to_felts(bytes: &[u8; 32]) -> [BabyBear; DIGEST_ELEMS] {
    let mut result = [BabyBear::default(); DIGEST_ELEMS];
    let mut index = 0usize;
    while index < DIGEST_ELEMS {
        let offset = index * 4;
        result[index] = felt(u32::from_le_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .expect("four-byte digest limb"),
        ));
        index += 1;
    }
    result
}

fn hash_felts(domain: &str, parts: &[&[BabyBear]]) -> [u8; 32] {
    let domain_felts = bytes_to_felts(domain.as_bytes());
    let part_len = parts.iter().map(|part| part.len()).sum::<usize>();
    let input_len = domain_felts.len() + part_len;
    let input = std::iter::once(felt(input_len as u32))
        .chain(domain_felts)
        .chain(parts.iter().flat_map(|part| part.iter().copied()));
    let digest = sponge().hash_iter(input);

    let mut bytes = [0u8; 32];
    let mut index = 0usize;
    while index < DIGEST_ELEMS {
        let offset = index * 4;
        bytes[offset..offset + 4].copy_from_slice(&digest[index].as_canonical_u32().to_le_bytes());
        index += 1;
    }
    bytes
}

/// `H("bind" ∥ raw_nf ∥ ctx)` as a full 32-byte digest.
pub fn hash_bind(raw_nf: &RawNf, ctx: &Ctx) -> [u8; 32] {
    let raw_felts = digest_to_felts(raw_nf);
    let ctx_felts = bytes_to_felts(ctx);
    hash_felts("bind", &[&raw_felts, &ctx_felts])
}

/// `H("batch" ∥ P_1 ∥ … ∥ P_n ∥ ctx)` as a full 32-byte digest.
pub fn hash_batch(payloads: &[Payload], ctx: &Ctx) -> [u8; 32] {
    let mut payload_bytes = Vec::with_capacity(payloads.len() * 24);
    let mut index = 0usize;
    while index < payloads.len() {
        payload_bytes.extend_from_slice(&payloads[index]);
        index += 1;
    }
    let payload_felts = bytes_to_felts(&payload_bytes);
    let ctx_felts = bytes_to_felts(ctx);
    hash_felts("batch", &[&payload_felts, &ctx_felts])
}
