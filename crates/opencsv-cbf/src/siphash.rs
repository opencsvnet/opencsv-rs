//! SipHash-2-4, as used by BIP158 compact block filters.
//!
//! Note: early BIP158 drafts specified SipHash-1-3; the deployed
//! specification (and every shipping implementation, including bitcoind's
//! `CSipHasher`) uses the standard SipHash-2-4. The BIP158 test vectors
//! (see `tests/bip158.rs`) pin this down.

const C0: u64 = 0x736f6d6570736575;
const C1: u64 = 0x646f72616e646f6d;
const C2: u64 = 0x6c7967656e657261;
const C3: u64 = 0x7465646279746573;

#[inline]
fn round(v: &mut [u64; 4]) {
    v[0] = v[0].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(13);
    v[1] ^= v[0];
    v[0] = v[0].rotate_left(32);
    v[2] = v[2].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(16);
    v[3] ^= v[2];
    v[0] = v[0].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(21);
    v[3] ^= v[0];
    v[2] = v[2].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(17);
    v[1] ^= v[2];
    v[2] = v[2].rotate_left(32);
}

/// SipHash-2-4 of `msg` under the 128-bit key `(k0, k1)` (each a
/// little-endian `u64` over the respective key half).
pub fn siphash24(k0: u64, k1: u64, msg: &[u8]) -> u64 {
    let mut v = [C0 ^ k0, C1 ^ k1, C2 ^ k0, C3 ^ k1];
    let mut chunks = msg.chunks_exact(8);
    for chunk in &mut chunks {
        let m = u64::from_le_bytes(chunk.try_into().expect("8-byte chunk"));
        v[3] ^= m;
        round(&mut v);
        round(&mut v);
        v[0] ^= m;
    }
    let mut b = (msg.len() as u64 & 0xff) << 56;
    for (i, &byte) in chunks.remainder().iter().enumerate() {
        b |= (byte as u64) << (8 * i);
    }
    v[3] ^= b;
    round(&mut v);
    round(&mut v);
    v[0] ^= b;
    v[2] ^= 0xff;
    round(&mut v);
    round(&mut v);
    round(&mut v);
    round(&mut v);
    v[0] ^ v[1] ^ v[2] ^ v[3]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The canonical SipHash-2-4 reference vectors (Aumasson & Bernstein,
    /// "SipHash: a fast short-input PRF", Appendix A): key = bytes
    /// 00..0f, input = the first `i` bytes of 00, 01, 02, …
    #[test]
    fn reference_vectors() {
        const EXPECTED: [u64; 16] = [
            0x726fdb47dd0e0e31,
            0x74f839c593dc67fd,
            0x0d6c8009d9a94f5a,
            0x85676696d7fb7e2d,
            0xcf2794e0277187b7,
            0x18765564cd99a68d,
            0xcbc9466e58fee3ce,
            0xab0200f58b01d137,
            0x93f5f5799a932462,
            0x9e0082df0ba9e4b0,
            0x7a5dbbc594ddb9f3,
            0xf4b32f46226bada7,
            0x751e8fbc860ee5fb,
            0x14ea5627c0843d90,
            0xf723ca908e7af2ee,
            0xa129ca6149be45e5,
        ];
        let k0 = u64::from_le_bytes([0, 1, 2, 3, 4, 5, 6, 7]);
        let k1 = u64::from_le_bytes([8, 9, 10, 11, 12, 13, 14, 15]);
        let input: Vec<u8> = (0..15).collect();
        for (i, &expected) in EXPECTED.iter().enumerate() {
            assert_eq!(siphash24(k0, k1, &input[..i]), expected, "input length {i}");
        }
    }
}
