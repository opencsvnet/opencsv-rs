//! Minimal BIP173 bech32 encoding — just enough to address the
//! protocol-constant marker output (a witness-v0 scriptPubKey) for
//! `createrawtransaction`. Encoding only; no decoding.

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

fn polymod(values: impl Iterator<Item = u8>) -> u32 {
    const GEN: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let mut chk = 1u32;
    for value in values {
        let top = chk >> 25;
        chk = ((chk & 0x1ff_ffff) << 5) ^ u32::from(value);
        for (i, g) in GEN.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    hrp.bytes()
        .map(|b| b >> 5)
        .chain(std::iter::once(0))
        .chain(hrp.bytes().map(|b| b & 31))
        .collect()
}

/// Re-group bytes into 5-bit values (BIP173 `convertbits`, padding).
fn to_5_bit_groups(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity((bytes.len() * 8).div_ceil(5));
    let mut acc = 0u16;
    let mut bits = 0u32;
    for &byte in bytes {
        acc = (acc << 8) | u16::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(((acc >> bits) & 31) as u8);
        }
    }
    if bits > 0 {
        out.push(((acc << (5 - bits)) & 31) as u8);
    }
    out
}

/// Bech32-encode a segwit-v0 address for `hrp` (`bc` / `tb` / `bcrt`)
/// over a 2–40 byte witness program.
pub fn encode_v0(hrp: &str, program: &[u8]) -> String {
    assert!((2..=40).contains(&program.len()), "witness program length");
    let mut data = vec![0u8]; // witness version 0
    data.extend_from_slice(&to_5_bit_groups(program));
    let checksum = polymod(
        hrp_expand(hrp)
            .into_iter()
            .chain(data.iter().copied())
            .chain(std::iter::repeat_n(0, 6)),
    ) ^ 1; // bech32 constant (v0)
    let mut out = String::with_capacity(hrp.len() + 1 + data.len() + 6);
    out.push_str(hrp);
    out.push('1');
    for value in &data {
        out.push(CHARSET[*value as usize] as char);
    }
    for i in 0..6 {
        out.push(CHARSET[((checksum >> (5 * (5 - i))) & 31) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// BIP173 reference valid addresses.
    #[test]
    fn reference_vectors() {
        assert_eq!(
            encode_v0("bc", &hex("751e76e8199196d454941c45d1b3a323f1433bd6")),
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        );
        assert_eq!(
            encode_v0(
                "bc",
                &hex("1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"),
            ),
            "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"
        );
        assert_eq!(
            encode_v0("tb", &hex("751e76e8199196d454941c45d1b3a323f1433bd6")),
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"
        );
    }
}
