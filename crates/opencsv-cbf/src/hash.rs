//! SHA-256 helpers and internal-order hash utilities.

use sha2::{Digest, Sha256};

/// `SHA256(SHA256(x))` — Bitcoin's `Hash()`, returned in internal byte
/// order (the byte string as it appears on the wire; block-explorer
/// display order is the reverse).
pub fn sha256d(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    Sha256::digest(first).into()
}

/// Lowercase hex encoding.
pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Decode hex, odd lengths rejected.
pub fn from_hex(s: &str) -> Result<Vec<u8>, crate::Error> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return Err(crate::Error::Protocol(format!(
            "odd-length hex ({})",
            s.len()
        )));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|_| crate::Error::Protocol(format!("non-hex byte at offset {i}")))
        })
        .collect()
}

/// Internal-order bytes of a display-order (block-explorer) hash hex
/// string.
pub fn hash_from_display(hex: &str) -> Result<[u8; 32], crate::Error> {
    let mut bytes: [u8; 32] = from_hex(hex)?
        .try_into()
        .map_err(|v: Vec<u8>| crate::Error::Protocol(format!("hash is {} bytes", v.len())))?;
    bytes.reverse();
    Ok(bytes)
}

/// Display-order hex of internal-order hash bytes.
pub fn hash_to_display(bytes: &[u8; 32]) -> String {
    let mut bytes = *bytes;
    bytes.reverse();
    to_hex(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256d_genesis_header() {
        // The mainnet genesis block header double-hashes to the well-known
        // genesis block hash (display order).
        let header = from_hex(concat!(
            "0100000000000000000000000000000000000000000000000000000000000000000000",
            "003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a",
            "29ab5f49ffff001d1dac2b7c"
        ))
        .unwrap();
        let hash = sha256d(&header);
        assert_eq!(
            hash_to_display(&hash),
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        );
    }
}
