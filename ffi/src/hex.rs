//! Lowercase-hex helpers for the JSON boundary.

/// Encode bytes as lowercase hex.
pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Decode lowercase/uppercase hex into bytes.
pub fn from_hex(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err(format!("odd-length hex string ({} chars)", s.len()));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| format!("invalid hex at offset {i}"))
        })
        .collect()
}

/// Decode hex into a fixed-size array.
pub fn from_hex_array<const N: usize>(s: &str, what: &str) -> Result<[u8; N], String> {
    let bytes = from_hex(s)?;
    bytes
        .try_into()
        .map_err(|_| format!("{what}: expected {N} bytes of hex, got {} chars", s.len()))
}
