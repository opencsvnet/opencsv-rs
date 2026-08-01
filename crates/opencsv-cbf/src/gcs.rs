//! BIP158 Golomb-coded sets: construction and membership queries.
//!
//! Conventions verified against the BIP158 test vectors
//! (`tests/bip158.rs`) and against live bitcoind filters:
//!
//! - items are hashed with SipHash-2-4 under a key derived from the
//!   block hash, then mapped into `[0, N * M)` via Lemire's reduction
//!   `(h * F) >> 64` (the 128-bit product's high half);
//! - sorted hashed values are delta-encoded with Golomb-Rice coding:
//!   quotient in unary (`q` one-bits then a zero), remainder as `P`
//!   bits in big-endian bit order;
//! - the bitstream packs bits **most-significant-bit first** within
//!   each byte (Bitcoin Core's `BitStreamWriter`), zero-padded to a
//!   byte boundary;
//! - the serialized filter is `N` as a CompactSize followed by the
//!   compressed bytes; a zero-element filter is the single byte `0x00`;
//! - elements are deduplicated (Bitcoin Core uses an `std::set`), so
//!   `N` counts distinct elements.

use crate::error::Error;
use crate::siphash::siphash24;
use crate::wire::{write_varint, Cursor};

/// Golomb-Rice bit parameter of BIP158 basic filters.
pub const BASIC_FILTER_P: u8 = 19;
/// Inverse false-positive rate of BIP158 basic filters.
pub const BASIC_FILTER_M: u64 = 784931;
/// Filter type byte of BIP158 basic filters (BIP157).
pub const BASIC_FILTER_TYPE: u8 = 0x00;

/// The 16-byte GCS key for a block: the first 16 bytes of the block hash
/// in internal (little-endian) byte order.
pub fn filter_key(block_hash: &[u8; 32]) -> [u8; 16] {
    block_hash[..16].try_into().expect("16 of 32 bytes")
}

/// Map a 64-bit hash uniformly into `[0, f)` (Lemire's reduction).
fn map_into_range(h: u64, f: u64) -> u64 {
    ((u128::from(h) * u128::from(f)) >> 64) as u64
}

/// Hash an item into the GCS value space for a filter of `n` elements.
fn hash_to_range(key: &[u8; 16], item: &[u8], n: u64, m: u64) -> u64 {
    let k0 = u64::from_le_bytes(key[..8].try_into().expect("8"));
    let k1 = u64::from_le_bytes(key[8..].try_into().expect("8"));
    map_into_range(siphash24(k0, k1, item), n * m)
}

/// Most-significant-bit-first bit writer (Bitcoin Core's
/// `BitStreamWriter`).
struct BitWriter {
    bytes: Vec<u8>,
    /// Number of bits already used in the last byte (0 = last byte full
    /// or no byte started).
    used: u32,
}

impl BitWriter {
    fn new() -> Self {
        Self {
            bytes: Vec::new(),
            used: 0,
        }
    }

    /// Write the `nbits` least significant bits of `data`, highest bit
    /// first.
    fn write(&mut self, data: u64, nbits: u32) {
        debug_assert!(nbits <= 64);
        for i in (0..nbits).rev() {
            let bit = (data >> i) & 1;
            if self.used == 0 {
                self.bytes.push(0);
            }
            if bit == 1 {
                let last = self.bytes.last_mut().expect("byte pushed above");
                *last |= 1 << (7 - self.used);
            }
            self.used = (self.used + 1) % 8;
        }
    }

    /// Golomb-Rice encode `x` with parameter `p`.
    fn golomb_rice_encode(&mut self, p: u8, x: u64) {
        let q = x >> p;
        for _ in 0..q {
            self.write(1, 1);
        }
        self.write(0, 1);
        self.write(x, u32::from(p));
    }
}

/// Big-endian-bit-order bit reader over a byte slice.
struct BitReader<'a> {
    data: &'a [u8],
    bit_pos: usize,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, bit_pos: 0 }
    }

    fn read_bit(&mut self) -> Result<u64, Error> {
        if self.bit_pos >= self.data.len() * 8 {
            return Err(Error::Filter("GCS bitstream truncated".into()));
        }
        let bit = (self.data[self.bit_pos / 8] >> (7 - (self.bit_pos % 8))) & 1;
        self.bit_pos += 1;
        Ok(u64::from(bit))
    }

    /// Read `nbits` bits; the first bit read is the most significant.
    fn read(&mut self, nbits: u32) -> Result<u64, Error> {
        let mut value = 0u64;
        for _ in 0..nbits {
            value = (value << 1) | self.read_bit()?;
        }
        Ok(value)
    }

    /// Golomb-Rice decode with parameter `p`.
    fn golomb_rice_decode(&mut self, p: u8) -> Result<u64, Error> {
        let mut q = 0u64;
        while self.read_bit()? == 1 {
            q += 1;
            if q > 1 << 32 {
                return Err(Error::Filter("GCS quotient unreasonably large".into()));
            }
        }
        let r = self.read(u32::from(p))?;
        Ok((q << p) + r)
    }
}

/// Construct a serialized GCS filter (CompactSize `N` + compressed
/// bytes) from raw items. Elements are deduplicated, matching Bitcoin
/// Core's `std::set` element collection. An empty element set encodes
/// as the single byte `0x00`.
pub fn encode(elements: &[Vec<u8>], key: &[u8; 16], p: u8, m: u64) -> Vec<u8> {
    use std::collections::BTreeSet;
    let set: BTreeSet<&[u8]> = elements.iter().map(Vec::as_slice).collect();
    let n = set.len() as u64;
    let mut out = Vec::new();
    write_varint(&mut out, n);
    if n == 0 {
        return out;
    }
    let mut hashed: Vec<u64> = set
        .iter()
        .map(|item| hash_to_range(key, item, n, m))
        .collect();
    hashed.sort_unstable();
    let mut writer = BitWriter::new();
    let mut last = 0u64;
    for value in hashed {
        writer.golomb_rice_encode(p, value - last);
        last = value;
    }
    out.extend_from_slice(&writer.bytes);
    out
}

/// A parsed GCS filter: `n` elements and the compressed bytes (without
/// the CompactSize prefix).
pub struct GcsFilter<'a> {
    n: u64,
    compressed: &'a [u8],
}

impl<'a> GcsFilter<'a> {
    /// Parse a serialized filter (CompactSize `N` prefix + bytes).
    pub fn parse(serialized: &'a [u8]) -> Result<Self, Error> {
        let mut cursor = Cursor::new(serialized);
        let n = cursor.read_varint()?;
        if n >= 1 << 32 {
            return Err(Error::Filter(format!("GCS N={n} out of range")));
        }
        if n == 0 && !cursor.is_empty() {
            return Err(Error::Filter("GCS filter with N=0 has data".into()));
        }
        Ok(Self {
            n,
            compressed: &serialized[serialized.len() - cursor.remaining()..],
        })
    }

    /// Number of elements the filter was built from.
    pub fn n(&self) -> u64 {
        self.n
    }

    /// Decode all hashed values (cumulative deltas), in ascending order.
    #[cfg(test)]
    fn decode_all(&self, p: u8) -> Result<Vec<u64>, Error> {
        let mut reader = BitReader::new(self.compressed);
        let mut values = Vec::with_capacity(self.n as usize);
        let mut last = 0u64;
        for _ in 0..self.n {
            let delta = reader.golomb_rice_decode(p)?;
            let value = last
                .checked_add(delta)
                .ok_or_else(|| Error::Filter("GCS value overflow during decode".into()))?;
            values.push(value);
            last = value;
        }
        Ok(values)
    }

    /// Membership query for a single item under `key` with parameters
    /// `p`/`m` (BIP158 basic: [`BASIC_FILTER_P`], [`BASIC_FILTER_M`]).
    pub fn matches(&self, key: &[u8; 16], item: &[u8], p: u8, m: u64) -> Result<bool, Error> {
        if self.n == 0 {
            return Ok(false);
        }
        let target = hash_to_range(key, item, self.n, m);
        let mut reader = BitReader::new(self.compressed);
        let mut last = 0u64;
        for _ in 0..self.n {
            let delta = read_delta(&mut reader, p)?;
            let value = last.checked_add(delta).ok_or_else(|| {
                Error::Filter("GCS value overflow during decode".into())
            })?;
            if value == target {
                return Ok(true);
            }
            if value > target {
                // Sorted: no later value can equal the target.
                return Ok(false);
            }
            last = value;
        }
        Ok(false)
    }
}

/// Decode one Golomb-Rice delta (helper so `p` is explicit at call
/// sites).
fn read_delta(reader: &mut BitReader<'_>, p: u8) -> Result<u64, Error> {
    reader.golomb_rice_decode(p)
}

/// The canonical hash of a serialized filter: `SHA256D(filter_bytes)`.
pub fn filter_hash(serialized_filter: &[u8]) -> [u8; 32] {
    crate::hash::sha256d(serialized_filter)
}

/// A filter header: `SHA256D(filter_hash ∥ previous_filter_header)`
/// (BIP157). The genesis block's previous filter header is 32 zero
/// bytes.
pub fn filter_header(filter_hash: &[u8; 32], previous_filter_header: &[u8; 32]) -> [u8; 32] {
    let mut data = [0u8; 64];
    data[..32].copy_from_slice(filter_hash);
    data[32..].copy_from_slice(previous_filter_header);
    crate::hash::sha256d(&data)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> [u8; 16] {
        [42u8; 16]
    }

    #[test]
    fn empty_filter() {
        let encoded = encode(&[], &key(), BASIC_FILTER_P, BASIC_FILTER_M);
        assert_eq!(encoded, [0x00]);
        let filter = GcsFilter::parse(&encoded).unwrap();
        assert!(!filter.matches(&key(), b"anything", BASIC_FILTER_P, BASIC_FILTER_M).unwrap());
    }

    #[test]
    fn encode_match_roundtrip() {
        let elements: Vec<Vec<u8>> = (0u8..50).map(|i| vec![i; (i % 7) as usize + 1]).collect();
        let encoded = encode(&elements, &key(), BASIC_FILTER_P, BASIC_FILTER_M);
        let filter = GcsFilter::parse(&encoded).unwrap();
        assert_eq!(filter.n(), 50);
        for element in &elements {
            assert!(
                filter.matches(&key(), element, BASIC_FILTER_P, BASIC_FILTER_M).unwrap(),
                "present element must match"
            );
        }
        // Absent items: count false positives; with M = 784931 and 50
        // elements, expect ~0 matches out of these probes.
        let false_positives = (200u16..300)
            .filter(|i| {
                let probe = i.to_le_bytes();
                filter
                    .matches(&key(), &probe, BASIC_FILTER_P, BASIC_FILTER_M)
                    .unwrap()
            })
            .count();
        assert!(false_positives <= 1, "{false_positives} false positives");
    }

    #[test]
    fn duplicates_are_deduplicated() {
        let one = encode(&[b"hello".to_vec()], &key(), BASIC_FILTER_P, BASIC_FILTER_M);
        let two = encode(
            &[b"hello".to_vec(), b"hello".to_vec()],
            &key(),
            BASIC_FILTER_P,
            BASIC_FILTER_M,
        );
        assert_eq!(one, two);
        assert_eq!(GcsFilter::parse(&two).unwrap().n(), 1);
    }

    #[test]
    fn decode_all_consistency() {
        let elements: Vec<Vec<u8>> = (0u8..10).map(|i| vec![i, i.wrapping_mul(3)]).collect();
        let encoded = encode(&elements, &key(), BASIC_FILTER_P, BASIC_FILTER_M);
        let filter = GcsFilter::parse(&encoded).unwrap();
        let values = filter.decode_all(BASIC_FILTER_P).unwrap();
        assert_eq!(values.len(), 10);
        assert!(values.windows(2).all(|w| w[0] <= w[1]));
    }

    #[test]
    fn filter_header_genesis_linkage() {
        // The BIP158 genesis-block vector (block 0 of testnet-19.json):
        // filter 019dfca8, previous header all-zero, header is the
        // display-order reverse of the computed value.
        let filter = from_hex("019dfca8");
        let fh = filter_hash(&filter);
        let header = filter_header(&fh, &[0u8; 32]);
        assert_eq!(
            crate::hash::hash_to_display(&header),
            "21584579b7eb08997773e5aeff3a7f932700042d0ed2a6129012b7d7ae81b750"
        );
    }

    fn from_hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
