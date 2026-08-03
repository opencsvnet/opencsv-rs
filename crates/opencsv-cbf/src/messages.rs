//! P2P message framing (24-byte header + payload) and the message
//! payloads the client speaks: `version`/`verack`,
//! `ping`/`pong`, `getheaders`/`headers`, `getcfheaders`/`cfheaders`,
//! `getcfilters`/`cfilter`, and `getdata` for block fetch.

use std::io::{Read, Write};

use crate::block::{Block, BlockHeader};
use crate::error::Error;
use crate::hash::sha256d;
use crate::wire::{write_varbytes, write_varint, Cursor};

/// Protocol version we speak (BIP157 requires ≥ 70015).
pub const PROTOCOL_VERSION: i32 = 70016;
/// `NODE_WITNESS` — required to be served witness-serialized blocks.
pub const NODE_WITNESS: u64 = 1 << 3;
/// `NODE_COMPACT_FILTERS` (BIP158) — we signal support for the basic
/// filter protocol.
pub const NODE_COMPACT_FILTERS: u64 = 1 << 6;
/// Inventory type: block without witness.
pub const MSG_BLOCK: u32 = 2;
/// Inventory type: block with witness serialization.
pub const MSG_WITNESS_BLOCK: u32 = 0x4000_0002;
/// Largest payload we accept from a peer (32 MiB; blocks are ≤ 4 MB).
pub const MAX_PAYLOAD: usize = 32 * 1024 * 1024;

/// A framed P2P message.
pub struct Message {
    /// Command string (e.g. `version`), without zero padding.
    pub command: String,
    /// Raw payload.
    pub payload: Vec<u8>,
    /// Complete wire size: 24-byte header plus payload.
    pub wire_bytes: usize,
}

fn protocol_err(what: impl std::fmt::Display) -> Error {
    Error::Protocol(what.to_string())
}

/// Serialize the 24-byte message header + payload.
pub fn frame(magic: u32, command: &str, payload: &[u8]) -> Vec<u8> {
    assert!(command.len() <= 12);
    let mut out = Vec::with_capacity(24 + payload.len());
    out.extend_from_slice(&magic.to_le_bytes());
    let mut cmd = [0u8; 12];
    cmd[..command.len()].copy_from_slice(command.as_bytes());
    out.extend_from_slice(&cmd);
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&sha256d(payload)[..4]);
    out.extend_from_slice(payload);
    out
}

/// Read one framed message, verifying magic, length, and checksum.
pub fn read_message(reader: &mut impl Read, magic: u32) -> Result<Message, Error> {
    let mut header = [0u8; 24];
    reader.read_exact(&mut header)?;
    let mut cursor = Cursor::new(&header);
    if cursor.read_u32()? != magic {
        return Err(protocol_err(
            "wrong network magic (peer on another network?)",
        ));
    }
    let command_bytes = cursor.read_bytes(12)?;
    let end = command_bytes.iter().position(|&b| b == 0).unwrap_or(12);
    let command = std::str::from_utf8(&command_bytes[..end])
        .map_err(|_| protocol_err("non-UTF8 command"))?
        .to_string();
    if command.bytes().any(|b| !(0x20..=0x7e).contains(&b)) {
        return Err(protocol_err("non-printable command"));
    }
    let length = cursor.read_u32()? as usize;
    let checksum: [u8; 4] = cursor.read_bytes(4)?.try_into().expect("4");
    if length > MAX_PAYLOAD {
        return Err(protocol_err(format!("payload too large ({length} bytes)")));
    }
    let mut payload = vec![0u8; length];
    reader.read_exact(&mut payload)?;
    if sha256d(&payload)[..4] != checksum {
        return Err(protocol_err(format!("bad checksum on `{command}`")));
    }
    Ok(Message {
        command,
        payload,
        wire_bytes: 24 + length,
    })
}

/// Write one framed message.
pub fn write_message(
    writer: &mut impl Write,
    magic: u32,
    command: &str,
    payload: &[u8],
) -> Result<usize, Error> {
    let message = frame(magic, command, payload);
    writer.write_all(&message)?;
    writer.flush()?;
    Ok(message.len())
}

/// Build a `version` payload.
pub fn version_payload(our_services: u64, start_height: i32) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    out.extend_from_slice(&our_services.to_le_bytes());
    out.extend_from_slice(
        &std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
            .to_le_bytes(),
    );
    // addr_recv + addr_from: empty (services 0, ::, port 0).
    for _ in 0..2 {
        out.extend_from_slice(&0u64.to_le_bytes());
        out.extend_from_slice(&[0u8; 16]);
        out.extend_from_slice(&0u16.to_be_bytes());
    }
    out.extend_from_slice(&0x6f636e6376u64.to_le_bytes()); // nonce ("opencsv"-ish, fixed is fine)
    write_varbytes(&mut out, b"/opencsv-cbf:0.1.0/");
    out.extend_from_slice(&start_height.to_le_bytes());
    out.push(0); // relay: no tx announcements wanted
    out
}

/// The interesting bits of a peer's `version` message.
pub struct VersionInfo {
    /// The peer's protocol version.
    pub version: i32,
    /// The peer's service bits.
    pub services: u64,
    /// The peer's claimed best height.
    pub start_height: i32,
}

/// Parse a `version` payload.
pub fn parse_version(payload: &[u8]) -> Result<VersionInfo, Error> {
    let mut cursor = Cursor::new(payload);
    let version = cursor.read_i32()?;
    let services = cursor.read_u64()?;
    cursor.read_i64()?; // timestamp
    // addr_recv: 26 bytes, then (if present) addr_from: 26 bytes.
    cursor.read_bytes(26)?;
    if cursor.remaining() >= 26 {
        cursor.read_bytes(26)?;
    }
    if cursor.remaining() >= 8 {
        cursor.read_u64()?; // nonce
    }
    let mut start_height = 0;
    if !cursor.is_empty() {
        let _agent = cursor.read_varbytes()?;
        if cursor.remaining() >= 4 {
            start_height = cursor.read_i32()?;
        }
    }
    Ok(VersionInfo {
        version,
        services,
        start_height,
    })
}

/// Build a `getheaders` payload: protocol version, block locator
/// hashes (tip to genesis), and a stop hash (zero = as many as
/// possible).
pub fn getheaders_payload(locator: &[[u8; 32]], stop: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    write_varint(&mut out, locator.len() as u64);
    for hash in locator {
        out.extend_from_slice(hash);
    }
    out.extend_from_slice(stop);
    out
}

/// Parse a `headers` payload: a vector of (80-byte header + always-zero
/// txn_count varint) entries.
pub fn parse_headers(payload: &[u8]) -> Result<Vec<BlockHeader>, Error> {
    let mut cursor = Cursor::new(payload);
    let count = cursor.read_varint()?;
    if count > 2000 {
        return Err(protocol_err(format!(
            "headers message with {count} entries"
        )));
    }
    let mut headers = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let bytes = cursor.read_bytes(80)?;
        headers.push(BlockHeader::parse(bytes)?);
        if cursor.read_varint()? != 0 {
            return Err(protocol_err("headers entry with nonzero txn_count"));
        }
    }
    Ok(headers)
}

/// Build a `getcfheaders` or `getcfilters` payload (identical layout):
/// filter type, start height (LE u32), stop hash.
pub fn getcfilter_range_payload(
    filter_type: u8,
    start_height: u32,
    stop_hash: &[u8; 32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(37);
    out.push(filter_type);
    out.extend_from_slice(&start_height.to_le_bytes());
    out.extend_from_slice(stop_hash);
    out
}

/// A parsed `cfheaders` message.
pub struct CfHeaders {
    /// The stop hash echoed back.
    pub stop_hash: [u8; 32],
    /// Filter header preceding the first block of the range.
    pub previous_filter_header: [u8; 32],
    /// One filter hash per block of the range, ascending by height.
    pub filter_hashes: Vec<[u8; 32]>,
}

/// Parse a `cfheaders` payload.
pub fn parse_cfheaders(payload: &[u8]) -> Result<CfHeaders, Error> {
    let mut cursor = Cursor::new(payload);
    let filter_type = cursor.read_u8()?;
    if filter_type != crate::gcs::BASIC_FILTER_TYPE {
        return Err(protocol_err(format!(
            "unexpected filter type {filter_type}"
        )));
    }
    let stop_hash = cursor.read_hash()?;
    let previous_filter_header = cursor.read_hash()?;
    let count = cursor.read_varint()?;
    if count > 2000 {
        return Err(protocol_err(format!("cfheaders with {count} hashes")));
    }
    let mut filter_hashes = Vec::with_capacity(count as usize);
    for _ in 0..count {
        filter_hashes.push(cursor.read_hash()?);
    }
    Ok(CfHeaders {
        stop_hash,
        previous_filter_header,
        filter_hashes,
    })
}

/// A parsed `cfilter` message.
pub struct CFilter {
    /// Block the filter belongs to.
    pub block_hash: [u8; 32],
    /// The serialized filter (CompactSize N + compressed bytes).
    pub filter_bytes: Vec<u8>,
}

/// Parse a `cfilter` payload.
pub fn parse_cfilter(payload: &[u8]) -> Result<CFilter, Error> {
    let mut cursor = Cursor::new(payload);
    let filter_type = cursor.read_u8()?;
    if filter_type != crate::gcs::BASIC_FILTER_TYPE {
        return Err(protocol_err(format!(
            "unexpected filter type {filter_type}"
        )));
    }
    let block_hash = cursor.read_hash()?;
    let filter_bytes = cursor.read_varbytes()?.to_vec();
    Ok(CFilter {
        block_hash,
        filter_bytes,
    })
}

/// Build a `getdata` payload requesting one inventory item.
pub fn getdata_payload(inv_type: u32, hash: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(37);
    write_varint(&mut out, 1);
    out.extend_from_slice(&inv_type.to_le_bytes());
    out.extend_from_slice(hash);
    out
}

/// Parse a `block` payload.
pub fn parse_block_message(payload: &[u8]) -> Result<Block, Error> {
    Block::parse(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framing_roundtrip() {
        let payload = b"hello world".to_vec();
        let framed = frame(0xdab5bffa, "version", &payload);
        assert_eq!(&framed[..4], &0xdab5bffau32.to_le_bytes());
        assert_eq!(&framed[4..16], b"version\0\0\0\0\0");
        let mut slice: &[u8] = &framed;
        let message = read_message(&mut slice, 0xdab5bffa).unwrap();
        assert_eq!(message.command, "version");
        assert_eq!(message.payload, payload);
        assert!(slice.is_empty());
    }

    #[test]
    fn framing_bad_checksum_rejected() {
        let mut framed = frame(0xdab5bffa, "ping", &[1, 2, 3, 4, 5, 6, 7, 8]);
        let last = framed.len() - 1;
        framed[last] ^= 0xff;
        let mut slice: &[u8] = &framed;
        assert!(read_message(&mut slice, 0xdab5bffa).is_err());
    }

    #[test]
    fn framing_wrong_magic_rejected() {
        let framed = frame(0xdab5bffa, "verack", &[]);
        let mut slice: &[u8] = &framed;
        assert!(read_message(&mut slice, 0xd9b4bef9).is_err());
    }

    #[test]
    fn version_roundtrip() {
        let payload = version_payload(NODE_WITNESS | NODE_COMPACT_FILTERS, 12345);
        let info = parse_version(&payload).unwrap();
        assert_eq!(info.version, PROTOCOL_VERSION);
        assert_eq!(info.services, NODE_WITNESS | NODE_COMPACT_FILTERS);
        assert_eq!(info.start_height, 12345);
    }

    #[test]
    fn cfheaders_range_payload_layout() {
        let stop = [0xaau8; 32];
        let payload = getcfilter_range_payload(0, 0x0102_0304, &stop);
        assert_eq!(payload.len(), 37);
        assert_eq!(payload[0], 0);
        assert_eq!(&payload[1..5], &0x0102_0304u32.to_le_bytes());
        assert_eq!(&payload[5..], &stop);
    }
}
