//! Bitcoin wire-format primitives: a byte cursor and CompactSize varints.

use crate::Error;

/// A bounds-checked little-endian byte cursor.
pub struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

fn truncated(what: &str) -> Error {
    Error::Protocol(format!("truncated {what}"))
}

impl<'a> Cursor<'a> {
    /// Wrap a byte slice.
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Bytes not yet consumed.
    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    /// True when the cursor is exhausted.
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Read exactly `n` bytes.
    pub fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if self.remaining() < n {
            return Err(truncated("bytes"));
        }
        let out = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    /// Read a 32-byte hash (internal order, as on the wire).
    pub fn read_hash(&mut self) -> Result<[u8; 32], Error> {
        Ok(self.read_bytes(32)?.try_into().expect("32 bytes"))
    }

    /// Read a `u8`.
    pub fn read_u8(&mut self) -> Result<u8, Error> {
        Ok(self.read_bytes(1)?[0])
    }

    /// Little-endian `u16`.
    pub fn read_u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_le_bytes(self.read_bytes(2)?.try_into().expect("2")))
    }

    /// Little-endian `u32`.
    pub fn read_u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(self.read_bytes(4)?.try_into().expect("4")))
    }

    /// Little-endian `i32`.
    pub fn read_i32(&mut self) -> Result<i32, Error> {
        Ok(i32::from_le_bytes(self.read_bytes(4)?.try_into().expect("4")))
    }

    /// Little-endian `u64`.
    pub fn read_u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_le_bytes(self.read_bytes(8)?.try_into().expect("8")))
    }

    /// Little-endian `i64`.
    pub fn read_i64(&mut self) -> Result<i64, Error> {
        Ok(i64::from_le_bytes(self.read_bytes(8)?.try_into().expect("8")))
    }

    /// A CompactSize unsigned integer, with canonical-encoding checks.
    pub fn read_varint(&mut self) -> Result<u64, Error> {
        match self.read_u8()? {
            0xff => {
                let n = self.read_u64()?;
                if n < 0x1_0000_0000 {
                    return Err(Error::Protocol("non-canonical varint".into()));
                }
                Ok(n)
            }
            0xfe => {
                let n = u64::from(self.read_u32()?);
                if n < 0x1_0000 {
                    return Err(Error::Protocol("non-canonical varint".into()));
                }
                Ok(n)
            }
            0xfd => {
                let n = u64::from(self.read_u16()?);
                if n < 0xfd {
                    return Err(Error::Protocol("non-canonical varint".into()));
                }
                Ok(n)
            }
            n => Ok(u64::from(n)),
        }
    }

    /// A CompactSize-prefixed byte vector (length sanity-checked by the
    /// caller's buffer size).
    pub fn read_varbytes(&mut self) -> Result<&'a [u8], Error> {
        let n = usize::try_from(self.read_varint()?)
            .map_err(|_| Error::Protocol("varbytes length overflows usize".into()))?;
        self.read_bytes(n)
    }
}

/// Append a CompactSize integer.
pub fn write_varint(out: &mut Vec<u8>, n: u64) {
    if n < 0xfd {
        out.push(n as u8);
    } else if n <= 0xffff {
        out.push(0xfd);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xffff_ffff {
        out.push(0xfe);
        out.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        out.push(0xff);
        out.extend_from_slice(&n.to_le_bytes());
    }
}

/// Append a CompactSize-prefixed byte vector.
pub fn write_varbytes(out: &mut Vec<u8>, bytes: &[u8]) {
    write_varint(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_roundtrip_boundaries() {
        for n in [
            0u64,
            0xfc,
            0xfd,
            0xff,
            0xffff,
            0x1_0000,
            0xffff_ffff,
            0x1_0000_0000,
            u64::MAX,
        ] {
            let mut buf = Vec::new();
            write_varint(&mut buf, n);
            let mut cursor = Cursor::new(&buf);
            assert_eq!(cursor.read_varint().unwrap(), n);
            assert!(cursor.is_empty());
        }
    }

    #[test]
    fn varint_encoding_bytes() {
        let mut buf = Vec::new();
        write_varint(&mut buf, 0xfd);
        assert_eq!(buf, [0xfd, 0xfd, 0x00]);
        buf.clear();
        write_varint(&mut buf, 0x1_0000);
        assert_eq!(buf, [0xfe, 0x00, 0x00, 0x01, 0x00]);
    }

    #[test]
    fn varint_non_canonical_rejected() {
        // 0xfc encoded with a 0xfd prefix is non-canonical.
        let mut cursor = Cursor::new(&[0xfd, 0xfc, 0x00]);
        assert!(cursor.read_varint().is_err());
    }

    #[test]
    fn cursor_bounds() {
        let mut cursor = Cursor::new(&[1u8, 2]);
        assert_eq!(cursor.read_u16().unwrap(), 0x0201);
        assert!(cursor.read_u8().is_err());
    }
}
