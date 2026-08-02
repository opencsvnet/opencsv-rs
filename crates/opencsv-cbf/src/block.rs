//! Block and transaction wire-format parsing, txids, and merkle roots.

use opencsv_core::ANCHOR_SIZE;

use crate::error::Error;
use crate::hash::sha256d;
use crate::wire::Cursor;

/// An 80-byte block header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockHeader {
    /// Block version.
    pub version: i32,
    /// Previous block hash (internal order).
    pub prev_block: [u8; 32],
    /// Merkle root (internal order).
    pub merkle_root: [u8; 32],
    /// Block timestamp (seconds since epoch).
    pub time: u32,
    /// Compact target representation.
    pub bits: u32,
    /// Proof-of-work nonce.
    pub nonce: u32,
}

impl BlockHeader {
    /// Parse from the 80-byte wire encoding.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut cursor = Cursor::new(bytes);
        let header = Self {
            version: cursor.read_i32()?,
            prev_block: cursor.read_hash()?,
            merkle_root: cursor.read_hash()?,
            time: cursor.read_u32()?,
            bits: cursor.read_u32()?,
            nonce: cursor.read_u32()?,
        };
        if !cursor.is_empty() {
            return Err(Error::Protocol("block header longer than 80 bytes".into()));
        }
        Ok(header)
    }

    /// Serialize to the 80-byte wire encoding.
    pub fn serialize(&self) -> [u8; 80] {
        let mut out = Vec::with_capacity(80);
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&self.prev_block);
        out.extend_from_slice(&self.merkle_root);
        out.extend_from_slice(&self.time.to_le_bytes());
        out.extend_from_slice(&self.bits.to_le_bytes());
        out.extend_from_slice(&self.nonce.to_le_bytes());
        out.try_into().expect("80 bytes")
    }

    /// The block hash (double-SHA256 of the header, internal order).
    pub fn hash(&self) -> [u8; 32] {
        sha256d(&self.serialize())
    }
}

/// A transaction outpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutPoint {
    /// Previous transaction id (internal order, as on the wire — the
    /// same byte order `opencsv_bitcoin::funding_ctx` expects).
    pub txid: [u8; 32],
    /// Output index within the previous transaction.
    pub vout: u32,
}

/// A transaction input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxIn {
    /// The outpoint being spent (null for coinbase).
    pub prev: OutPoint,
    /// Unlocking script.
    pub script_sig: Vec<u8>,
    /// Sequence number.
    pub sequence: u32,
}

/// A transaction output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxOut {
    /// Value in satoshis.
    pub value: u64,
    /// Locking script.
    pub script_pubkey: Vec<u8>,
}

/// A parsed transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    /// Transaction version.
    pub version: i32,
    /// Inputs.
    pub inputs: Vec<TxIn>,
    /// Outputs.
    pub outputs: Vec<TxOut>,
    /// Lock time.
    pub lock_time: u32,
    /// Witness stacks, one per input (empty for non-segwit
    /// transactions). The txid never commits to these; they are kept
    /// because batch anchors carry their payload envelope in the
    /// funding input's witness.
    pub witnesses: Vec<Vec<Vec<u8>>>,
}

impl Transaction {
    /// Parse one transaction from the cursor (handles the segwit
    /// marker/flag and consumes witness stacks).
    pub fn parse(cursor: &mut Cursor<'_>) -> Result<Self, Error> {
        let version = cursor.read_i32()?;
        // Segwit (BIP144): marker byte 0x00 followed by flag 0x01, then
        // the input vector. A legacy transaction's input count is never
        // zero, so a leading 0x00 unambiguously means segwit.
        let first = cursor.read_u8()?;
        let (segwit, input_count) = if first == 0 {
            let flag = cursor.read_u8()?;
            if flag != 1 {
                return Err(Error::Protocol(format!(
                    "unsupported segwit flag byte {flag}"
                )));
            }
            (true, cursor.read_varint()?)
        } else {
            (false, u64::from(first))
        };
        if input_count > 1_000_000 {
            return Err(Error::Protocol("absurd input count".into()));
        }
        let mut inputs = Vec::with_capacity(input_count as usize);
        for _ in 0..input_count {
            inputs.push(TxIn {
                prev: OutPoint {
                    txid: cursor.read_hash()?,
                    vout: cursor.read_u32()?,
                },
                script_sig: cursor.read_varbytes()?.to_vec(),
                sequence: cursor.read_u32()?,
            });
        }
        let output_count = cursor.read_varint()?;
        if output_count > 1_000_000 {
            return Err(Error::Protocol("absurd output count".into()));
        }
        let mut outputs = Vec::with_capacity(output_count as usize);
        for _ in 0..output_count {
            outputs.push(TxOut {
                value: cursor.read_u64()?,
                script_pubkey: cursor.read_varbytes()?.to_vec(),
            });
        }
        let mut witnesses = Vec::new();
        if segwit {
            for _ in 0..input_count {
                let item_count = cursor.read_varint()?;
                if item_count > 1000 {
                    return Err(Error::Protocol("absurd witness item count".into()));
                }
                let mut stack = Vec::with_capacity(item_count as usize);
                for _ in 0..item_count {
                    stack.push(cursor.read_varbytes()?.to_vec());
                }
                witnesses.push(stack);
            }
        }
        let lock_time = cursor.read_u32()?;
        Ok(Self {
            version,
            inputs,
            outputs,
            lock_time,
            witnesses,
        })
    }

    /// Serialize without witness data (the legacy encoding that txids
    /// commit to).
    fn serialize_legacy(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.version.to_le_bytes());
        crate::wire::write_varint(&mut out, self.inputs.len() as u64);
        for input in &self.inputs {
            out.extend_from_slice(&input.prev.txid);
            out.extend_from_slice(&input.prev.vout.to_le_bytes());
            crate::wire::write_varbytes(&mut out, &input.script_sig);
            out.extend_from_slice(&input.sequence.to_le_bytes());
        }
        crate::wire::write_varint(&mut out, self.outputs.len() as u64);
        for output in &self.outputs {
            out.extend_from_slice(&output.value.to_le_bytes());
            crate::wire::write_varbytes(&mut out, &output.script_pubkey);
        }
        out.extend_from_slice(&self.lock_time.to_le_bytes());
        out
    }

    /// The transaction id: double-SHA256 of the non-witness
    /// serialization, in internal byte order.
    pub fn txid(&self) -> [u8; 32] {
        sha256d(&self.serialize_legacy())
    }

    /// True for a coinbase transaction (single null-prevout input).
    pub fn is_coinbase(&self) -> bool {
        self.inputs.len() == 1
            && self.inputs[0].prev.txid == [0u8; 32]
            && self.inputs[0].prev.vout == 0xffff_ffff
    }
}

/// A parsed block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    /// Block header.
    pub header: BlockHeader,
    /// Transactions, in block order (index 0 is the coinbase).
    pub txs: Vec<Transaction>,
}

impl Block {
    /// Parse a full block from its wire encoding.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut cursor = Cursor::new(bytes);
        let header_bytes = cursor.read_bytes(80)?;
        let header = BlockHeader::parse(header_bytes)?;
        let tx_count = cursor.read_varint()?;
        if tx_count > 1_000_000 {
            return Err(Error::Protocol("absurd transaction count".into()));
        }
        let mut txs = Vec::with_capacity(tx_count as usize);
        for _ in 0..tx_count {
            txs.push(Transaction::parse(&mut cursor)?);
        }
        if !cursor.is_empty() {
            return Err(Error::Protocol("trailing bytes after block".into()));
        }
        Ok(Self { header, txs })
    }

    /// Recompute the merkle root from the transactions' txids.
    pub fn compute_merkle_root(&self) -> [u8; 32] {
        merkle_root(&self.txs.iter().map(Transaction::txid).collect::<Vec<_>>())
    }

    /// The basic-filter (BIP158) element set of this block given the
    /// prevout scripts of every non-coinbase input, in block order:
    /// every non-empty, non-OP_RETURN output scriptPubKey plus every
    /// non-empty prevout script.
    pub fn basic_filter_elements(&self, prevout_scripts: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, Error> {
        let mut elements = Vec::new();
        let mut prevouts = prevout_scripts.iter();
        for (index, tx) in self.txs.iter().enumerate() {
            for output in &tx.outputs {
                let script = &output.script_pubkey;
                if !script.is_empty() && script[0] != 0x6a {
                    elements.push(script.clone());
                }
            }
            if index > 0 {
                for _ in &tx.inputs {
                    let script = prevouts.next().ok_or_else(|| {
                        Error::Protocol("fewer prevout scripts than block inputs".into())
                    })?;
                    if !script.is_empty() {
                        elements.push(script.clone());
                    }
                }
            }
        }
        if prevouts.next().is_some() {
            return Err(Error::Protocol(
                "more prevout scripts than block inputs".into(),
            ));
        }
        Ok(elements)
    }
}

/// The Bitcoin merkle root over internal-order hashes (the odd-last
/// level is duplicated, per consensus).
pub fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    assert!(!leaves.is_empty(), "a block has at least one transaction");
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let (left, right) = (pair[0], *pair.last().expect("non-empty chunk"));
            let mut data = [0u8; 64];
            data[..32].copy_from_slice(&left);
            data[32..].copy_from_slice(&right);
            next.push(sha256d(&data));
        }
        level = next;
    }
    level[0]
}

/// The canonical OP_RETURN scriptPubKey carrying an anchor record:
/// `OP_RETURN` + a minimal direct push of the 64 record bytes
/// (`6a 40 ∥ record`).
pub fn anchor_script(record_bytes: &[u8; ANCHOR_SIZE]) -> Vec<u8> {
    let mut script = Vec::with_capacity(2 + ANCHOR_SIZE);
    script.push(0x6a);
    script.push(ANCHOR_SIZE as u8);
    script.extend_from_slice(record_bytes);
    script
}

/// Extract a 64-byte `OP_RETURN` payload from a scriptPubKey:
/// `6a` followed by a single direct/`PUSHDATA1`/`PUSHDATA2` push of
/// exactly 64 bytes and nothing else (same rule as `opencsv-bitcoin`'s
/// scanner).
pub fn op_return_payload(script: &[u8]) -> Option<[u8; ANCHOR_SIZE]> {
    let rest = script.strip_prefix(&[0x6a])?;
    let data = match rest {
        [0x40, data @ ..] => data,
        [0x4c, 0x40, data @ ..] => data,
        [0x4d, 0x40, 0x00, data @ ..] => data,
        _ => return None,
    };
    data.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::from_hex;

    #[test]
    fn merkle_single_tx() {
        let txid = [7u8; 32];
        assert_eq!(merkle_root(&[txid]), txid);
    }

    #[test]
    fn merkle_two_txs() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let mut data = [0u8; 64];
        data[..32].copy_from_slice(&a);
        data[32..].copy_from_slice(&b);
        assert_eq!(merkle_root(&[a, b]), sha256d(&data));
    }

    #[test]
    fn merkle_odd_count_duplicates_last() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let c = [3u8; 32];
        let pair = |x: [u8; 32], y: [u8; 32]| {
            let mut data = [0u8; 64];
            data[..32].copy_from_slice(&x);
            data[32..].copy_from_slice(&y);
            sha256d(&data)
        };
        // Level 1: H(a,b), H(c,c). Level 2: H(H(a,b), H(c,c)).
        let expected = pair(pair(a, b), pair(c, c));
        assert_eq!(merkle_root(&[a, b, c]), expected);
    }

    #[test]
    fn parse_genesis_block() {
        // The testnet genesis block (BIP158 test vector row 0).
        let block_hex = concat!(
            "0100000000000000000000000000000000000000000000000000000000000000000000",
            "003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a",
            "dae5494dffff001d1aa4ae1801",
            "01000000010000000000000000000000000000000000000000000000000000000000000000",
            "ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368",
            "616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420",
            "666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1",
            "a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112",
            "de5c384df7ba0b8d578a4c702b6bf11d5fac00000000"
        );
        let block = Block::parse(&from_hex(block_hex).unwrap()).unwrap();
        assert_eq!(block.txs.len(), 1);
        assert!(block.txs[0].is_coinbase());
        assert_eq!(
            crate::hash::hash_to_display(&block.header.hash()),
            "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"
        );
        assert_eq!(block.compute_merkle_root(), block.header.merkle_root);
        // The genesis coinbase output script is the only basic-filter
        // element.
        let elements = block.basic_filter_elements(&[]).unwrap();
        assert_eq!(elements.len(), 1);
        assert_eq!(elements[0][0], 0x41);
    }

    #[test]
    fn segwit_tx_parse_and_txid() {
        // A minimal segwit transaction: 1 input, 1 output, 1 witness item.
        // version 2, marker/flag, 1 input (null-ish prevout), empty
        // scriptSig, sequence ffffffff, 1 output (0 sats, empty script),
        // witness: 1 item of 2 bytes, locktime 0.
        let mut raw = vec![2, 0, 0, 0, 0, 1];
        raw.push(1); // 1 input
        raw.extend_from_slice(&[9u8; 32]); // prev txid
        raw.extend_from_slice(&1u32.to_le_bytes()); // vout
        raw.push(0); // empty scriptSig
        raw.extend_from_slice(&[0xff; 4]); // sequence
        raw.push(1); // 1 output
        raw.extend_from_slice(&0u64.to_le_bytes());
        raw.push(0); // empty scriptPubKey
        raw.push(1); // witness: 1 item
        raw.push(2); // item length 2
        raw.extend_from_slice(&[0xaa, 0xbb]);
        raw.extend_from_slice(&0u32.to_le_bytes()); // locktime
        let mut cursor = Cursor::new(&raw);
        let tx = Transaction::parse(&mut cursor).unwrap();
        assert!(cursor.is_empty());
        assert_eq!(tx.inputs[0].prev.txid, [9u8; 32]);
        assert_eq!(tx.outputs.len(), 1);
        assert_eq!(tx.witnesses.len(), 1);
        assert_eq!(tx.witnesses[0], vec![vec![0xaa, 0xbb]]);
        // The txid commits to the legacy serialization only (no marker,
        // flag, or witness bytes).
        let mut legacy = vec![2, 0, 0, 0, 1];
        legacy.extend_from_slice(&[9u8; 32]);
        legacy.extend_from_slice(&1u32.to_le_bytes());
        legacy.push(0);
        legacy.extend_from_slice(&[0xff; 4]);
        legacy.push(1);
        legacy.extend_from_slice(&0u64.to_le_bytes());
        legacy.push(0);
        legacy.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(tx.txid(), sha256d(&legacy));
    }

    #[test]
    fn op_return_payload_variants() {
        let record = [0xabu8; ANCHOR_SIZE];
        let direct = anchor_script(&record);
        assert_eq!(op_return_payload(&direct), Some(record));
        let mut pushdata1 = vec![0x6a, 0x4c, 0x40];
        pushdata1.extend_from_slice(&record);
        assert_eq!(op_return_payload(&pushdata1), Some(record));
        let mut pushdata2 = vec![0x6a, 0x4d, 0x40, 0x00];
        pushdata2.extend_from_slice(&record);
        assert_eq!(op_return_payload(&pushdata2), Some(record));
        // Wrong length and trailing garbage are rejected.
        assert_eq!(op_return_payload(&[0x6a, 0x3f]), None);
        let mut trailing = direct.clone();
        trailing.push(0x00);
        assert_eq!(op_return_payload(&trailing), None);
    }
}
