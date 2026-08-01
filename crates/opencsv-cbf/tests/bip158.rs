//! BIP158 Appendix C test vectors (`bip158_testnet19.json`, from the
//! BIP itself): ten testnet blocks with their prevout scripts, expected
//! basic filters (P=19, M=784931), and the filter-header chain.
//!
//! Each block is parsed with the crate's own wire-format parser, its
//! basic-filter elements collected per BIP158 (non-empty, non-OP_RETURN
//! output scripts + non-empty prevout scripts of non-coinbase inputs),
//! the GCS filter constructed and compared byte-for-byte, and the
//! filter-header chain verified. Membership queries against real
//! filters (present and absent items) close the loop.

use opencsv_cbf::block::Block;
use opencsv_cbf::gcs::{
    filter_hash, filter_header, filter_key, GcsFilter, BASIC_FILTER_M, BASIC_FILTER_P,
};
use opencsv_cbf::hash::{from_hex, hash_from_display};
use opencsv_cbf::gcs;

struct Row {
    height: u64,
    block_hash: [u8; 32],
    block: Block,
    prev_scripts: Vec<Vec<u8>>,
    prev_header: [u8; 32],
    filter: Vec<u8>,
    header: [u8; 32],
}

fn load_rows() -> Vec<Row> {
    let json: serde_json::Value = serde_json::from_str(include_str!("bip158_testnet19.json"))
        .expect("valid test vector JSON");
    let rows = json.as_array().expect("top-level array");
    let mut out = Vec::new();
    for row in &rows[1..] {
        let row = row.as_array().expect("row array");
        let block_bytes = from_hex(row[2].as_str().unwrap()).unwrap();
        out.push(Row {
            height: row[0].as_u64().unwrap(),
            block_hash: hash_from_display(row[1].as_str().unwrap()).unwrap(),
            block: Block::parse(&block_bytes).expect("block parses"),
            prev_scripts: row[3]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| from_hex(s.as_str().unwrap()).unwrap())
                .collect(),
            prev_header: hash_from_display(row[4].as_str().unwrap()).unwrap(),
            filter: from_hex(row[5].as_str().unwrap()).unwrap(),
            header: hash_from_display(row[6].as_str().unwrap()).unwrap(),
        });
    }
    out
}

#[test]
fn block_hashes_match_headers() {
    for row in load_rows() {
        assert_eq!(row.block.header.hash(), row.block_hash, "height {}", row.height);
        assert_eq!(
            row.block.compute_merkle_root(),
            row.block.header.merkle_root,
            "merkle root, height {}",
            row.height
        );
    }
}

#[test]
fn filter_construction_matches_vectors() {
    for row in load_rows() {
        let elements = row
            .block
            .basic_filter_elements(&row.prev_scripts)
            .expect("prevout script count matches inputs");
        let key = filter_key(&row.block_hash);
        let filter = gcs::encode(&elements, &key, BASIC_FILTER_P, BASIC_FILTER_M);
        assert_eq!(
            filter,
            row.filter,
            "filter bytes, height {} ({} elements)",
            row.height,
            elements.len()
        );
    }
}

#[test]
fn filter_header_chain_matches_vectors() {
    for row in load_rows() {
        let header = filter_header(&filter_hash(&row.filter), &row.prev_header);
        assert_eq!(header, row.header, "filter header, height {}", row.height);
    }
}

#[test]
fn membership_queries_against_real_filters() {
    for row in load_rows() {
        let key = filter_key(&row.block_hash);
        let filter = GcsFilter::parse(&row.filter).expect("filter parses");
        let elements = row.block.basic_filter_elements(&row.prev_scripts).unwrap();
        // Every element must match (probability 1).
        for element in &elements {
            assert!(
                filter
                    .matches(&key, element, BASIC_FILTER_P, BASIC_FILTER_M)
                    .unwrap(),
                "element must match, height {}",
                row.height
            );
        }
        // The OP_RETURN scriptPubKey form used by OpenCSV anchors is
        // never in a basic filter: probe with a fixed OP_RETURN script
        // per block and require no match (a false positive here has
        // probability ~N/M; these ten probes are deterministic).
        let mut probe = vec![0x6a, 0x40];
        probe.extend_from_slice(&[0xabu8; 64]);
        assert!(
            !filter
                .matches(&key, &probe, BASIC_FILTER_P, BASIC_FILTER_M)
                .unwrap(),
            "OP_RETURN probe must not match, height {}",
            row.height
        );
    }
}

#[test]
fn empty_filter_is_single_zero_byte() {
    let rows = load_rows();
    let empty = rows
        .iter()
        .find(|r| r.filter == vec![0x00])
        .expect("vectors include an empty filter (height 1414221)");
    let elements = empty.block.basic_filter_elements(&empty.prev_scripts).unwrap();
    assert!(elements.is_empty());
}
