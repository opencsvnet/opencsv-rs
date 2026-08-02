//! First-occurrence scan (mirror of
//! `opencsv-core::chain::AnchorChain::first_nullifier_occurrence`).

use crate::types::{Entry, RawNf};

/// The first occurrence of a raw nullifier in the entry list, if any
/// (paper §4.7 rule 1): the index of the first entry whose record binds
/// `raw_nf` under the entry's own `ctx`. The caller supplies entries in
/// canonical chain order (crate README); read the entry's `location` off
/// the returned index.
///
/// Loop-based (Aeneas-compatible shape): linear scan, first match wins.
pub fn first_occurrence(entries: &[Entry], raw_nf: &RawNf) -> Option<usize> {
    let mut i = 0usize;
    while i < entries.len() {
        let entry = &entries[i];
        if entry.record.well_formed(&entry.ctx, raw_nf) {
            return Some(i);
        }
        i += 1;
    }
    None
}
