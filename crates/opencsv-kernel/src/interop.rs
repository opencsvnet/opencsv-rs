//! Conversions from `opencsv-core` types to kernel types — glue for
//! callers and the equivalence tests. **Not** part of the verification
//! surface (excluded from the Aeneas translation; see crate README).

use opencsv_core::anchor::AnchorRecord;
use opencsv_core::chain::{AnchorChain, AnchorLocation, AnchorRef};

use crate::record::Record;
use crate::types::{Entry, Location};

/// Convert a location.
pub fn location(location: &AnchorLocation) -> Location {
    Location {
        height: location.height,
        position: location.position,
    }
}

/// Convert an anchor record (layout-compatible; see `crate::record`).
pub fn record(record: &AnchorRecord) -> Record {
    match record {
        AnchorRecord::Mint {
            asset_id,
            value,
            mint_commit,
        } => Record::Mint {
            asset_id: asset_id.0,
            value: *value,
            mint_commit: mint_commit.0,
        },
        AnchorRecord::Xfer { payloads } => Record::Xfer {
            payloads: [payloads[0].0, payloads[1].0],
        },
        AnchorRecord::XferCompressed {
            nullifier_commit, ..
        } => Record::XferCompressed {
            payload: nullifier_commit.0,
        },
        AnchorRecord::BatchHeader {
            count,
            batch_commit,
        } => Record::BatchHeader {
            count: *count,
            batch_commit: batch_commit.0,
        },
        AnchorRecord::Redeem {
            asset_id,
            value,
            payload,
        } => Record::Redeem {
            asset_id: asset_id.0,
            value: *value,
            payload: payload.0,
        },
    }
}

/// Resolve an anchor reference to a kernel entry (record, ctx, location),
/// using the chain's `anchor_at` / `ctx_at` lookups. Returns `None` if
/// either lookup fails.
pub fn entry_at<C: AnchorChain>(chain: &C, anchor_ref: &AnchorRef) -> Option<Entry> {
    let record = chain.anchor_at(anchor_ref)?;
    let ctx = chain.ctx_at(anchor_ref)?;
    Some(Entry {
        record: self::record(&record),
        ctx,
        location: location(&anchor_ref.location),
    })
}
