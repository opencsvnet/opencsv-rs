//! Type conversions at the verified-kernel boundary. Keeping the adapters in
//! core leaves the kernel independent of serde, traits, storage and I/O.

use crate::anchor::AnchorRecord;

pub(crate) fn record(record: &AnchorRecord) -> opencsv_kernel::Record {
    match *record {
        AnchorRecord::Mint {
            asset_id,
            value,
            mint_commit,
        } => opencsv_kernel::Record::Mint {
            asset_id: asset_id.0,
            value,
            mint_commit: mint_commit.0,
        },
        AnchorRecord::Xfer { payloads } => opencsv_kernel::Record::Xfer {
            payloads: [payloads[0].0, payloads[1].0],
        },
        AnchorRecord::XferCompressed { nullifier_commit } => {
            opencsv_kernel::Record::XferCompressed {
                payload: nullifier_commit.0,
            }
        }
        AnchorRecord::BatchHeader {
            count,
            batch_commit,
        } => opencsv_kernel::Record::BatchHeader {
            count,
            batch_commit: batch_commit.0,
        },
        AnchorRecord::Redeem {
            asset_id,
            value,
            payload,
        } => opencsv_kernel::Record::Redeem {
            asset_id: asset_id.0,
            value,
            payload: payload.0,
        },
    }
}
