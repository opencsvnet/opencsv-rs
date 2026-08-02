//! Anchor record shapes and the occurrence test
//! (mirror of `opencsv-core::anchor::AnchorRecord`).

use crate::binding::binding;
use crate::types::{AssetId24, Ctx, MintCommit, Payload, RawNf};

/// An OpenCSV anchor record (paper §4.4–4.6, amended: bound payloads and
/// batch headers). Byte-layout-compatible with
/// `opencsv_core::anchor::AnchorRecord`; see `interop` for conversions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Record {
    /// `MINT ∥ asset_id ∥ V ∥ mint_commit` — transparent mint (§4.4).
    Mint {
        /// Asset being minted (truncated).
        asset_id: AssetId24,
        /// Total minted value `V` (public).
        value: u64,
        /// `H("mint" ∥ asset_id ∥ V ∥ mint_nonce)` (truncated).
        mint_commit: MintCommit,
    },
    /// `P_1 ∥ P_2` — shielded transfer consuming 1–2 coins (§4.5);
    /// `payloads[1]` is zero for single-input transfers.
    Xfer {
        /// Bound nullifier payloads of the consumed coins, in order.
        payloads: [Payload; 2],
    },
    /// `P` — shielded transfer with `m > 2` inputs: the bound nullifier
    /// commitment (§4.5; the raw list travels in the consignment).
    XferCompressed {
        /// Bound commitment to the full nullifier list.
        payload: Payload,
    },
    /// `[0x05][count][batch_commit]` — a batch header committing to N
    /// witness-carried payloads (§4.7.1 amended; see `crate::batch`).
    BatchHeader {
        /// Number of payloads in the batch envelope.
        count: u8,
        /// `H("batch" ∥ P_1 ∥ … ∥ P_n ∥ ctx)` (truncated).
        batch_commit: Payload,
    },
    /// `REDEEM ∥ asset_id ∥ V ∥ P` — transparent burn (§4.6).
    Redeem {
        /// Asset being redeemed (truncated).
        asset_id: AssetId24,
        /// Redeemed value `V` (public at burn time).
        value: u64,
        /// Bound nullifier payload of the destroyed coin.
        payload: Payload,
    },
}

impl Record {
    /// Occurrence test / well-formedness relative to a raw nullifier
    /// supplied by the verifier (mirror of
    /// `AnchorRecord::well_formed` + `payload_slots`): does some payload
    /// slot of this record equal `H("bind" ∥ raw_nf ∥ ctx)`? Only someone
    /// holding `raw_nf` can evaluate this — by design. For XFERC records,
    /// pass the raw nullifier *commitment*. MINT and BatchHeader records
    /// carry no nullifier payload slots.
    pub fn well_formed(&self, ctx: &Ctx, raw_nf: &RawNf) -> bool {
        let bound = binding(raw_nf, ctx);
        match self {
            Record::Mint { .. } | Record::BatchHeader { .. } => false,
            Record::Xfer { payloads } => payloads[0] == bound || payloads[1] == bound,
            Record::XferCompressed { payload } => *payload == bound,
            Record::Redeem { payload, .. } => *payload == bound,
        }
    }
}
