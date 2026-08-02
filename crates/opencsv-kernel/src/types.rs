//! Plain data types of the kernel — no serde, no embedded field elements.

/// Raw nullifier (never on-chain): a full 32-byte digest.
pub type RawNf = [u8; 32];

/// Transaction context (derived from the carrying transaction's inputs).
pub type Ctx = [u8; 32];

/// On-chain payload: the 24-byte anchor form of a digest
/// (`TruncatedDigest` in opencsv-core).
pub type Payload = [u8; 24];

/// Truncated asset id, as carried in MINT/REDEEM records.
pub type AssetId24 = [u8; 24];

/// Truncated mint commitment (`H("mint" ∥ asset_id ∥ V ∥ mint_nonce)`).
pub type MintCommit = [u8; 24];

/// Location of an anchor in the canonical chain order (paper §4.7):
/// block height, then in-block position.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Location {
    /// Block height containing the anchor transaction.
    pub height: u64,
    /// In-block position of the anchor transaction.
    pub position: u32,
}

/// One entry of the canonical anchor log, as the scan sees it: the anchor
/// record, the transaction context it is bound under, and its location.
/// The caller supplies entries in canonical order (see crate README).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    /// The anchor record.
    pub record: crate::record::Record,
    /// The carrying transaction's context.
    pub ctx: Ctx,
    /// Canonical location of the entry.
    pub location: Location,
}
