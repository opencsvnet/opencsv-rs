//! The CLI-side wrapper around [`opencsv_bitcoin::BitcoinAnchorChain`]:
//! adapts it to the [`crate::chain::AnchorWriter`] seam (real records are
//! built from the funding input's ctx via
//! [`AnchorWriter::append_bound`]; a caller-drawn `ctx` cannot be honored
//! and is an error) and maps errors into the wallet [`Error`] type.

use opencsv_bitcoin::{BitcoinAnchorChain, Config};
use opencsv_core::chain::{AnchorChain, AnchorLocation, AnchorRef};
use opencsv_core::{AnchorRecord, Digest};

use crate::chain::AnchorWriter;
use crate::error::Error;

/// The real Bitcoin chain backend (`bitcoind` RPC); see the
/// `opencsv-bitcoin` crate docs for the two-pass anchor construction and
/// the scanning/index model.
pub struct BitcoinBackend {
    inner: BitcoinAnchorChain,
}

impl BitcoinBackend {
    /// Open the backend against `config` (probes the node, scans to tip).
    pub fn open(config: &Config) -> Result<Self, Error> {
        Ok(Self {
            inner: BitcoinAnchorChain::open(config)?,
        })
    }

    /// Mine `n` blocks (regtest only — see
    /// [`opencsv_bitcoin::BitcoinAnchorChain::generate_blocks`]).
    pub fn generate_blocks(&mut self, n: u64) -> Result<(), Error> {
        self.inner.generate_blocks(n)?;
        Ok(())
    }
}

impl AnchorChain for BitcoinBackend {
    fn tip_height(&self) -> u64 {
        self.inner.tip_height()
    }

    fn anchor_at(&self, anchor_ref: &AnchorRef) -> Option<AnchorRecord> {
        self.inner.anchor_at(anchor_ref)
    }

    fn ctx_at(&self, anchor_ref: &AnchorRef) -> Option<[u8; 32]> {
        self.inner.ctx_at(anchor_ref)
    }

    fn locate(&self, anchor_ref: &AnchorRef) -> Option<AnchorLocation> {
        self.inner.locate(anchor_ref)
    }

    fn first_nullifier_occurrence(&self, raw_nf: &Digest) -> Option<AnchorLocation> {
        self.inner.first_nullifier_occurrence(raw_nf)
    }

    fn nullifier_occurrences(&self, raw_nf: &Digest) -> Vec<AnchorLocation> {
        self.inner.nullifier_occurrences(raw_nf)
    }

    fn anchors_up_to(&self, height: u64) -> Vec<(AnchorLocation, AnchorRecord)> {
        self.inner.anchors_up_to(height)
    }

    fn confirmations_at(&self, height: u64) -> u64 {
        self.inner.confirmations_at(height)
    }
}

impl AnchorWriter for BitcoinBackend {
    fn append(&mut self, _record: AnchorRecord, _ctx: [u8; 32]) -> Result<AnchorRef, Error> {
        Err(Error::Backend(
            "the bitcoind backend derives ctx from the anchor transaction's \
             funding input — records must be built via append_bound"
                .into(),
        ))
    }

    fn append_bound(
        &mut self,
        build: impl FnMut(&[u8; 32]) -> AnchorRecord,
    ) -> Result<AnchorRef, Error> {
        Ok(self.inner.anchor(build)?)
    }
}
