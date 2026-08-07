//! The proof-of-work-verified header chain and the BIP157 filter-header
//! chain, both backed by a rebuildable on-disk cache.

use std::path::{Path, PathBuf};

use crate::block::BlockHeader;
use crate::error::Error;
use crate::network::{params, validate_header, Params};
use crate::peer::Peer;

/// A fully validated header chain (index = height), with cumulative
/// work per height.
#[derive(Clone)]
pub struct HeaderChain {
    params: Params,
    headers: Vec<BlockHeader>,
    hashes: Vec<[u8; 32]>,
    /// `chainwork[h]` = total work of blocks 0..=h.
    chainwork: Vec<u128>,
}

impl HeaderChain {
    /// Start a fresh chain from the network genesis header, which the
    /// first `getheaders` response must reproduce (a peer serving a
    /// different genesis is on the wrong network).
    fn new(params: Params) -> Result<Self, Error> {
        Ok(Self {
            params,
            headers: Vec::new(),
            hashes: Vec::new(),
            chainwork: Vec::new(),
        })
    }

    /// Load the cached chain from `cache_dir/headers.bin`, fully
    /// revalidating it (the cache saves bandwidth, never validation).
    /// A missing or invalid cache starts empty.
    pub fn load(params: Params, cache_dir: &Path) -> Result<Self, Error> {
        let path = headers_path(cache_dir);
        let mut chain = Self::new(params)?;
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(chain),
            Err(e) => return Err(Error::Io(e)),
        };
        if bytes.len() % 80 != 0 {
            // Corrupt cache: treat as absent (it is rebuildable).
            return Ok(chain);
        }
        for chunk in bytes.chunks_exact(80) {
            let header = BlockHeader::parse(chunk)?;
            if chain.append_validated(header).is_err() {
                // The cache no longer validates (should not happen);
                // rebuild from scratch rather than trust it.
                return Self::new(params);
            }
        }
        Ok(chain)
    }

    /// Persist the chain (rebuildable cache).
    pub fn persist(&self, cache_dir: &Path) -> Result<(), Error> {
        std::fs::create_dir_all(cache_dir)?;
        let mut bytes = Vec::with_capacity(self.headers.len() * 80);
        for header in &self.headers {
            bytes.extend_from_slice(&header.serialize());
        }
        std::fs::write(headers_path(cache_dir), bytes)?;
        Ok(())
    }

    /// Genesis-only chains are empty; the genesis block is validated
    /// when the peer first serves it.
    fn append_validated(&mut self, header: BlockHeader) -> Result<(), Error> {
        let height = self.headers.len();
        let work = if height == 0 {
            if header.hash() != self.params.genesis_hash {
                return Err(Error::Consensus(
                    "peer's genesis block does not match the network".into(),
                ));
            }
            crate::network::work_from_target(
                &crate::network::from_compact(header.bits)
                    .ok_or_else(|| Error::Consensus("bad genesis bits".into()))?,
            )
        } else {
            validate_header(&self.params, &self.headers, height, &header)?
        };
        let total = self.chainwork.last().copied().unwrap_or(0) + work;
        self.hashes.push(header.hash());
        self.headers.push(header);
        self.chainwork.push(total);
        Ok(())
    }

    /// Tip height (`None` before even genesis is synced).
    pub fn tip_height(&self) -> Option<u64> {
        self.headers.len().checked_sub(1).map(|h| h as u64)
    }

    /// Hash of the block at `height`.
    pub fn hash_at(&self, height: u64) -> Option<[u8; 32]> {
        self.hashes.get(height as usize).copied()
    }

    /// Header at `height`.
    pub fn header_at(&self, height: u64) -> Option<&BlockHeader> {
        self.headers.get(height as usize)
    }

    /// Cumulative chainwork at the tip.
    pub fn tip_work(&self) -> u128 {
        self.chainwork.last().copied().unwrap_or(0)
    }

    /// Number of identical headers at the start of both chains.
    pub fn common_prefix_len(&self, other: &Self) -> u64 {
        self.hashes
            .iter()
            .zip(&other.hashes)
            .take_while(|(left, right)| left == right)
            .count() as u64
    }

    /// Sync headers from a peer to its tip. Follows the peer across
    /// reorgs by truncating back to the fork point when a batch
    /// attaches below our tip. Returns the number of new headers
    /// appended.
    pub fn sync(&mut self, peer: &mut Peer) -> Result<u64, Error> {
        let mut appended = 0u64;
        if self.headers.is_empty() {
            // Bootstrap: with an empty locator, Bitcoin Core serves
            // exactly the stop-hash block (its null-locator rule), and
            // with stop = 0 it serves nothing — so the genesis header
            // must be requested explicitly.
            let genesis = self.params.genesis_hash;
            let headers = peer.get_headers(&[], &genesis)?;
            if headers.len() != 1 {
                return Err(Error::Protocol(format!(
                    "genesis request returned {} headers",
                    headers.len()
                )));
            }
            self.append_validated(headers[0])?;
            appended += 1;
        }
        loop {
            let locator = self.locator();
            let headers = peer.get_headers(&locator, &[0u8; 32])?;
            if headers.is_empty() {
                return Ok(appended);
            }
            for header in headers {
                if self.hashes.last() == Some(&header.prev_block) {
                    self.append_validated(header)?;
                    appended += 1;
                } else if let Some(fork) = self.hashes.iter().position(|h| h == &header.prev_block)
                {
                    // The peer's chain forks below our tip: truncate to
                    // the fork point and follow it.
                    self.headers.truncate(fork + 1);
                    self.hashes.truncate(fork + 1);
                    self.chainwork.truncate(fork + 1);
                    self.append_validated(header)?;
                    appended += 1;
                }
                // A header that attaches nowhere is ignored (the batch
                // still ends when the peer runs out of new headers).
            }
        }
    }

    /// The block-locator for `getheaders`: tip, then exponentially
    /// spaced ancestors, then genesis (per the Bitcoin protocol).
    fn locator(&self) -> Vec<[u8; 32]> {
        let mut locator = Vec::new();
        let mut height = self.headers.len() as i64 - 1;
        let mut step = 1i64;
        while height > 0 {
            locator.push(self.hashes[height as usize]);
            height = if locator.len() > 10 {
                step *= 2;
                height - step
            } else {
                height - 1
            };
        }
        if !self.hashes.is_empty() {
            locator.push(self.hashes[0]);
        }
        locator
    }
}

fn headers_path(cache_dir: &Path) -> PathBuf {
    cache_dir.join("headers.bin")
}

fn filter_hashes_path(cache_dir: &Path) -> PathBuf {
    cache_dir.join("filter-hashes.bin")
}

/// The BIP157 basic-filter header chain: one filter hash per height,
/// from which filter headers derive by chaining.
///
/// Note what this does and does not establish: filter headers are not
/// committed in block headers, so a filter-header chain is only as
/// trustworthy as the peer(s) that served it. The client therefore
/// cross-checks the chain across all connected peers (see
/// `CbfClient::connect`); agreement means at least one honest peer
/// suffices for correctness (BIP157's security model).
#[derive(Clone)]
pub struct FilterHeaderChain {
    /// Filter hash per height (internal order).
    filter_hashes: Vec<[u8; 32]>,
}

impl FilterHeaderChain {
    /// Start with no cached filter hashes.
    pub fn empty() -> Self {
        Self {
            filter_hashes: Vec::new(),
        }
    }

    /// Adopt a complete hash chain cross-checked across peers.
    pub fn from_verified(filter_hashes: Vec<[u8; 32]>) -> Self {
        Self { filter_hashes }
    }

    /// Load from `cache_dir/filter-hashes.bin` (no independent
    /// validation is possible — the chain is re-derived from peers on
    /// every connect anyway, and only entries re-validated against a
    /// peer this session are used).
    pub fn load(cache_dir: &Path) -> Result<Self, Error> {
        let bytes = match std::fs::read(filter_hashes_path(cache_dir)) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self {
                    filter_hashes: Vec::new(),
                })
            }
            Err(e) => return Err(Error::Io(e)),
        };
        if bytes.len() % 32 != 0 {
            return Ok(Self {
                filter_hashes: Vec::new(),
            });
        }
        Ok(Self {
            filter_hashes: bytes
                .chunks_exact(32)
                .map(|c| c.try_into().expect("32"))
                .collect(),
        })
    }

    /// Persist (rebuildable cache).
    pub fn persist(&self, cache_dir: &Path) -> Result<(), Error> {
        std::fs::create_dir_all(cache_dir)?;
        let mut bytes = Vec::with_capacity(self.filter_hashes.len() * 32);
        for hash in &self.filter_hashes {
            bytes.extend_from_slice(hash);
        }
        std::fs::write(filter_hashes_path(cache_dir), bytes)?;
        Ok(())
    }

    /// Number of filter hashes held (heights 0..len-1).
    pub fn len(&self) -> u64 {
        self.filter_hashes.len() as u64
    }

    /// True when no filter hashes are held.
    pub fn is_empty(&self) -> bool {
        self.filter_hashes.is_empty()
    }

    /// The filter hash committed for `height`.
    pub fn filter_hash_at(&self, height: u64) -> Option<[u8; 32]> {
        self.filter_hashes.get(height as usize).copied()
    }

    /// The filter header for `height`, derived by chaining from the
    /// all-zero pre-genesis header.
    pub fn filter_header_at(&self, height: u64) -> Option<[u8; 32]> {
        if height >= self.len() {
            return None;
        }
        Some(advance_filter_header(
            [0u8; 32],
            &self.filter_hashes[..=height as usize],
        ))
    }

    /// Verify a downloaded filter for `height` against the committed
    /// filter hash.
    pub fn verify_filter(&self, height: u64, filter_bytes: &[u8]) -> Result<(), Error> {
        let committed = self
            .filter_hash_at(height)
            .ok_or_else(|| Error::Filter(format!("no filter hash synced for height {height}")))?;
        if crate::gcs::filter_hash(filter_bytes) != committed {
            return Err(Error::Filter(format!(
                "filter for height {height} does not match the committed filter hash"
            )));
        }
        Ok(())
    }

    /// Fetch the filter-hash chain for `self.len()..=stop_height` from
    /// a peer, verifying the chain linkage against everything already
    /// held. Returns the new hashes (heights `self.len()..=stop_height`)
    /// without committing them — the caller cross-checks independent
    /// peers before [`FilterHeaderChain::extend`]ing.
    pub fn fetch_range(
        &self,
        peer: &mut Peer,
        chain: &HeaderChain,
        stop_height: u64,
    ) -> Result<Vec<[u8; 32]>, Error> {
        let mut out: Vec<[u8; 32]> = Vec::new();
        let mut start = self.len();
        // Compute the held prefix once. Each response then advances this
        // rolling header by only its newly fetched hashes. Re-folding the
        // complete held + fetched prefix for every 2,000-height page makes a
        // full signet/mainnet re-attestation quadratic in chain length.
        let mut expected_prev = if start == 0 {
            [0u8; 32]
        } else {
            self.filter_header_at(start - 1).ok_or_else(|| {
                Error::Filter(format!(
                    "no preceding filter header at height {}",
                    start - 1
                ))
            })?
        };
        while start <= stop_height {
            let stop = (start + 1999).min(stop_height);
            let stop_hash = chain
                .hash_at(stop)
                .ok_or_else(|| Error::Filter(format!("no block hash at height {stop}")))?;
            let response = peer.get_cfheaders(start as u32, &stop_hash)?;
            if response.previous_filter_header != expected_prev {
                return Err(Error::Filter(format!(
                    "filter-header linkage broken at height {start}"
                )));
            }
            let expected_count = (stop - start + 1) as usize;
            if response.filter_hashes.len() != expected_count {
                return Err(Error::Filter(format!(
                    "cfheaders returned {} hashes, expected {expected_count}",
                    response.filter_hashes.len()
                )));
            }
            expected_prev = advance_filter_header(expected_prev, &response.filter_hashes);
            out.extend_from_slice(&response.filter_hashes);
            start = stop + 1;
        }
        Ok(out)
    }

    /// Re-attest the cached chain tail against one live peer without
    /// replaying every historical `cfheaders` page over the network.
    ///
    /// The response commits to the filter header immediately before `start`.
    /// That header is re-derived from the complete local prefix, so changing
    /// any earlier cached filter hash changes the expected linkage unless an
    /// attacker finds a SHA256d second preimage. The peer must then return the
    /// exact cached tail. Header-chain reorg handling truncates this cache
    /// before this method runs.
    pub(crate) fn reattest_tail(
        &self,
        peer: &mut Peer,
        chain: &HeaderChain,
        max_blocks: u64,
    ) -> Result<(), Error> {
        if self.is_empty() {
            return Ok(());
        }
        if max_blocks == 0 {
            return Err(Error::InvalidInput(
                "filter-cache re-attestation window must be nonzero".into(),
            ));
        }
        let stop = self.len() - 1;
        let start = (stop + 1).saturating_sub(max_blocks);
        let prefix = Self::from_verified(self.filter_hashes[..start as usize].to_vec());
        let fetched = prefix.fetch_range(peer, chain, stop)?;
        if fetched != self.filter_hashes[start as usize..=stop as usize] {
            return Err(Error::Filter(format!(
                "peer filter-hash tail differs from cached chain at height {start}"
            )));
        }
        Ok(())
    }

    /// Extend the chain with peer-verified hashes.
    pub fn extend(&mut self, hashes: &[[u8; 32]]) {
        self.filter_hashes.extend_from_slice(hashes);
    }

    /// Truncate to `len` entries (e.g. when peers serve a conflicting
    /// chain for a reorged range).
    pub fn truncate(&mut self, len: u64) {
        self.filter_hashes.truncate(len as usize);
    }
}

fn advance_filter_header(mut header: [u8; 32], filter_hashes: &[[u8; 32]]) -> [u8; 32] {
    for filter_hash in filter_hashes {
        header = crate::gcs::filter_header(filter_hash, &header);
    }
    header
}

/// The consensus parameters for a network (re-export for clients).
pub fn network_params(network: opencsv_bitcoin::Network) -> Params {
    params(network)
}

#[cfg(test)]
mod tests {
    use super::{advance_filter_header, FilterHeaderChain};

    #[test]
    fn rolling_filter_header_matches_one_shot_chain() {
        let hashes = (0u32..5_005)
            .map(|height| {
                let mut hash = [0u8; 32];
                hash[..4].copy_from_slice(&height.to_le_bytes());
                hash
            })
            .collect::<Vec<_>>();
        let chain = FilterHeaderChain::from_verified(hashes.clone());
        let one_shot = chain.filter_header_at((hashes.len() - 1) as u64).unwrap();

        let rolling = hashes.chunks(2_000).fold([0u8; 32], advance_filter_header);

        assert_eq!(rolling, one_shot);
    }

    #[test]
    fn changing_an_early_hash_changes_the_tail_linkage_commitment() {
        let hashes = (0u32..500)
            .map(|height| {
                let mut hash = [0u8; 32];
                hash[..4].copy_from_slice(&height.to_le_bytes());
                hash
            })
            .collect::<Vec<_>>();
        let honest = FilterHeaderChain::from_verified(hashes.clone());
        let mut changed = hashes;
        changed[3][7] ^= 1;
        let changed = FilterHeaderChain::from_verified(changed);

        assert_ne!(
            honest.filter_header_at(355),
            changed.filter_header_at(355),
            "a peer's previous-filter-header response binds the complete cached prefix"
        );
    }
}
