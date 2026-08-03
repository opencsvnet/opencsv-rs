//! [`AnchorChain`] over real Bitcoin via `bitcoind` RPC, plus the write
//! side. See the crate docs (`opencsv-bitcoin`) for the two-pass anchor
//! construction and the scanning/indexing model.

use std::path::PathBuf;

use bitcoin::Transaction;
use opencsv_core::chain::{AnchorChain, AnchorLocation, AnchorRef};
use opencsv_core::{AnchorRecord, Digest, ANCHOR_SIZE};
use serde_json::{json, Value};

use crate::error::{io_err, Error};
use crate::rpc::{HttpTransport, RpcAuth, RpcClient, Transport};

/// Location carried in an [`AnchorRef`] for a transaction that is
/// broadcast but not yet mined. Height 0 / position 0 is unambiguous: the
/// only real height-0 transaction is the genesis coinbase, which carries
/// no anchor. A mempool anchor has 0 confirmations
/// ([`BitcoinAnchorChain::confirmations_at`]) and never counts as a
/// nullifier occurrence (canonical chain order only exists once mined).
pub const MEMPOOL_LOCATION: AnchorLocation = AnchorLocation {
    height: 0,
    position: 0,
};

/// A Bitcoin network.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    /// mainnet.
    Mainnet,
    /// signet.
    Signet,
    /// regtest (local testing; `chain advance` mines via the wallet).
    Regtest,
}

impl Network {
    /// Human/config name (`signet`, `mainnet`, `regtest`).
    pub fn name(self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Signet => "signet",
            Self::Regtest => "regtest",
        }
    }

    /// bitcoind's default RPC port on this network.
    pub fn default_rpc_port(self) -> u16 {
        match self {
            Self::Mainnet => 8332,
            Self::Signet => 38332,
            Self::Regtest => 18443,
        }
    }

    /// Subdirectory of the default datadir holding this network's cookie
    /// (`""` for mainnet).
    pub fn datadir_subdir(self) -> &'static str {
        match self {
            Self::Mainnet => "",
            Self::Signet => "signet",
            Self::Regtest => "regtest",
        }
    }

    /// bitcoind's `getblockchaininfo.chain` value for this network.
    fn rpc_chain_name(self) -> &'static str {
        match self {
            Self::Mainnet => "main",
            Self::Signet => "signet",
            Self::Regtest => "regtest",
        }
    }

    /// Parse `signet` / `mainnet` / `regtest` (also accepts `main`).
    pub fn parse(s: &str) -> Result<Self, Error> {
        match s {
            "mainnet" | "main" => Ok(Self::Mainnet),
            "signet" => Ok(Self::Signet),
            "regtest" => Ok(Self::Regtest),
            _ => Err(Error::Config(format!(
                "unknown network `{s}` (expected signet|mainnet|regtest)"
            ))),
        }
    }
}

/// Everything needed to open a [`BitcoinAnchorChain`].
#[derive(Clone, Debug)]
pub struct Config {
    /// Which network the node must be on (verified against
    /// `getblockchaininfo` at open; a mismatch is a hard error).
    pub network: Network,
    /// `http://host:port` of the node's RPC endpoint.
    pub rpc_url: String,
    /// Cookie file or `user:password`.
    pub auth: RpcAuth,
    /// Wallet name for bitcoind's multi-wallet endpoint (`/wallet/<name>`);
    /// `None` uses the default wallet.
    pub wallet: Option<String>,
    /// Height to start scanning from on first open (default: the tip at
    /// first open — a fresh wallet has no earlier anchors). Changing this
    /// value rebuilds the index. See the crate docs for why this is not
    /// genesis.
    pub scan_from: Option<u64>,
    /// Path of the persistent anchor index (a rebuildable cache).
    pub index_path: PathBuf,
}

/// The 32-byte transaction context of a funding-input outpoint:
///
/// ```text
/// ctx = SHA-256( txid_internal_order (32 bytes) ∥ vout (4 bytes, LE) )
/// ```
///
/// **This is protocol-canonical**: `ctx` is what an anchor record's bound
/// payloads commit to, so every backend and every third-party indexer must
/// compute it identically or they stop recognizing each other's anchors
/// (see opencsv-rs#2). SHA-256 over the explicit 36-byte outpoint is
/// self-describing, available in every language, and free of truncation or
/// byte-order subtleties beyond the one fixed here: the txid is in
/// **internal byte order** (the reverse of block-explorer display order —
/// use [`hash_from_rpc`] on RPC/REST hex), and `vout` is little-endian.
///
/// Any new backend MUST call this function rather than reimplement it.
pub fn funding_ctx(txid: &[u8; 32], vout: u32) -> [u8; 32] {
    use sha2::{Digest as _, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(txid);
    hasher.update(vout.to_le_bytes());
    hasher.finalize().into()
}

/// The protocol-constant marker witness script: `OP_RETURN`. The P2WSH
/// scriptPubKey remains BIP158-visible while the witness program is
/// provably unspendable, preventing third parties from attaching a child
/// transaction that pins an anchor's RBF replacement.
pub const MARKER_SCRIPT: [u8; 1] = [0x6a];

/// The current marker output's scriptPubKey:
/// `OP_0 <sha256(OP_RETURN)>`. Anchor transactions carry one at output
/// index 1 so BIP158 basic filters — which exclude a direct OP_RETURN
/// scriptPubKey but include this P2WSH program — can find anchor-bearing
/// blocks. The marker carries zero authority and cannot be spent.
pub const MARKER_SPK: [u8; 34] = [
    0x00, 0x20, 0x18, 0x9f, 0x40, 0x03, 0x4b, 0xe7, 0xa1, 0x99, 0xf1, 0xfa, 0x98, 0x91, 0x66, 0x8e,
    0xe3, 0xab, 0x60, 0x49, 0xf8, 0x2d, 0x38, 0xc6, 0x8b, 0xe7, 0x0f, 0x59, 0x6e, 0xab, 0x2e, 0x18,
    0x57, 0xb7,
];

/// Historical anyone-can-spend marker witness script (`OP_TRUE`). New
/// anchors must not create it; scanners retain it for old anchors.
pub const LEGACY_MARKER_SCRIPT: [u8; 1] = [0x51];

/// Historical `OP_0 <sha256(OP_TRUE)>` marker scriptPubKey. New anchors
/// use [`MARKER_SPK`]; readers accept both exact constants.
pub const LEGACY_MARKER_SPK: [u8; 34] = [
    0x00, 0x20, 0x4a, 0xe8, 0x15, 0x72, 0xf0, 0x6e, 0x1b, 0x88, 0xfd, 0x5c, 0xed, 0x7a, 0x1a, 0x00,
    0x09, 0x45, 0x43, 0x2e, 0x83, 0xe1, 0x55, 0x1e, 0x6f, 0x72, 0x1e, 0xe9, 0xc0, 0x0b, 0x8c, 0xc3,
    0x32, 0x60,
];

/// Whether `script_pubkey` is a current or historical OpenCSV marker.
pub fn is_marker_spk(script_pubkey: &[u8]) -> bool {
    script_pubkey == MARKER_SPK || script_pubkey == LEGACY_MARKER_SPK
}

/// The marker output's value in satoshis (above the P2WSH dust limit of
/// 294, matching the conventional 546-sat dust constant).
pub const MARKER_DUST_SATS: u64 = 546;

/// The marker output's value in BTC (for `createrawtransaction` amounts).
pub const MARKER_DUST_BTC: f64 = 0.00000546;

/// The bech32 address of the marker scriptPubKey on `network` (needed
/// because `createrawtransaction` takes address-keyed outputs).
pub fn marker_address(network: Network) -> String {
    let hrp = match network {
        Network::Mainnet => "bc",
        Network::Signet => "tb",
        Network::Regtest => "bcrt",
    };
    crate::bech32::encode_v0(hrp, &MARKER_SPK[2..])
}

/// Internal-order bytes of a display-order RPC txid/block hash hex string.
pub(crate) fn hash_from_rpc(hex: &str) -> Result<[u8; 32], Error> {
    let mut bytes: [u8; 32] = from_hex(hex)?
        .try_into()
        .map_err(|v: Vec<u8>| Error::Malformed(format!("hash `{hex}` is {} bytes", v.len())))?;
    bytes.reverse();
    Ok(bytes)
}

/// Display-order hex of internal-order bytes (the inverse of
/// [`hash_from_rpc`]).
fn hash_to_rpc(bytes: &[u8; 32]) -> String {
    let mut bytes = *bytes;
    bytes.reverse();
    to_hex(&bytes)
}

/// Display-order hex of an internal-order txid (block-explorer order).
pub fn display_txid(txid: &[u8; 32]) -> String {
    hash_to_rpc(txid)
}

/// Lowercase hex encoding.
pub(crate) fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Decode hex, odd lengths rejected.
fn from_hex(s: &str) -> Result<Vec<u8>, Error> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return Err(Error::Malformed(format!("odd-length hex ({})", s.len())));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|_| Error::Malformed(format!("non-hex byte at offset {i}")))
        })
        .collect()
}

/// Extract a 64-byte `OP_RETURN` payload from a scriptPubKey hex string:
/// `6a` followed by a single direct/`PUSHDATA1`/`PUSHDATA2` push of
/// exactly 64 bytes and nothing else.
fn op_return_payload(script_hex: &str) -> Option<[u8; ANCHOR_SIZE]> {
    let script = from_hex(script_hex).ok()?;
    let rest = script.strip_prefix(&[0x6a])?;
    let data = match rest {
        [0x40, data @ ..] => data,
        [0x4c, 0x40, data @ ..] => data,
        [0x4d, 0x40, 0x00, data @ ..] => data,
        _ => return None,
    };
    data.try_into().ok()
}

#[derive(Clone, Copy, Debug)]
struct Entry {
    txid: [u8; 32],
    location: AnchorLocation,
    record: AnchorRecord,
    ctx: [u8; 32],
}

/// An [`AnchorChain`] reading real Bitcoin blocks over `bitcoind` RPC and
/// anchoring by broadcasting `OP_RETURN` transactions (see the crate
/// docs). Generic over the RPC [`Transport`] so unit tests can script
/// canned responses; the product path is `BitcoinAnchorChain` (=
/// `BitcoinAnchorChain<HttpTransport>`).
pub struct BitcoinAnchorChain<T: Transport = HttpTransport> {
    client: RpcClient<T>,
    network: Network,
    index_path: PathBuf,
    start_height: u64,
    tip: u64,
    /// Last scanned (height, block hash); `None` before the start height.
    scanned: Option<(u64, [u8; 32])>,
    /// Confirmed anchors, in canonical order.
    entries: Vec<Entry>,
    /// Anchors broadcast by this process and not yet seen mined
    /// (in-memory only — a fresh process learns them from the scan once
    /// they confirm).
    mempool: Vec<Entry>,
    /// Per-scanned-block marker presence: does the block contain the current
    /// [`MARKER_SPK`] or exact historical marker (i.e. is it discoverable by
    /// a BIP158 filter scan)?
    markers: std::collections::BTreeMap<u64, bool>,
    /// The batch-funding outpoints tracked by this backend, keyed by
    /// payload count (see `batch.rs`): anyone-can-spend, so the wallet
    /// does not report them in `listunspent` — they are tracked here
    /// and verified against the node's UTXO set with `gettxout`.
    funding_utxos: std::collections::BTreeMap<u8, ([u8; 32], u32)>,
}

impl BitcoinAnchorChain<HttpTransport> {
    /// Open the backend: build the HTTP transport, probe the node (hard
    /// error on unreachability, auth failure, or network mismatch), load
    /// or initialize the index, and scan up to the tip.
    pub fn open(config: &Config) -> Result<Self, Error> {
        let transport =
            HttpTransport::new(&config.rpc_url, config.wallet.as_deref(), &config.auth)?;
        Self::with_transport(RpcClient::new(transport), config)
    }
}

impl<T: Transport> BitcoinAnchorChain<T> {
    /// Open over an explicit RPC client (the transport-agnostic core of
    /// [`BitcoinAnchorChain::open`]).
    pub fn with_transport(client: RpcClient<T>, config: &Config) -> Result<Self, Error> {
        // Probe: unreachable node, bad auth, and wrong network are hard
        // errors — never a fallback.
        let info = client.call("getblockchaininfo", json!([]))?;
        let actual = info
            .get("chain")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::Malformed("getblockchaininfo: no `chain`".into()))?;
        if actual != config.network.rpc_chain_name() {
            return Err(Error::WrongNetwork {
                expected: config.network,
                actual: actual.to_string(),
            });
        }
        let tip = info
            .get("blocks")
            .and_then(Value::as_u64)
            .ok_or_else(|| Error::Malformed("getblockchaininfo: no `blocks`".into()))?;
        let mut chain = Self {
            client,
            network: config.network,
            index_path: config.index_path.clone(),
            start_height: 0,
            tip,
            scanned: None,
            entries: Vec::new(),
            mempool: Vec::new(),
            markers: std::collections::BTreeMap::new(),
            funding_utxos: std::collections::BTreeMap::new(),
        };
        chain.load_or_init(config.scan_from)?;
        chain.refresh()?;
        Ok(chain)
    }

    /// The network this backend is connected to.
    pub fn network(&self) -> Network {
        self.network
    }

    /// The RPC client (crate-internal: the batch flow needs raw calls).
    pub(crate) fn client(&self) -> &RpcClient<T> {
        &self.client
    }

    /// Record a broadcast anchor in the in-memory mempool view
    /// (crate-internal: the batch flow shares the resolution contract).
    pub(crate) fn note_mempool(&mut self, txid: [u8; 32], record: AnchorRecord, ctx: [u8; 32]) {
        self.mempool.push(Entry {
            txid,
            location: MEMPOOL_LOCATION,
            record,
            ctx,
        });
    }

    /// The tracked batch-funding outpoint for `payload_count`
    /// (crate-internal).
    pub(crate) fn funding_utxo(&self, payload_count: u8) -> Option<([u8; 32], u32)> {
        self.funding_utxos.get(&payload_count).copied()
    }

    /// Track/replace the batch-funding outpoint for `payload_count`
    /// and persist it (crate-internal).
    pub(crate) fn set_funding_utxo(
        &mut self,
        payload_count: u8,
        outpoint: ([u8; 32], u32),
    ) -> Result<(), Error> {
        self.funding_utxos.insert(payload_count, outpoint);
        self.persist()
    }

    /// The height scanning started (or will start) from.
    pub fn start_height(&self) -> u64 {
        self.start_height
    }

    /// The last height scanned into the index (`None` if the start height
    /// is above the tip).
    pub fn scanned_height(&self) -> Option<u64> {
        self.scanned.map(|(h, _)| h)
    }

    /// Number of confirmed anchors in the index.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Broadcast an already signed, protocol-validated Bitcoin
    /// transaction. The exact transaction is never rebuilt or wallet-
    /// signed here; peers use this after durably persisting the C2 batch
    /// transaction. A transaction already in this node's mempool is an
    /// idempotent success, covering a crash after RPC acceptance but before
    /// the session journal advances.
    pub fn broadcast_transaction(&self, transaction: &Transaction) -> Result<String, Error> {
        let expected = transaction.compute_txid().to_string();
        match self.client.call("getmempoolentry", json!([expected])) {
            Ok(_) => return Ok(expected),
            Err(Error::Rpc { code: -5, .. }) => {}
            Err(error) => return Err(error),
        }
        let raw = bitcoin::consensus::encode::serialize(transaction);
        let txid = match self
            .client
            .call_str("sendrawtransaction", json!([to_hex(&raw)]))
        {
            Ok(txid) => txid,
            Err(Error::Rpc { code: -27, .. }) => return Ok(expected),
            Err(error) => return Err(error),
        };
        if txid != expected {
            return Err(Error::Malformed(format!(
                "sendrawtransaction returned {txid}, expected {expected}"
            )));
        }
        Ok(txid)
    }

    /// Rescan from the last scanned height to the current tip, picking up
    /// newly mined anchors. On a stale tip hash (reorg) the index is
    /// truncated back to the start height and rebuilt (crate docs).
    pub fn refresh(&mut self) -> Result<(), Error> {
        self.tip = self
            .client
            .call("getblockcount", json!([]))?
            .as_u64()
            .ok_or_else(|| Error::Malformed("getblockcount: not a number".into()))?;
        if let Some((h, hash)) = self.scanned {
            let actual = self.client.call_str("getblockhash", json!([h]))?;
            if hash_from_rpc(&actual)? != hash {
                self.scanned = None;
                self.entries.clear();
                self.markers.clear();
            }
        }
        let mut height = self
            .scanned
            .map(|(h, _)| h + 1)
            .unwrap_or(self.start_height);
        let mut dirty = false;
        while height <= self.tip {
            let hash = self.client.call_str("getblockhash", json!([height]))?;
            let block = self.client.call("getblock", json!([hash, 2]))?;
            self.scan_block(&block, height)?;
            self.scanned = Some((height, hash_from_rpc(&hash)?));
            dirty = true;
            height += 1;
        }
        if !self.mempool.is_empty() {
            self.mempool
                .retain(|m| !self.entries.iter().any(|e| e.txid == m.txid));
        }
        if dirty {
            self.persist()?;
        }
        Ok(())
    }

    /// Broadcast a 64-byte anchor record in an `OP_RETURN` output of a
    /// real Bitcoin transaction (two-pass construction; see the crate
    /// docs). `build` constructs the record from the transaction context
    /// — the bound payloads commit to it — and is evaluated once per
    /// candidate funding input until the record
    /// [`AnchorRecord::parses_cleanly`]. Returns a reference carrying
    /// [`MEMPOOL_LOCATION`]; the confirmed location is resolved by txid
    /// once the transaction mines.
    ///
    /// The anchor transaction's output layout is protocol-fixed: output
    /// 0 is the OP_RETURN record, output 1 is the constant
    /// [`MARKER_SPK`] output ([`MARKER_DUST_SATS`] sats) that makes the
    /// block discoverable by BIP158 filter scans, outputs 2.. are change
    /// (`fundrawtransaction` places change at position 2). The marker is
    /// included in the pass-1 dummy transaction so the funding and fee
    /// math is exact.
    pub fn anchor(
        &mut self,
        mut build: impl FnMut(&[u8; 32]) -> AnchorRecord,
    ) -> Result<AnchorRef, Error> {
        // Pass 1: fund a transaction carrying a dummy 64-byte OP_RETURN
        // and the marker output, letting the wallet select inputs and
        // price change + fee. Change is pinned to position 2 so the
        // output layout is the protocol's (record@0, marker@1, change@2).
        let dummy = to_hex(&[0u8; ANCHOR_SIZE]);
        let marker = marker_address(self.network);
        let raw1 = self.client.call_str(
            "createrawtransaction",
            json!([[], [{"data": dummy}, {marker: MARKER_DUST_BTC}]]),
        )?;
        let funded = self
            .client
            .call("fundrawtransaction", json!([raw1, {"change_position": 2}]))?;
        let funded_hex = funded
            .get("hex")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::Malformed("fundrawtransaction: no `hex`".into()))?;
        let tx = self
            .client
            .call("decoderawtransaction", json!([funded_hex]))?;
        let malformed = |what: &str| Error::Malformed(format!("funded transaction: {what}"));
        let vin = tx
            .get("vin")
            .and_then(Value::as_array)
            .ok_or_else(|| malformed("no `vin`"))?;
        let vout = tx
            .get("vout")
            .and_then(Value::as_array)
            .ok_or_else(|| malformed("no `vout`"))?;
        let mut candidates: Vec<(String, u32)> = Vec::with_capacity(vin.len());
        for input in vin {
            let txid = input
                .get("txid")
                .and_then(Value::as_str)
                .ok_or_else(|| malformed("vin entry without `txid`"))?;
            let n = input
                .get("vout")
                .and_then(Value::as_u64)
                .ok_or_else(|| malformed("vin entry without `vout`"))?;
            candidates.push((
                txid.to_string(),
                u32::try_from(n).map_err(|_| malformed("`vout` overflows u32"))?,
            ));
        }
        if candidates.is_empty() {
            return Err(Error::NoFundingInputs);
        }
        // Choose the funding input: the first whose ctx yields a cleanly
        // parsing record (the tag-collision redraw, with input order as
        // the redraw freedom — vin[0] is the ctx input).
        let mut chosen = None;
        for (i, (txid, n)) in candidates.iter().enumerate() {
            let ctx = funding_ctx(&hash_from_rpc(txid)?, *n);
            let record = build(&ctx);
            if record.parses_cleanly() {
                chosen = Some((i, ctx, record));
                break;
            }
        }
        let (chosen_idx, ctx, record) = chosen.ok_or(Error::TagCollision)?;
        // Pass 2: identical inputs (chosen first) and identical outputs —
        // same fee, same change — with the real record bytes in place of
        // the dummy payload.
        let mut inputs = Vec::with_capacity(candidates.len());
        inputs.push(json!({
            "txid": &candidates[chosen_idx].0,
            "vout": candidates[chosen_idx].1,
        }));
        for (i, (txid, n)) in candidates.iter().enumerate() {
            if i != chosen_idx {
                inputs.push(json!({"txid": txid, "vout": n}));
            }
        }
        let record_hex = to_hex(&record.to_bytes());
        let mut outputs = Vec::with_capacity(vout.len());
        for output in vout {
            let script = output
                .get("scriptPubKey")
                .ok_or_else(|| malformed("vout entry without `scriptPubKey`"))?;
            if script.get("type").and_then(Value::as_str) == Some("nulldata") {
                outputs.push(json!({"data": record_hex}));
            } else {
                let address = script
                    .get("address")
                    .and_then(Value::as_str)
                    .ok_or_else(|| malformed("vout entry without `address`"))?;
                // `value` passes through untouched (arbitrary-precision
                // JSON): the amount is exactly what pass 1 priced.
                let mut obj = serde_json::Map::new();
                obj.insert(address.to_string(), output["value"].clone());
                outputs.push(Value::Object(obj));
            }
        }
        let raw2 = self
            .client
            .call_str("createrawtransaction", json!([inputs, outputs]))?;
        let signed = self
            .client
            .call("signrawtransactionwithwallet", json!([raw2]))?;
        if signed.get("complete").and_then(Value::as_bool) != Some(true) {
            return Err(Error::SigningFailed(
                signed
                    .get("errors")
                    .map(Value::to_string)
                    .unwrap_or_else(|| "unknown signing error".into()),
            ));
        }
        let signed_hex = signed
            .get("hex")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::Malformed("signrawtransactionwithwallet: no `hex`".into()))?;
        let txid_hex = self
            .client
            .call_str("sendrawtransaction", json!([signed_hex]))?;
        let txid = hash_from_rpc(&txid_hex)?;
        self.mempool.push(Entry {
            txid,
            location: MEMPOOL_LOCATION,
            record,
            ctx,
        });
        Ok(AnchorRef {
            txid,
            location: MEMPOOL_LOCATION,
        })
    }

    /// Mine `n` blocks to a fresh wallet address (regtest only — backs the
    /// CLI's `chain advance`; on real networks blocks arrive by mining and
    /// this is a hard error).
    pub fn generate_blocks(&mut self, n: u64) -> Result<(), Error> {
        if self.network != Network::Regtest {
            return Err(Error::NotRegtest);
        }
        let address = self.client.call_str("getnewaddress", json!([]))?;
        self.client.call("generatetoaddress", json!([n, address]))?;
        self.refresh()
    }

    fn scan_block(&mut self, block: &Value, height: u64) -> Result<(), Error> {
        let txs = block
            .get("tx")
            .and_then(Value::as_array)
            .ok_or_else(|| Error::Malformed("getblock: no `tx` array".into()))?;
        let marker_hex = to_hex(&MARKER_SPK);
        let legacy_marker_hex = to_hex(&LEGACY_MARKER_SPK);
        let mut has_marker = false;
        for (position, tx) in txs.iter().enumerate() {
            if !has_marker {
                has_marker = tx
                    .get("vout")
                    .and_then(Value::as_array)
                    .is_some_and(|vout| {
                        vout.iter().any(|o| {
                            o.get("scriptPubKey")
                                .and_then(|s| s.get("hex"))
                                .and_then(Value::as_str)
                                .is_some_and(|script| {
                                    script == marker_hex || script == legacy_marker_hex
                                })
                        })
                    });
            }
            if let Some(entry) = scan_tx(tx, height, position as u32)? {
                self.entries.push(entry);
            }
        }
        self.markers.insert(height, has_marker);
        Ok(())
    }

    /// Whether the block at `height` carries the protocol-constant
    /// current or historical marker output; `None` for blocks not (yet)
    /// scanned.
    pub fn block_has_marker(&self, height: u64) -> Option<bool> {
        self.markers.get(&height).copied()
    }

    fn load_or_init(&mut self, scan_from: Option<u64>) -> Result<(), Error> {
        match self.load_index()? {
            Some((start, scanned, entries, markers, funding_utxos))
                if scan_from.is_none() || scan_from == Some(start) =>
            {
                self.start_height = start;
                self.scanned = scanned;
                self.entries = entries;
                self.markers = markers;
                self.funding_utxos = funding_utxos;
            }
            Some(_) | None => {
                // No index, or an explicit --scan-from that differs from
                // the stored start: (re)build from the requested height.
                self.start_height = scan_from.unwrap_or(self.tip);
                self.scanned = None;
                self.entries.clear();
                self.markers.clear();
            }
        }
        Ok(())
    }

    fn persist(&self) -> Result<(), Error> {
        if let Some(parent) = self.index_path.parent() {
            std::fs::create_dir_all(parent).map_err(io_err(parent))?;
        }
        let mut out = format!(
            "{MAGIC}\nnetwork {}\nstart {}\n",
            self.network.name(),
            self.start_height
        );
        if let Some((height, hash)) = self.scanned {
            out.push_str(&format!("scanned {} {}\n", height, hash_to_rpc(&hash)));
        }
        for (height, has_marker) in &self.markers {
            out.push_str(&format!(
                "marker {} {}\n",
                height,
                u8::from(*has_marker)
            ));
        }
        for (count, (txid, vout)) in &self.funding_utxos {
            out.push_str(&format!(
                "fundingutxo {} {} {}\n",
                count,
                hash_to_rpc(txid),
                vout
            ));
        }
        for e in &self.entries {
            out.push_str(&format!(
                "entry {} {} {} {} {}\n",
                e.location.height,
                e.location.position,
                hash_to_rpc(&e.txid),
                to_hex(&e.ctx),
                to_hex(&e.record.to_bytes()),
            ));
        }
        std::fs::write(&self.index_path, out).map_err(io_err(&self.index_path))
    }

    /// Load the index file, returning `(start, scanned, entries)`; `None`
    /// if the file does not exist. A network mismatch is a hard error.
    fn load_index(&self) -> Result<Option<PersistedIndex>, Error> {
        let text = match std::fs::read_to_string(&self.index_path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(io_err(&self.index_path)(e)),
        };
        let decode = |message: String| Error::Decode {
            path: self.index_path.clone(),
            message,
        };
        let mut start = None;
        let mut scanned = None;
        let mut entries = Vec::new();
        let mut markers = std::collections::BTreeMap::new();
        let mut funding_utxos = std::collections::BTreeMap::new();
        let mut lines = text.lines().enumerate();
        match lines.next() {
            // A v1 cache predates the marker lines: rebuild (the index
            // is a cache — this is an upgrade, not corruption).
            Some((_, line)) if line.trim() == MAGIC_V1 => return Ok(None),
            Some((_, line)) if line.trim() == MAGIC => {}
            _ => return Err(decode("bad magic line".into())),
        }
        for (n, line) in lines {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let bad = || decode(format!("line {}: malformed `{line}`", n + 1));
            let fields: Vec<&str> = line.split_whitespace().collect();
            match fields.as_slice() {
                ["network", name] => {
                    if Network::parse(name).ok() != Some(self.network) {
                        return Err(decode(format!(
                            "index is for network `{name}`, not {}",
                            self.network.name()
                        )));
                    }
                }
                ["start", h] => start = Some(h.parse().map_err(|_| bad())?),
                ["fundingutxo", count, txid, vout] => {
                    funding_utxos.insert(
                        count.parse().map_err(|_| bad())?,
                        (
                            hash_from_rpc(txid).map_err(|_| bad())?,
                            vout.parse().map_err(|_| bad())?,
                        ),
                    );
                }
                ["marker", h, f] => {
                    let height = h.parse().map_err(|_| bad())?;
                    let has_marker = match *f {
                        "0" => false,
                        "1" => true,
                        _ => return Err(bad()),
                    };
                    markers.insert(height, has_marker);
                }
                ["scanned", h, hash] => {
                    scanned = Some((
                        h.parse().map_err(|_| bad())?,
                        hash_from_rpc(hash).map_err(|_| bad())?,
                    ));
                }
                ["entry", h, p, txid, ctx, record] => {
                    let record_bytes: [u8; ANCHOR_SIZE] = from_hex(record)
                        .map_err(|_| bad())?
                        .try_into()
                        .map_err(|_| bad())?;
                    entries.push(Entry {
                        txid: hash_from_rpc(txid).map_err(|_| bad())?,
                        location: AnchorLocation {
                            height: h.parse().map_err(|_| bad())?,
                            position: p.parse().map_err(|_| bad())?,
                        },
                        record: AnchorRecord::from_bytes(&record_bytes),
                        ctx: from_hex(ctx)
                            .map_err(|_| bad())?
                            .try_into()
                            .map_err(|_| bad())?,
                    });
                }
                _ => return Err(bad()),
            }
        }
        let start = start.ok_or_else(|| decode("missing `start` line".into()))?;
        Ok(Some((start, scanned, entries, markers, funding_utxos)))
    }

    fn find(&self, anchor_ref: &AnchorRef) -> Option<&Entry> {
        let matches = |e: &&Entry| {
            e.txid == anchor_ref.txid
                && (e.location == anchor_ref.location || anchor_ref.location == MEMPOOL_LOCATION)
        };
        self.entries
            .iter()
            .find(matches)
            .or_else(|| self.mempool.iter().find(matches))
    }
}

/// Extract an anchor entry from a decoded transaction (verbosity 2): the
/// first 64-byte `OP_RETURN` output, with `ctx` from vin\[0\]. Coinbase
/// transactions and transactions without a 64-byte data output yield
/// `None`.
fn scan_tx(tx: &Value, height: u64, position: u32) -> Result<Option<Entry>, Error> {
    let malformed = || Error::Malformed("scanned transaction has no `txid`".into());
    let txid_hex = tx
        .get("txid")
        .and_then(Value::as_str)
        .ok_or_else(malformed)?;
    let vin0 = tx
        .get("vin")
        .and_then(Value::as_array)
        .and_then(|vin| vin.first());
    let Some(vin0) = vin0 else {
        return Ok(None); // vin-less: no funding input
    };
    let (Some(prev_txid), Some(prev_vout)) = (
        vin0.get("txid").and_then(Value::as_str),
        vin0.get("vout").and_then(Value::as_u64),
    ) else {
        return Ok(None); // coinbase: no prevout
    };
    let prev_vout = u32::try_from(prev_vout)
        .map_err(|_| Error::Malformed("scanned vin `vout` overflows u32".into()))?;
    let ctx = funding_ctx(&hash_from_rpc(prev_txid)?, prev_vout);
    let Some(vout) = tx.get("vout").and_then(Value::as_array) else {
        return Ok(None);
    };
    for output in vout {
        let script = output.get("scriptPubKey");
        if script.and_then(|s| s.get("type")).and_then(Value::as_str) != Some("nulldata") {
            continue;
        }
        if let Some(payload) = script
            .and_then(|s| s.get("hex"))
            .and_then(Value::as_str)
            .and_then(op_return_payload)
        {
            return Ok(Some(Entry {
                txid: hash_from_rpc(txid_hex)?,
                location: AnchorLocation { height, position },
                record: AnchorRecord::from_bytes(&payload),
                ctx,
            }));
        }
    }
    Ok(None)
}

impl<T: Transport> AnchorChain for BitcoinAnchorChain<T> {
    fn tip_height(&self) -> u64 {
        // Cached at open/refresh — the trait cannot surface RPC errors.
        self.tip
    }

    fn anchor_at(&self, anchor_ref: &AnchorRef) -> Option<AnchorRecord> {
        self.find(anchor_ref).map(|e| e.record)
    }

    fn ctx_at(&self, anchor_ref: &AnchorRef) -> Option<[u8; 32]> {
        self.find(anchor_ref).map(|e| e.ctx)
    }

    fn locate(&self, anchor_ref: &AnchorRef) -> Option<AnchorLocation> {
        // Resolve by txid: the consignment's location may be the mempool
        // placeholder while the confirmed position only exists post-scan.
        self.find(anchor_ref).map(|e| e.location)
    }

    fn first_nullifier_occurrence(&self, raw_nf: &Digest) -> Option<AnchorLocation> {
        self.nullifier_occurrences(raw_nf).into_iter().next()
    }

    fn nullifier_occurrences(&self, raw_nf: &Digest) -> Vec<AnchorLocation> {
        // Confirmed anchors only: canonical chain order does not exist for
        // mempool transactions.
        let mut locations: Vec<_> = self
            .entries
            .iter()
            .filter(|e| e.record.well_formed(&e.ctx, raw_nf))
            .map(|e| e.location)
            .collect();
        locations.sort();
        locations
    }

    fn anchors_up_to(&self, height: u64) -> Vec<(AnchorLocation, AnchorRecord)> {
        let mut anchors: Vec<_> = self
            .entries
            .iter()
            .filter(|e| e.location.height <= height)
            .map(|e| (e.location, e.record))
            .collect();
        anchors.sort_by_key(|(location, _)| *location);
        anchors
    }

    fn confirmations_at(&self, height: u64) -> u64 {
        // Height 0 is the mempool placeholder: 0 confirmations.
        if height == 0 || height > self.tip {
            0
        } else {
            self.tip - height + 1
        }
    }
}

/// First line of every index file (format version tag; v2 adds the
/// per-block `marker` lines).
const MAGIC: &str = "opencsv-bitcoin-index-v2";
/// The pre-marker format's magic: rebuilt silently (rebuildable cache).
const MAGIC_V1: &str = "opencsv-bitcoin-index-v1";

/// `(start_height, last_scanned(height, block_hash), confirmed entries,
/// per-block marker flags)` as persisted in the index file.
type PersistedIndex = (
    u64,
    Option<(u64, [u8; 32])>,
    Vec<Entry>,
    std::collections::BTreeMap<u64, bool>,
    std::collections::BTreeMap<u8, ([u8; 32], u32)>,
);

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
