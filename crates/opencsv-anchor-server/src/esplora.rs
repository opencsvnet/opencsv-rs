//! Bitcoin backend over the esplora REST API (mempool.space, blockstream.info,
//! or any custom instance): scans blocks for OpenCSV OP_RETURN anchors,
//! maintains the ordered anchor log locally, and broadcasts new anchors from
//! a funded P2WPKH key.
//!
//! The served `/snapshot` shape is identical to the file backend's, so
//! wallets cannot tell the difference — except that `POST /anchor` returns
//! `{"txid","status":"pending"}` and clients poll `GET /anchor/<txid>`
//! until the transaction is mined (a real chain assigns `(height, position)`
//! only at confirmation).
//!
//! Prototype caveats: reorgs are not tracked (the scan cursor only moves
//! forward), and one anchor output per transaction is indexed.

use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::sighash::SighashCache;
use bitcoin::{
    absolute, transaction, Address, Amount, CompressedPublicKey, EcdsaSighashType, Network,
    OutPoint, PrivateKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use opencsv_core::chain::{AnchorLocation, AnchorRef};
use opencsv_core::{AnchorRecord, ANCHOR_SIZE};
use serde::Deserialize;

use opencsv_cli::hexutil::{from_hex, to_hex};

/// A named network with a well-known esplora endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum KnownNetwork {
    /// Bitcoin mainnet (default endpoint: mempool.space).
    Mainnet,
    /// Bitcoin signet (default endpoint: mempool.space/signet).
    Signet,
    /// The Mutiny custom signet — 30-second blocks, ideal for demos
    /// (default endpoint: mutinynet.com).
    Mutinynet,
}

impl KnownNetwork {
    pub fn default_esplora_url(self) -> &'static str {
        match self {
            Self::Mainnet => "https://mempool.space/api",
            Self::Signet => "https://mempool.space/signet/api",
            Self::Mutinynet => "https://mutinynet.com/api",
        }
    }

    pub fn bitcoin_network(self) -> Network {
        match self {
            Self::Mainnet => Network::Bitcoin,
            Self::Signet | Self::Mutinynet => Network::Signet,
        }
    }
}

// ---------------------------------------------------------------------------
// Esplora REST client.
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct EsploraTxStatus {
    pub confirmed: bool,
    pub block_height: Option<u64>,
    pub block_hash: Option<String>,
}

#[derive(Deserialize)]
struct EsploraVout {
    scriptpubkey: String,
    #[serde(default)]
    scriptpubkey_type: String,
}

#[derive(Deserialize)]
struct EsploraVin {
    txid: String,
    vout: u32,
}

#[derive(Deserialize)]
struct EsploraTx {
    txid: String,
    #[serde(default)]
    vin: Vec<EsploraVin>,
    vout: Vec<EsploraVout>,
}

/// The transaction context of an anchor: the funding input's outpoint,
/// hashed by [`opencsv_bitcoin::funding_ctx`] — the canonical derivation
/// (`SHA-256(txid_internal ∥ vout_le)`), so every backend agrees on what a
/// record binds to (opencsv-rs#2). Deriving `ctx` from chain data means the 32 bytes need
/// no room in the 64-byte OP_RETURN and any scanner recomputes it
/// independently, so a snapshot server cannot lie about it.
pub fn ctx_from_outpoint(txid: &Txid, vout: u32) -> [u8; 32] {
    opencsv_bitcoin::funding_ctx(&txid.to_byte_array(), vout)
}

#[derive(Deserialize)]
pub struct EsploraUtxo {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
    pub status: EsploraTxStatus,
}

pub struct EsploraClient {
    base: String,
    agent: ureq::Agent,
}

impl EsploraClient {
    pub fn new(base_url: &str) -> Self {
        Self {
            base: base_url.trim_end_matches('/').to_string(),
            agent: ureq::AgentBuilder::new()
                .timeout(std::time::Duration::from_secs(30))
                .build(),
        }
    }

    fn get_text(&self, path: &str) -> Result<String, String> {
        self.agent
            .get(&format!("{}{path}", self.base))
            .call()
            .map_err(|e| format!("GET {path}: {e}"))?
            .into_string()
            .map_err(|e| format!("GET {path}: {e}"))
    }

    fn get_json<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T, String> {
        self.agent
            .get(&format!("{}{path}", self.base))
            .call()
            .map_err(|e| format!("GET {path}: {e}"))?
            .into_json()
            .map_err(|e| format!("GET {path}: {e}"))
    }

    pub fn tip_height(&self) -> Result<u64, String> {
        self.get_text("/blocks/tip/height")?
            .trim()
            .parse()
            .map_err(|e| format!("tip height: {e}"))
    }

    fn block_hash_at(&self, height: u64) -> Result<String, String> {
        Ok(self
            .get_text(&format!("/block-height/{height}"))?
            .trim()
            .to_string())
    }

    fn block_txs(&self, hash: &str, start: usize) -> Result<Vec<EsploraTx>, String> {
        self.get_json(&format!("/block/{hash}/txs/{start}"))
    }

    pub fn block_txids(&self, hash: &str) -> Result<Vec<String>, String> {
        self.get_json(&format!("/block/{hash}/txids"))
    }

    pub fn tx_status(&self, txid: &str) -> Result<EsploraTxStatus, String> {
        self.get_json(&format!("/tx/{txid}/status"))
    }

    pub fn utxos(&self, address: &str) -> Result<Vec<EsploraUtxo>, String> {
        self.get_json(&format!("/address/{address}/utxo"))
    }

    /// Fastest-confirmation fee rate in sat/vB (floor 1.0).
    pub fn fee_rate(&self) -> f64 {
        let estimates: Result<std::collections::HashMap<String, f64>, _> =
            self.get_json("/fee-estimates");
        estimates
            .ok()
            .and_then(|m| m.get("1").or_else(|| m.get("2")).copied())
            .unwrap_or(1.0)
            .max(1.0)
    }

    pub fn broadcast(&self, tx_hex: &str) -> Result<String, String> {
        self.agent
            .post(&format!("{}/tx", self.base))
            .send_string(tx_hex)
            .map_err(|e| format!("POST /tx: {e}"))?
            .into_string()
            .map_err(|e| format!("POST /tx: {e}"))
            .map(|s| s.trim().to_string())
    }
}

/// Extract an OpenCSV anchor record from an OP_RETURN script
/// (`OP_RETURN <push 64 bytes>` exactly).
fn record_from_op_return(script_hex: &str) -> Option<AnchorRecord> {
    let bytes = from_hex(script_hex).ok()?;
    let payload: [u8; ANCHOR_SIZE] = match bytes.as_slice() {
        // 0x6a OP_RETURN, 0x40 = direct push of 64 bytes.
        [0x6a, 0x40, rest @ ..] => rest.try_into().ok()?,
        _ => return None,
    };
    Some(AnchorRecord::from_bytes(&payload))
}

// ---------------------------------------------------------------------------
// Scanner state, persisted to a cache file for incremental restarts.
// ---------------------------------------------------------------------------

const CACHE_MAGIC: &str = "opencsv-esplora-cache-v1";

pub struct ScanState {
    pub entries: Vec<(AnchorRef, AnchorRecord, [u8; 32])>,
    pub tip_height: u64,
    scanned_to: u64,
    cache_path: PathBuf,
}

impl ScanState {
    pub fn load(cache_path: PathBuf, birth_height: u64) -> Result<Self, String> {
        let mut state = Self {
            entries: Vec::new(),
            tip_height: 0,
            scanned_to: birth_height.saturating_sub(1),
            cache_path,
        };
        let content = match std::fs::read_to_string(&state.cache_path) {
            Ok(content) => content,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(state),
            Err(e) => return Err(format!("cache: {e}")),
        };
        let mut lines = content.lines();
        if lines.next().map(str::trim) != Some(CACHE_MAGIC) {
            return Err("cache: bad magic (delete the cache file to rescan)".into());
        }
        for line in lines {
            let fields: Vec<&str> = line.split_whitespace().collect();
            match fields.as_slice() {
                ["scanned", h] => {
                    state.scanned_to = h.parse().map_err(|e| format!("cache: {e}"))?;
                }
                ["entry", h, p, txid_hex, record_hex, ctx_hex] => {
                    let txid: [u8; 32] = from_hex(txid_hex)
                        .map_err(|e| format!("cache: {e}"))?
                        .try_into()
                        .map_err(|_| "cache: bad txid".to_string())?;
                    let record_bytes: [u8; ANCHOR_SIZE] = from_hex(record_hex)
                        .map_err(|e| format!("cache: {e}"))?
                        .try_into()
                        .map_err(|_| "cache: bad record".to_string())?;
                    let record = AnchorRecord::from_bytes(&record_bytes);
                    let ctx: [u8; 32] = from_hex(ctx_hex)
                        .map_err(|e| format!("cache: {e}"))?
                        .try_into()
                        .map_err(|_| "cache: bad ctx".to_string())?;
                    state.entries.push((
                        AnchorRef {
                            txid,
                            location: AnchorLocation {
                                height: h.parse().map_err(|e| format!("cache: {e}"))?,
                                position: p.parse().map_err(|e| format!("cache: {e}"))?,
                            },
                        },
                        record,
                        ctx,
                    ));
                }
                [] => {}
                _ => return Err(format!("cache: malformed line `{line}`")),
            }
        }
        Ok(state)
    }

    fn append_cache_line(&self, line: &str) -> Result<(), String> {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.cache_path)
            .map_err(|e| format!("cache: {e}"))?;
        if file.metadata().map(|m| m.len()).unwrap_or(0) == 0 {
            writeln!(file, "{CACHE_MAGIC}").map_err(|e| format!("cache: {e}"))?;
        }
        writeln!(file, "{line}").map_err(|e| format!("cache: {e}"))
    }
}

/// Scan any newly mined blocks into `state`. Returns the number of new
/// anchors found.
pub fn scan_new_blocks(client: &EsploraClient, state: &mut ScanState) -> Result<usize, String> {
    let tip = client.tip_height()?;
    state.tip_height = tip;
    let mut found = 0;
    while state.scanned_to < tip {
        let height = state.scanned_to + 1;
        let hash = client.block_hash_at(height)?;
        let mut index = 0usize;
        loop {
            let txs = client.block_txs(&hash, index)?;
            if txs.is_empty() {
                break;
            }
            let page_len = txs.len();
            for (offset, tx) in txs.into_iter().enumerate() {
                let position = (index + offset) as u32;
                for vout in &tx.vout {
                    if vout.scriptpubkey_type != "op_return" {
                        continue;
                    }
                    let Some(record) = record_from_op_return(&vout.scriptpubkey) else {
                        continue;
                    };
                    let txid: [u8; 32] = match from_hex(&tx.txid) {
                        Ok(bytes) => match <[u8; 32]>::try_from(bytes) {
                            Ok(txid) => txid,
                            Err(_) => continue,
                        },
                        Err(_) => continue,
                    };
                    // ctx comes from the funding input, recomputed from
                    // chain data (see ctx_from_outpoint).
                    let Some(funding) = tx.vin.first() else {
                        continue;
                    };
                    let Ok(funding_txid) = funding.txid.parse::<Txid>() else {
                        continue;
                    };
                    let ctx = ctx_from_outpoint(&funding_txid, funding.vout);
                    let anchor_ref = AnchorRef {
                        txid,
                        location: AnchorLocation { height, position },
                    };
                    state.append_cache_line(&format!(
                        "entry {height} {position} {} {} {}",
                        to_hex(&anchor_ref.txid),
                        to_hex(&record.to_bytes()),
                        to_hex(&ctx),
                    ))?;
                    state.entries.push((anchor_ref, record, ctx));
                    found += 1;
                    break; // one anchor per transaction
                }
            }
            if page_len < 25 {
                break;
            }
            index += page_len;
        }
        state.scanned_to = height;
        state.append_cache_line(&format!("scanned {height}"))?;
        if height.is_multiple_of(100) || state.scanned_to == tip {
            eprintln!(
                "scanned to height {height} ({} anchors)",
                state.entries.len()
            );
        }
    }
    Ok(found)
}

// ---------------------------------------------------------------------------
// The anchoring wallet: one P2WPKH key funding OP_RETURN anchor txs.
// ---------------------------------------------------------------------------

const DUST_SATS: u64 = 546;
/// Conservative vsize for 1 P2WPKH input, OP_RETURN(64) + change output.
const ANCHOR_TX_VSIZE: u64 = 210;

/// A funding outpoint held for a client between `reserve_context` and
/// `broadcast_anchor`.
struct Reservation {
    outpoint: (String, u32),
    made_at: std::time::Instant,
}

/// How long a reserved funding outpoint is held before it can be reused.
const RESERVATION_TTL: std::time::Duration = std::time::Duration::from_secs(180);

pub struct AnchorWallet {
    secp: Secp256k1<bitcoin::secp256k1::All>,
    key: PrivateKey,
    public_key: CompressedPublicKey,
    pub address: Address,
    /// Outpoints spent by our own unconfirmed broadcasts.
    reserved: Mutex<HashSet<(String, u32)>>,
    /// Funding outpoints handed out by `reserve_context`, keyed by the ctx
    /// they derive: the wallet binds its record to this ctx, so the anchor
    /// transaction must spend exactly this outpoint. Entries carry the
    /// reservation time and expire — an abandoned handshake (client
    /// crashed, user cancelled) must not strand the coin forever.
    contexts: Mutex<HashMap<[u8; 32], Reservation>>,
}

impl AnchorWallet {
    pub fn from_wif(wif: &str, network: Network) -> Result<Self, String> {
        let secp = Secp256k1::new();
        let key = PrivateKey::from_wif(wif.trim()).map_err(|e| format!("WIF: {e}"))?;
        if key.network != network.into() {
            return Err(format!(
                "WIF network {:?} does not match --network ({network:?})",
                key.network
            ));
        }
        let public_key =
            CompressedPublicKey::from_private_key(&secp, &key).map_err(|e| format!("key: {e}"))?;
        let address = Address::p2wpkh(&public_key, network);
        Ok(Self {
            secp,
            key,
            public_key,
            address,
            reserved: Mutex::new(HashSet::new()),
            contexts: Mutex::new(HashMap::new()),
        })
    }

    /// Generate a fresh key for `network`, printing WIF + address.
    pub fn generate(network: Network) -> (String, String) {
        let secp = Secp256k1::new();
        let (secret, _) = secp.generate_keypair(&mut bitcoin::secp256k1::rand::thread_rng());
        let key = PrivateKey::new(secret, network);
        let public_key =
            CompressedPublicKey::from_private_key(&secp, &key).expect("fresh key compresses");
        let address = Address::p2wpkh(&public_key, network);
        (key.to_wif(), address.to_string())
    }

    /// Reserve a funding UTXO and return the `ctx` it derives. The wallet
    /// binds its anchor record to this context; [`Self::broadcast_anchor`]
    /// then spends exactly this outpoint.
    pub fn reserve_context(&self, client: &EsploraClient) -> Result<[u8; 32], String> {
        let fee = (client.fee_rate() * ANCHOR_TX_VSIZE as f64).ceil() as u64;
        let mut reserved = self
            .reserved
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Release abandoned handshakes so their coins are spendable again.
        {
            let mut contexts = self
                .contexts
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            contexts.retain(|_, reservation| {
                let live = reservation.made_at.elapsed() < RESERVATION_TTL;
                if !live {
                    reserved.remove(&reservation.outpoint);
                }
                live
            });
        }
        let utxo = client
            .utxos(&self.address.to_string())?
            .into_iter()
            .filter(|u| !reserved.contains(&(u.txid.clone(), u.vout)))
            .filter(|u| u.value >= fee + DUST_SATS)
            // Prefer confirmed coins; unconfirmed own change still spends
            // (RBF chains permitting) when anchoring rapidly.
            .max_by_key(|u| (u.status.confirmed, u.value))
            .ok_or_else(|| {
                format!(
                    "no spendable UTXO covering fee {fee} + dust at {} — fund this address",
                    self.address
                )
            })?;
        let txid: Txid = utxo.txid.parse().map_err(|e| format!("utxo txid: {e}"))?;
        let ctx = ctx_from_outpoint(&txid, utxo.vout);
        reserved.insert((utxo.txid.clone(), utxo.vout));
        self.contexts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(
                ctx,
                Reservation {
                    outpoint: (utxo.txid, utxo.vout),
                    made_at: std::time::Instant::now(),
                },
            );
        Ok(ctx)
    }

    /// Build, sign, and broadcast an OP_RETURN transaction carrying `record`,
    /// spending the funding outpoint that `ctx` was reserved from.
    pub fn broadcast_anchor(
        &self,
        client: &EsploraClient,
        record: &AnchorRecord,
        ctx: &[u8; 32],
    ) -> Result<Txid, String> {
        let fee = (client.fee_rate() * ANCHOR_TX_VSIZE as f64).ceil() as u64;
        let reservation = self
            .contexts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(ctx)
            .ok_or_else(|| {
                "unknown or expired ctx: reserve one with POST /anchor/context, \
                 then anchor within the reservation window"
                    .to_string()
            })?
            .outpoint;
        let utxo = client
            .utxos(&self.address.to_string())?
            .into_iter()
            .find(|u| (u.txid.clone(), u.vout) == reservation)
            .ok_or_else(|| "the reserved funding UTXO is gone (respent?)".to_string())?;
        if utxo.value < fee + DUST_SATS {
            return Err(format!(
                "reserved UTXO {} sats does not cover fee {fee} + dust",
                utxo.value
            ));
        }

        let prev_txid: Txid = utxo.txid.parse().map_err(|e| format!("utxo txid: {e}"))?;
        let change = utxo.value - fee;
        let push = bitcoin::script::PushBytesBuf::try_from(record.to_bytes().to_vec())
            .map_err(|e| format!("op_return payload: {e}"))?;
        let mut tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(prev_txid, utxo.vout),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![
                TxOut {
                    value: Amount::ZERO,
                    script_pubkey: ScriptBuf::new_op_return(push),
                },
                TxOut {
                    value: Amount::from_sat(change),
                    script_pubkey: self.address.script_pubkey(),
                },
            ],
        };

        let sighash = SighashCache::new(&tx)
            .p2wpkh_signature_hash(
                0,
                &self.address.script_pubkey(),
                Amount::from_sat(utxo.value),
                EcdsaSighashType::All,
            )
            .map_err(|e| format!("sighash: {e}"))?;
        let signature = bitcoin::ecdsa::Signature {
            signature: self.secp.sign_ecdsa(
                &Message::from_digest(sighash.to_byte_array()),
                &self.key.inner,
            ),
            sighash_type: EcdsaSighashType::All,
        };
        tx.input[0].witness = Witness::p2wpkh(&signature, &self.public_key.0);

        let txid = client.broadcast(&bitcoin::consensus::encode::serialize_hex(&tx))?;
        txid.parse().map_err(|e| format!("broadcast txid: {e}"))
    }
}
