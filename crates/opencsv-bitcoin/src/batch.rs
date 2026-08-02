//! Batch anchoring (see `opencsv-core`'s `batch` module for the v1
//! format): one anchor transaction carrying N witness-envelope payloads
//! under a coordinator-pre-committed OP_TRUE funding outpoint.
//!
//! The coordinator flow mirrors the solo two-pass [`crate::BitcoinAnchorChain::anchor`]:
//!
//! 1. [`BitcoinAnchorChain::marker_utxo_ctx`] ensures a coordinator-owned
//!    P2WSH funding UTXO for the batch size exists (creating one if
//!    absent — a one-time self-funded setup per batch size) and returns
//!    the batch ctx (`funding_ctx` of that outpoint). Senders bind
//!    their payloads against this ctx: `P_i = H("bind" ∥ raw_nf_i ∥ ctx)`.
//! 2. [`BitcoinAnchorChain::anchor_batch`] assembles and broadcasts the
//!    batch transaction: input 0 spends the funding UTXO (witness:
//!    `OCSV` magic, one 24-byte item per payload, the witness script —
//!    all items ≤ 80 bytes, standardness-clean), output 0 is the
//!    OP_RETURN batch header record, output 1 is the constant marker
//!    output, output 2 returns the remaining funds to the funding
//!    scriptPubKey (self-sustaining stock for the next same-size batch).
//!
//! **Deviation from the original design note** (verified against
//! `testmempoolaccept`): bare `OP_TRUE` as the witness script does NOT
//! work with junk stack arguments — CLEANSTACK requires exactly one
//! stack element after execution. The witness script is therefore
//! `OP_DROP×(n+1) OP_TRUE` for a batch of n payloads (it consumes the
//! envelope arguments), and the funding scriptPubKey is
//! `OP_0 <sha256(OP_DROP×(n+1) OP_TRUE)>` — sized by payload count,
//! independent of the payloads, still no EC / quantum-clean /
//! anyone-can-spend. The constant [`MARKER_SPK`] output at output 1 is
//! unchanged, so filter discovery works as-is.
//!
//! The batch transaction is built and "signed" manually: the funding
//! script needs no signature (its arguments are ignored), so the
//! wallet is only needed for the funding setup.

use opencsv_core::anchor::ANCHOR_SIZE;
use opencsv_core::chain::AnchorRef;
use opencsv_core::{AnchorRecord, TruncatedDigest};
use serde_json::{json, Value};

use crate::chain::{
    hash_from_rpc, to_hex, BitcoinAnchorChain, MEMPOOL_LOCATION,
};
use crate::error::Error;
use crate::rpc::Transport;
use crate::{funding_ctx, MARKER_DUST_SATS, MARKER_SPK};

/// Value of the one-time OP_TRUE funding output created by
/// [`BitcoinAnchorChain::marker_utxo_ctx`] when none exists: covers the
/// marker output and many batches' fees (change cycles back to the
/// OP_TRUE scriptPubKey).
pub const BATCH_FUNDING_SATS: u64 = 100_000;

/// Fallback feerate (sat/vB) when `estimatesmartfee` has no estimate
/// (regtest); mainnet/signet use the node's estimate.
const FALLBACK_FEE_RATE: u64 = 1;

/// The batch funding witness script for `payload_count` payloads:
/// `OP_DROP×(payload_count+1) OP_TRUE` — consumes the envelope
/// arguments and leaves exactly one truthy stack element (CLEANSTACK).
pub fn drop_script(payload_count: usize) -> Vec<u8> {
    let mut script = vec![0x75; payload_count + 1]; // OP_DROP
    script.push(0x51); // OP_TRUE
    script
}

/// The batch funding scriptPubKey for `payload_count` payloads:
/// `OP_0 <sha256(drop_script(payload_count))>` (P2WSH).
pub fn batch_funding_spk(payload_count: usize) -> [u8; 34] {
    use sha2::{Digest as _, Sha256};
    let program: [u8; 32] = Sha256::digest(drop_script(payload_count)).into();
    let mut spk = [0u8; 34];
    spk[0] = 0x00;
    spk[1] = 0x20;
    spk[2..].copy_from_slice(&program);
    spk
}

/// The bech32 address of the batch funding scriptPubKey on `network`.
fn batch_funding_address(network: crate::Network, payload_count: usize) -> String {
    let hrp = match network {
        crate::Network::Mainnet => "bc",
        crate::Network::Signet => "tb",
        crate::Network::Regtest => "bcrt",
    };
    crate::bech32::encode_v0(hrp, &batch_funding_spk(payload_count)[2..])
}

/// Decode a BTC-denominated JSON amount (arbitrary precision) into
/// satoshis, rejecting anything past 8 decimals.
fn btc_to_sats(value: &Value) -> Result<u64, Error> {
    let text = value
        .as_str()
        .map(str::to_owned)
        .or_else(|| value.as_f64().map(|f| format!("{f:.8}")))
        .ok_or_else(|| Error::Malformed(format!("amount `{value}` is not a number")))?;
    let (whole, frac) = text.split_once('.').unwrap_or((text.as_str(), ""));
    if frac.len() > 8 {
        return Err(Error::Malformed(format!("amount `{text}` exceeds 8 decimals")));
    }
    let whole: u64 = whole
        .parse()
        .map_err(|_| Error::Malformed(format!("amount `{text}`")))?;
    let frac = format!("{frac:0<8}");
    let frac: u64 = frac
        .parse()
        .map_err(|_| Error::Malformed(format!("amount `{text}`")))?;
    Ok(whole * 100_000_000 + frac)
}

fn write_varint(out: &mut Vec<u8>, n: u64) {
    if n < 0xfd {
        out.push(n as u8);
    } else if n <= 0xffff {
        out.push(0xfd);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xffff_ffff {
        out.push(0xfe);
        out.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        out.push(0xff);
        out.extend_from_slice(&n.to_le_bytes());
    }
}

fn write_varbytes(out: &mut Vec<u8>, bytes: &[u8]) {
    write_varint(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

/// Serialize the batch transaction. `witness_items` is the full witness
/// stack of input 0 (magic + payloads + witness script).
fn serialize_batch_tx(
    outpoint: &([u8; 32], u32),
    record: &[u8; ANCHOR_SIZE],
    change_sats: u64,
    change_spk: &[u8; 34],
    witness_items: &[Vec<u8>],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&2i32.to_le_bytes()); // version
    out.extend_from_slice(&[0x00, 0x01]); // segwit marker + flag
    write_varint(&mut out, 1);
    out.extend_from_slice(&outpoint.0);
    out.extend_from_slice(&outpoint.1.to_le_bytes());
    write_varint(&mut out, 0); // empty scriptSig
    out.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // sequence
    write_varint(&mut out, 3);
    // Output 0: the OP_RETURN batch header record.
    out.extend_from_slice(&0u64.to_le_bytes());
    let mut record_script = Vec::with_capacity(2 + ANCHOR_SIZE);
    record_script.push(0x6a);
    record_script.push(ANCHOR_SIZE as u8);
    record_script.extend_from_slice(record);
    write_varbytes(&mut out, &record_script);
    // Output 1: the constant marker output.
    out.extend_from_slice(&MARKER_DUST_SATS.to_le_bytes());
    write_varbytes(&mut out, &MARKER_SPK);
    // Output 2: change back to the funding scriptPubKey.
    out.extend_from_slice(&change_sats.to_le_bytes());
    write_varbytes(&mut out, change_spk);
    // Witness of input 0.
    write_varint(&mut out, witness_items.len() as u64);
    for item in witness_items {
        write_varbytes(&mut out, item);
    }
    out.extend_from_slice(&0u32.to_le_bytes()); // locktime
    out
}

/// Build a batch transaction, returning `(tx_bytes, base_bytes,
/// witness_bytes)`.
fn batch_tx_parts(
    outpoint: &([u8; 32], u32),
    record: &[u8; ANCHOR_SIZE],
    change_sats: u64,
    change_spk: &[u8; 34],
    witness_items: &[Vec<u8>],
) -> (Vec<u8>, usize, usize) {
    let tx = serialize_batch_tx(outpoint, record, change_sats, change_spk, witness_items);
    // Recompute the base/witness split from the known layout: base =
    // everything except marker+flag (2) and the witness region.
    let witness_region: usize = {
        let mut size = 1; // item count varint (n+2 ≤ 255 always)
        for item in witness_items {
            size += 1 + item.len(); // each item ≤ 80 → 1-byte length
        }
        size
    };
    let base = tx.len() - 2 - witness_region;
    (tx, base, witness_region)
}

fn sha256d(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest as _, Sha256};
    let first = Sha256::digest(data);
    Sha256::digest(first).into()
}

/// An unspent wallet output paying the OP_TRUE marker scriptPubKey.
#[derive(Clone, Copy, Debug)]
struct MarkerUtxo {
    txid: [u8; 32],
    vout: u32,
    sats: u64,
}

impl<T: Transport> BitcoinAnchorChain<T> {
    /// The OP_TRUE funding UTXO tracked by this backend, if it is
    /// still unspent: anyone-can-spend outputs are invisible to the
    /// wallet's `listunspent`, so the outpoint is tracked in the
    /// persistent index (written at creation and after every batch —
    /// the batch change cycles back to the same scriptPubKey) and
    /// verified against the node's UTXO set. `None` when it was swept
    /// (it is anyone-can-spend) or never created.
    fn find_marker_utxo(&self, payload_count: u8) -> Result<Option<MarkerUtxo>, Error> {
        let Some((txid, vout)) = self.funding_utxo(payload_count) else {
            return Ok(None);
        };
        let out = self.client().call(
            "gettxout",
            json!([crate::chain::display_txid(&txid), vout, true]),
        )?;
        if out.is_null() {
            return Ok(None);
        }
        let sats = btc_to_sats(
            out.get("value")
                .ok_or_else(|| Error::Malformed("gettxout: no `value`".into()))?,
        )?;
        Ok(Some(MarkerUtxo { txid, vout, sats }))
    }

    /// Create the one-time funding output for a batch size (plain
    /// wallet-funded transaction; see module docs). Returns the new UTXO.
    fn create_marker_utxo(&mut self, payload_count: u8) -> Result<MarkerUtxo, Error> {
        let marker = batch_funding_address(self.network(), payload_count as usize);
        let spk_hex = to_hex(&batch_funding_spk(payload_count as usize));
        let raw = self.client().call_str(
            "createrawtransaction",
            json!([[], [{marker: BATCH_FUNDING_SATS as f64 / 1e8}]]),
        )?;
        let funded = self.client().call("fundrawtransaction", json!([raw, {}]))?;
        let funded_hex = funded
            .get("hex")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::Malformed("fundrawtransaction: no `hex`".into()))?;
        let signed = self
            .client()
            .call("signrawtransactionwithwallet", json!([funded_hex]))?;
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
        let txid_hex = self.client().call_str("sendrawtransaction", json!([signed_hex]))?;
        let tx = self.client().call("decoderawtransaction", json!([signed_hex]))?;
        let marker_hex = spk_hex;
        for output in tx
            .get("vout")
            .and_then(Value::as_array)
            .ok_or_else(|| Error::Malformed("decoderawtransaction: no `vout`".into()))?
        {
            let spk = output.get("scriptPubKey");
            if spk.and_then(|s| s.get("hex")).and_then(Value::as_str) == Some(marker_hex.as_str()) {
                let vout = output
                    .get("n")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| Error::Malformed("vout without `n`".into()))?;
                let utxo = MarkerUtxo {
                    txid: hash_from_rpc(&txid_hex)?,
                    vout: u32::try_from(vout).map_err(|_| Error::Malformed("vout overflow".into()))?,
                    sats: BATCH_FUNDING_SATS,
                };
                self.set_funding_utxo(payload_count, (utxo.txid, utxo.vout))?;
                return Ok(utxo);
            }
        }
        Err(Error::Malformed(
            "funding transaction is missing its marker output".into(),
        ))
    }

    /// Ensure a coordinator-owned funding UTXO for batches of
    /// `payload_count` payloads exists (creating one if absent) and
    /// return the batch ctx — `funding_ctx` of that outpoint. Senders
    /// bind payloads against this ctx before calling
    /// [`BitcoinAnchorChain::anchor_batch`].
    pub fn marker_utxo_ctx(&mut self, payload_count: u8) -> Result<[u8; 32], Error> {
        if payload_count == 0 {
            return Err(Error::Config("a batch carries 1–255 payloads".into()));
        }
        let utxo = match self.find_marker_utxo(payload_count)? {
            Some(utxo) => utxo,
            None => self.create_marker_utxo(payload_count)?,
        };
        Ok(funding_ctx(&utxo.txid, utxo.vout))
    }

    /// Broadcast a batch anchor carrying `payloads` (each
    /// `H("bind" ∥ raw_nf_i ∥ ctx)` for the ctx returned by
    /// [`BitcoinAnchorChain::marker_utxo_ctx`]) in the witness envelope
    /// of the OP_TRUE funding spend (module docs). Returns a reference
    /// carrying [`MEMPOOL_LOCATION`]; the confirmed location is resolved
    /// by txid once the transaction mines.
    pub fn anchor_batch(&mut self, payloads: &[TruncatedDigest]) -> Result<AnchorRef, Error> {
        if payloads.is_empty() || payloads.len() > u8::MAX as usize {
            return Err(Error::Config(format!(
                "a batch carries 1–255 payloads (got {})",
                payloads.len()
            )));
        }
        let utxo = self
            .find_marker_utxo(payloads.len() as u8)?
            .ok_or_else(|| {
                Error::Config(
                    "no funding UTXO for this batch size; call marker_utxo_ctx first".into(),
                )
            })?;
        let ctx = funding_ctx(&utxo.txid, utxo.vout);
        let record = AnchorRecord::batch_header(payloads, &ctx);
        debug_assert!(record.parses_cleanly(), "batch headers are tagged");
        let record_bytes = record.to_bytes();

        // Feerate: node estimate, falling back on regtest.
        let fee_rate = self
            .client()
            .call("estimatesmartfee", json!([6]))
            .ok()
            .and_then(|r| r.get("feerate").cloned())
            .and_then(|f| btc_to_sats(&f).ok())
            .map(|sats| sats.div_ceil(1000).max(1))
            .unwrap_or(FALLBACK_FEE_RATE);

        // Witness envelope: magic, one item per payload, the witness
        // script (consumes the arguments — CLEANSTACK, module docs).
        let mut witness_items = Vec::with_capacity(payloads.len() + 2);
        witness_items.push(opencsv_core::batch::WITNESS_MAGIC.to_vec());
        for payload in payloads {
            witness_items.push(payload.as_bytes().to_vec());
        }
        witness_items.push(drop_script(payloads.len()));
        let change_spk = batch_funding_spk(payloads.len());

        // Size the transaction with a zero-fee change, then rebuild with
        // the fee deducted from the OP_TRUE change output.
        let outpoint = (utxo.txid, utxo.vout);
        let (_, base, witness) =
            batch_tx_parts(&outpoint, &record_bytes, 0, &change_spk, &witness_items);
        let weight = base as u64 * 3 + (base + 2 + witness) as u64;
        let vbytes = weight.div_ceil(4);
        let fee = fee_rate * vbytes;
        let change = utxo
            .sats
            .checked_sub(MARKER_DUST_SATS + fee)
            .ok_or_else(|| {
                Error::Config(format!(
                    "OP_TRUE funding UTXO ({} sats) cannot cover marker + fee ({fee} sats); top it up",
                    utxo.sats
                ))
            })?;
        if change < MARKER_DUST_SATS {
            return Err(Error::Config(format!(
                "OP_TRUE change would be dust ({change} sats); top up the funding UTXO"
            )));
        }
        let (tx, _, _) = batch_tx_parts(&outpoint, &record_bytes, change, &change_spk, &witness_items);
        let txid = sha256d(&strip_witness(&tx, base, witness));
        let accepted = self.client().call("testmempoolaccept", json!([[to_hex(&tx)]]))?;
        let ok = accepted
            .as_array()
            .and_then(|a| a.first())
            .and_then(|r| r.get("allowed"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !ok {
            let reason = accepted
                .as_array()
                .and_then(|a| a.first())
                .and_then(|r| r.get("reject-reason").cloned())
                .map(|r| r.to_string())
                .unwrap_or_else(|| "unknown".into());
            return Err(Error::Malformed(format!(
                "batch transaction rejected by mempool: {reason}"
            )));
        }
        let broadcast = self.client().call_str("sendrawtransaction", json!([to_hex(&tx)]))?;
        debug_assert_eq!(hash_from_rpc(&broadcast)?, txid);
        // The change output (index 2) is the funding stock of the next
        // same-size batch — same scriptPubKey, tracked in the index.
        self.set_funding_utxo(payloads.len() as u8, (txid, 2))?;
        self.note_mempool(txid, record, ctx);
        Ok(AnchorRef {
            txid,
            location: MEMPOOL_LOCATION,
        })
    }
}

/// The non-witness serialization (what the txid commits to): the batch
/// tx without the marker/flag and the witness region.
fn strip_witness(tx: &[u8], base: usize, witness: usize) -> Vec<u8> {
    // Layout: [version(4)][marker+flag(2)][...base-body...][witness][locktime(4)]
    // strip_witness gets (tx, base, witness) where base includes
    // version+body (not marker/flag, not witness, not locktime)? — see
    // batch_tx_parts: base = total - 2 - witness_region, so base
    // covers version..locktime EXCEPT marker/flag and witness. The
    // legacy serialization = base minus nothing (it never included
    // marker/flag/witness)... but it must EXCLUDE the witness region:
    // base = version + vin/vout + locktime. So legacy = tx without the
    // 2 marker/flag bytes and without the witness region:
    let mut legacy = Vec::with_capacity(base);
    legacy.extend_from_slice(&tx[..4]); // version
    legacy.extend_from_slice(&tx[6..6 + (base - 4 - 4)]); // vin/vout body (skip marker/flag; minus locktime)
    legacy.extend_from_slice(&tx[tx.len() - 4..]); // locktime
    let _ = witness;
    legacy
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn btc_amount_parsing() {
        assert_eq!(btc_to_sats(&json!(0.001)).unwrap(), 100_000);
        assert_eq!(btc_to_sats(&json!(0.00000546)).unwrap(), 546);
        assert_eq!(btc_to_sats(&json!(1.5)).unwrap(), 150_000_000);
        assert!(btc_to_sats(&json!("0.000000001")).is_err());
    }

    #[test]
    fn batch_tx_layout() {
        let outpoint = ([0xaau8; 32], 1);
        let ctx = funding_ctx(&outpoint.0, outpoint.1);
        let payloads = vec![
            TruncatedDigest([1u8; 24]),
            TruncatedDigest([2u8; 24]),
        ];
        let record = AnchorRecord::batch_header(&payloads, &ctx).to_bytes();
        let mut witness_items = vec![opencsv_core::batch::WITNESS_MAGIC.to_vec()];
        witness_items.extend(payloads.iter().map(|p| p.as_bytes().to_vec()));
        witness_items.push(drop_script(payloads.len()));
        let change_spk = batch_funding_spk(payloads.len());
        let (tx, base, witness) = batch_tx_parts(&outpoint, &record, 9000, &change_spk, &witness_items);
        // version + marker/flag
        assert_eq!(&tx[..6], &[2, 0, 0, 0, 0, 1]);
        // vin count 1, then the outpoint.
        assert_eq!(tx[6], 1);
        assert_eq!(&tx[7..39], &[0xaau8; 32]);
        assert_eq!(&tx[39..43], &1u32.to_le_bytes());
        // The witness region is magic + 2×(1+24) + (1+4) + count byte.
        assert_eq!(witness, 1 + 1 + 4 + 2 * 25 + 5);
        // Legacy serialization size = base; txid is over it.
        let legacy = strip_witness(&tx, base, witness);
        assert_eq!(legacy.len(), base);
        assert_eq!(&legacy[..4], &tx[..4]);
        assert_eq!(&legacy[legacy.len() - 4..], &tx[tx.len() - 4..]);
        // Outputs: 3, starting right after the (empty-scriptSig) input.
        // vin end: 7 + 36 + 1 + 4 = 48 → vout count at 48.
        assert_eq!(tx[48], 3);
    }
}
