//! An [`AnchorChain`]/[`AnchorWriter`] backed by `opencsv-anchor-server`.
//!
//! With `--anchor-server <url>` the CLI reads its chain view from
//! `GET /snapshot` and publishes anchors with `POST /anchor`, making the
//! server the single anchoring authority — required whenever another party
//! (e.g. a phone wallet) shares the chain over HTTP, since concurrent
//! writers on one chain *file* would desync the server's in-memory view.
//!
//! Snapshot entries carry each anchor's transaction context `ctx`; the
//! client draws `ctx` itself before constructing a record (the bound
//! payloads commit to it — see `opencsv-core`'s anchor docs) and posts it
//! alongside the record. Nullifier occurrences are recognized client-side
//! by scanning the snapshot and testing the binding against the raw
//! nullifier.
//!
//! The client is deliberately dependency-free: a blocking HTTP/1.1 exchange
//! over [`TcpStream`] with `Connection: close`, which the demo server
//! honors. Not production transport — the demo server stands in for Bitcoin,
//! and this client stands in for a node RPC.

use std::io::{Read, Write};
use std::net::TcpStream;

use opencsv_core::chain::{AnchorChain, AnchorLocation, AnchorRef};
use opencsv_core::{AnchorRecord, Digest, ANCHOR_SIZE};
use rand::RngExt;
use serde::Deserialize;

use crate::chain::AnchorWriter;
use crate::error::Error;
use crate::hexutil::{from_hex, to_hex};

/// Bound on tag-collision redraws (each costs a UTXO reservation on
/// real-chain backends).
const MAX_CTX_DRAWS: usize = 16;

#[derive(Deserialize)]
struct SnapshotJson {
    tip_height: u64,
    entries: Vec<EntryJson>,
}

#[derive(Deserialize)]
struct EntryJson {
    height: u64,
    position: u32,
    txid: String,
    ctx: String,
    record: String,
}

#[derive(Deserialize)]
struct AnchorReplyJson {
    txid: String,
    // Present when the backend anchors immediately (file backend); absent
    // on real chains, where the anchor is pending until mined.
    height: Option<u64>,
    position: Option<u32>,
}

#[derive(Deserialize)]
struct ContextReplyJson {
    ctx: String,
}

#[derive(Deserialize)]
struct AnchorStatusJson {
    confirmed: bool,
    height: Option<u64>,
    position: Option<u32>,
}

/// A chain view fetched from (and anchored via) `opencsv-anchor-server`.
pub struct HttpAnchorChain {
    /// `host:port` of the server.
    authority: String,
    tip_height: u64,
    entries: Vec<(AnchorRef, AnchorRecord, [u8; 32])>,
}

impl HttpAnchorChain {
    /// Connect to `url` (e.g. `http://192.168.1.10:8787`) and fetch the
    /// current snapshot.
    pub fn open(url: &str) -> Result<Self, Error> {
        let authority = match url.trim_end_matches('/').strip_prefix("http://") {
            Some(authority) if !authority.is_empty() && !authority.contains('/') => {
                authority.to_string()
            }
            _ => {
                return Err(Error::Parse(format!(
                    "anchor server URL must be http://host:port, got `{url}`"
                )));
            }
        };
        let mut chain = Self {
            authority,
            tip_height: 0,
            entries: Vec::new(),
        };
        chain.refresh()?;
        Ok(chain)
    }

    fn refresh(&mut self) -> Result<(), Error> {
        let body = self.request("GET", "/snapshot", None)?;
        let snapshot: SnapshotJson = serde_json::from_str(&body)
            .map_err(|e| Error::Parse(format!("anchor server snapshot: {e}")))?;
        let mut entries = Vec::with_capacity(snapshot.entries.len());
        for e in &snapshot.entries {
            let txid: [u8; 32] = from_hex(&e.txid)?
                .try_into()
                .map_err(|_| Error::Parse("snapshot txid is not 32 bytes".into()))?;
            let ctx: [u8; 32] = from_hex(&e.ctx)?
                .try_into()
                .map_err(|_| Error::Parse("snapshot ctx is not 32 bytes".into()))?;
            let record_bytes: [u8; ANCHOR_SIZE] = from_hex(&e.record)?
                .try_into()
                .map_err(|_| Error::Parse("snapshot record is not 64 bytes".into()))?;
            let record = AnchorRecord::from_bytes(&record_bytes);
            let anchor_ref = AnchorRef {
                txid,
                location: AnchorLocation {
                    height: e.height,
                    position: e.position,
                },
            };
            entries.push((anchor_ref, record, ctx));
        }
        entries.sort_by_key(|(r, _, _)| r.location);
        self.tip_height = snapshot.tip_height;
        self.entries = entries;
        Ok(())
    }

    /// Poll `GET /anchor/<txid>` until the anchor is mined. Real blocks can
    /// take from seconds (mutinynet) to tens of minutes (mainnet).
    fn wait_for_confirmation(&self, txid: &str) -> Result<(u64, u32), Error> {
        const POLL_SECS: u64 = 10;
        const MAX_POLLS: u64 = 12 * 60; // two hours
        eprintln!("anchor {txid} broadcast; waiting for confirmation…");
        for polls in 1..=MAX_POLLS {
            std::thread::sleep(std::time::Duration::from_secs(POLL_SECS));
            let status = self.request("GET", &format!("/anchor/{txid}"), None)?;
            let status: AnchorStatusJson = serde_json::from_str(&status)
                .map_err(|e| Error::Parse(format!("anchor status: {e}")))?;
            if let (true, Some(height), Some(position)) =
                (status.confirmed, status.height, status.position)
            {
                eprintln!("anchor confirmed at height {height} position {position}");
                return Ok((height, position));
            }
            if polls.is_multiple_of(30) {
                eprintln!(
                    "still waiting for anchor {txid} ({} min)…",
                    polls * POLL_SECS / 60
                );
            }
        }
        Err(Error::Parse(format!(
            "anchor {txid} not confirmed after two hours; retry later"
        )))
    }

    /// Advance the server's tip by `n` blocks (`POST /advance`).
    pub fn advance_blocks(&mut self, n: u64) -> Result<(), Error> {
        self.request("POST", "/advance", Some(&format!(r#"{{"blocks":{n}}}"#)))?;
        self.refresh()
    }

    fn request(&self, method: &str, path: &str, body: Option<&str>) -> Result<String, Error> {
        let http_err =
            |what: &str, e: std::io::Error| Error::Parse(format!("anchor server {what}: {e}"));
        let mut stream = TcpStream::connect(&self.authority).map_err(|e| http_err("connect", e))?;
        let body = body.unwrap_or("");
        let request = format!(
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            self.authority,
            body.len(),
        );
        stream
            .write_all(request.as_bytes())
            .map_err(|e| http_err("send", e))?;
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .map_err(|e| http_err("read", e))?;
        let (head, reply_body) = response
            .split_once("\r\n\r\n")
            .ok_or_else(|| Error::Parse("anchor server: malformed HTTP response".into()))?;
        let status_line = head.lines().next().unwrap_or("");
        if !status_line.contains(" 200 ") {
            return Err(Error::Parse(format!(
                "anchor server {method} {path}: {status_line}; body {reply_body}"
            )));
        }
        Ok(reply_body.to_string())
    }
}

impl AnchorWriter for HttpAnchorChain {
    /// Anchor through the server, letting it choose the transaction
    /// context.
    ///
    /// Real-chain backends derive `ctx` from the anchor transaction's
    /// funding outpoint, so the wallet cannot pick it: `POST
    /// /anchor/context` reserves that outpoint and reports its `ctx`, the
    /// record is built against it here, and `POST /anchor` spends exactly
    /// that outpoint. Demo-file backends have no such route (404) — fall
    /// back to locally drawn contexts, which is what they store. Either
    /// way an untagged record whose bound payload collides with the
    /// MINT/REDEEM tag bytes is redrawn (see `opencsv-core`'s anchor docs).
    fn append_bound(
        &mut self,
        mut build: impl FnMut(&[u8; 32]) -> AnchorRecord,
    ) -> Result<AnchorRef, Error> {
        for _ in 0..MAX_CTX_DRAWS {
            let ctx = match self.request("POST", "/anchor/context", Some("{}")) {
                Ok(reply) => {
                    let reply: ContextReplyJson = serde_json::from_str(&reply)
                        .map_err(|e| Error::Parse(format!("anchor context reply: {e}")))?;
                    from_hex(&reply.ctx)?
                        .try_into()
                        .map_err(|_| Error::Parse("anchor context is not 32 bytes".into()))?
                }
                Err(_) => rand::rng().random(),
            };
            let record = build(&ctx);
            if record.parses_cleanly() {
                return self.append(record, ctx);
            }
        }
        Err(Error::Parse(
            "could not draw a non-colliding transaction context".into(),
        ))
    }

    fn append(&mut self, record: AnchorRecord, ctx: [u8; 32]) -> Result<AnchorRef, Error> {
        let body = format!(
            r#"{{"record":"{}","ctx":"{}"}}"#,
            to_hex(&record.to_bytes()),
            to_hex(&ctx)
        );
        let reply = self.request("POST", "/anchor", Some(&body))?;
        let reply: AnchorReplyJson = serde_json::from_str(&reply)
            .map_err(|e| Error::Parse(format!("anchor server reply: {e}")))?;
        let txid: [u8; 32] = from_hex(&reply.txid)?
            .try_into()
            .map_err(|_| Error::Parse("anchor server txid is not 32 bytes".into()))?;

        let (height, position) = match (reply.height, reply.position) {
            // File backend: anchored immediately.
            (Some(height), Some(position)) => (height, position),
            // Real chain: poll until the anchor transaction is mined.
            _ => self.wait_for_confirmation(&reply.txid)?,
        };
        // Pick up the appended entry and any advanced tip.
        self.refresh()?;
        Ok(AnchorRef {
            txid,
            location: AnchorLocation { height, position },
        })
    }
}

impl AnchorChain for HttpAnchorChain {
    fn tip_height(&self) -> u64 {
        self.tip_height
    }

    fn anchor_at(&self, anchor_ref: &AnchorRef) -> Option<AnchorRecord> {
        self.entries
            .iter()
            .find(|(r, _, _)| r.location == anchor_ref.location && r.txid == anchor_ref.txid)
            .map(|(_, record, _)| *record)
    }

    fn ctx_at(&self, anchor_ref: &AnchorRef) -> Option<[u8; 32]> {
        self.entries
            .iter()
            .find(|(r, _, _)| r.location == anchor_ref.location && r.txid == anchor_ref.txid)
            .map(|(_, _, ctx)| *ctx)
    }

    fn first_nullifier_occurrence(&self, raw_nf: &Digest) -> Option<AnchorLocation> {
        self.nullifier_occurrences(raw_nf).into_iter().next()
    }

    fn nullifier_occurrences(&self, raw_nf: &Digest) -> Vec<AnchorLocation> {
        let mut locations: Vec<_> = self
            .entries
            .iter()
            .filter(|(_, record, ctx)| record.well_formed(ctx, raw_nf))
            .map(|(r, _, _)| r.location)
            .collect();
        locations.sort();
        locations
    }

    fn anchors_up_to(&self, height: u64) -> Vec<(AnchorLocation, AnchorRecord)> {
        self.entries
            .iter()
            .filter(|(r, _, _)| r.location.height <= height)
            .map(|(r, record, _)| (r.location, *record))
            .collect()
    }
}
