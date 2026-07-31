//! An [`AnchorChain`]/[`AnchorWriter`] backed by `opencsv-anchor-server`.
//!
//! With `--anchor-server <url>` the CLI reads its chain view from
//! `GET /snapshot` and publishes anchors with `POST /anchor`, making the
//! server the single anchoring authority — required whenever another party
//! (e.g. a phone wallet) shares the chain over HTTP, since concurrent
//! writers on one chain *file* would desync the server's in-memory view.
//!
//! The client is deliberately dependency-free: a blocking HTTP/1.1 exchange
//! over [`TcpStream`] with `Connection: close`, which the demo server
//! honors. Not production transport — the demo server stands in for Bitcoin,
//! and this client stands in for a node RPC.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;

use opencsv_core::chain::{AnchorChain, AnchorLocation, AnchorRef};
use opencsv_core::{AnchorRecord, TruncatedDigest, ANCHOR_SIZE};
use serde::Deserialize;

use crate::chain::AnchorWriter;
use crate::error::Error;
use crate::hexutil::{from_hex, to_hex};

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
    record: String,
}

#[derive(Deserialize)]
struct AnchorReplyJson {
    txid: String,
    height: u64,
    position: u32,
}

/// A chain view fetched from (and anchored via) `opencsv-anchor-server`.
pub struct HttpAnchorChain {
    /// `host:port` of the server.
    authority: String,
    tip_height: u64,
    entries: Vec<(AnchorRef, AnchorRecord)>,
    nullifier_index: HashMap<TruncatedDigest, AnchorLocation>,
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
            nullifier_index: HashMap::new(),
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
            let record_bytes: [u8; ANCHOR_SIZE] = from_hex(&e.record)?
                .try_into()
                .map_err(|_| Error::Parse("snapshot record is not 64 bytes".into()))?;
            let record = AnchorRecord::from_bytes(&record_bytes)
                .map_err(|err| Error::Parse(format!("snapshot record: {err}")))?;
            let anchor_ref = AnchorRef {
                txid,
                location: AnchorLocation {
                    height: e.height,
                    position: e.position,
                },
            };
            entries.push((anchor_ref, record));
        }
        entries.sort_by_key(|(r, _)| r.location);
        self.nullifier_index.clear();
        for (r, record) in &entries {
            for key in record.nullifier_keys() {
                self.nullifier_index.entry(key).or_insert(r.location);
            }
        }
        self.tip_height = snapshot.tip_height;
        self.entries = entries;
        Ok(())
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
    fn append(&mut self, record: AnchorRecord) -> Result<AnchorRef, Error> {
        let body = format!(r#"{{"record":"{}"}}"#, to_hex(&record.to_bytes()));
        let reply = self.request("POST", "/anchor", Some(&body))?;
        let reply: AnchorReplyJson = serde_json::from_str(&reply)
            .map_err(|e| Error::Parse(format!("anchor server reply: {e}")))?;
        let txid: [u8; 32] = from_hex(&reply.txid)?
            .try_into()
            .map_err(|_| Error::Parse("anchor server txid is not 32 bytes".into()))?;
        // Pick up the appended entry and any auto-advanced tip.
        self.refresh()?;
        Ok(AnchorRef {
            txid,
            location: AnchorLocation {
                height: reply.height,
                position: reply.position,
            },
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
            .find(|(r, _)| r.location == anchor_ref.location && r.txid == anchor_ref.txid)
            .map(|(_, record)| *record)
    }

    fn first_nullifier_occurrence(&self, key: &TruncatedDigest) -> Option<AnchorLocation> {
        self.nullifier_index.get(key).copied()
    }

    fn nullifier_occurrences(&self, key: &TruncatedDigest) -> Vec<AnchorLocation> {
        self.entries
            .iter()
            .filter(|(_, record)| record.nullifier_keys().contains(key))
            .map(|(r, _)| r.location)
            .collect()
    }

    fn anchors_up_to(&self, height: u64) -> Vec<(AnchorLocation, AnchorRecord)> {
        self.entries
            .iter()
            .filter(|(r, _)| r.location.height <= height)
            .map(|(r, record)| (r.location, *record))
            .collect()
    }
}

/// The CLI's chain backend: a local demo file (default) or a shared
/// `opencsv-anchor-server`.
pub enum ChainBackend {
    /// Append-only local file ([`crate::chain::FileAnchorChain`]).
    File(crate::chain::FileAnchorChain),
    /// Remote demo server ([`HttpAnchorChain`]).
    Http(HttpAnchorChain),
}

impl ChainBackend {
    /// Open the HTTP backend when `server` is set, else the file backend.
    pub fn open(chain_path: &std::path::Path, server: Option<&str>) -> Result<Self, Error> {
        match server {
            Some(url) => Ok(Self::Http(HttpAnchorChain::open(url)?)),
            None => Ok(Self::File(crate::chain::FileAnchorChain::open(chain_path)?)),
        }
    }

    /// Advance the tip by `n` blocks on whichever backend is active.
    pub fn advance_blocks(&mut self, n: u64) -> Result<(), Error> {
        match self {
            Self::File(c) => c.advance_blocks(n),
            Self::Http(c) => c.advance_blocks(n),
        }
    }
}

impl AnchorWriter for ChainBackend {
    fn append(&mut self, record: AnchorRecord) -> Result<AnchorRef, Error> {
        match self {
            Self::File(c) => c.append(record),
            Self::Http(c) => c.append(record),
        }
    }
}

impl AnchorChain for ChainBackend {
    fn tip_height(&self) -> u64 {
        match self {
            Self::File(c) => c.tip_height(),
            Self::Http(c) => c.tip_height(),
        }
    }

    fn anchor_at(&self, anchor_ref: &AnchorRef) -> Option<AnchorRecord> {
        match self {
            Self::File(c) => c.anchor_at(anchor_ref),
            Self::Http(c) => c.anchor_at(anchor_ref),
        }
    }

    fn first_nullifier_occurrence(&self, key: &TruncatedDigest) -> Option<AnchorLocation> {
        match self {
            Self::File(c) => c.first_nullifier_occurrence(key),
            Self::Http(c) => c.first_nullifier_occurrence(key),
        }
    }

    fn nullifier_occurrences(&self, key: &TruncatedDigest) -> Vec<AnchorLocation> {
        match self {
            Self::File(c) => c.nullifier_occurrences(key),
            Self::Http(c) => c.nullifier_occurrences(key),
        }
    }

    fn anchors_up_to(&self, height: u64) -> Vec<(AnchorLocation, AnchorRecord)> {
        match self {
            Self::File(c) => c.anchors_up_to(height),
            Self::Http(c) => c.anchors_up_to(height),
        }
    }
}
