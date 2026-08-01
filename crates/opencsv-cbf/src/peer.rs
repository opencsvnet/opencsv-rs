//! A hand-rolled P2P peer over `std::net::TcpStream`: version/verack
//! handshake, `sendheaders`, and blocking request/response helpers for
//! headers, compact-filter headers, filters, and blocks.

use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use crate::block::{Block, BlockHeader};
use crate::error::Error;
use crate::messages::{
    self, CfHeaders, CFilter, Message, MSG_BLOCK, MSG_WITNESS_BLOCK, NODE_COMPACT_FILTERS,
    NODE_WITNESS,
};
use crate::network::Params;

fn protocol_err(what: impl std::fmt::Display) -> Error {
    Error::Protocol(what.to_string())
}

/// A connected, handshaken peer.
pub struct Peer {
    stream: TcpStream,
    addr: SocketAddr,
    magic: u32,
    /// The peer's service bits, from its `version`.
    pub services: u64,
    /// The peer's claimed best height, from its `version`.
    pub start_height: i32,
}

impl Peer {
    /// Connect and complete the version/verack handshake, then send
    /// `sendheaders`.
    pub fn connect(addr: SocketAddr, params: &Params, timeout: Duration, tip_height: u64) -> Result<Self, Error> {
        let stream = TcpStream::connect_timeout(&addr, timeout)
            .map_err(|e| protocol_err(format!("connect {addr}: {e}")))?;
        stream
            .set_read_timeout(Some(timeout))
            .and_then(|()| stream.set_write_timeout(Some(timeout)))
            .and_then(|()| stream.set_nodelay(true))
            .map_err(|e| protocol_err(format!("connect {addr}: {e}")))?;
        let mut peer = Self {
            stream,
            addr,
            magic: params.magic,
            services: 0,
            start_height: 0,
        };
        peer.handshake(tip_height)?;
        Ok(peer)
    }

    /// The remote address.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    fn handshake(&mut self, tip_height: u64) -> Result<(), Error> {
        let services = NODE_WITNESS | NODE_COMPACT_FILTERS;
        let payload = messages::version_payload(services, tip_height as i32);
        messages::write_message(&mut self.stream, self.magic, "version", &payload)?;
        let mut got_version = false;
        let mut got_verack = false;
        while !(got_version && got_verack) {
            let message = self.next_message()?;
            match message.command.as_str() {
                "version" => {
                    let info = messages::parse_version(&message.payload)?;
                    self.services = info.services;
                    self.start_height = info.start_height;
                    messages::write_message(&mut self.stream, self.magic, "verack", &[])?;
                    got_version = true;
                }
                "verack" => got_verack = true,
                // bitcoind sends these between `version` and `verack`.
                "wtxidrelay" | "sendaddrv2" => {}
                other => {
                    return Err(protocol_err(format!(
                        "expected version/verack from {}, got `{other}`",
                        self.addr
                    )))
                }
            }
        }
        messages::write_message(&mut self.stream, self.magic, "sendheaders", &[])?;
        Ok(())
    }

    /// Read the next message, answering `ping` with `pong` and ignoring
    /// announcements (`inv`, `addr`, `feefilter`, `sendcmpct`, …).
    /// Returns only messages a request loop might be waiting on.
    fn next_message(&mut self) -> Result<Message, Error> {
        loop {
            let message = messages::read_message(&mut self.stream, self.magic)
                .map_err(|e| protocol_err(format!("read from {}: {e}", self.addr)))?;
            match message.command.as_str() {
                "ping" => {
                    messages::write_message(&mut self.stream, self.magic, "pong", &message.payload)?;
                }
                // Unsolicited requests we cannot serve; a light client
                // answers with empty responses to stay polite.
                "getheaders" | "getblocks" => {
                    messages::write_message(&mut self.stream, self.magic, "headers", &[0])?;
                }
                "getaddr" | "mempool" | "sendheaders" | "sendcmpct" | "feefilter" | "inv"
                | "addr" | "wtxidrelay" | "sendaddrv2" | "pong" | "getdata" => {}
                _ => return Ok(message),
            }
        }
    }

    /// Send a request and wait for a message whose command is one of
    /// `expected`.
    fn request(&mut self, command: &str, payload: &[u8], expected: &[&str]) -> Result<Message, Error> {
        messages::write_message(&mut self.stream, self.magic, command, payload)?;
        loop {
            let message = self.next_message()?;
            if expected.contains(&message.command.as_str()) {
                return Ok(message);
            }
            // Unknown/irrelevant messages are ignored.
        }
    }

    /// `getheaders` → `headers`: up to 2000 headers after the locator.
    pub fn get_headers(
        &mut self,
        locator: &[[u8; 32]],
        stop: &[u8; 32],
    ) -> Result<Vec<BlockHeader>, Error> {
        let payload = messages::getheaders_payload(locator, stop);
        let message = self.request("getheaders", &payload, &["headers"])?;
        messages::parse_headers(&message.payload)
    }

    /// `getcfheaders` → `cfheaders` for `start_height..=stop`.
    pub fn get_cfheaders(&mut self, start_height: u32, stop: &[u8; 32]) -> Result<CfHeaders, Error> {
        let payload =
            messages::getcfilter_range_payload(crate::gcs::BASIC_FILTER_TYPE, start_height, stop);
        let message = self.request("getcfheaders", &payload, &["cfheaders"])?;
        let parsed = messages::parse_cfheaders(&message.payload)?;
        if parsed.stop_hash != *stop {
            return Err(protocol_err(format!(
                "cfheaders stop-hash mismatch from {}",
                self.addr
            )));
        }
        Ok(parsed)
    }

    /// `getcfilters` for exactly one block (`start_height == height of
    /// stop`) → its `cfilter`.
    pub fn get_cfilter(&mut self, start_height: u32, block_hash: &[u8; 32]) -> Result<CFilter, Error> {
        let payload =
            messages::getcfilter_range_payload(crate::gcs::BASIC_FILTER_TYPE, start_height, block_hash);
        let message = self.request("getcfilters", &payload, &["cfilter"])?;
        let parsed = messages::parse_cfilter(&message.payload)?;
        if parsed.block_hash != *block_hash {
            return Err(protocol_err(format!(
                "cfilter for wrong block from {}",
                self.addr
            )));
        }
        Ok(parsed)
    }

    /// `getdata` a full block: witness serialization first, falling
    /// back to non-witness if the peer answers `notfound`.
    pub fn get_block(&mut self, block_hash: &[u8; 32]) -> Result<Block, Error> {
        for inv_type in [MSG_WITNESS_BLOCK, MSG_BLOCK] {
            let payload = messages::getdata_payload(inv_type, block_hash);
            let message = self.request("getdata", &payload, &["block", "notfound"])?;
            match message.command.as_str() {
                "block" => {
                    let block = messages::parse_block_message(&message.payload)?;
                    if block.header.hash() != *block_hash {
                        return Err(protocol_err(format!(
                            "peer {} sent a block that hashes differently",
                            self.addr
                        )));
                    }
                    return Ok(block);
                }
                "notfound" => continue,
                _ => unreachable!(),
            }
        }
        Err(protocol_err(format!(
            "peer {} does not have block {}",
            self.addr,
            crate::hash::hash_to_display(block_hash)
        )))
    }

    /// Read timed out / disconnected: classify for the caller's
    /// peer-fallback logic.
    pub fn is_io_error(error: &Error) -> bool {
        match error {
            Error::Io(e) => !matches!(e.kind(), ErrorKind::Interrupted),
            _ => false,
        }
    }
}

/// Allow treating the peer's stream as a plain reader in tests.
impl Read for Peer {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.stream.read(buf)
    }
}

impl Write for Peer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.stream.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}
