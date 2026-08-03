//! Direct Bitcoin P2P transaction relay.
//!
//! OpenCSV does not need an application-specific anchor server. A signed
//! protocol transaction is handed directly to several ordinary Bitcoin
//! peers after a version/verack handshake. Read-side observation is a
//! separate step: a successful socket write is evidence of submission, not
//! evidence that any mempool accepted the transaction.

use std::io::{BufReader, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bitcoin::consensus::{encode, Decodable};
use bitcoin::p2p::{address, message, message_network, ServiceFlags};
use bitcoin::{Network, Transaction};
use rand::RngExt as _;

/// Result for one configured relay peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerRelayResult {
    /// Host and port supplied by the caller.
    pub peer: String,
    /// Whether a complete transaction message was written after handshake.
    pub submitted: bool,
    /// Failure detail when `submitted` is false.
    pub error: Option<String>,
}

/// Aggregate direct-relay receipt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayReport {
    /// Per-peer outcomes in caller order.
    pub peers: Vec<PeerRelayResult>,
}

impl RelayReport {
    /// Number of peers to which the full transaction message was written.
    pub fn submitted_count(&self) -> usize {
        self.peers.iter().filter(|peer| peer.submitted).count()
    }
}

/// Submit a signed transaction to every configured Bitcoin P2P peer.
///
/// Failures are isolated per peer. The caller decides whether zero
/// successful writes should fall back to a generic public relay. A non-zero
/// count still requires independent read-side observation before delivery.
pub fn relay_transaction(
    network: Network,
    peers: &[String],
    transaction: &Transaction,
    timeout: Duration,
) -> RelayReport {
    RelayReport {
        peers: peers
            .iter()
            .map(
                |peer| match relay_one(network, peer, transaction, timeout) {
                    Ok(()) => PeerRelayResult {
                        peer: peer.clone(),
                        submitted: true,
                        error: None,
                    },
                    Err(error) => PeerRelayResult {
                        peer: peer.clone(),
                        submitted: false,
                        error: Some(error),
                    },
                },
            )
            .collect(),
    }
}

fn relay_one(
    network: Network,
    peer: &str,
    transaction: &Transaction,
    timeout: Duration,
) -> Result<(), String> {
    let addresses: Vec<SocketAddr> = peer
        .to_socket_addrs()
        .map_err(|error| format!("resolve: {error}"))?
        .collect();
    if addresses.is_empty() {
        return Err("resolve returned no addresses".into());
    }
    let mut last_error = None;
    for socket in addresses {
        match TcpStream::connect_timeout(&socket, timeout) {
            Ok(mut stream) => {
                stream
                    .set_read_timeout(Some(timeout))
                    .map_err(|error| format!("read timeout: {error}"))?;
                stream
                    .set_write_timeout(Some(timeout))
                    .map_err(|error| format!("write timeout: {error}"))?;
                let result = handshake_and_submit(network, socket, &mut stream, transaction);
                let _ = stream.shutdown(Shutdown::Both);
                return result;
            }
            Err(error) => last_error = Some(error.to_string()),
        }
    }
    Err(format!(
        "connect: {}",
        last_error.unwrap_or_else(|| "unknown error".into())
    ))
}

fn handshake_and_submit(
    network: Network,
    peer: SocketAddr,
    stream: &mut TcpStream,
    transaction: &Transaction,
) -> Result<(), String> {
    write_message(stream, network, version_message(peer))?;
    let read_stream = stream
        .try_clone()
        .map_err(|error| format!("clone stream: {error}"))?;
    let mut reader = BufReader::new(read_stream);
    let mut received_version = false;
    let mut received_verack = false;
    for _ in 0..16 {
        let reply = message::RawNetworkMessage::consensus_decode(&mut reader)
            .map_err(|error| format!("handshake decode: {error}"))?;
        if *reply.magic() != network.magic() {
            return Err("peer used the wrong Bitcoin network magic".into());
        }
        match reply.payload() {
            message::NetworkMessage::Version(_) => {
                received_version = true;
                write_message(stream, network, message::NetworkMessage::Verack)?;
            }
            message::NetworkMessage::Verack => received_verack = true,
            message::NetworkMessage::Ping(nonce) => {
                write_message(stream, network, message::NetworkMessage::Pong(*nonce))?;
            }
            message::NetworkMessage::Reject(reject) => {
                return Err(format!("peer rejected handshake: {reject:?}"));
            }
            _ => {}
        }
        if received_version && received_verack {
            write_message(
                stream,
                network,
                message::NetworkMessage::Tx(transaction.clone()),
            )?;
            stream
                .flush()
                .map_err(|error| format!("flush transaction: {error}"))?;
            return Ok(());
        }
    }
    Err("peer did not complete version/verack handshake".into())
}

fn write_message(
    stream: &mut TcpStream,
    network: Network,
    payload: message::NetworkMessage,
) -> Result<(), String> {
    let message = message::RawNetworkMessage::new(network.magic(), payload);
    stream
        .write_all(&encode::serialize(&message))
        .map_err(|error| format!("write {}: {error}", message.command()))
}

fn version_message(peer: SocketAddr) -> message::NetworkMessage {
    let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or_default();
    message::NetworkMessage::Version(message_network::VersionMessage::new(
        ServiceFlags::NONE,
        timestamp,
        address::Address::new(&peer, ServiceFlags::NONE),
        address::Address::new(&local, ServiceFlags::NONE),
        rand::rng().random(),
        "/OpenCSV:0.1.0/".into(),
        0,
    ))
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;
    use std::thread;

    use bitcoin::absolute;
    use bitcoin::blockdata::transaction;
    use bitcoin::{Amount, ScriptBuf, TxOut};

    use super::*;

    fn transaction() -> Transaction {
        Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: Vec::new(),
            output: vec![TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::new(),
            }],
        }
    }

    #[test]
    fn isolates_peer_failure_and_submits_to_live_peer() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let expected = transaction();
        let server_expected = expected.clone();
        let server = thread::spawn(move || {
            let (mut stream, peer) = listener.accept().unwrap();
            let read_stream = stream.try_clone().unwrap();
            let mut reader = BufReader::new(read_stream);
            let first = message::RawNetworkMessage::consensus_decode(&mut reader).unwrap();
            assert!(matches!(
                first.payload(),
                message::NetworkMessage::Version(_)
            ));
            write_message(&mut stream, Network::Regtest, version_message(peer)).unwrap();
            write_message(
                &mut stream,
                Network::Regtest,
                message::NetworkMessage::Verack,
            )
            .unwrap();
            let mut saw_transaction = false;
            for _ in 0..4 {
                let reply = message::RawNetworkMessage::consensus_decode(&mut reader).unwrap();
                if let message::NetworkMessage::Tx(transaction) = reply.payload() {
                    assert_eq!(transaction, &server_expected);
                    saw_transaction = true;
                    break;
                }
            }
            assert!(saw_transaction);
        });
        let report = relay_transaction(
            Network::Regtest,
            &[address.to_string(), "127.0.0.1:1".into()],
            &expected,
            Duration::from_secs(2),
        );
        assert_eq!(report.submitted_count(), 1);
        assert!(report.peers[0].submitted);
        assert!(!report.peers[1].submitted);
        server.join().unwrap();
    }
}
