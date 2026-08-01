//! A minimal blocking `bitcoind` JSON-RPC client.
//!
//! Follows the project's existing pattern (`opencsv-cli`'s anchor-server
//! client): HTTP/1.1 over a plain [`TcpStream`] with `Connection: close`,
//! which bitcoind honors. No TLS — bitcoind RPC is a loopback/plain-LAN
//! transport with its own auth (cookie or `rpcuser`/`rpcpassword`); if a
//! remote TLS endpoint is ever needed, implement [`Transport`] for it.
//!
//! The [`Transport`] seam exists so unit tests can script canned
//! responses; the product path always uses [`HttpTransport`].

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::time::Duration;

use base64::Engine;
use serde_json::Value;

use crate::error::{Error, io_err};

/// How the JSON-RPC request body gets to bitcoind and the reply body back.
pub trait Transport {
    /// POST `body` (a JSON-RPC request) and return the reply body.
    fn post(&self, body: &str) -> Result<String, Error>;
}

/// RPC authentication: a cookie file or an explicit `user:password`.
#[derive(Clone, Debug)]
pub enum RpcAuth {
    /// Path to bitcoind's `.cookie` file (its contents are the
    /// `__cookie__:<secret>` credentials pair, used verbatim).
    Cookie(PathBuf),
    /// `user:password` (bitcoind `rpcuser`/`rpcpassword`).
    UserPass(String),
}

impl RpcAuth {
    fn authorization_header(&self) -> Result<String, Error> {
        let credentials = match self {
            // The .cookie file already holds `__cookie__:<secret>`.
            Self::Cookie(path) => {
                let raw = std::fs::read_to_string(path).map_err(io_err(path))?;
                raw.trim().to_string()
            }
            Self::UserPass(user_pass) => user_pass.clone(),
        };
        Ok(format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(credentials)
        ))
    }
}

/// Blocking HTTP/1.1 transport to a bitcoind RPC endpoint.
pub struct HttpTransport {
    authority: String,
    path: String,
    authorization: String,
}

impl HttpTransport {
    /// Connect parameters: `rpc_url` is `http://host:port` (or a bare
    /// `host:port`); `wallet` selects the `/wallet/<name>` endpoint of
    /// bitcoind's multi-wallet interface.
    pub fn new(rpc_url: &str, wallet: Option<&str>, auth: &RpcAuth) -> Result<Self, Error> {
        let trimmed = rpc_url.trim_end_matches('/');
        let authority = trimmed
            .strip_prefix("http://")
            .unwrap_or(trimmed)
            .to_string();
        if authority.is_empty() || authority.contains('/') {
            return Err(Error::Config(format!(
                "RPC URL must be http://host:port, got `{rpc_url}`"
            )));
        }
        let path = match wallet {
            Some(name) => format!("/wallet/{name}"),
            None => "/".to_string(),
        };
        Ok(Self {
            authority,
            path,
            authorization: auth.authorization_header()?,
        })
    }
}

impl Transport for HttpTransport {
    fn post(&self, body: &str) -> Result<String, Error> {
        let http_err = |what: &str, e: std::io::Error| {
            Error::Http(format!("{} ({what}): {e}", self.authority))
        };
        let mut stream = TcpStream::connect(&self.authority).map_err(|e| http_err("connect", e))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(120)))
            .map_err(|e| http_err("configure", e))?;
        let request = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nAuthorization: {}\r\nConnection: close\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            self.path,
            self.authority,
            self.authorization,
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
            .ok_or_else(|| Error::Http("malformed HTTP response from bitcoind".into()))?;
        let status_line = head.lines().next().unwrap_or("");
        if status_line.contains(" 200 ") {
            return Ok(reply_body.to_string());
        }
        // bitcoind answers RPC-level errors (bad auth, insufficient funds,
        // …) with a non-200 status AND a JSON-RPC error body; hand the body
        // to the client layer so it can surface the real error.
        let looks_like_json_rpc_error = serde_json::from_str::<Value>(reply_body)
            .ok()
            .and_then(|v| v.get("error").cloned())
            .is_some_and(|e| !e.is_null());
        if looks_like_json_rpc_error {
            return Ok(reply_body.to_string());
        }
        Err(Error::Http(format!(
            "{status_line}; body {reply_body}"
        )))
    }
}

/// A JSON-RPC client over a [`Transport`].
pub struct RpcClient<T: Transport> {
    transport: T,
    next_id: std::cell::Cell<u64>,
}

impl<T: Transport> RpcClient<T> {
    /// Wrap a transport.
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            next_id: std::cell::Cell::new(1),
        }
    }

    /// Call `method` with `params` (array or object), returning the
    /// `result` field. A JSON-RPC `error` is an [`Error::Rpc`] — never a
    /// fallback.
    pub fn call(&self, method: &str, params: Value) -> Result<Value, Error> {
        let id = self.next_id.get();
        self.next_id.set(id + 1);
        let request = serde_json::json!({
            "jsonrpc": "1.0",
            "id": id,
            "method": method,
            "params": params,
        });
        let body = self.transport.post(&request.to_string())?;
        let reply: Value = serde_json::from_str(&body)
            .map_err(|e| Error::Malformed(format!("{method}: reply is not JSON: {e}")))?;
        if let Some(error) = reply.get("error").filter(|e| !e.is_null()) {
            return Err(Error::Rpc {
                code: error.get("code").and_then(Value::as_i64).unwrap_or(0),
                message: error
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("<no message>")
                    .to_string(),
            });
        }
        reply
            .get("result")
            .cloned()
            .ok_or_else(|| Error::Malformed(format!("{method}: no `result` field")))
    }

    /// Convenience: string result of a no-param call.
    pub fn call_str(&self, method: &str, params: Value) -> Result<String, Error> {
        self.call(method, params)?
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| Error::Malformed(format!("{method}: result is not a string")))
    }
}
