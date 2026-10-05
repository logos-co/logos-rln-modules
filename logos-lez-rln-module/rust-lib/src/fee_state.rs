//! `get_fee_state`: the sequencer's head fee market, read from the sequencer
//! itself.
//!
//! A registration's `max_fee` is only a cap. What the chain holds back from
//! the payer is `gas_limit x base_fee_exec + data_bytes x base_fee_stor + tip`
//! at the block the tx lands in, and a caller deciding whether it can afford
//! to register needs that number, not the cap. `wallet_ffi` exposes no fee
//! read, so this is the one call this module makes to the sequencer directly
//! instead of through its wallet — to the sequencer the wallet's own config
//! names, so it is always the same chain.
//!
//! The transport is `ureq` with rustls, so an https sequencer (the LEZ 0.3
//! testnet zone serves https only) is read like an http one. A failed read is
//! still "" — which a caller must already treat as "fee state unknown".

use std::time::Duration;

use crate::wallet;

const REQUEST: &str = r#"{"jsonrpc":"2.0","id":1,"method":"getFeeState","params":[]}"#;

/// Connect bound. Handlers run on a worker under `concurrency:"multi"`, so a
/// dead sequencer costs a worker this long, not the module.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Bound on each read and write once connected.
const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// A quote is ~250 bytes and a transaction a few KB; anything past this is
/// not a reply this module asked for.
const MAX_REPLY: u64 = 1024 * 1024;

/// The RPC `result` object as compact JSON; "" before a network is selected
/// and on any transport or parse error (logged).
pub(crate) fn get_fee_state() -> String {
    let Some(sequencer) = wallet::sequencer_addr() else {
        eprintln!("get_fee_state: no sequencer configured yet");
        return String::new();
    };
    match fetch(&sequencer) {
        Ok(state) => state,
        Err(e) => {
            eprintln!("get_fee_state: {sequencer}: {e}");
            String::new()
        }
    }
}

pub(crate) fn fetch(sequencer: &str) -> Result<String, String> {
    result_of(&post(sequencer, REQUEST)?)
}

/// Whether the transaction `tx_hash` is in a block: `Some(true)` included,
/// `Some(false)` not (still queued, or dropped at the door), `None` when the
/// sequencer could not be asked. Inclusion is not success: on LEZ v0.3.0 a
/// transaction whose program panicked is included as a charged, effect-free
/// revert, so a caller pairs this with a read of the state it meant to change.
/// Same transport and sequencer as `get_fee_state`.
pub(crate) fn tx_included(tx_hash: &str) -> Option<bool> {
    let sequencer = wallet::sequencer_addr()?;
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "getTransaction", "params": [tx_hash]
    })
    .to_string();
    let reply = match post(&sequencer, &body) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("tx_included: {sequencer}: {e}");
            return None;
        }
    };
    let doc: serde_json::Value = serde_json::from_str(&reply).ok()?;
    if let Some(error) = doc.get("error") {
        eprintln!("tx_included: RPC error {error}");
        return None;
    }
    Some(!doc.get("result")?.is_null())
}

/// POST a JSON-RPC body to an http:// or https:// sequencer; the 200 reply's
/// body.
fn post(url: &str, body: &str) -> Result<String, String> {
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err(format!("not an http(s) sequencer: '{url}'"));
    }
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(CONNECT_TIMEOUT)
        .timeout_read(IO_TIMEOUT)
        .timeout_write(IO_TIMEOUT)
        .build();
    let reply = agent
        .post(url)
        .set("Content-Type", "application/json")
        .send_string(body)
        .map_err(|e| e.to_string())?;
    let mut text = String::new();
    std::io::Read::read_to_string(
        &mut std::io::Read::take(reply.into_reader(), MAX_REPLY),
        &mut text,
    )
    .map_err(|e| format!("read: {e}"))?;
    Ok(text)
}

/// A JSON-RPC reply's `result`, which must be an object; its `error` otherwise.
fn result_of(body: &str) -> Result<String, String> {
    let reply: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("reply parse: {e}"))?;
    if let Some(error) = reply.get("error") {
        return Err(format!("RPC error {error}"));
    }
    match reply.get("result") {
        Some(result) if result.is_object() => Ok(result.to_string()),
        _ => Err("reply carries no result object".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    const QUOTE: &str = r#"{"height":15082,"base_fee_exec":8,"base_fee_stor":8,"next_base_fee_exec_floor":8,"next_base_fee_exec_ceiling":9,"next_base_fee_stor_floor":8,"next_base_fee_stor_ceiling":9,"max_gas_exec":10000000,"max_gas_stor":1000000}"#;

    fn ok_reply(body: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    #[test]
    fn only_http_and_https_sequencers_are_asked() {
        assert!(post("ftp://seq.local/", REQUEST).unwrap_err().contains("not an http(s)"));
        assert!(post("209.38.241.182:3140", REQUEST).is_err());
    }

    #[test]
    fn a_quote_passes_through_with_every_field() {
        let rpc = format!(r#"{{"jsonrpc":"2.0","id":1,"result":{QUOTE}}}"#);
        let out = result_of(&rpc).unwrap();
        let got: serde_json::Value = serde_json::from_str(&out).unwrap();
        let want: serde_json::Value = serde_json::from_str(QUOTE).unwrap();
        assert_eq!(got, want);
        assert!(!out.contains(' '), "compact JSON: {out}");
    }

    /// A sequencer that predates getFeeState answers "Method not found"; that
    /// is an error, not an empty quote.
    #[test]
    fn rpc_errors_and_non_objects_are_refused() {
        let missing =
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}"#;
        assert!(result_of(missing).is_err());
        assert!(result_of(r#"{"jsonrpc":"2.0","id":1,"result":8}"#).is_err());
        assert!(result_of("garbage").is_err());
    }

    #[test]
    fn a_non_200_reply_is_an_error() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut chunk = [0u8; 4096];
            let _ = conn.read(&mut chunk).unwrap();
            conn.write_all(b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\n\r\n").unwrap();
        });
        assert!(fetch(&format!("http://127.0.0.1:{port}/")).is_err());
        server.join().unwrap();
    }

    /// The whole round trip against a local listener: request shape on the
    /// way out, the quote on the way back.
    #[test]
    fn a_round_trip_against_a_local_server() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut chunk = [0u8; 1024];
            while !request.ends_with(REQUEST.as_bytes()) {
                let n = conn.read(&mut chunk).unwrap();
                assert!(n > 0, "client closed before sending the whole request");
                request.extend_from_slice(&chunk[..n]);
            }
            let request = String::from_utf8(request).unwrap();
            let rpc = format!(r#"{{"jsonrpc":"2.0","id":1,"result":{QUOTE}}}"#);
            conn.write_all(&ok_reply(&rpc)).unwrap();
            request
        });
        let out = fetch(&format!("http://127.0.0.1:{port}/")).unwrap();
        let request = server.join().unwrap();
        assert!(request.starts_with("POST / HTTP/1.1\r\n"), "{request}");
        assert!(request.ends_with(REQUEST), "{request}");
        assert!(out.contains(r#""next_base_fee_exec_ceiling":9"#), "{out}");
    }

    #[test]
    fn nothing_listening_is_an_error_not_a_hang() {
        // Bind then drop: the port is closed for the moment the test needs.
        let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        assert!(fetch(&format!("http://127.0.0.1:{port}/")).is_err());
    }
}
