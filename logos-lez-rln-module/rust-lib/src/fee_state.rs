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
//! The transport is a plain HTTP/1.0 POST over `std::net`, like the curl
//! subprocess `testnet_tests` uses for the same reason: the crate gains no
//! HTTP or TLS dependency. HTTP/1.0 because a server may not answer it
//! chunked, so the body is whatever follows the headers. The cost is that an
//! https sequencer answers "" — which a caller must already treat as "fee
//! state unknown".

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::wallet;

const REQUEST: &str = r#"{"jsonrpc":"2.0","id":1,"method":"getFeeState","params":[]}"#;

/// Per-address connect bound. Handlers run on a worker under
/// `concurrency:"multi"`, so a dead sequencer costs a worker this long, not
/// the module.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Bound on each read and write once connected.
const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// A quote is ~250 bytes; anything past this is not one.
const MAX_REPLY: u64 = 64 * 1024;

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
    let (authority, path) = split_http_url(sequencer)?;
    let reply = post(authority, path, REQUEST)?;
    result_of(&http_body(&reply)?)
}

/// `http://host[:port][/path]` → (`host[:port]`, `/path`).
fn split_http_url(url: &str) -> Result<(&str, &str), String> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| format!("only http:// sequencers can be read (got '{url}')"))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.is_empty() {
        return Err(format!("no host in '{url}'"));
    }
    Ok((authority, path))
}

fn post(authority: &str, path: &str, body: &str) -> Result<Vec<u8>, String> {
    // An authority without a port takes http's default.
    let target = if authority.rsplit_once(':').is_some_and(|(_, p)| p.parse::<u16>().is_ok()) {
        authority.to_owned()
    } else {
        format!("{authority}:80")
    };
    let addrs = target.to_socket_addrs().map_err(|e| format!("resolve {target}: {e}"))?;
    let mut last = format!("{target} resolved to no address");
    let mut stream = None;
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
            Ok(s) => {
                stream = Some(s);
                break;
            }
            Err(e) => last = format!("connect {addr}: {e}"),
        }
    }
    let mut stream = stream.ok_or(last)?;
    stream.set_read_timeout(Some(IO_TIMEOUT)).map_err(|e| e.to_string())?;
    stream.set_write_timeout(Some(IO_TIMEOUT)).map_err(|e| e.to_string())?;
    let request = format!(
        "POST {path} HTTP/1.0\r\nHost: {authority}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).map_err(|e| format!("send: {e}"))?;
    let mut reply = Vec::new();
    stream
        .take(MAX_REPLY)
        .read_to_end(&mut reply)
        .map_err(|e| format!("read: {e}"))?;
    Ok(reply)
}

/// The body of a 200 reply, cut to its Content-Length when it has one.
fn http_body(reply: &[u8]) -> Result<String, String> {
    let text = std::str::from_utf8(reply).map_err(|_| "reply is not UTF-8".to_owned())?;
    let (head, body) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| "reply has no header terminator".to_owned())?;
    let mut lines = head.split("\r\n");
    let status = lines.next().unwrap_or_default();
    if status.split_whitespace().nth(1) != Some("200") {
        return Err(format!("HTTP status '{status}'"));
    }
    let mut body = body;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else { continue };
        let value = value.trim();
        if name.eq_ignore_ascii_case("transfer-encoding") && !value.eq_ignore_ascii_case("identity") {
            return Err(format!("unsupported transfer-encoding '{value}'"));
        }
        if name.eq_ignore_ascii_case("content-length") {
            let len = value.parse::<usize>().map_err(|_| format!("content-length '{value}'"))?;
            body = body.get(..len).ok_or_else(|| "reply shorter than its content-length".to_owned())?;
        }
    }
    Ok(body.to_owned())
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
    use std::net::TcpListener;

    const QUOTE: &str = r#"{"height":15082,"base_fee_exec":8,"base_fee_stor":8,"next_base_fee_exec_floor":8,"next_base_fee_exec_ceiling":9,"next_base_fee_stor_floor":8,"next_base_fee_stor_ceiling":9,"max_gas_exec":10000000,"max_gas_stor":1000000}"#;

    fn ok_reply(body: &str) -> Vec<u8> {
        format!(
            "HTTP/1.0 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    #[test]
    fn urls_split_into_authority_and_path() {
        assert_eq!(
            split_http_url("http://209.38.241.182:3140/"),
            Ok(("209.38.241.182:3140", "/"))
        );
        assert_eq!(split_http_url("http://seq.local"), Ok(("seq.local", "/")));
        assert_eq!(split_http_url("http://h:1/rpc"), Ok(("h:1", "/rpc")));
        assert!(split_http_url("https://testnet.lez.logos.co/").is_err());
        assert!(split_http_url("http:///").is_err());
    }

    #[test]
    fn a_quote_passes_through_with_every_field() {
        let rpc = format!(r#"{{"jsonrpc":"2.0","id":1,"result":{QUOTE}}}"#);
        let out = result_of(&http_body(&ok_reply(&rpc)).unwrap()).unwrap();
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
    fn only_a_complete_200_body_is_accepted() {
        assert!(http_body(b"HTTP/1.0 503 Service Unavailable\r\n\r\n").is_err());
        assert!(http_body(b"HTTP/1.0 200 OK\r\ncontent-length: 10\r\n\r\nshort").is_err());
        assert!(http_body(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n5\r\n").is_err());
        assert!(http_body(b"no headers").is_err());
        // No content-length under HTTP/1.0: the body runs to the close.
        assert_eq!(http_body(b"HTTP/1.0 200 OK\r\n\r\n{}").unwrap(), "{}");
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
        assert!(request.starts_with("POST / HTTP/1.0\r\n"), "{request}");
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
