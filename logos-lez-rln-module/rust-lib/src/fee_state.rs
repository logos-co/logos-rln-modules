//! The sequencer reads `core_ffi` has no call for, made over JSON-RPC to the
//! sequencer the wallet's own config names — so always the same chain:
//!
//! - `getFeeState` (`get_fee_state`): a registration's `max_fee` is only a
//!   cap; what the chain holds back from the payer is `gas_limit x
//!   base_fee_exec + data_bytes x base_fee_stor + tip` at the block the tx
//!   lands in, and a caller deciding whether it can afford to register needs
//!   that number.
//! - `getLastBlockId` and `getBlock` (`head_block_timestamp_ms`): chain time
//!   is the head block's timestamp — what the registry judges a membership's
//!   lifecycle by and what a `Register` dates itself with. The block comes
//!   back as a base64 string of its borsh encoding; the header is a
//!   fixed-width prefix of that.
//! - `getTransaction` (`tx_included`): whether a submitted transaction is in a
//!   block. `wallet_ffi_poll_transaction_status` would answer the same
//!   question, but it blocks for the whole poll window holding the wallet's
//!   lock, which would stall every other handler.
//!
//! The transport is `ureq` with rustls, so an https sequencer (the LEZ 0.3
//! testnet zone serves https only) is read like an http one. A failed read is
//! "" / `None` — which a caller must already treat as "unknown".

use std::time::Duration;

use base64::Engine as _;

use crate::wallet;

// OWNERSHIP: every error here is an owned String (most are formatted), so the
// literal messages are converted with `to_owned`.

const REQUEST: &str = r#"{"jsonrpc":"2.0","id":1,"method":"getFeeState","params":[]}"#;
const HEAD_REQUEST: &str = r#"{"jsonrpc":"2.0","id":1,"method":"getLastBlockId","params":[]}"#;

/// Connect bound. Handlers run on a worker under `concurrency:"multi"`, so a
/// dead sequencer costs a worker this long, not the module.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Bound on each read and write once connected.
const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// A quote is ~250 bytes and a transaction a few KB; anything past this is
/// not a reply this module asked for.
const MAX_REPLY: u64 = 1024 * 1024;

/// A block carries every transaction in it: up to the sequencer's block size
/// cap (1 MiB on a local devnet), ~1.33 MiB as base64. A reply cut short at
/// `MAX_REPLY` would fail to decode and read as "unavailable" rather than as a
/// wrong time, but it would make chain time unreadable under load.
const MAX_BLOCK_REPLY: u64 = 8 * 1024 * 1024;

/// Where the timestamp sits in a borsh `Block`: the header is `block_id u64`,
/// `prev_block_hash [u8; 32]`, `hash [u8; 32]`, then `timestamp u64`.
const BLOCK_TIMESTAMP_OFFSET: usize = 8 + 32 + 32;
const BLOCK_HEADER_SIZE: usize = BLOCK_TIMESTAMP_OFFSET + 8;

/// The RPC `result` object as compact JSON; "" before a network is selected
/// and on any transport or parse error (logged).
pub(crate) fn get_fee_state() -> String {
    fee_quote()
        .map(|quote| quote.to_string())
        .unwrap_or_default()
}

/// `get_fee_state`'s `result` object as a value; `None` where that answers ""
/// (logged the same way).
pub(crate) fn fee_quote() -> Option<serde_json::Value> {
    let Some(sequencer) = wallet::sequencer_addr() else {
        eprintln!("get_fee_state: no sequencer configured yet");
        return None;
    };
    match fetch_quote(&sequencer) {
        Ok(quote) => Some(quote),
        Err(e) => {
            eprintln!("get_fee_state: {sequencer}: {e}");
            None
        }
    }
}

/// `fetch_quote` as `get_fee_state`'s compact JSON text.
#[cfg(test)]
pub(crate) fn fetch(sequencer: &str) -> Result<String, String> {
    fetch_quote(sequencer).map(|quote| quote.to_string())
}

fn fetch_quote(sequencer: &str) -> Result<serde_json::Value, String> {
    result_object(&post(sequencer, REQUEST)?)
}

/// The sequencer's last block id (getLastBlockId), or None when it cannot be
/// asked. Same transport and sequencer as `get_fee_state`.
pub(crate) fn chain_head() -> Option<u64> {
    let sequencer = wallet::sequencer_addr()?;
    rpc_result(&sequencer, HEAD_REQUEST, MAX_REPLY)
        .ok()?
        .as_u64()
}

/// Chain time in milliseconds: the head block's timestamp. `None` when it
/// cannot be read (logged) — never a local clock, which the registry does not
/// judge by.
pub(crate) fn head_block_timestamp_ms() -> Option<u64> {
    let Some(sequencer) = wallet::sequencer_addr() else {
        eprintln!("head_block_timestamp_ms: no sequencer configured yet");
        return None;
    };
    match fetch_head_timestamp(&sequencer) {
        Ok(timestamp) => Some(timestamp),
        Err(e) => {
            eprintln!("head_block_timestamp_ms: {sequencer}: {e}");
            None
        }
    }
}

/// The head block's timestamp from `sequencer`: getLastBlockId, then getBlock.
pub(crate) fn fetch_head_timestamp(sequencer: &str) -> Result<u64, String> {
    let head = rpc_result(sequencer, HEAD_REQUEST, MAX_REPLY)?
        .as_u64()
        .ok_or_else(|| "getLastBlockId reply is not a block number".to_owned())?;
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "getBlock", "params": [head]
    })
    .to_string();
    let result = rpc_result(sequencer, &body, MAX_BLOCK_REPLY)?;
    if result.is_null() {
        return Err(format!("block {head} is missing"));
    }
    let encoded = result
        .as_str()
        .ok_or_else(|| "getBlock reply is not a base64 block".to_owned())?;
    let block = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| format!("getBlock reply is not base64: {e}"))?;
    block_header_timestamp(&block).ok_or_else(|| format!("block {head} carries no timestamp"))
}

/// The timestamp in a borsh-encoded block's header; `None` for anything
/// shorter than a header or a zero timestamp.
fn block_header_timestamp(block: &[u8]) -> Option<u64> {
    let field = block.get(BLOCK_TIMESTAMP_OFFSET..BLOCK_HEADER_SIZE)?;
    let timestamp = u64::from_le_bytes(field.try_into().ok()?);
    (timestamp != 0).then_some(timestamp)
}

/// Whether the transaction `tx_hash` is in a block: `Some(true)` included,
/// `Some(false)` not (still queued, or dropped at the door), `None` when the
/// sequencer could not be asked. Inclusion is not success: a transaction whose
/// program refused its message is included as a charged, effect-free revert,
/// so a caller pairs this with a read of the state it meant to change.
pub(crate) fn tx_included(tx_hash: &str) -> Option<bool> {
    let sequencer = wallet::sequencer_addr()?;
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "getTransaction", "params": [tx_hash]
    })
    .to_string();
    match rpc_result(&sequencer, &body, MAX_REPLY) {
        Ok(result) => Some(!result.is_null()),
        Err(e) => {
            eprintln!("tx_included: {sequencer}: {e}");
            None
        }
    }
}

/// POST a JSON-RPC body to an http:// or https:// sequencer; the 200 reply's
/// body, read up to `cap` bytes.
fn post_capped(url: &str, body: &str, cap: u64) -> Result<String, String> {
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
        &mut std::io::Read::take(reply.into_reader(), cap),
        &mut text,
    )
    .map_err(|e| format!("read: {e}"))?;
    Ok(text)
}

fn post(url: &str, body: &str) -> Result<String, String> {
    post_capped(url, body, MAX_REPLY)
}

/// A JSON-RPC reply's `result` value (null included); its `error` otherwise.
fn rpc_result(url: &str, body: &str, cap: u64) -> Result<serde_json::Value, String> {
    let mut reply: serde_json::Value = serde_json::from_str(&post_capped(url, body, cap)?)
        .map_err(|e| format!("reply parse: {e}"))?;
    if let Some(error) = reply.get("error") {
        return Err(format!("RPC error {error}"));
    }
    reply
        .get_mut("result")
        .map(serde_json::Value::take)
        .ok_or_else(|| "reply carries no result".to_owned())
}

/// `result_object` as compact JSON text.
#[cfg(test)]
fn result_of(body: &str) -> Result<String, String> {
    result_object(body).map(|result| result.to_string())
}

/// A JSON-RPC reply's `result`, which must be an object; its `error` otherwise.
fn result_object(body: &str) -> Result<serde_json::Value, String> {
    let mut reply: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("reply parse: {e}"))?;
    if let Some(error) = reply.get("error") {
        return Err(format!("RPC error {error}"));
    }
    match reply.get_mut("result") {
        Some(result) if result.is_object() => Ok(result.take()),
        _ => Err("reply carries no result object".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};

    const QUOTE: &str = r#"{"height":15082,"base_fee_exec":8,"base_fee_stor":8,"next_base_fee_exec_floor":8,"next_base_fee_exec_ceiling":9,"next_base_fee_stor_floor":8,"next_base_fee_stor_ceiling":9,"max_gas_exec":10000000,"max_gas_stor":1000000}"#;

    fn ok_reply(body: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    /// One HTTP request off a connection: the headers, then exactly
    /// `content-length` bytes of body.
    fn read_request(conn: &mut TcpStream) -> String {
        let mut raw = Vec::new();
        let mut chunk = [0u8; 1024];
        let header_end = loop {
            if let Some(at) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                break at + 4;
            }
            let n = conn.read(&mut chunk).unwrap();
            assert!(n > 0, "client closed before sending the headers");
            raw.extend_from_slice(&chunk[..n]);
        };
        let headers = String::from_utf8_lossy(&raw[..header_end]).to_ascii_lowercase();
        let length: usize = headers
            .lines()
            .find_map(|l| l.strip_prefix("content-length:"))
            .expect("content-length header")
            .trim()
            .parse()
            .unwrap();
        while raw.len() < header_end + length {
            let n = conn.read(&mut chunk).unwrap();
            assert!(n > 0, "client closed before sending the whole body");
            raw.extend_from_slice(&chunk[..n]);
        }
        String::from_utf8(raw).unwrap()
    }

    #[test]
    fn only_http_and_https_sequencers_are_asked() {
        assert!(post("ftp://seq.local/", REQUEST)
            .unwrap_err()
            .contains("not an http(s)"));
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
            conn.write_all(b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\n\r\n")
                .unwrap();
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
            let request = read_request(&mut conn);
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
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        assert!(fetch(&format!("http://127.0.0.1:{port}/")).is_err());
    }

    /// A borsh block: the 80-byte header, then a body. Pins the timestamp's
    /// place in the header.
    fn borsh_block(timestamp: u64) -> Vec<u8> {
        let mut raw = Vec::new();
        raw.extend_from_slice(&7u64.to_le_bytes());
        raw.extend_from_slice(&[0x11; 32]);
        raw.extend_from_slice(&[0x22; 32]);
        raw.extend_from_slice(&timestamp.to_le_bytes());
        // An empty transaction list, an empty reverted list, a bedrock status.
        raw.extend_from_slice(&[0; 9]);
        raw
    }

    #[test]
    fn the_timestamp_is_the_last_header_field() {
        let block = borsh_block(1_700_000_000_123);
        assert_eq!(block_header_timestamp(&block), Some(1_700_000_000_123));
        assert_eq!(BLOCK_HEADER_SIZE, 80);
        assert_eq!(
            block_header_timestamp(&block[..79]),
            None,
            "shorter than a header"
        );
        assert_eq!(
            block_header_timestamp(&borsh_block(0)),
            None,
            "a zero timestamp is no time"
        );
    }

    /// getLastBlockId, then getBlock for that id, decoded from base64 borsh.
    #[test]
    fn the_head_timestamp_is_read_in_two_calls() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let first = read_request(&mut conn);
            assert!(first.ends_with(HEAD_REQUEST), "{first}");
            conn.write_all(&ok_reply(r#"{"jsonrpc":"2.0","id":1,"result":41}"#))
                .unwrap();
            drop(conn);
            let (mut conn, _) = listener.accept().unwrap();
            let second = read_request(&mut conn);
            assert!(second.contains(r#""method":"getBlock""#), "{second}");
            assert!(second.contains(r#""params":[41]"#), "{second}");
            let encoded =
                base64::engine::general_purpose::STANDARD.encode(borsh_block(1_700_000_000_123));
            conn.write_all(&ok_reply(&format!(
                r#"{{"jsonrpc":"2.0","id":1,"result":"{encoded}"}}"#
            )))
            .unwrap();
        });
        let timestamp = fetch_head_timestamp(&format!("http://127.0.0.1:{port}/")).unwrap();
        server.join().unwrap();
        assert_eq!(timestamp, 1_700_000_000_123);
    }

    /// A missing block (`null`) and a reply that is not base64 are errors, not
    /// times.
    #[test]
    fn a_missing_or_malformed_block_is_no_time() {
        for result in [r#"null"#, r#""not base64!""#, r#"{"header":{}}"#] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let reply = format!(r#"{{"jsonrpc":"2.0","id":1,"result":{result}}}"#);
            let server = std::thread::spawn(move || {
                let (mut conn, _) = listener.accept().unwrap();
                read_request(&mut conn);
                conn.write_all(&ok_reply(r#"{"jsonrpc":"2.0","id":1,"result":3}"#))
                    .unwrap();
                drop(conn);
                let (mut conn, _) = listener.accept().unwrap();
                read_request(&mut conn);
                conn.write_all(&ok_reply(&reply)).unwrap();
            });
            assert!(
                fetch_head_timestamp(&format!("http://127.0.0.1:{port}/")).is_err(),
                "{result}"
            );
            server.join().unwrap();
        }
    }
}
