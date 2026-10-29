//! The zone's JSON API, read into the wire messages: `GET /roots/{n}` and
//! `GET /merkle_proof/{leaf_index}[?at=…]` of logos-rln-membership-zone's
//! Zone indexer (`zone-sequencer/src/http.rs`), field for field, as the
//! membership module's own HTTP transport reads them
//! (`logos-rln-module/rust-lib/src/zone.rs`, `http_ask`). A refusal (any
//! non-2xx) is the indexer's `{"error": text}` with its status, which becomes
//! the `error` reply the libp2p transport carries.

use std::time::Duration;

use crate::zone_wire::{
    MerkleProof, Query, Reply, RootEntry, Roots, Status, ZoneError, ZoneQueryRequest, ZoneQueryResponse,
};

/// The zone is local to this node: a read that takes longer than this is
/// a zone problem, and the member waiting on the libp2p side gives up at
/// 20 s end to end.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// The most a zone reply may hold: a depth-20 proof is about 3 KiB of JSON.
const MAX_HTTP_REPLY: u64 = 64 * 1024;

/// The zone did not answer a usable body: unreachable, not JSON, or a field
/// missing or malformed. Served to the member as `error` 502.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ZoneHttpError(pub(crate) String);

impl std::fmt::Display for ZoneHttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn failure(msg: &str) -> ZoneHttpError {
    ZoneHttpError(format!("zone: {msg}"))
}

/// Whitespace-trimming, 0x/0X-tolerant hex decoder. Even length required.
pub(crate) fn hex_to_vec(hex: &str) -> Option<Vec<u8>> {
    let s = hex.trim();
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok())
        .collect()
}

pub(crate) fn hex_to_bytes32(hex: &str) -> Option<[u8; 32]> {
    hex_to_vec(hex)?.try_into().ok()
}

pub(crate) fn bytes_to_hex(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(data.len() * 2);
    for b in data {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

/// `GET base + path`: the JSON body, or the indexer's refusal.
fn http_get(base: &str, path: &str) -> Result<Result<serde_json::Value, ZoneError>, ZoneHttpError> {
    let url = format!("{}{path}", base.trim_end_matches('/'));
    let agent = ureq::AgentBuilder::new().timeout(REQUEST_TIMEOUT).build();
    let read = |reply: ureq::Response| -> Result<serde_json::Value, ZoneHttpError> {
        let mut body = Vec::new();
        std::io::Read::read_to_end(&mut std::io::Read::take(reply.into_reader(), MAX_HTTP_REPLY), &mut body)
            .map_err(|e| failure(&format!("GET {url}: read: {e}")))?;
        serde_json::from_slice(&body).map_err(|e| failure(&format!("GET {url}: not JSON: {e}")))
    };
    match agent.get(&url).call() {
        Ok(reply) => Ok(Ok(read(reply)?)),
        Err(ureq::Error::Status(code, reply)) => {
            let error = read(reply)
                .ok()
                .and_then(|v| v.get("error").and_then(serde_json::Value::as_str).map(str::to_owned))
                .unwrap_or_else(|| format!("HTTP {code}"));
            Ok(Err(ZoneError { code: u32::from(code), error }))
        }
        Err(e) => Err(failure(&format!("GET {url}: {e}"))),
    }
}

fn json_u64(v: &serde_json::Value, key: &str) -> u64 {
    v.get(key).and_then(serde_json::Value::as_u64).unwrap_or(0)
}

/// A 32-byte LE hex value of an indexer reply.
fn hex32(v: Option<&serde_json::Value>, what: &str) -> Result<[u8; 32], ZoneHttpError> {
    v.and_then(serde_json::Value::as_str)
        .and_then(hex_to_bytes32)
        .ok_or_else(|| failure(&format!("{what}: expected 32-byte hex")))
}

/// Hex of any length (`tx_hash`, `msg_id`); absent is empty.
fn hex_bytes(v: &serde_json::Value, key: &str) -> Result<Vec<u8>, ZoneHttpError> {
    let Some(h) = v.get(key).and_then(serde_json::Value::as_str) else { return Ok(Vec::new()) };
    hex_to_vec(h).ok_or_else(|| failure(&format!("{key}: not hex")))
}

/// The indexer's status, flattened into the object that carries it.
fn status_of(v: &serde_json::Value) -> Status {
    Status {
        status: v.get("status").and_then(serde_json::Value::as_str).unwrap_or_default().to_owned(),
        l1_slot: v.get("l1_slot").and_then(serde_json::Value::as_u64),
    }
}

/// The path a query is `GET` at.
pub(crate) fn path_of(query: &Query) -> String {
    match *query {
        Query::Roots { window_size } => format!("/roots/{window_size}"),
        Query::MerkleProof { leaf_index, at: None } => format!("/merkle_proof/{leaf_index}"),
        Query::MerkleProof { leaf_index, at: Some(at) } => format!("/merkle_proof/{leaf_index}?at={}", at.as_str()),
    }
}

/// Ask the Zone indexer's JSON API and read its body into the message the
/// member decodes, field for field.
pub(crate) fn http_ask(base: &str, request: &ZoneQueryRequest) -> Result<ZoneQueryResponse, ZoneHttpError> {
    let reply = match http_get(base, &path_of(&request.query))? {
        Err(e) => Reply::Error(e),
        Ok(v) => match request.query {
            Query::Roots { .. } => Reply::Roots(roots_of(&v)?),
            Query::MerkleProof { leaf_index, .. } => match proof_of(&v, leaf_index)? {
                Ok(p) => Reply::MerkleProof(p),
                Err(e) => Reply::Error(e),
            },
        },
    };
    Ok(ZoneQueryResponse { request_id: request.request_id.clone(), reply })
}

/// The `/roots` body.
pub(crate) fn roots_of(v: &serde_json::Value) -> Result<Roots, ZoneHttpError> {
    Ok(Roots {
        latest_lez_block_id: json_u64(v, "latest_lez_block_id"),
        lez_timestamp_ms: json_u64(v, "lez_timestamp_ms"),
        covered_to_lez_block_id: json_u64(v, "covered_to_lez_block_id"),
        roots: v
            .get("roots")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| failure("roots: no roots array"))?
            .iter()
            .map(|e| {
                Ok(RootEntry {
                    root: hex32(e.get("root"), "roots[].root")?,
                    from_lez_block_id: json_u64(e, "from_lez_block_id"),
                    to_lez_block_id: json_u64(e, "to_lez_block_id"),
                    change_count: json_u64(e, "change_count"),
                    published_at_unix: json_u64(e, "published_at_unix"),
                    status: status_of(e),
                    tx_hash: hex_bytes(e, "tx_hash")?,
                    msg_id: hex_bytes(e, "msg_id")?,
                })
            })
            .collect::<Result<_, ZoneHttpError>>()?,
    })
}

/// The `/merkle_proof` body: the membership's record at the head with the
/// path's fields under `proof` (`null` once the leaf is removed, `removed` —
/// or `status` — saying why, which is a 404 to the member); an older service
/// puts the path's fields at the top level.
fn proof_of(v: &serde_json::Value, leaf_index: u64) -> Result<Result<MerkleProof, ZoneError>, ZoneHttpError> {
    let path = match v.get("proof") {
        None => v,
        Some(serde_json::Value::Null) => {
            let why = ["removed", "status"]
                .iter()
                .find_map(|k| v.get(*k).and_then(serde_json::Value::as_str))
                .filter(|s| !s.is_empty())
                .unwrap_or("removed")
                .to_owned();
            return Ok(Err(ZoneError {
                code: 404,
                error: format!("leaf {leaf_index} is {why} at the LEZ head: no path to serve"),
            }));
        }
        Some(path) => path,
    };
    // The head's block is `lez_block_id`; an older service, which served a
    // batch, named it `to_lez_block_id`.
    let block = if v.get("to_lez_block_id").is_some() { "to_lez_block_id" } else { "lez_block_id" };
    Ok(Ok(MerkleProof {
        root: hex32(v.get("root"), "merkle_proof.root")?,
        to_lez_block_id: json_u64(v, block),
        leaf_index: v
            .get("leaf_index")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| failure("merkle_proof: no leaf_index"))?,
        rate_commitment: hex32(path.get("rate_commitment"), "merkle_proof.rate_commitment")?,
        path_elements: path
            .get("path_elements")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| failure("merkle_proof: no path_elements"))?
            .iter()
            .map(|e| hex32(Some(e), "path_elements[]"))
            .collect::<Result<_, _>>()?,
        identity_path_index: path
            .get("identity_path_index")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| failure("merkle_proof: no identity_path_index"))?
            .iter()
            .map(|b| b.as_u64().and_then(|b| u8::try_from(b).ok()))
            .collect::<Option<_>>()
            .ok_or_else(|| failure("merkle_proof: identity_path_index is not bytes"))?,
        status: status_of(v),
    }))
}

#[cfg(test)]
pub(crate) mod fake {
    /// Serve `reply(path)` for `GET path` as JSON on a loopback port, one
    /// request per connection, for `requests` requests; the base URL.
    pub(crate) fn serve_json(reply: impl Fn(&str) -> (u16, String) + Send + 'static, requests: usize) -> String {
        use std::io::{BufRead, BufReader, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            for stream in listener.incoming().take(requests) {
                let mut stream = stream.unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut request_line = String::new();
                reader.read_line(&mut request_line).unwrap();
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line.trim_end().is_empty() {
                        break;
                    }
                }
                let path = request_line.split_whitespace().nth(1).unwrap_or("").to_owned();
                let (code, body) = reply(&path);
                write!(
                    stream,
                    "HTTP/1.1 {code} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
            }
        });
        url
    }
}

#[cfg(test)]
mod tests {
    use super::fake::serve_json;
    use super::*;

    fn request(query: Query) -> ZoneQueryRequest {
        ZoneQueryRequest { request_id: "zq-t".into(), registry: [0x5A; 32], query }
    }

    fn hex(b: &[u8]) -> String {
        bytes_to_hex(b)
    }

    #[test]
    fn hex_helpers() {
        assert_eq!(hex_to_bytes32(&"ab".repeat(32)), Some([0xAB; 32]));
        assert_eq!(hex_to_bytes32(&format!(" 0x{} ", "ab".repeat(32))), Some([0xAB; 32]));
        assert_eq!(hex_to_bytes32("abc"), None);
        assert_eq!(hex_to_vec("zz"), None);
        assert_eq!(bytes_to_hex(&[0x01, 0xEF]), "01ef");
    }

    #[test]
    fn paths_follow_the_indexer_api() {
        assert_eq!(path_of(&Query::Roots { window_size: 5 }), "/roots/5");
        assert_eq!(path_of(&Query::MerkleProof { leaf_index: 9, at: None }), "/merkle_proof/9");
        assert_eq!(
            path_of(&Query::MerkleProof { leaf_index: 0, at: Some(crate::zone_wire::ServeAt::Finalized) }),
            "/merkle_proof/0?at=finalized"
        );
    }

    /// The indexer's bodies, as served on 2026-10-29, read into the messages.
    #[test]
    fn the_indexer_bodies_become_the_wire_messages() {
        let roots = serde_json::json!({
            "covered_to_lez_block_id": 69520, "lez_block_id": 69523, "lez_timestamp_ms": 1793304500000u64,
            "root": hex(&[0x32; 32]),
            "roots": [
                { "carried_to_lez_block_id": 69520, "change_count": 1, "from_lez_block_id": 69507,
                  "msg_id": hex(&[0xE0; 32]), "published_at_unix": 1793304100, "root": hex(&[0x32; 32]),
                  "status": "adopted", "to_lez_block_id": 69520, "tx_hash": hex(&[0x66; 32]) },
                { "change_count": 0, "from_lez_block_id": 49431, "msg_id": hex(&[0xE1; 32]),
                  "published_at_unix": 1793303664, "root": hex(&[0x26; 32]), "status": "finalized",
                  "l1_slot": 12, "to_lez_block_id": 69468, "tx_hash": hex(&[0x67; 32]) }
            ]
        })
        .to_string();
        let proof = serde_json::json!({
            "active": true, "expiry_timestamp_ms": 1796502500000u64, "id_commitment": hex(&[0x2F; 32]),
            "leaf_index": 10, "lez_block_id": 69523, "lez_timestamp_ms": 1793304500000u64,
            "newest_adopted": { "root": hex(&[0x32; 32]), "to_lez_block_id": 69520 }, "newest_finalized": null,
            "proof": { "rate_commitment": hex(&[0x9E; 32]), "path_elements": [hex(&[0x01; 32]), hex(&[0x02; 32])],
                       "identity_path_index": [0, 1] },
            "removed": null, "root": hex(&[0x32; 32])
        })
        .to_string();
        let slashed = serde_json::json!({
            "active": false, "id_commitment": hex(&[0x33; 32]), "leaf_index": 3, "lez_block_id": 69523,
            "proof": null, "removed": "slashed", "root": hex(&[0x32; 32])
        })
        .to_string();
        let url = serve_json(
            move |path| match path {
                "/roots/5" => (200, roots.clone()),
                "/merkle_proof/10" => (200, proof.clone()),
                "/merkle_proof/3" => (200, slashed.clone()),
                _ => (404, r#"{"error":"no such membership"}"#.to_owned()),
            },
            4,
        );
        let got = http_ask(&url, &request(Query::Roots { window_size: 5 })).unwrap();
        assert_eq!(got.request_id, "zq-t");
        let Reply::Roots(r) = got.reply else { panic!("roots") };
        assert_eq!((r.latest_lez_block_id, r.covered_to_lez_block_id, r.roots.len()), (0, 69520, 2));
        assert_eq!(r.roots[0].root, [0x32; 32]);
        assert_eq!(r.roots[0].status, Status { status: "adopted".into(), l1_slot: None });
        assert_eq!(r.roots[1].status, Status { status: "finalized".into(), l1_slot: Some(12) });
        assert_eq!(r.roots[1].msg_id, vec![0xE1; 32]);

        let got = http_ask(&url, &request(Query::MerkleProof { leaf_index: 10, at: None })).unwrap();
        let Reply::MerkleProof(p) = got.reply else { panic!("proof") };
        assert_eq!((p.leaf_index, p.to_lez_block_id, p.root), (10, 69523, [0x32; 32]));
        assert_eq!(p.rate_commitment, [0x9E; 32]);
        assert_eq!(p.path_elements, vec![[0x01; 32], [0x02; 32]]);
        assert_eq!(p.identity_path_index, vec![0, 1]);
        assert_eq!(p.status, Status::default(), "no batch status on a head-served path");

        let got = http_ask(&url, &request(Query::MerkleProof { leaf_index: 3, at: None })).unwrap();
        assert_eq!(
            got.reply,
            Reply::Error(ZoneError { code: 404, error: "leaf 3 is slashed at the LEZ head: no path to serve".into() })
        );
        let got = http_ask(&url, &request(Query::MerkleProof { leaf_index: 99, at: None })).unwrap();
        assert_eq!(got.reply, Reply::Error(ZoneError { code: 404, error: "no such membership".into() }));
    }

    #[test]
    fn a_zone_that_is_down_or_malformed_is_a_failure_not_a_refusal() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);
        assert!(http_ask(&url, &request(Query::Roots { window_size: 5 })).is_err(), "unreachable");
        let url = serve_json(|_| (200, r#"{"roots":[{"root":"zz"}]}"#.to_owned()), 1);
        let err = http_ask(&url, &request(Query::Roots { window_size: 5 })).unwrap_err();
        assert!(err.0.contains("roots[].root"), "{err}");
    }
}
