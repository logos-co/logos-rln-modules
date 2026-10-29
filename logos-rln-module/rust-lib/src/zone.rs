//! The zone service client: where a `logos` registry's merkle tree lives now
//! that the registration program keeps none on chain.
//!
//! A zone service (logos-rln-membership-zone's Zone indexer) follows the
//! program's `Registered`/`Extended`/`Slashed`/`Erased` events and keeps the
//! registry's Poseidon tree (depth 20). It answers two questions (spec in
//! `docs/zone-query.md`): the newest published roots (the module asks for
//! five — the valid-root window), and one leaf's Merkle proof at the root it
//! serves. Everything the membership module used to read from the chain's
//! tree comes from here. The leaf index it asks about
//! is not the service's to give: the registry module sent the registration
//! that claimed it, and answers it in `get_membership`.
//!
//! The transport is libp2p: the protobuf messages of `zone_wire.rs` on a
//! stream with the `/logos/rln/zone-query/1.0.0` codec, reached through
//! `libp2p_module`'s generic `protocolRequest` bridge (the typed
//! `Libp2pModuleClient`, from `deps/libp2p_module.lidl`). libp2p_module is a
//! metadata.json dependency, so installing this module installs it and
//! loading this module loads it: a delivery node never has to know the zone
//! client needs it. For development a service can instead be named by the
//! base URL of the Zone indexer's JSON API (`GET /roots/{n}` and
//! `GET /merkle_proof/{leaf_index}`, read with `ureq`): the messages mirror
//! those bodies field for field (a refusal is an `error` reply with the
//! status code), so both answers become a `ZoneQueryResponse` and one set of
//! checks serves both.
//!
//! Which service serves which registry is configuration: `start()`'s
//! `zone_service` (per registry entry, or top-level for all), else the
//! environment — `LOGOS_RLN_ZONE_PEER_ID` + `LOGOS_RLN_ZONE_MULTIADDR`, or
//! `LOGOS_RLN_ZONE_URL` (which wins when both are set). With none of these,
//! every zone read is `not_ready`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, LazyLock, Mutex};
use std::time::Duration;

use base64::Engine as _;
use crate::libp2p_module::Libp2pModuleClient;
use crate::proof::RLN_TREE_DEPTH;
use crate::registry_id::{bytes_to_hex, hex_to_bytes32, CanonicalRegistryId};
use crate::zone_wire::{
    MerkleProof, Query, Reply, RootEntry, Roots, Status, ZoneError, ZoneQueryRequest, ZoneQueryResponse, ROOTS_WINDOW,
    ZONE_QUERY_CODEC,
};
use crate::{lock, ApiError, ErrorKind};

/// What `protocolRequest` gives the remote: dial, stream, one exchange.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
/// The module call around it, with dispatch margin.
const CALL_TIMEOUT: Duration = Duration::from_secs(30);
const REPLY_MARGIN: Duration = Duration::from_secs(10);

const ENV_URL: &str = "LOGOS_RLN_ZONE_URL";
const ENV_PEER_ID: &str = "LOGOS_RLN_ZONE_PEER_ID";
const ENV_MULTIADDR: &str = "LOGOS_RLN_ZONE_MULTIADDR";

/// A zone service to ask, and how to reach it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ZoneService {
    /// The Zone indexer's JSON API at this http(s) base URL (development).
    Http { url: String },
    /// Dial this libp2p peer on one of these addresses.
    Libp2p { peer_id: String, multiaddrs: Vec<String> },
}

impl ZoneService {
    /// `{"url":"http(s)://…"}`, or `{"peer_id":s,"multiaddrs":[s,…]}` (a
    /// single `"multiaddr":s` is also taken). A URL wins when both are given.
    /// `None` when neither is complete, or the URL is not http(s).
    pub(crate) fn from_json(v: &serde_json::Value) -> Option<Self> {
        if let Some(url) = v.get("url").and_then(serde_json::Value::as_str).map(str::trim) {
            return (url.starts_with("http://") || url.starts_with("https://"))
                .then(|| Self::Http { url: url.to_owned() });
        }
        let peer_id = v.get("peer_id")?.as_str()?.trim().to_owned();
        let mut multiaddrs: Vec<String> = v
            .get("multiaddrs")
            .and_then(serde_json::Value::as_array)
            .map(|a| a.iter().filter_map(|m| m.as_str()).map(str::to_owned).collect())
            .unwrap_or_default();
        if let Some(one) = v.get("multiaddr").and_then(serde_json::Value::as_str) {
            multiaddrs.push(one.to_owned());
        }
        multiaddrs.retain(|m| !m.trim().is_empty());
        (!peer_id.is_empty() && !multiaddrs.is_empty()).then_some(Self::Libp2p { peer_id, multiaddrs })
    }

    fn from_env() -> Option<Self> {
        if let Ok(url) = std::env::var(ENV_URL) {
            return Self::from_json(&serde_json::json!({ "url": url }));
        }
        let peer_id = std::env::var(ENV_PEER_ID).ok()?;
        let addrs = std::env::var(ENV_MULTIADDR).ok()?;
        Self::from_json(&serde_json::json!({
            "peer_id": peer_id,
            "multiaddrs": addrs.split(',').map(str::trim).collect::<Vec<_>>(),
        }))
    }
}

/// `start()`'s zone configuration: a service per canonical registry id, and
/// one for every registry that names none.
#[derive(Default)]
struct PeerConfig {
    default: Option<ZoneService>,
    per_registry: HashMap<String, ZoneService>,
}

static PEERS: LazyLock<Mutex<PeerConfig>> = LazyLock::new(|| Mutex::new(PeerConfig::default()));

/// Replace the configured zone peers (start() is idempotent, so a reconfigure
/// drops what the previous one set).
pub(crate) fn configure(default: Option<ZoneService>, per_registry: HashMap<String, ZoneService>) {
    *lock(&PEERS) = PeerConfig { default, per_registry };
}

fn service_for(registry: &CanonicalRegistryId) -> Result<ZoneService, ApiError> {
    {
        let peers = lock(&PEERS);
        if let Some(p) = peers.per_registry.get(&registry.canonical).or(peers.default.as_ref()) {
            return Ok(p.clone());
        }
    }
    ZoneService::from_env().ok_or_else(|| {
        ApiError::new(
            ErrorKind::NotReady,
            &format!(
                "no zone service configured for {} (start() zone_service, or \
                 {ENV_URL}, or {ENV_PEER_ID} + {ENV_MULTIADDR})",
                registry.canonical
            ),
        )
    })
}

// ----------------------------------------------------------------- transport

static LIBP2P_CLIENT: Mutex<Option<Arc<Libp2pModuleClient>>> = Mutex::new(None);

/// Warm the shared client at load, like `provider::init_client`.
pub(crate) fn init_client() {
    let _ = libp2p_client();
}

fn libp2p_client() -> Arc<Libp2pModuleClient> {
    let mut slot = lock(&LIBP2P_CLIENT);
    Arc::clone(slot.get_or_insert_with(|| Arc::new(Libp2pModuleClient::new())))
}

fn transport_failure(msg: &str) -> ApiError {
    ApiError::new(ErrorKind::ProviderFailure, &format!("zone service: {msg}"))
}

/// The most a zone reply may hold: a depth-20 proof is about 3 KiB of JSON.
const MAX_HTTP_REPLY: u64 = 64 * 1024;

/// `GET base + path`: the JSON body and the HTTP status. A refusal (any
/// non-2xx) is the indexer's `{"error": text}` with its status, which
/// `http_ask` turns into the `error` reply the libp2p transport carries.
fn http_get(base: &str, path: &str) -> Result<Result<serde_json::Value, ZoneError>, ApiError> {
    let url = format!("{}{path}", base.trim_end_matches('/'));
    let agent = ureq::AgentBuilder::new().timeout(REQUEST_TIMEOUT).build();
    let read = |reply: ureq::Response| -> Result<serde_json::Value, ApiError> {
        let mut body = Vec::new();
        std::io::Read::read_to_end(&mut std::io::Read::take(reply.into_reader(), MAX_HTTP_REPLY), &mut body)
            .map_err(|e| transport_failure(&format!("GET {url}: read: {e}")))?;
        serde_json::from_slice(&body).map_err(|e| transport_failure(&format!("GET {url}: not JSON: {e}")))
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
        Err(e) => Err(transport_failure(&format!("GET {url}: {e}"))),
    }
}

fn json_u64(v: &serde_json::Value, key: &str) -> u64 {
    v.get(key).and_then(serde_json::Value::as_u64).unwrap_or(0)
}

/// A 32-byte LE hex value of an indexer reply.
fn hex32(v: Option<&serde_json::Value>, what: &str) -> Result<[u8; 32], ApiError> {
    v.and_then(serde_json::Value::as_str)
        .and_then(hex_to_bytes32)
        .ok_or_else(|| transport_failure(&format!("{what}: expected 32-byte hex")))
}

/// Hex of any length (`tx_hash`, `msg_id`); absent is empty.
fn hex_bytes(v: &serde_json::Value, key: &str) -> Result<Vec<u8>, ApiError> {
    let Some(h) = v.get(key).and_then(serde_json::Value::as_str) else { return Ok(Vec::new()) };
    (0..h.len() / 2)
        .map(|i| u8::from_str_radix(h.get(2 * i..2 * i + 2).unwrap_or("x"), 16))
        .collect::<Result<_, _>>()
        .ok()
        .filter(|_| h.len() % 2 == 0)
        .ok_or_else(|| transport_failure(&format!("{key}: not hex")))
}

/// The indexer's status, flattened into the object that carries it.
fn status_of(v: &serde_json::Value) -> Status {
    Status {
        status: v.get("status").and_then(serde_json::Value::as_str).unwrap_or_default().to_owned(),
        l1_slot: v.get("l1_slot").and_then(serde_json::Value::as_u64),
    }
}

/// Ask the Zone indexer's JSON API and read its body into the message the
/// libp2p transport would have decoded, field for field.
fn http_ask(base: &str, request: &ZoneQueryRequest) -> Result<ZoneQueryResponse, ApiError> {
    let path = match request.query {
        Query::Roots { window_size } => format!("/roots/{window_size}"),
        Query::MerkleProof { leaf_index, at: None } => format!("/merkle_proof/{leaf_index}"),
        Query::MerkleProof { leaf_index, at: Some(at) } => format!("/merkle_proof/{leaf_index}?at={}", at.as_str()),
    };
    let reply = match http_get(base, &path)? {
        Err(e) => Reply::Error(e),
        Ok(v) => match request.query {
            Query::Roots { .. } => Reply::Roots(Roots {
                latest_lez_block_id: json_u64(&v, "latest_lez_block_id"),
                lez_timestamp_ms: json_u64(&v, "lez_timestamp_ms"),
                covered_to_lez_block_id: json_u64(&v, "covered_to_lez_block_id"),
                roots: v
                    .get("roots")
                    .and_then(serde_json::Value::as_array)
                    .ok_or_else(|| transport_failure("roots: no roots array"))?
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
                    .collect::<Result<_, ApiError>>()?,
            }),
            Query::MerkleProof { leaf_index, .. } => {
                // The body is the membership's record at the head with the
                // path's fields under `proof` (`null` once the leaf is
                // removed, `removed` — or `status` — saying why); an older
                // service puts the path's fields at the top level.
                let path = match v.get("proof") {
                    None => &v,
                    Some(serde_json::Value::Null) => {
                        let why = ["removed", "status"]
                            .iter()
                            .find_map(|k| v.get(*k).and_then(serde_json::Value::as_str))
                            .filter(|s| !s.is_empty())
                            .unwrap_or("removed")
                            .to_owned();
                        return Ok(ZoneQueryResponse {
                            request_id: request.request_id.clone(),
                            reply: Reply::Error(ZoneError {
                                code: 404,
                                error: format!("leaf {leaf_index} is {why} at the LEZ head: no path to serve"),
                            }),
                        });
                    }
                    Some(path) => path,
                };
                // The head's block is `lez_block_id`; an older service, which
                // served a batch, named it `to_lez_block_id`.
                let block = if v.get("to_lez_block_id").is_some() { "to_lez_block_id" } else { "lez_block_id" };
                Reply::MerkleProof(MerkleProof {
                    root: hex32(v.get("root"), "merkle_proof.root")?,
                    to_lez_block_id: json_u64(&v, block),
                    leaf_index: v
                        .get("leaf_index")
                        .and_then(serde_json::Value::as_u64)
                        .ok_or_else(|| transport_failure("merkle_proof: no leaf_index"))?,
                    rate_commitment: hex32(path.get("rate_commitment"), "merkle_proof.rate_commitment")?,
                    path_elements: path
                        .get("path_elements")
                        .and_then(serde_json::Value::as_array)
                        .ok_or_else(|| transport_failure("merkle_proof: no path_elements"))?
                        .iter()
                        .map(|e| hex32(Some(e), "path_elements[]"))
                        .collect::<Result<_, _>>()?,
                    identity_path_index: path
                        .get("identity_path_index")
                        .and_then(serde_json::Value::as_array)
                        .ok_or_else(|| transport_failure("merkle_proof: no identity_path_index"))?
                        .iter()
                        .map(|b| b.as_u64().and_then(|b| u8::try_from(b).ok()))
                        .collect::<Option<_>>()
                        .ok_or_else(|| transport_failure("merkle_proof: identity_path_index is not bytes"))?,
                    status: status_of(&v),
                })
            }
        },
    };
    Ok(ZoneQueryResponse { request_id: request.request_id.clone(), reply })
}

/// One request→response exchange with a libp2p peer through libp2p_module's
/// `protocolRequest`. libp2p_module is a universal (C++) module: its reply is
/// a `{success, error, value}` envelope, possibly as a JSON string, whose
/// value carries `responseB64`.
fn libp2p_exchange(peer_id: &str, multiaddrs: &[String], request: &[u8]) -> Result<Vec<u8>, ApiError> {
    let args = serde_json::json!({
        "peerId": peer_id,
        "multiaddrs": multiaddrs,
        "proto": ZONE_QUERY_CODEC,
        "requestB64": base64::engine::general_purpose::STANDARD.encode(request),
        "timeoutMs": REQUEST_TIMEOUT.as_millis() as u64,
    });
    let (tx, rx) = mpsc::channel();
    libp2p_client().protocol_request_async_with_timeout(
        &args.to_string(),
        CALL_TIMEOUT,
        move |result| {
            let _ = tx.send(result);
        },
    );
    let reply = match rx.recv_timeout(CALL_TIMEOUT + REPLY_MARGIN) {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => return Err(transport_failure(&format!("protocolRequest: {e}"))),
        Err(_) => return Err(transport_failure("protocolRequest: reply channel timed out")),
    };
    let response_b64 = unwrap_libp2p_reply(reply)?;
    base64::engine::general_purpose::STANDARD
        .decode(response_b64)
        .map_err(|e| transport_failure(&format!("responseB64: {e}")))
}

/// The `responseB64` of a `protocolRequest` reply, through the envelope.
fn unwrap_libp2p_reply(reply: serde_json::Value) -> Result<String, ApiError> {
    let env = match reply {
        serde_json::Value::String(s) if !s.is_empty() => serde_json::from_str(&s)
            .map_err(|e| transport_failure(&format!("protocolRequest reply parse: {e}")))?,
        other => other,
    };
    let value = if env.get("success").is_some() {
        if env.get("success").and_then(serde_json::Value::as_bool) == Some(false) {
            let e = env
                .get("error")
                .and_then(serde_json::Value::as_str)
                .filter(|s| !s.is_empty())
                .unwrap_or("libp2p call failed");
            return Err(transport_failure(&format!("protocolRequest: {e}")));
        }
        env.get("value").cloned().unwrap_or(serde_json::Value::Null)
    } else {
        env
    };
    // The value may itself be a JSON string.
    let value = match value {
        serde_json::Value::String(s) => serde_json::from_str(&s).unwrap_or(serde_json::Value::Null),
        other => other,
    };
    value
        .get("responseB64")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| transport_failure(&format!("protocolRequest: no responseB64 in {value}")))
}

// ------------------------------------------------------------------- queries

/// One zone query, validated against what was asked.
type Ask<'a> = dyn Fn(Query) -> Result<ZoneQueryResponse, ApiError> + 'a;

static REQUEST_SEQ: AtomicU64 = AtomicU64::new(0);

fn ask(registry: &CanonicalRegistryId, query: Query) -> Result<ZoneQueryResponse, ApiError> {
    let service = service_for(registry)?;
    let anchor = hex_to_bytes32(&registry.account).ok_or_else(|| {
        ApiError::new(ErrorKind::InvalidArgument, "registry account is not 32-byte hex")
    })?;
    let request = ZoneQueryRequest {
        request_id: format!("zq-{}-{}", crate::now_unix(), REQUEST_SEQ.fetch_add(1, Ordering::Relaxed)),
        registry: anchor,
        query,
    };
    let response = match &service {
        ZoneService::Http { url } => http_ask(url, &request)?,
        ZoneService::Libp2p { peer_id, multiaddrs } => {
            let raw = libp2p_exchange(peer_id, multiaddrs, &request.encode())?;
            ZoneQueryResponse::decode(&raw).map_err(|e| transport_failure(&format!("response decode: {e}")))?
        }
    };
    checked(&request, response)
}

/// Refuse a response that does not answer the request it claims to, and turn
/// a refusal into the error it means on either transport: 404 (no leaf at
/// that index at the served root — most often a registration not yet in a
/// published root) and 503 (nothing to serve yet) are `not_ready`, anything
/// else a provider failure. Roots: none is `not_ready`, more than asked for
/// are dropped (oldest first). A proof: of the asked leaf, a path 1..=20
/// levels deep with one 0/1 bit per level.
fn checked(request: &ZoneQueryRequest, mut r: ZoneQueryResponse) -> Result<ZoneQueryResponse, ApiError> {
    if r.request_id != request.request_id {
        return Err(transport_failure("response request_id mismatch"));
    }
    match (&request.query, &mut r.reply) {
        (_, Reply::Error(ZoneError { code: code @ (404 | 503), error })) => {
            Err(ApiError::new(ErrorKind::NotReady, &format!("zone service ({code}): {error}")))
        }
        (_, Reply::Error(ZoneError { code, error })) => Err(transport_failure(&format!("refused ({code}): {error}"))),
        (Query::Roots { window_size }, Reply::Roots(roots)) => {
            roots.roots.truncate(*window_size as usize);
            if roots.roots.is_empty() {
                return Err(ApiError::new(ErrorKind::NotReady, "zone service: no root published yet"));
            }
            Ok(r)
        }
        (Query::MerkleProof { leaf_index, .. }, Reply::MerkleProof(p)) => {
            if p.leaf_index != *leaf_index {
                return Err(transport_failure(&format!("asked for leaf {leaf_index}, got leaf {}", p.leaf_index)));
            }
            let depth = p.path_elements.len();
            if depth == 0 || depth > RLN_TREE_DEPTH {
                return Err(transport_failure(&format!("leaf {leaf_index}: impossible tree depth {depth}")));
            }
            if p.identity_path_index.len() != depth {
                return Err(transport_failure(&format!("leaf {leaf_index}: path is not {depth} levels")));
            }
            if p.identity_path_index.iter().any(|&i| i > 1) {
                return Err(transport_failure(&format!("leaf {leaf_index}: path index not 0/1")));
            }
            Ok(r)
        }
        _ => Err(transport_failure("the reply answers another question")),
    }
}

/// `{"depth":N,"valid_roots":[…]}` — the shape the chain-backed provider
/// answered, so the provider's root lift is unchanged. Every listed root is
/// valid, whatever its status: the status says how settled its batch is on
/// Bedrock, not whether the tree is right. `/roots` carries no depth; the
/// zone's tree is the circuit's.
pub(crate) fn valid_roots(registry: &CanonicalRegistryId) -> Result<serde_json::Value, ApiError> {
    roots_reply(&|q| ask(registry, q))
}

fn roots_reply(ask: &Ask) -> Result<serde_json::Value, ApiError> {
    let Reply::Roots(roots) = ask(Query::Roots { window_size: ROOTS_WINDOW })?.reply else {
        unreachable!("checked: a roots query's answer is roots")
    };
    let valid: Vec<String> =
        roots.roots.iter().map(|e| e.root).filter(|root| *root != [0u8; 32]).map(|root| bytes_to_hex(&root)).collect();
    Ok(serde_json::json!({ "depth": RLN_TREE_DEPTH, "valid_roots": valid }))
}

/// One leaf's proof at the service's default root, in the provider's
/// proof-object shape (`{depth, leaf, leaf_index, path_elements,
/// path_indices, root}`), so `path_cache` reads it as it read the chain's.
/// No `valid_roots`: one root is not a window.
pub(crate) fn merkle_proof(
    registry: &CanonicalRegistryId,
    leaf_index: u64,
) -> Result<serde_json::Value, ApiError> {
    proof_reply(&|q| ask(registry, q), leaf_index)
}

#[cfg(test)]
pub(crate) fn proof_reply_for_test(ask: &Ask, leaf_index: u64) -> Result<serde_json::Value, ApiError> {
    proof_reply(ask, leaf_index)
}

fn proof_reply(ask: &Ask, leaf_index: u64) -> Result<serde_json::Value, ApiError> {
    let Reply::MerkleProof(p) = ask(Query::MerkleProof { leaf_index, at: None })?.reply else {
        unreachable!("checked: a proof query's answer is a proof")
    };
    // The indexer answers 404 for an empty leaf; one that sends its path
    // anyway (removed: slashed, erased, expired) would fail verification
    // after burning a message-id slot.
    if p.rate_commitment == [0u8; 32] {
        return Err(ApiError::new(
            ErrorKind::UnknownMembership,
            &format!("leaf {leaf_index} is empty in the zone tree (removed or expired)"),
        ));
    }
    Ok(serde_json::json!({
        "depth": p.path_elements.len(),
        "leaf": bytes_to_hex(&p.rate_commitment),
        "leaf_index": p.leaf_index,
        "path_elements": p.path_elements.iter().map(|e| bytes_to_hex(e)).collect::<Vec<_>>(),
        "path_indices": p.identity_path_index,
        "root": bytes_to_hex(&p.root),
    }))
}

#[cfg(test)]
pub(crate) mod fake {
    //! An in-memory zone service: zerokit's `OptimalMerkleTree` at depth 20,
    //! as the Zone indexer builds it, answering the same messages over the
    //! wire codec and as the indexer's JSON over loopback HTTP.

    use super::*;
    use rln::prelude::{CanonicalDeserialize, CanonicalSerialize, Fr, PoseidonHash};
    use zerokit_utils::merkle_tree::{OptimalMerkleTree, ZerokitMerkleProof, ZerokitMerkleTree};

    pub(crate) const DEPTH: usize = 20;

    pub(crate) struct FakeZone {
        tree: OptimalMerkleTree<PoseidonHash>,
        /// Published roots before the current one, newest first; the current
        /// one is listed `adopted`, these `finalized`.
        pub(crate) previous_roots: Vec<[u8; 32]>,
        /// A batch just published, listed `pending` ahead of the current root.
        pub(crate) pending_root: Option<[u8; 32]>,
    }

    fn fr(b: &[u8; 32]) -> Fr {
        Fr::deserialize_compressed(&b[..]).expect("field element")
    }

    fn bytes(f: &Fr) -> [u8; 32] {
        let mut out = [0u8; 32];
        f.serialize_compressed(&mut out[..]).expect("32 bytes");
        out
    }

    fn status(s: &str, l1_slot: Option<u64>) -> Status {
        Status { status: s.into(), l1_slot }
    }

    impl FakeZone {
        /// `leaves[i]` at index `i`; a zero leaf is an empty (removed) one.
        pub(crate) fn new(leaves: Vec<[u8; 32]>) -> Self {
            let mut tree = OptimalMerkleTree::<PoseidonHash>::default(DEPTH).unwrap();
            for (i, leaf) in leaves.iter().enumerate() {
                tree.set(i, fr(leaf)).unwrap();
            }
            Self { tree, previous_roots: vec![], pending_root: None }
        }

        pub(crate) fn root(&self) -> [u8; 32] {
            bytes(&self.tree.root())
        }

        pub(crate) fn respond(&self, query: Query) -> Result<ZoneQueryResponse, ApiError> {
            let request = ZoneQueryRequest { request_id: "fake".into(), registry: [0u8; 32], query };
            // Through the wire and the checks, as the libp2p path goes.
            checked(&request, ZoneQueryResponse::decode(&self.serve(&request).encode()).unwrap())
        }

        /// The service's answer to `request`, unchecked — what a real
        /// service would put on the wire.
        pub(crate) fn serve(&self, request: &ZoneQueryRequest) -> ZoneQueryResponse {
            let entry = |root: [u8; 32], status: Status| RootEntry {
                root,
                to_lez_block_id: 9,
                change_count: 1,
                status,
                tx_hash: vec![0xAB; 32],
                msg_id: vec![0xCD; 32],
                ..Default::default()
            };
            let reply = match request.query {
                Query::Roots { window_size } => Reply::Roots(Roots {
                    latest_lez_block_id: 10,
                    lez_timestamp_ms: 10_000,
                    covered_to_lez_block_id: 9,
                    roots: self
                        .pending_root
                        .map(|r| entry(r, status("pending", None)))
                        .into_iter()
                        .chain(std::iter::once(entry(self.root(), status("adopted", None))))
                        .chain(self.previous_roots.iter().map(|r| entry(*r, status("finalized", Some(40)))))
                        .take(window_size as usize)
                        .collect(),
                }),
                Query::MerkleProof { leaf_index, .. } => {
                    let index = leaf_index as usize;
                    match self.tree.get(index) {
                        Ok(leaf) if leaf != Fr::from(0u64) => {
                            let path = self.tree.proof(index).unwrap();
                            Reply::MerkleProof(MerkleProof {
                                root: self.root(),
                                to_lez_block_id: 9,
                                leaf_index,
                                rate_commitment: bytes(&leaf),
                                path_elements: path.get_path_elements().iter().map(bytes).collect(),
                                identity_path_index: path.get_path_index(),
                                status: status("adopted", None),
                            })
                        }
                        _ => Reply::Error(ZoneError { code: 404, error: "no leaf at this index at the served root".into() }),
                    }
                }
            };
            ZoneQueryResponse { request_id: request.request_id.clone(), reply }
        }

        /// Serve this tree as the Zone indexer's JSON API on a loopback port,
        /// one request per connection, for `requests` requests; the base URL.
        pub(crate) fn serve_http(self, requests: usize) -> String {
            serve_json(move |path| self.indexer_reply(path), requests)
        }

        /// The indexer's answer to `GET path`: `serve`'s message as its JSON.
        fn indexer_reply(&self, path: &str) -> (u16, String) {
            let (path, at) = path.split_once("?at=").unwrap_or((path, ""));
            let at = match at {
                "" => None,
                "head" => Some(crate::zone_wire::ServeAt::Head),
                "finalized" => Some(crate::zone_wire::ServeAt::Finalized),
                _ => Some(crate::zone_wire::ServeAt::Adopted),
            };
            let query = match path.strip_prefix("/roots/") {
                Some(n) => Query::Roots { window_size: n.parse().unwrap() },
                None => Query::MerkleProof { leaf_index: path.trim_start_matches("/merkle_proof/").parse().unwrap(), at },
            };
            let request = ZoneQueryRequest { request_id: String::new(), registry: [0u8; 32], query };
            let flat = |mut v: serde_json::Value, s: &Status| {
                v["status"] = s.status.clone().into();
                if let Some(slot) = s.l1_slot {
                    v["l1_slot"] = slot.into();
                }
                v
            };
            let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
            match self.serve(&request).reply {
                Reply::Roots(r) => (
                    200,
                    serde_json::json!({
                        "latest_lez_block_id": r.latest_lez_block_id,
                        "lez_timestamp_ms": r.lez_timestamp_ms,
                        "covered_to_lez_block_id": r.covered_to_lez_block_id,
                        "roots": r.roots.iter().map(|e| flat(serde_json::json!({
                            "root": hex(&e.root),
                            "from_lez_block_id": e.from_lez_block_id,
                            "to_lez_block_id": e.to_lez_block_id,
                            "change_count": e.change_count,
                            "published_at_unix": e.published_at_unix,
                            "tx_hash": hex(&e.tx_hash),
                            "msg_id": hex(&e.msg_id),
                        }), &e.status)).collect::<Vec<_>>(),
                    })
                    .to_string(),
                ),
                Reply::MerkleProof(p) => (
                    200,
                    flat(
                        serde_json::json!({
                            "root": hex(&p.root),
                            "to_lez_block_id": p.to_lez_block_id,
                            "leaf_index": p.leaf_index,
                            "rate_commitment": hex(&p.rate_commitment),
                            "path_elements": p.path_elements.iter().map(|e| hex(e)).collect::<Vec<_>>(),
                            "identity_path_index": p.identity_path_index,
                        }),
                        &p.status,
                    )
                    .to_string(),
                ),
                Reply::Error(e) => (e.code as u16, serde_json::json!({ "error": e.error }).to_string()),
            }
        }
    }

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
    use super::fake::{serve_json, FakeZone, DEPTH};
    use super::*;

    fn leaf(n: u64) -> [u8; 32] {
        crate::proof::rate_commitment(&{
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(&n.to_le_bytes());
            bytes_to_hex(&id)
        }, 100)
        .expect("canonical commitment")
    }

    /// The proof object hashes back to the root it names.
    #[test]
    fn a_zone_proof_recomputes_its_root() {
        use rln::prelude::{CanonicalDeserialize, CanonicalSerialize, Fr, Hasher, PoseidonHash};
        let zone = FakeZone::new((0..5).map(leaf).collect());
        let v = proof_reply(&|q| zone.respond(q), 3).unwrap();
        let hex_fr = |h: &str| Fr::deserialize_compressed(&hex_to_bytes32(h).unwrap()[..]).unwrap();
        let mut node = hex_fr(v["leaf"].as_str().unwrap());
        let elements = v["path_elements"].as_array().unwrap();
        let indices = v["path_indices"].as_array().unwrap();
        assert_eq!(elements.len(), DEPTH, "one sibling per level of the service's tree");
        assert_eq!(v["depth"], DEPTH);
        for (e, i) in elements.iter().zip(indices) {
            let sib = hex_fr(e.as_str().unwrap());
            node = if i.as_u64() == Some(1) {
                Hasher::<PoseidonHash>::hash_pair(sib, node)
            } else {
                Hasher::<PoseidonHash>::hash_pair(node, sib)
            };
        }
        let mut root = [0u8; 32];
        node.serialize_compressed(&mut root[..]).unwrap();
        assert_eq!(v["root"], bytes_to_hex(&root));
        assert_eq!(root, zone.root());
        assert_eq!(v["leaf_index"], 3);
        assert_eq!(v["leaf"], bytes_to_hex(&leaf(3)));
        assert!(v.get("valid_roots").is_none(), "one root is not a window");
    }

    /// The indexer answers 404 for an empty or unreached leaf: not ready (its
    /// registration may not be in a published root yet), not a failure.
    #[test]
    fn a_removed_or_missing_leaf_is_not_ready() {
        let mut leaves: Vec<[u8; 32]> = (0..3).map(leaf).collect();
        leaves[1] = [0u8; 32];
        let zone = FakeZone::new(leaves);
        let q = |q| zone.respond(q);
        for i in [1, 7] {
            let err = proof_reply(&q, i).unwrap_err();
            assert_eq!(err.kind, ErrorKind::NotReady, "{}", err.message);
            assert!(err.message.contains("(404)"), "{}", err.message);
        }
    }

    #[test]
    fn roots_reply_keeps_the_chain_shape() {
        let mut zone = FakeZone::new((0..2).map(leaf).collect());
        zone.pending_root = Some([0x0F; 32]);
        zone.previous_roots = vec![[0x02; 32], [0x03; 32], [0x04; 32], [0x05; 32], [0x06; 32]];
        let v = roots_reply(&|q| zone.respond(q)).unwrap();
        assert_eq!(v["depth"], RLN_TREE_DEPTH);
        let roots = v["valid_roots"].as_array().unwrap();
        assert_eq!(roots.len(), ROOTS_WINDOW as usize, "asked for the window, not the history");
        assert_eq!(roots[0], bytes_to_hex(&[0x0F; 32]), "a pending root is valid too");
        assert_eq!(roots[1], bytes_to_hex(&zone.root()));
        // A young tree has fewer roots than the window; a zero one is none.
        zone.pending_root = None;
        zone.previous_roots = vec![[0u8; 32]];
        let v = roots_reply(&|q| zone.respond(q)).unwrap();
        assert_eq!(v["valid_roots"].as_array().unwrap().len(), 1);
    }

    fn request(query: Query) -> ZoneQueryRequest {
        ZoneQueryRequest { request_id: "r".into(), registry: [0u8; 32], query }
    }

    fn reply(reply: Reply) -> ZoneQueryResponse {
        ZoneQueryResponse { request_id: "r".into(), reply }
    }

    fn proof(i: u64, depth: usize) -> MerkleProof {
        MerkleProof {
            root: [9; 32],
            leaf_index: i,
            rate_commitment: [1; 32],
            path_elements: vec![[2; 32]; depth],
            identity_path_index: vec![0; depth],
            ..Default::default()
        }
    }

    #[test]
    fn a_proof_answer_to_another_question_is_refused() {
        let ask = request(Query::MerkleProof { leaf_index: 4, at: None });
        assert!(checked(&ask, reply(Reply::MerkleProof(proof(4, 20)))).is_ok());
        assert!(checked(&ask, reply(Reply::MerkleProof(proof(4, 10)))).is_ok(), "a shallower tree is lifted later");
        let bad = [
            ZoneQueryResponse { request_id: "other".into(), ..reply(Reply::MerkleProof(proof(4, 20))) },
            reply(Reply::MerkleProof(proof(5, 20))),
            reply(Reply::MerkleProof(proof(4, 0))),
            reply(Reply::MerkleProof(proof(4, 21))),
            reply(Reply::MerkleProof(MerkleProof { identity_path_index: vec![0; 19], ..proof(4, 20) })),
            reply(Reply::MerkleProof(MerkleProof { identity_path_index: vec![2; 20], ..proof(4, 20) })),
            reply(Reply::Roots(Roots { roots: vec![RootEntry { root: [9; 32], ..Default::default() }], ..Default::default() })),
            reply(Reply::Error(ZoneError { code: 400, error: "at must be head, adopted or finalized".into() })),
        ];
        for r in bad {
            assert_eq!(checked(&ask, r.clone()).unwrap_err().kind, ErrorKind::ProviderFailure, "{r:?}");
        }
        for code in [404, 503] {
            let r = reply(Reply::Error(ZoneError { code, error: "later".into() }));
            assert_eq!(checked(&ask, r).unwrap_err().kind, ErrorKind::NotReady, "{code}");
        }
    }

    #[test]
    fn a_roots_answer_keeps_at_most_what_was_asked() {
        let ask = request(Query::Roots { window_size: ROOTS_WINDOW });
        let entry = RootEntry { root: [3; 32], ..Default::default() };
        let many = reply(Reply::Roots(Roots { roots: vec![entry; 7], ..Default::default() }));
        let Reply::Roots(r) = checked(&ask, many).unwrap().reply else { panic!("roots") };
        assert_eq!(r.roots.len(), ROOTS_WINDOW as usize);
        let none = reply(Reply::Roots(Roots::default()));
        assert_eq!(checked(&ask, none).unwrap_err().kind, ErrorKind::NotReady, "nothing published yet");
        assert_eq!(checked(&ask, reply(Reply::MerkleProof(proof(0, 20)))).unwrap_err().kind, ErrorKind::ProviderFailure);
    }

    #[test]
    fn libp2p_envelopes_unwrap_to_the_response() {
        let inner = serde_json::json!({"responseB64": "AAE="});
        for reply in [
            inner.clone(),
            serde_json::json!({"success": true, "value": inner.clone()}),
            serde_json::json!({"success": true, "value": inner.to_string()}),
            serde_json::Value::String(serde_json::json!({"success": true, "value": inner}).to_string()),
        ] {
            assert_eq!(unwrap_libp2p_reply(reply).unwrap(), "AAE=");
        }
        let failed = serde_json::json!({"success": false, "error": "dial failed"});
        assert!(unwrap_libp2p_reply(failed).unwrap_err().message.contains("dial failed"));
    }

    #[test]
    fn peers_resolve_per_registry_then_default_then_not_ready() {
        let _serial = crate::lock(&crate::TEST_GLOBAL_LOCK);
        let a = crate::registry_id::parse(&format!("logos:zone-test:{}", "aa".repeat(32))).unwrap();
        let b = crate::registry_id::parse(&format!("logos:zone-test:{}", "bb".repeat(32))).unwrap();
        let pa = ZoneService::Libp2p { peer_id: "A".into(), multiaddrs: vec!["/ip4/1.2.3.4/tcp/1".into()] };
        let pd = ZoneService::Http { url: "http://5.6.7.8:1".into() };
        configure(Some(pd.clone()), HashMap::from([(a.canonical.clone(), pa.clone())]));
        assert_eq!(service_for(&a).unwrap(), pa);
        assert_eq!(service_for(&b).unwrap(), pd);
        configure(None, HashMap::new());
        if std::env::var(ENV_URL).is_err() && std::env::var(ENV_PEER_ID).is_err() {
            assert_eq!(service_for(&b).unwrap_err().kind, ErrorKind::NotReady);
        }
    }

    #[test]
    fn a_peer_needs_an_id_and_an_address() {
        let j = |v: serde_json::Value| ZoneService::from_json(&v);
        assert!(j(serde_json::json!({"peer_id": "P", "multiaddr": "/ip4/1.1.1.1/tcp/1"})).is_some());
        assert!(j(serde_json::json!({"peer_id": "P", "multiaddrs": ["/a", "/b"]})).is_some());
        assert!(j(serde_json::json!({"peer_id": "P"})).is_none());
        assert!(j(serde_json::json!({"peer_id": "", "multiaddr": "/a"})).is_none());
        assert!(j(serde_json::json!({"multiaddrs": ["/a"]})).is_none());
    }

    #[test]
    fn a_url_names_an_http_service() {
        let j = |v: serde_json::Value| ZoneService::from_json(&v);
        assert_eq!(
            j(serde_json::json!({"url": " http://zone.local:8080 "})),
            Some(ZoneService::Http { url: "http://zone.local:8080".into() })
        );
        assert!(matches!(j(serde_json::json!({"url": "https://z/q"})), Some(ZoneService::Http { .. })));
        assert!(
            matches!(
                j(serde_json::json!({"url": "http://z/q", "peer_id": "P", "multiaddr": "/a"})),
                Some(ZoneService::Http { .. })
            ),
            "a URL wins"
        );
        assert!(j(serde_json::json!({"url": "ftp://z/q"})).is_none());
        assert!(j(serde_json::json!({"url": ""})).is_none());
    }

    /// The two transports carry the same messages: one tree served as the
    /// indexer's JSON and as protobuf decodes to identical responses.
    #[test]
    fn http_and_libp2p_answers_are_the_same_message() {
        let mut zone = FakeZone::new((0..3).map(leaf).collect());
        zone.pending_root = Some([0x0F; 32]);
        zone.previous_roots = vec![[0x02; 32]];
        let queries = [
            Query::Roots { window_size: ROOTS_WINDOW },
            Query::MerkleProof { leaf_index: 2, at: None },
            Query::MerkleProof { leaf_index: 0, at: Some(crate::zone_wire::ServeAt::Finalized) },
            Query::MerkleProof { leaf_index: 9, at: None },
        ];
        let wire: Vec<_> = queries
            .iter()
            .map(|q| {
                let r = request(q.clone());
                ZoneQueryResponse::decode(&zone.serve(&r).encode()).unwrap()
            })
            .collect();
        let url = zone.serve_http(queries.len());
        for (q, w) in queries.iter().zip(wire) {
            assert_eq!(http_ask(&url, &request(q.clone())).unwrap(), w, "{q:?}");
        }
    }

    /// The current service answers `/merkle_proof` with the membership's
    /// record at the head, the path under `proof` and the block as
    /// `lez_block_id`: it decodes to the same message as the older flat body,
    /// and a removed leaf (`proof` null) is a 404 naming the cause.
    #[test]
    fn the_nested_proof_body_reads_as_the_flat_one() {
        let zone = FakeZone::new((0..3).map(leaf).collect());
        let flat = match zone.serve(&request(Query::MerkleProof { leaf_index: 2, at: None })).reply {
            Reply::MerkleProof(p) => p,
            other => panic!("{other:?}"),
        };
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let nested = serde_json::json!({
            "id_commitment": hex(&[7u8; 32]),
            "leaf_index": flat.leaf_index,
            "active": true,
            "removed": null,
            "expiry_timestamp_ms": 1_795_794_676_639u64,
            "root": hex(&flat.root),
            "lez_block_id": flat.to_lez_block_id,
            "lez_timestamp_ms": 1_792_743_136_914u64,
            "newest_adopted": { "root": hex(&flat.root), "to_lez_block_id": flat.to_lez_block_id },
            "newest_finalized": null,
            "proof": {
                "rate_commitment": hex(&flat.rate_commitment),
                "path_elements": flat.path_elements.iter().map(|e| hex(e)).collect::<Vec<_>>(),
                "identity_path_index": flat.identity_path_index,
            },
        })
        .to_string();
        let mut slashed: serde_json::Value = serde_json::from_str(&nested).unwrap();
        slashed["active"] = false.into();
        slashed["removed"] = "slashed".into();
        slashed["proof"] = serde_json::Value::Null;
        let slashed = slashed.to_string();
        let url = serve_json(
            move |path| match path {
                "/merkle_proof/2" => (200, nested.clone()),
                "/merkle_proof/1" => (200, slashed.clone()),
                _ => (404, r#"{"error":"no such membership"}"#.to_owned()),
            },
            2,
        );
        let got = http_ask(&url, &request(Query::MerkleProof { leaf_index: 2, at: None })).unwrap();
        assert_eq!(got.reply, Reply::MerkleProof(MerkleProof { status: Status::default(), ..flat }), "no batch status on a head-served path");
        let got = http_ask(&url, &request(Query::MerkleProof { leaf_index: 1, at: None })).unwrap();
        assert_eq!(
            got.reply,
            Reply::Error(ZoneError { code: 404, error: "leaf 1 is slashed at the LEZ head: no path to serve".to_owned() })
        );
    }

    /// The whole client path over HTTP: configure a URL, ask for the window
    /// and a proof, get them back from a real (loopback) server.
    #[test]
    fn roots_and_a_proof_come_back_over_http() {
        let _serial = crate::lock(&crate::TEST_GLOBAL_LOCK);
        let registry = crate::registry_id::parse(&format!("logos:zone-http-test:{}", "cc".repeat(32))).unwrap();
        let mut zone = FakeZone::new((0..3).map(leaf).collect());
        zone.pending_root = Some([0x0F; 32]);
        zone.previous_roots = vec![[0x02; 32]];
        let root = zone.root();
        let url = zone.serve_http(3);
        configure(None, HashMap::from([(registry.canonical.clone(), ZoneService::Http { url })]));
        let roots = valid_roots(&registry).unwrap();
        assert_eq!(
            roots["valid_roots"],
            serde_json::json!([bytes_to_hex(&[0x0F; 32]), bytes_to_hex(&root), bytes_to_hex(&[0x02; 32])]),
            "every listed root, whatever its status"
        );
        let proof = merkle_proof(&registry, 2).unwrap();
        assert_eq!((proof["leaf_index"].as_u64(), proof["root"].as_str()), (Some(2), Some(bytes_to_hex(&root).as_str())));
        assert_eq!(proof["leaf"], bytes_to_hex(&leaf(2)));
        assert_eq!(proof["depth"], DEPTH, "a proof's depth is its path's length");
        let err = merkle_proof(&registry, 9).unwrap_err();
        assert_eq!(err.kind, ErrorKind::NotReady, "not in the served root (yet)");
        assert!(err.message.contains("no leaf at this index"), "{}", err.message);
        configure(None, HashMap::new());
    }
}
