//! The service: configuration, the libp2p bring-up, the accept loop, and the
//! one-exchange handler that turns a wire request into the zone's answer.
//!
//! One worker thread owns the loop. Each inbound stream is one exchange —
//! read a request frame, answer with a response frame, release — so a
//! request that takes long (a zone read is capped at 5 s) delays the next
//! member by that much at most, and the member side's own deadline is 20 s.
//! The roots window is cached for `roots_cache_ms` because every member polls
//! it every 10 s; proofs are never cached (a leaf's path changes with every
//! insert).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::lock;
use crate::lp;
use crate::zone_http::{bytes_to_hex, http_ask, ZoneHttpError};
use crate::zone_wire::{Query, Reply, Roots, ZoneError, ZoneQueryRequest, ZoneQueryResponse, ZONE_QUERY_CODEC};

const ENV_URL: &str = "LOGOS_RLN_ZONE_URL";
const ENV_LISTEN: &str = "LOGOS_RLN_DATA_SERVICE_LISTEN";

/// How long one accept poll waits inside libp2p_module. Short, because the
/// module serves every caller from one thread.
const ACCEPT_POLL_MS: u64 = 500;
/// The pause between polls that found nothing.
const IDLE_PAUSE: Duration = Duration::from_millis(100);
/// A dialer that opened a stream sends its request at once.
const READ_TIMEOUT_MS: u64 = 5_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Config {
    /// The zone for every registry `registries` does not name.
    pub(crate) default_url: Option<String>,
    /// Registry (config account, lowercase hex) → zone base URL.
    pub(crate) registries: HashMap<String, String>,
    /// `createNode` + `start` libp2p on these; empty: the node is someone
    /// else's to bring up, only `start` is called.
    pub(crate) listen: Vec<String>,
    pub(crate) roots_cache_ms: u64,
    pub(crate) max_request_bytes: u64,
}

impl Config {
    /// `start()`'s `config_json` (empty is `{}`), with the environment
    /// filling in a missing zone URL and listen list.
    pub(crate) fn parse(config_json: &str) -> Result<Self, String> {
        let v: serde_json::Value = if config_json.trim().is_empty() {
            serde_json::json!({})
        } else {
            serde_json::from_str(config_json).map_err(|e| format!("config_json: {e}"))?
        };
        let url_of = |v: &serde_json::Value, what: &str| -> Result<Option<String>, String> {
            match v.get("url").and_then(serde_json::Value::as_str).map(str::trim) {
                None => Ok(None),
                Some(url) if url.starts_with("http://") || url.starts_with("https://") => Ok(Some(url.to_owned())),
                Some(other) => Err(format!("{what}.url: not http(s): {other:?}")),
            }
        };
        let mut default_url = match v.get("zone") {
            Some(zone) => url_of(zone, "zone")?,
            None => None,
        };
        if default_url.is_none() {
            default_url = std::env::var(ENV_URL).ok().filter(|u| u.starts_with("http://") || u.starts_with("https://"));
        }
        let mut registries = HashMap::new();
        if let Some(map) = v.get("registries") {
            let map = map.as_object().ok_or("registries: expected an object")?;
            for (registry, zone) in map {
                let key = canonical_registry(registry).ok_or_else(|| format!("registries: {registry:?} is not a config account (hex or base58)"))?;
                let url = url_of(zone, &format!("registries.{registry}"))?
                    .ok_or_else(|| format!("registries.{registry}: no url"))?;
                registries.insert(key, url);
            }
        }
        if default_url.is_none() && registries.is_empty() {
            return Err(format!("no zone: set zone.url (or {ENV_URL}) or registries"));
        }
        let mut listen: Vec<String> = v
            .get("listen")
            .and_then(serde_json::Value::as_array)
            .map(|a| a.iter().filter_map(|m| m.as_str()).map(str::trim).filter(|m| !m.is_empty()).map(str::to_owned).collect())
            .unwrap_or_default();
        if listen.is_empty() {
            if let Ok(env) = std::env::var(ENV_LISTEN) {
                listen = env.split(',').map(str::trim).filter(|m| !m.is_empty()).map(str::to_owned).collect();
            }
        }
        Ok(Self {
            default_url,
            registries,
            listen,
            roots_cache_ms: v.get("roots_cache_ms").and_then(serde_json::Value::as_u64).unwrap_or(2_000),
            max_request_bytes: v.get("max_request_bytes").and_then(serde_json::Value::as_u64).unwrap_or(4_096),
        })
    }

    /// The zone serving this registry (its config account), if any.
    fn zone_for(&self, registry: &[u8; 32]) -> Option<&str> {
        self.registries.get(&bytes_to_hex(registry)).or(self.default_url.as_ref()).map(String::as_str)
    }
}

/// A config account as lowercase hex: 64 hex digits (0x-tolerant) or the
/// base58 the chain tools print.
fn canonical_registry(s: &str) -> Option<String> {
    if let Some(b) = crate::zone_http::hex_to_bytes32(s) {
        return Some(bytes_to_hex(&b));
    }
    base58_decode32(s.trim()).map(|b| bytes_to_hex(&b))
}

const BASE58: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// The base58 of 32 bytes, and nothing else: a string that is not the
/// encoding of the bytes it decodes to (too short for 32 bytes, say) is
/// refused rather than read as a small number.
fn base58_decode32(s: &str) -> Option<[u8; 32]> {
    if s.is_empty() || s.len() > 64 {
        return None;
    }
    let mut n = [0u8; 32];
    for c in s.bytes() {
        let d = BASE58.iter().position(|&a| a == c)? as u32;
        let mut carry = d;
        for byte in n.iter_mut().rev() {
            let v = u32::from(*byte) * 58 + carry;
            *byte = (v & 0xff) as u8;
            carry = v >> 8;
        }
        if carry != 0 {
            return None;
        }
    }
    (base58_encode(&n) == s).then_some(n)
}

fn base58_encode(bytes: &[u8]) -> String {
    let mut digits: Vec<u8> = vec![0];
    for &b in bytes {
        let mut carry = u32::from(b);
        for d in digits.iter_mut() {
            carry += u32::from(*d) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let zeros = bytes.iter().take_while(|&&b| b == 0).count();
    let mut out: String = std::iter::repeat_n('1', zeros).collect();
    out.extend(digits.iter().rev().map(|&d| BASE58[d as usize] as char));
    out
}

// ------------------------------------------------------------------ counters

#[derive(Default)]
pub(crate) struct Counters {
    pub(crate) served: AtomicU64,
    pub(crate) errors: AtomicU64,
    pub(crate) last_served_unix: AtomicU64,
    pub(crate) last_error: Mutex<String>,
}

impl Counters {
    fn error(&self, msg: String) {
        self.errors.fetch_add(1, Ordering::Relaxed);
        eprintln!("rln data service: {msg}");
        *lock(&self.last_error) = msg;
    }
}

/// What `start` learned and `status` reports.
#[derive(Debug, Clone, Default)]
pub(crate) struct Identity {
    pub(crate) peer_id: String,
    pub(crate) multiaddrs: Vec<String>,
}

struct Running {
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
    identity: Identity,
    zone_url: String,
}

struct Service {
    running: Option<Running>,
    counters: Arc<Counters>,
}

static SERVICE: LazyLock<Mutex<Service>> =
    LazyLock::new(|| Mutex::new(Service { running: None, counters: Arc::new(Counters::default()) }));

/// The roots window the zone answered, by (zone URL, window size).
type RootsCache = Mutex<HashMap<(String, u32), (Roots, Instant)>>;

// ------------------------------------------------------------------- handler

/// Where a request's answer comes from: the zone, through the cache.
pub(crate) struct Handler {
    config: Config,
    cache: RootsCache,
    counters: Arc<Counters>,
}

impl Handler {
    pub(crate) fn new(config: Config, counters: Arc<Counters>) -> Self {
        Self { config, cache: Mutex::new(HashMap::new()), counters }
    }

    /// One exchange: the request frame in, the response frame out. Every
    /// failure is a reply the member understands: 400 for a frame that is
    /// not a request (with an empty `request_id`, there is none to echo),
    /// 404 for a registry this service does not serve, 502 when the zone
    /// did not answer a usable body; the zone's own refusals pass through.
    pub(crate) fn handle(&self, frame: &[u8]) -> Vec<u8> {
        let request = match ZoneQueryRequest::decode(frame) {
            Ok(r) => r,
            Err(e) => {
                self.counters.error(format!("request: {e}"));
                return refuse(String::new(), 400, format!("bad request: {e}"));
            }
        };
        let Some(zone) = self.config.zone_for(&request.registry) else {
            let hex = bytes_to_hex(&request.registry);
            self.counters.error(format!("registry {hex} not served"));
            return refuse(request.request_id, 404, format!("registry {hex} is not served here"));
        };
        let response = match self.ask(zone, &request) {
            Ok(r) => r,
            Err(e) => {
                self.counters.error(e.to_string());
                return refuse(request.request_id, 502, e.to_string());
            }
        };
        self.counters.served.fetch_add(1, Ordering::Relaxed);
        self.counters.last_served_unix.store(crate::now_unix(), Ordering::Relaxed);
        response.encode()
    }

    fn ask(&self, zone: &str, request: &ZoneQueryRequest) -> Result<ZoneQueryResponse, ZoneHttpError> {
        let Query::Roots { window_size } = request.query else {
            return http_ask(zone, request);
        };
        let key = (zone.to_owned(), window_size);
        let ttl = Duration::from_millis(self.config.roots_cache_ms);
        if ttl > Duration::ZERO {
            if let Some((roots, at)) = lock(&self.cache).get(&key) {
                if at.elapsed() < ttl {
                    return Ok(ZoneQueryResponse {
                        request_id: request.request_id.clone(),
                        reply: Reply::Roots(roots.clone()),
                    });
                }
            }
        }
        let response = http_ask(zone, request)?;
        if let Reply::Roots(roots) = &response.reply {
            lock(&self.cache).insert(key, (roots.clone(), Instant::now()));
        }
        Ok(response)
    }
}

fn refuse(request_id: String, code: u32, error: String) -> Vec<u8> {
    ZoneQueryResponse { request_id, reply: Reply::Error(ZoneError { code, error }) }.encode()
}

// ------------------------------------------------------------------ lifecycle

/// Bring the service up (idempotent: a running service is stopped and
/// restarted with the new config). Returns what members must be told.
pub(crate) fn start(config_json: &str) -> Result<serde_json::Value, String> {
    let config = Config::parse(config_json)?;
    stop_locked(&mut lock(&SERVICE));

    if !config.listen.is_empty() {
        lp::create_node(&config.listen)?;
    }
    lp::start_node()?;
    lp::mount_protocol(ZONE_QUERY_CODEC)?;
    let identity = Identity {
        peer_id: lp::node_info("PeerId")?
            .as_str()
            .map(str::to_owned)
            .ok_or("getNodeInfo PeerId: not a string")?,
        multiaddrs: lp::node_info("Multiaddrs")?
            .as_array()
            .map(|a| a.iter().filter_map(|m| m.as_str()).map(str::to_owned).collect())
            .unwrap_or_default(),
    };
    let zone_url = config.default_url.clone().unwrap_or_default();

    let mut service = lock(&SERVICE);
    let counters = Arc::clone(&service.counters);
    let stop = Arc::new(AtomicBool::new(false));
    let handler = Arc::new(Handler::new(config, Arc::clone(&counters)));
    let worker = {
        let stop = Arc::clone(&stop);
        std::thread::Builder::new()
            .name("rln-data-service".into())
            .spawn(move || serve_loop(&handler, &stop))
            .map_err(|e| format!("worker thread: {e}"))?
    };
    service.running = Some(Running { stop, worker: Some(worker), identity: identity.clone(), zone_url: zone_url.clone() });
    Ok(serde_json::json!({
        "started": true,
        "peer_id": identity.peer_id,
        "multiaddrs": identity.multiaddrs,
        "protocol": ZONE_QUERY_CODEC,
        "zone_url": zone_url,
    }))
}

pub(crate) fn stop() -> Result<serde_json::Value, String> {
    let was_running = stop_locked(&mut lock(&SERVICE));
    Ok(serde_json::json!({ "stopped": true, "was_running": was_running }))
}

fn stop_locked(service: &mut Service) -> bool {
    let Some(mut running) = service.running.take() else { return false };
    running.stop.store(true, Ordering::SeqCst);
    if let Some(worker) = running.worker.take() {
        let _ = worker.join();
    }
    true
}

pub(crate) fn status() -> serde_json::Value {
    let service = lock(&SERVICE);
    let c = &service.counters;
    let (running, identity, zone_url) = match &service.running {
        Some(r) => (true, r.identity.clone(), r.zone_url.clone()),
        None => (false, Identity::default(), String::new()),
    };
    serde_json::json!({
        "running": running,
        "protocol": ZONE_QUERY_CODEC,
        "peer_id": identity.peer_id,
        "multiaddrs": identity.multiaddrs,
        "zone_url": zone_url,
        "served": c.served.load(Ordering::Relaxed),
        "errors": c.errors.load(Ordering::Relaxed),
        "last_error": lock(&c.last_error).clone(),
        "last_served_unix": c.last_served_unix.load(Ordering::Relaxed),
    })
}

/// The worker: accept, read, answer, release, until told to stop.
fn serve_loop(handler: &Handler, stop: &AtomicBool) {
    while !stop.load(Ordering::SeqCst) {
        let (stream_id, peer) = match lp::accept_stream(ZONE_QUERY_CODEC, ACCEPT_POLL_MS) {
            Ok(s) => s,
            Err(e) if lp::is_accept_timeout(&e) => {
                std::thread::sleep(IDLE_PAUSE);
                continue;
            }
            Err(e) => {
                handler.counters.error(format!("accept: {e}"));
                std::thread::sleep(Duration::from_secs(1));
                continue;
            }
        };
        match lp::read_frame(stream_id, handler.config.max_request_bytes, READ_TIMEOUT_MS) {
            Ok(frame) => {
                let reply = handler.handle(&frame);
                if let Err(e) = lp::write_frame(stream_id, &reply) {
                    handler.counters.error(format!("reply to {peer}: {e}"));
                }
            }
            Err(e) => handler.counters.error(format!("request from {peer}: {e}")),
        }
        if let Err(e) = lp::release_stream(stream_id) {
            handler.counters.error(format!("release {stream_id}: {e}"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zone_http::fake::serve_json;
    use crate::zone_wire::{MerkleProof, RootEntry, Status};

    const REGISTRY: [u8; 32] = [0xA0; 32];

    fn config(url: &str) -> Config {
        Config {
            default_url: Some(url.to_owned()),
            registries: HashMap::new(),
            listen: Vec::new(),
            roots_cache_ms: 2_000,
            max_request_bytes: 4_096,
        }
    }

    fn request(id: &str, registry: [u8; 32], query: Query) -> Vec<u8> {
        ZoneQueryRequest { request_id: id.into(), registry, query }.encode()
    }

    fn hex(b: &[u8]) -> String {
        bytes_to_hex(b)
    }

    fn zone_bodies() -> (String, String) {
        let roots = serde_json::json!({
            "covered_to_lez_block_id": 69520, "lez_block_id": 69523,
            "roots": [{ "change_count": 1, "from_lez_block_id": 69507, "published_at_unix": 1793304100,
                        "root": hex(&[0x32; 32]), "status": "adopted", "to_lez_block_id": 69520 }]
        })
        .to_string();
        let proof = serde_json::json!({
            "leaf_index": 10, "lez_block_id": 69523, "root": hex(&[0x32; 32]), "removed": null,
            "proof": { "rate_commitment": hex(&[0x9E; 32]), "path_elements": [hex(&[0x01; 32])],
                       "identity_path_index": [1] }
        })
        .to_string();
        (roots, proof)
    }

    #[test]
    fn config_parses_zone_registries_and_listen() {
        let c = Config::parse(
            r#"{"zone":{"url":"http://127.0.0.1:3000/"},
                "registries":{"BpxYQFLWf6Wi5HhWAaZRtbhxmeKa5P9THK7WBDCoXRg9":{"url":"http://z2"},
                              "0xA0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0":{"url":"http://z3"}},
                "listen":["/ip4/127.0.0.1/tcp/0"],"roots_cache_ms":0}"#,
        )
        .unwrap();
        assert_eq!(c.default_url.as_deref(), Some("http://127.0.0.1:3000/"));
        assert_eq!(c.listen, vec!["/ip4/127.0.0.1/tcp/0"]);
        assert_eq!(c.roots_cache_ms, 0);
        assert_eq!(c.max_request_bytes, 4_096);
        assert_eq!(
            c.zone_for(&crate::zone_http::hex_to_bytes32("a0ddf7d84417d72a08ebe4959d8d4208d1c453e3cd4431edf46f0f806191b0ae").unwrap()),
            Some("http://z2"),
            "base58 config account canonicalizes to the hex the wire carries"
        );
        assert_eq!(c.zone_for(&REGISTRY), Some("http://z3"));
        assert_eq!(c.zone_for(&[0x01; 32]), Some("http://127.0.0.1:3000/"), "the default");
        assert!(Config::parse(r#"{"zone":{"url":"ftp://x"}}"#).is_err());
        assert!(Config::parse(r#"{"registries":{"nope":{"url":"http://z"}}}"#).is_err());
        let only = Config::parse(r#"{"registries":{"0xA0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0":{"url":"http://z3"}}}"#).unwrap();
        assert_eq!(only.zone_for(&[0x01; 32]), None, "no default: other registries are not served");
    }

    #[test]
    fn base58_round_trips_a_config_account() {
        let b = base58_decode32("BpxYQFLWf6Wi5HhWAaZRtbhxmeKa5P9THK7WBDCoXRg9").unwrap();
        assert_eq!(hex(&b), "a0ddf7d84417d72a08ebe4959d8d4208d1c453e3cd4431edf46f0f806191b0ae");
        assert!(base58_decode32("0OIl").is_none());
    }

    #[test]
    fn requests_are_answered_from_the_zone_with_the_request_id_echoed() {
        let (roots, proof) = zone_bodies();
        let url = serve_json(
            move |path| match path {
                "/roots/5" => (200, roots.clone()),
                "/merkle_proof/10" => (200, proof.clone()),
                _ => (404, r#"{"error":"no such membership"}"#.to_owned()),
            },
            3,
        );
        let h = Handler::new(config(&url), Arc::new(Counters::default()));
        let r = ZoneQueryResponse::decode(&h.handle(&request("zq-1", REGISTRY, Query::Roots { window_size: 5 }))).unwrap();
        assert_eq!(r.request_id, "zq-1");
        let Reply::Roots(roots) = r.reply else { panic!("roots") };
        assert_eq!(roots.roots, vec![RootEntry {
            root: [0x32; 32], from_lez_block_id: 69507, to_lez_block_id: 69520, change_count: 1,
            published_at_unix: 1793304100, status: Status { status: "adopted".into(), l1_slot: None },
            tx_hash: vec![], msg_id: vec![],
        }]);
        let r = ZoneQueryResponse::decode(&h.handle(&request("zq-2", REGISTRY, Query::MerkleProof { leaf_index: 10, at: None }))).unwrap();
        assert_eq!(r.request_id, "zq-2");
        assert_eq!(r.reply, Reply::MerkleProof(MerkleProof {
            root: [0x32; 32], to_lez_block_id: 69523, leaf_index: 10, rate_commitment: [0x9E; 32],
            path_elements: vec![[0x01; 32]], identity_path_index: vec![1], status: Status::default(),
        }));
        let r = ZoneQueryResponse::decode(&h.handle(&request("zq-3", REGISTRY, Query::MerkleProof { leaf_index: 99, at: None }))).unwrap();
        assert_eq!(r.reply, Reply::Error(ZoneError { code: 404, error: "no such membership".into() }), "the zone's refusal passes through");
        assert_eq!(h.counters.served.load(Ordering::Relaxed), 3);
        assert_eq!(h.counters.errors.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn the_roots_window_is_cached_and_proofs_are_not() {
        let (roots, proof) = zone_bodies();
        // Two roots reads and two proof reads are allowed; the cache must
        // make the second roots request not need a third connection.
        let url = serve_json(
            move |path| match path {
                "/roots/5" => (200, roots.clone()),
                _ => (200, proof.clone()),
            },
            3,
        );
        let h = Handler::new(config(&url), Arc::new(Counters::default()));
        for id in ["a", "b"] {
            let r = ZoneQueryResponse::decode(&h.handle(&request(id, REGISTRY, Query::Roots { window_size: 5 }))).unwrap();
            assert_eq!(r.request_id, id);
            assert!(matches!(r.reply, Reply::Roots(_)));
        }
        for id in ["c", "d"] {
            let r = ZoneQueryResponse::decode(&h.handle(&request(id, REGISTRY, Query::MerkleProof { leaf_index: 10, at: None }))).unwrap();
            assert!(matches!(r.reply, Reply::MerkleProof(_)), "{id}");
        }
        // A third roots read after the cache expired would need a fourth
        // connection, which the server does not grant: it is a 502.
        lock(&h.cache).clear();
        let r = ZoneQueryResponse::decode(&h.handle(&request("e", REGISTRY, Query::Roots { window_size: 5 }))).unwrap();
        assert!(matches!(r.reply, Reply::Error(ZoneError { code: 502, .. })), "{r:?}");
        assert_eq!(h.counters.errors.load(Ordering::Relaxed), 1);
        assert!(lock(&h.counters.last_error).contains("GET"), "{}", lock(&h.counters.last_error));
    }

    #[test]
    fn refusals_name_the_cause() {
        let h = Handler::new(config("http://127.0.0.1:1"), Arc::new(Counters::default()));
        let r = ZoneQueryResponse::decode(&h.handle(&[0x15, 0, 0, 0, 0])).unwrap();
        assert_eq!(r.request_id, "", "nothing to echo");
        assert!(matches!(r.reply, Reply::Error(ZoneError { code: 400, .. })), "{r:?}");
        let mut only = config("http://127.0.0.1:1");
        only.default_url = None;
        only.registries.insert(hex(&[0x01; 32]), "http://127.0.0.1:1".into());
        let h = Handler::new(only, Arc::new(Counters::default()));
        let r = ZoneQueryResponse::decode(&h.handle(&request("zq-9", REGISTRY, Query::Roots { window_size: 5 }))).unwrap();
        assert_eq!(r.request_id, "zq-9");
        assert_eq!(r.reply, Reply::Error(ZoneError { code: 404, error: format!("registry {} is not served here", hex(&REGISTRY)) }));
        assert_eq!(status()["running"], false);
    }
}
