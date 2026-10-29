//! Wire codec for the zone query protocol (`logos-rln-module/docs/zone-query.md`):
//! the two questions a membership module asks over libp2p — the latest
//! published roots, or one leaf's Merkle proof — and the answer.
//!
//! A copy of `logos-rln-module/rust-lib/src/zone_wire.rs` with the service
//! side (`ZoneQueryRequest::decode`, the response `encode`s) compiled in; the
//! two files must stay identical apart from this header and those gates, and
//! both pin the same byte vectors in their tests. A nix module build sees only
//! its own directory, which is why this is a copy and not a shared crate.
//!
//! The messages mirror the Zone indexer's HTTP API (logos-rln-membership-zone,
//! `zone-sequencer/src/http.rs`) field for field: `RootsRequest` is
//! `GET /roots/{window_size}`, `MerkleProofRequest` is
//! `GET /merkle_proof/{leaf_index}[?at=…]`, the replies carry the JSON bodies'
//! fields under the same names (32-byte values as raw bytes instead of hex),
//! and a refusal carries the HTTP status code with the `error` text.
//!
//! Hand-rolled protobuf (varint keys, LEN-delimited bytes/strings/messages,
//! varint integers). Integer fields are written even when zero — leaf 0 is a
//! real leaf — and a decoder treats an absent one as zero, as protobuf does;
//! `l1_slot` is the one field whose presence is meaningful.

#![allow(dead_code)]

pub(crate) const ZONE_QUERY_CODEC: &str = "/logos/rln/zone-query/1.0.0";

/// How many roots the module asks for: the valid-root window it accepts
/// proofs against.
pub(crate) const ROOTS_WINDOW: u32 = 5;

/// Which root a proof is served at — the indexer's `?at=`. `None` in a
/// request is the service's default (`adopted`: the newest root in a Bedrock
/// block, or the head while none is). The module always asks at the
/// default; the variants are the protocol's.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ServeAt {
    Head,
    Adopted,
    Finalized,
}

impl ServeAt {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Head => "head",
            Self::Adopted => "adopted",
            Self::Finalized => "finalized",
        }
    }

    fn parse(s: &str) -> Result<Option<Self>, String> {
        match s {
            "" => Ok(None),
            "head" => Ok(Some(Self::Head)),
            "adopted" => Ok(Some(Self::Adopted)),
            "finalized" => Ok(Some(Self::Finalized)),
            other => Err(format!("at: unknown {other:?}")),
        }
    }
}

/// What a request asks — the `oneof query` of `ZoneQueryRequest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Query {
    /// `GET /roots/{window_size}`: the newest published roots, newest first.
    Roots { window_size: u32 },
    /// `GET /merkle_proof/{leaf_index}[?at=…]`.
    MerkleProof { leaf_index: u64, at: Option<ServeAt> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ZoneQueryRequest {
    pub(crate) request_id: String,
    /// The registry's config account id — the anchor of a `logos` registry
    /// id; the service maps it to its tree (over HTTP, the URL names it).
    pub(crate) registry: [u8; 32],
    pub(crate) query: Query,
}

/// How settled a root's batch is on Bedrock — the indexer's flattened
/// `"status"` (`pending`, `adopted`, `orphaned`, `finalized`, or `head` for a
/// proof served from the tree at the LEZ head), with `l1_slot` when finalized.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct Status {
    pub(crate) status: String,
    pub(crate) l1_slot: Option<u64>,
}

/// One published root — an entry of `/roots`' `roots`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct RootEntry {
    pub(crate) root: [u8; 32],
    pub(crate) from_lez_block_id: u64,
    pub(crate) to_lez_block_id: u64,
    pub(crate) change_count: u64,
    pub(crate) published_at_unix: u64,
    pub(crate) status: Status,
    pub(crate) tx_hash: Vec<u8>,
    pub(crate) msg_id: Vec<u8>,
}

/// The `/roots` body.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct Roots {
    pub(crate) latest_lez_block_id: u64,
    pub(crate) lez_timestamp_ms: u64,
    pub(crate) covered_to_lez_block_id: u64,
    /// Newest first, orphaned ones left out.
    pub(crate) roots: Vec<RootEntry>,
}

/// The `/merkle_proof` body.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct MerkleProof {
    /// The served root, which the path hashes to.
    pub(crate) root: [u8; 32],
    pub(crate) to_lez_block_id: u64,
    pub(crate) leaf_index: u64,
    /// The leaf: `poseidon(id_commitment, rate_limit)`, little-endian.
    pub(crate) rate_commitment: [u8; 32],
    /// Siblings, leaf level first; one per tree level.
    pub(crate) path_elements: Vec<[u8; 32]>,
    /// 1 where the node on the path is a right child; one per tree level.
    pub(crate) identity_path_index: Vec<u8>,
    pub(crate) status: Status,
}

/// A refusal: the HTTP status the indexer would answer (404 no leaf at that
/// index at the served root, 503 nothing to serve yet, 400 a bad request…)
/// and its `error` text.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct ZoneError {
    pub(crate) code: u32,
    pub(crate) error: String,
}

/// The `oneof result` of `ZoneQueryResponse`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Reply {
    Roots(Roots),
    MerkleProof(MerkleProof),
    Error(ZoneError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ZoneQueryResponse {
    pub(crate) request_id: String,
    pub(crate) reply: Reply,
}

// ---------------------------------------------------------------- low-level

fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let mut b = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            b |= 0x80;
        }
        out.push(b);
        if v == 0 {
            break;
        }
    }
}

fn put_len_field(out: &mut Vec<u8>, field: u64, data: &[u8]) {
    put_varint(out, (field << 3) | 2);
    put_varint(out, data.len() as u64);
    out.extend_from_slice(data);
}

fn put_varint_field(out: &mut Vec<u8>, field: u64, v: u64) {
    put_varint(out, field << 3);
    put_varint(out, v);
}

fn read_varint(buf: &[u8], i: &mut usize) -> Option<u64> {
    let mut result = 0u64;
    let mut shift = 0u32;
    loop {
        let b = *buf.get(*i)?;
        *i += 1;
        result |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            return Some(result);
        }
        shift += 7;
        if shift >= 64 {
            return None;
        }
    }
}

enum FieldVal<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
}

/// Walk varint (wire 0) and LEN (wire 2) fields — the only two this schema
/// uses. `f` sees each (field number, value) and may refuse it.
fn walk_fields<'a>(
    buf: &'a [u8],
    mut f: impl FnMut(u64, FieldVal<'a>) -> Result<(), String>,
) -> Result<(), String> {
    let mut i = 0usize;
    while i < buf.len() {
        let key = read_varint(buf, &mut i).ok_or("truncated field key")?;
        let field = key >> 3;
        match key & 7 {
            0 => {
                let v = read_varint(buf, &mut i).ok_or("truncated varint value")?;
                f(field, FieldVal::Varint(v))?;
            }
            2 => {
                let len = read_varint(buf, &mut i).ok_or("truncated length")? as usize;
                let end = i.checked_add(len).ok_or("length overflow")?;
                if end > buf.len() {
                    return Err("length exceeds buffer".into());
                }
                f(field, FieldVal::Bytes(&buf[i..end]))?;
                i = end;
            }
            w => return Err(format!("unsupported wire type {w}")),
        }
    }
    Ok(())
}

fn varint(v: FieldVal, what: &str) -> Result<u64, String> {
    match v {
        FieldVal::Varint(n) => Ok(n),
        FieldVal::Bytes(_) => Err(format!("{what}: expected a varint")),
    }
}

fn bytes<'a>(v: FieldVal<'a>, what: &str) -> Result<&'a [u8], String> {
    match v {
        FieldVal::Bytes(b) => Ok(b),
        FieldVal::Varint(_) => Err(format!("{what}: expected bytes")),
    }
}

fn bytes32(v: FieldVal, what: &str) -> Result<[u8; 32], String> {
    bytes(v, what)?
        .try_into()
        .map_err(|_| format!("{what}: expected 32 bytes"))
}

fn string(v: FieldVal, what: &str) -> Result<String, String> {
    String::from_utf8(bytes(v, what)?.to_vec()).map_err(|_| format!("{what}: not UTF-8"))
}

// ------------------------------------------------------------------ messages

fn sub(v: FieldVal, what: &str, f: impl FnMut(u64, FieldVal) -> Result<(), String>) -> Result<(), String> {
    walk_fields(bytes(v, what)?, f)
}

impl ServeAt {
    fn put(at: Option<Self>, out: &mut Vec<u8>, field: u64) {
        if let Some(at) = at {
            put_len_field(out, field, at.as_str().as_bytes());
        }
    }
}

impl ZoneQueryRequest {
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_len_field(&mut out, 1, self.request_id.as_bytes());
        put_len_field(&mut out, 2, &self.registry);
        let mut inner = Vec::new();
        match self.query {
            Query::Roots { window_size } => {
                put_varint_field(&mut inner, 1, u64::from(window_size));
                put_len_field(&mut out, 3, &inner);
            }
            Query::MerkleProof { leaf_index, at } => {
                put_varint_field(&mut inner, 1, leaf_index);
                ServeAt::put(at, &mut inner, 2);
                put_len_field(&mut out, 4, &inner);
            }
        }
        out
    }

    /// The service's side; the module only encodes.
    pub(crate) fn decode(buf: &[u8]) -> Result<Self, String> {
        let mut request_id = String::new();
        let mut registry = [0u8; 32];
        let mut query = None;
        walk_fields(buf, |field, v| {
            match field {
                1 => request_id = string(v, "request_id")?,
                2 => registry = bytes32(v, "registry")?,
                3 => {
                    let mut window_size = 0u64;
                    sub(v, "roots", |f, v| {
                        if f == 1 {
                            window_size = varint(v, "window_size")?;
                        }
                        Ok(())
                    })?;
                    let window_size = u32::try_from(window_size).map_err(|_| "window_size: out of range")?;
                    query = Some(Query::Roots { window_size });
                }
                4 => {
                    let (mut leaf_index, mut at) = (0u64, None);
                    sub(v, "merkle_proof", |f, v| {
                        match f {
                            1 => leaf_index = varint(v, "leaf_index")?,
                            2 => at = ServeAt::parse(&string(v, "at")?)?,
                            _ => {}
                        }
                        Ok(())
                    })?;
                    query = Some(Query::MerkleProof { leaf_index, at });
                }
                _ => {}
            }
            Ok(())
        })?;
        Ok(Self { request_id, registry, query: query.ok_or("no query")? })
    }
}

impl Status {
    /// `status` and `l1_slot` at fields `first` and `first + 1` of the
    /// enclosing message, as the indexer flattens them into it.
    fn put(&self, out: &mut Vec<u8>, first: u64) {
        put_len_field(out, first, self.status.as_bytes());
        if let Some(slot) = self.l1_slot {
            put_varint_field(out, first + 1, slot);
        }
    }

    fn take(&mut self, field: u64, first: u64, v: FieldVal) -> Result<bool, String> {
        if field == first {
            self.status = string(v, "status")?;
        } else if field == first + 1 {
            self.l1_slot = Some(varint(v, "l1_slot")?);
        } else {
            return Ok(false);
        }
        Ok(true)
    }
}

impl RootEntry {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_len_field(&mut out, 1, &self.root);
        put_varint_field(&mut out, 2, self.from_lez_block_id);
        put_varint_field(&mut out, 3, self.to_lez_block_id);
        put_varint_field(&mut out, 4, self.change_count);
        put_varint_field(&mut out, 5, self.published_at_unix);
        self.status.put(&mut out, 6);
        put_len_field(&mut out, 8, &self.tx_hash);
        put_len_field(&mut out, 9, &self.msg_id);
        out
    }

    fn decode(buf: &[u8]) -> Result<Self, String> {
        let mut m = Self::default();
        walk_fields(buf, |field, v| {
            match field {
                1 => m.root = bytes32(v, "root")?,
                2 => m.from_lez_block_id = varint(v, "from_lez_block_id")?,
                3 => m.to_lez_block_id = varint(v, "to_lez_block_id")?,
                4 => m.change_count = varint(v, "change_count")?,
                5 => m.published_at_unix = varint(v, "published_at_unix")?,
                8 => m.tx_hash = bytes(v, "tx_hash")?.to_vec(),
                9 => m.msg_id = bytes(v, "msg_id")?.to_vec(),
                f => {
                    m.status.take(f, 6, v)?;
                }
            }
            Ok(())
        })?;
        Ok(m)
    }
}

impl Roots {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_varint_field(&mut out, 1, self.latest_lez_block_id);
        put_varint_field(&mut out, 2, self.lez_timestamp_ms);
        put_varint_field(&mut out, 3, self.covered_to_lez_block_id);
        for r in &self.roots {
            put_len_field(&mut out, 4, &r.encode());
        }
        out
    }

    fn decode(buf: &[u8]) -> Result<Self, String> {
        let mut m = Self::default();
        walk_fields(buf, |field, v| {
            match field {
                1 => m.latest_lez_block_id = varint(v, "latest_lez_block_id")?,
                2 => m.lez_timestamp_ms = varint(v, "lez_timestamp_ms")?,
                3 => m.covered_to_lez_block_id = varint(v, "covered_to_lez_block_id")?,
                4 => m.roots.push(RootEntry::decode(bytes(v, "roots")?)?),
                _ => {}
            }
            Ok(())
        })?;
        Ok(m)
    }
}

impl MerkleProof {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_len_field(&mut out, 1, &self.root);
        put_varint_field(&mut out, 2, self.to_lez_block_id);
        put_varint_field(&mut out, 3, self.leaf_index);
        put_len_field(&mut out, 4, &self.rate_commitment);
        for e in &self.path_elements {
            put_len_field(&mut out, 5, e);
        }
        put_len_field(&mut out, 6, &self.identity_path_index);
        self.status.put(&mut out, 7);
        out
    }

    fn decode(buf: &[u8]) -> Result<Self, String> {
        let mut m = Self::default();
        walk_fields(buf, |field, v| {
            match field {
                1 => m.root = bytes32(v, "root")?,
                2 => m.to_lez_block_id = varint(v, "to_lez_block_id")?,
                3 => m.leaf_index = varint(v, "leaf_index")?,
                4 => m.rate_commitment = bytes32(v, "rate_commitment")?,
                5 => m.path_elements.push(bytes32(v, "path_elements")?),
                6 => m.identity_path_index = bytes(v, "identity_path_index")?.to_vec(),
                f => {
                    m.status.take(f, 7, v)?;
                }
            }
            Ok(())
        })?;
        Ok(m)
    }
}

impl ZoneError {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_varint_field(&mut out, 1, u64::from(self.code));
        put_len_field(&mut out, 2, self.error.as_bytes());
        out
    }

    fn decode(buf: &[u8]) -> Result<Self, String> {
        let mut m = Self::default();
        walk_fields(buf, |field, v| {
            match field {
                1 => m.code = u32::try_from(varint(v, "code")?).map_err(|_| "code: out of range".to_string())?,
                2 => m.error = string(v, "error")?,
                _ => {}
            }
            Ok(())
        })?;
        Ok(m)
    }
}

impl ZoneQueryResponse {
    /// The service's side; the module only decodes. Kept for the tests and
    /// as the executable half of the spec.
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_len_field(&mut out, 1, self.request_id.as_bytes());
        match &self.reply {
            Reply::Roots(r) => put_len_field(&mut out, 2, &r.encode()),
            Reply::MerkleProof(p) => put_len_field(&mut out, 3, &p.encode()),
            Reply::Error(e) => put_len_field(&mut out, 4, &e.encode()),
        }
        out
    }

    pub(crate) fn decode(buf: &[u8]) -> Result<Self, String> {
        let mut request_id = String::new();
        let mut reply = None;
        walk_fields(buf, |field, v| {
            match field {
                1 => request_id = string(v, "request_id")?,
                2 => reply = Some(Reply::Roots(Roots::decode(bytes(v, "roots")?)?)),
                3 => reply = Some(Reply::MerkleProof(MerkleProof::decode(bytes(v, "merkle_proof")?)?)),
                4 => reply = Some(Reply::Error(ZoneError::decode(bytes(v, "error")?)?)),
                _ => {}
            }
            Ok(())
        })?;
        Ok(Self { request_id, reply: reply.ok_or("no result")? })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(s: &str, l1_slot: Option<u64>) -> Status {
        Status { status: s.into(), l1_slot }
    }

    fn sample_proof() -> ZoneQueryResponse {
        ZoneQueryResponse {
            request_id: "zq-1".into(),
            reply: Reply::MerkleProof(MerkleProof {
                root: [0xAA; 32],
                to_lez_block_id: 55_801,
                leaf_index: 300,
                rate_commitment: [0x01; 32],
                path_elements: vec![[0x02; 32], [0x03; 32]],
                identity_path_index: vec![0, 1],
                status: status("head", None),
            }),
        }
    }

    fn sample_roots() -> ZoneQueryResponse {
        let entry = |root: u8, s: Status| RootEntry {
            root: [root; 32],
            from_lez_block_id: 49_431,
            to_lez_block_id: 55_502,
            change_count: 5,
            published_at_unix: 1_792_674_667,
            status: s,
            tx_hash: vec![0x66; 32],
            msg_id: vec![0xE0; 32],
        };
        ZoneQueryResponse {
            request_id: "zq-2".into(),
            reply: Reply::Roots(Roots {
                latest_lez_block_id: 55_594,
                lez_timestamp_ms: 1_792_676_126_847,
                covered_to_lez_block_id: 55_502,
                roots: vec![
                    entry(0xAA, status("pending", None)),
                    entry(0xBB, status("adopted", None)),
                    entry(0xCC, status("finalized", Some(0))),
                ],
            }),
        }
    }

    #[test]
    fn responses_round_trip() {
        let refused = ZoneQueryResponse {
            request_id: "zq-3".into(),
            reply: Reply::Error(ZoneError { code: 404, error: "no leaf at this index at the served root".into() }),
        };
        for r in [sample_proof(), sample_roots(), refused] {
            assert_eq!(ZoneQueryResponse::decode(&r.encode()).unwrap(), r);
        }
    }

    #[test]
    fn requests_round_trip() {
        for query in [
            Query::Roots { window_size: ROOTS_WINDOW },
            Query::MerkleProof { leaf_index: 0, at: None },
            Query::MerkleProof { leaf_index: 1023, at: Some(ServeAt::Finalized) },
            Query::MerkleProof { leaf_index: 7, at: Some(ServeAt::Head) },
        ] {
            let q = ZoneQueryRequest { request_id: "zq-4".into(), registry: [0x5A; 32], query };
            assert_eq!(ZoneQueryRequest::decode(&q.encode()).unwrap(), q);
        }
    }

    /// The bytes are what another implementation must produce and parse, so
    /// they are pinned as literals rather than re-derived.
    #[test]
    fn request_bytes_pin() {
        let head = |q: Query| {
            let mut expected = vec![0x0A, 0x01, b'a', 0x12, 0x20];
            expected.extend_from_slice(&[0x11; 32]);
            (ZoneQueryRequest { request_id: "a".into(), registry: [0x11; 32], query: q }.encode(), expected)
        };
        // roots (field 3) { window_size (field 1) = 5 }
        let (got, mut expected) = head(Query::Roots { window_size: 5 });
        expected.extend_from_slice(&[0x1A, 0x02, 0x08, 0x05]);
        assert_eq!(got, expected);
        // merkle_proof (field 4) { leaf_index (field 1) = 300 = 0xAC 0x02 }
        let (got, mut expected) = head(Query::MerkleProof { leaf_index: 300, at: None });
        expected.extend_from_slice(&[0x22, 0x03, 0x08, 0xAC, 0x02]);
        assert_eq!(got, expected);
        // leaf 0 is written, so the proof query is never an empty message.
        let (got, mut expected) = head(Query::MerkleProof { leaf_index: 0, at: None });
        expected.extend_from_slice(&[0x22, 0x02, 0x08, 0x00]);
        assert_eq!(got, expected);
        // ?at=finalized: at (field 2) = "finalized".
        let (got, mut expected) = head(Query::MerkleProof { leaf_index: 0, at: Some(ServeAt::Finalized) });
        expected.extend_from_slice(&[0x22, 0x0D, 0x08, 0x00, 0x12, 0x09]);
        expected.extend_from_slice(b"finalized");
        assert_eq!(got, expected);
    }

    #[test]
    fn response_bytes_pin() {
        // error (field 4) { code (field 1) = 503 = 0xF7 0x03, error (field 2) = "x" }
        let r = ZoneQueryResponse { request_id: "a".into(), reply: Reply::Error(ZoneError { code: 503, error: "x".into() }) };
        assert_eq!(r.encode(), vec![0x0A, 0x01, b'a', 0x22, 0x06, 0x08, 0xF7, 0x03, 0x12, 0x01, b'x']);
    }

    #[test]
    fn absent_integers_decode_as_zero() {
        // A proof of leaf 0 at block 0 with only its root: proto3 omits zeros.
        let mut inner = vec![0x0A, 0x20];
        inner.extend_from_slice(&[0x77; 32]);
        let mut buf = vec![0x1A, inner.len() as u8];
        buf.extend_from_slice(&inner);
        let Reply::MerkleProof(p) = ZoneQueryResponse::decode(&buf).unwrap().reply else { panic!("a proof") };
        assert_eq!((p.root, p.leaf_index, p.to_lez_block_id), ([0x77; 32], 0, 0));
        assert_eq!(p.status, Status::default(), "no l1_slot unless it is on the wire");
        // A finalized root at L1 slot 0 keeps its slot.
        let Reply::Roots(r) = ZoneQueryResponse::decode(&sample_roots().encode()).unwrap().reply else { panic!("roots") };
        assert_eq!(r.roots[2].status.l1_slot, Some(0));
        assert_eq!(r.roots[1].status.l1_slot, None);
    }

    #[test]
    fn malformed_frames_are_refused() {
        let good = sample_proof().encode();
        assert!(ZoneQueryResponse::decode(&good[..good.len() - 1]).is_err(), "truncated");
        assert!(ZoneQueryResponse::decode(&[0x0A, 0x01, b'a']).is_err(), "no result");
        // A proof root that is not 32 bytes.
        assert!(ZoneQueryResponse::decode(&[0x1A, 0x03, 0x0A, 0x01, 0x00]).is_err());
        // Wire type 5 (fixed32) is not part of the schema.
        assert!(ZoneQueryResponse::decode(&[0x15, 0, 0, 0, 0]).is_err());
        // A varint where a message belongs.
        assert!(ZoneQueryResponse::decode(&[0x10, 0x01]).is_err());
    }

    #[test]
    fn unknown_fields_are_skipped() {
        let mut buf = sample_proof().encode();
        put_varint_field(&mut buf, 99, 7);
        put_len_field(&mut buf, 98, b"future");
        assert_eq!(ZoneQueryResponse::decode(&buf).unwrap(), sample_proof());
    }
}
