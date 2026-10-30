# Zone query protocol — `/logos/rln/zone-query/1.0.0`

The RLN registration program on LEZ keeps no Merkle tree. It emits
`Registered`, `Extended`, `Slashed` and `Erased` events; the chain still
numbers registrations (the config's `next_leaf_index`, claimed by `Register`
and carried by `Registered` as `leaf_index`), but no account records a
member's index, so a **zone service** follows the events and maintains the
registry's depth-20 Poseidon tree. This document is the request/response
protocol `liblogos_rln_module` (0.15.0+) speaks to such a service. The client
is `rust-lib/src/zone.rs`; the codec, with byte-pinned tests, is
`rust-lib/src/zone_wire.rs`.

## Transport

The protocol is the protobuf messages below on a libp2p stream with protocol
id `/logos/rln/zone-query/1.0.0`. The membership module sends a request
through `libp2p_module`'s generic `protocolRequest` bridge (`{peerId,
multiaddrs, proto, requestB64, timeoutMs}` → `{responseB64}`), the same bridge
the RLN gifter uses, so the service side mounts the codec with
`mountProtocol` and answers with `protocolAcceptStream` / `streamReadLpJson` /
`streamWriteLpJson` or any equivalent length-prefixed exchange.

The messages are the Zone indexer's HTTP API
([logos-rln-membership-zone](https://github.com/logos-co/logos-rln-membership-zone),
`zone-sequencer/src/http.rs`) field for field, so one service handler can
answer both and the client judges both alike. For development the client can
reach that JSON API directly, at a base URL naming one registry (a reply is at
most 64 KiB). The tree is depth 20; 32-byte values are little-endian (hex
without `0x` in JSON, raw bytes in protobuf).

| | libp2p (`ZoneQueryRequest.query`) | HTTP (development) |
|---|---|---|
| roots | `roots { window_size }` | `GET <url>/roots/{window_size}` |
| proof | `merkle_proof { leaf_index, at }` | `GET <url>/merkle_proof/{leaf_index}[?at=head\|adopted\|finalized]` |
| answer | `roots` / `merkle_proof`, the body's fields | 200 + JSON body |
| refusal | `error { code, error }`, the same status and text | status + `{"error": text}` |

The client is configured with the service's peer id and multiaddrs, or its
URL: `start()`'s `zone_service` (`{"peer_id":…,"multiaddrs":[…]}` or
`{"url":"http(s)://…"}`, top-level or per registry entry; a URL wins when
both are given), else `LOGOS_RLN_ZONE_PEER_ID` + `LOGOS_RLN_ZONE_MULTIADDR`
(comma-separated) or `LOGOS_RLN_ZONE_URL` from the environment.

## Messages

Standard protobuf wire format (proto3 semantics). Integer fields may be
omitted when zero and are then read as zero; the client writes them
regardless. Unknown fields are skipped. Field names are the JSON keys.

```protobuf
message ZoneQueryRequest {
  string request_id = 1;  // echoed back unchanged
  bytes  registry   = 2;  // 32 bytes: the registry's config account id (HTTP: the URL)
  oneof query {
    RootsRequest       roots        = 3;  // GET /roots/{window_size}
    MerkleProofRequest merkle_proof = 4;  // GET /merkle_proof/{leaf_index}[?at=…]
  }
}

message RootsRequest {
  uint32 window_size = 1;  // the client asks 5
}

message MerkleProofRequest {
  uint64 leaf_index = 1;
  string at         = 2;  // "head" | "adopted" | "finalized"; absent = the
                          // service's default (the client always omits it)
}

message ZoneQueryResponse {
  string request_id = 1;
  oneof result {
    Roots       roots        = 2;  // the /roots body
    MerkleProof merkle_proof = 3;  // the /merkle_proof body
    Error       error        = 4;  // a non-2xx answer
  }
}

message Roots {
  uint64 latest_lez_block_id     = 1;
  uint64 lez_timestamp_ms        = 2;
  uint64 covered_to_lez_block_id = 3;
  repeated RootEntry roots       = 4;  // newest first, orphaned ones left out
}

message RootEntry {
  bytes  root              = 1;  // 32 bytes
  uint64 from_lez_block_id = 2;
  uint64 to_lez_block_id   = 3;
  uint64 change_count      = 4;
  uint64 published_at_unix = 5;
  string status            = 6;  // "pending" | "adopted" | "finalized"
  optional uint64 l1_slot  = 7;  // set when finalized
  bytes  tx_hash           = 8;
  bytes  msg_id            = 9;
}

message MerkleProof {
  bytes  root                = 1;  // 32 bytes: the served root, which the path hashes to
  uint64 to_lez_block_id     = 2;
  uint64 leaf_index          = 3;
  bytes  rate_commitment     = 4;  // 32 bytes: the leaf
  repeated bytes path_elements = 5;  // 32 bytes each, leaf level first
  bytes  identity_path_index = 6;  // one byte per level: 1 = node is a right child
  string status              = 7;  // the served root's: as RootEntry's, or "head"
  optional uint64 l1_slot    = 8;
}

message Error {
  uint32 code  = 1;  // the HTTP status: 404, 503, 400…
  string error = 2;  // the JSON body's "error"
}
```

`registry` is the anchor of a `logos` CAIP-10 registry id
(`logos:<network>:<config account hex>`), not the tree id: the client knows the
former, and the service maps it to the tree it follows (the config account is
the registration program's PDA of `["config", tree_id]`). Over HTTP the base
URL names the registry instead.

## Service obligations

- **Leaves.** A `Registered` event's `leaf_index` is the member's leaf
  (consecutive per registry: 0, 1, 2… in block order), holding
  `poseidon(id_commitment, rate_limit)` as a little-endian BN254 field
  element. An index is never reused. A `Slashed`/`Erased` member, or one
  whose `expiry_timestamp_ms` has passed, is removed (the zero leaf).
- **Roots.** The newest published roots, one entry per distinct root, newest
  first, at most `window_size` of them, orphaned ones left out; `status` says
  how settled each batch is on Bedrock. Once the service has caught up, the
  head root is listed, so a validator holds the root a fresh proof is at.
- **Merkle proof.** The path of `leaf_index` at the served root: the tree at
  the LEZ head. `rate_commitment` is the leaf; the path's length is the
  tree's depth. Over HTTP the body is the membership's record at the head
  (`active`, `removed` `null|expired|slashed|erased`, `expiry_timestamp_ms`,
  `id_commitment`, `lez_block_id`, `newest_adopted` / `newest_finalized`) with
  the path's three fields under `proof`; `proof` is `null` for a removed leaf,
  which the client reads as a 404 naming the `removed` cause. The client also
  reads the older body with the path's fields at the top level and the block
  as `to_lez_block_id`.
- **Refusals.** `404` when the served root has no leaf at that index (or no
  such membership), `503` when there is nothing to serve at the requested
  point, `400` for a bad `at` or leaf; `error` carries the text.

## Client behaviour

- A response is rejected (provider failure) if its `request_id` differs or it
  answers the other question. An `error` with code 404 or 503 is
  `not_ready` (most often a registration not in a served root yet); any
  other code is a provider failure.
- **Valid roots**: one roots request with `window_size = 5`; the window is
  every listed non-zero root, whatever its `status`; none is `not_ready`.
  Roots beyond `window_size` are dropped.
- **Proof**: one proof request at the service's default root. Rejected unless
  it is of the asked leaf, its path is 1..=20 levels with one 0/1 bit each; a
  zero `rate_commitment` is `unknown_membership`, and one that is not the
  membership's own `poseidon(id_commitment, rate_limit)` is refused before its
  path is cached. The proof's root is admitted at the front of the
  valid-root window, so the node can validate a proof it just generated.
- **Leaf index**: not asked of the service. `liblogos_lez_rln_module` sent the
  registration and recorded the `leaf_index` it claimed (a send that loses
  the index to a registration landing first reverts with `StaleLeafIndex` and
  is re-sent with the next); its `get_membership` answers the claim of the
  send that landed.

## Open items for the service

What the module side is ready for and the service does not do yet.

- **The libp2p transport** is mounted by `liblogos_rln_data_service_module`
  (`logos-rln-data-service-module/`), not by the service: one node per
  deployment runs it next to the zone and answers
  `/logos/rln/zone-query/1.0.0` from the zone's JSON API (the HTTP mapping
  above, folding `proof` into the flat `MerkleProof`), with the roots window
  cached for a couple of seconds. Members are told its `peer_id` and
  `multiaddrs` (`start()`'s reply) through `zone_service` or
  `LOGOS_RLN_ZONE_PEER_ID` + `LOGOS_RLN_ZONE_MULTIADDR`. A service that
  mounts the protocol itself would make that node unnecessary.
- **An indexer-only mode.** Running with no Bedrock node: follow a LEZ
  sequencer, serve the head as `/roots` entry 0 with status `head`, publish
  nothing. The only way to run the service beside a local sequencer in an e2e.
- **Several registries.** The request's `registry` (config account) has no
  HTTP counterpart: a service for more than one registry needs it in the path,
  or a `404` when it is not the one served.
- **Privacy-preserving transactions.** The reader hand-decodes `getBlockRange`
  bodies and stops at the first `LeeTransaction::PrivacyPreserving` (tag 1),
  whose layout it does not know, so it cannot read past that block (testnet
  block 61148, 2026-10-29) and never publishes again. Decode the block with
  the LEZ crates' borsh types, or skip a transaction by a length the
  sequencer serves.
- **A wire version.** A body-shape change is a wire change for every reader:
  a `version` field in the `/` summary, or a path prefix (`/v1/…`), would let
  a module refuse an unknown shape with a clear message instead of a field
  error.
- Smaller: `identity_path_index` as a hex string like the other byte fields
  would be uniform (today a JSON array of 0/1); the summary's `endpoints` list
  is useful, keep it.
