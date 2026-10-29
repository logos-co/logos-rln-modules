# logos-rln-data-service-module — the RLN data service

`liblogos_rln_data_service_module`, built on logos-rust-sdk /
logos-module-builder. One node per deployment runs it next to a membership
zone ([logos-rln-membership-zone](https://github.com/logos-co/logos-rln-membership-zone)'s
Zone indexer, reachable over HTTP) and serves the zone's roots and Merkle
proofs to every other node's `liblogos_rln_module` over libp2p: the
`/logos/rln/zone-query/1.0.0` protocol of
[`logos-rln-module/docs/zone-query.md`](../logos-rln-module/docs/zone-query.md),
mounted on `libp2p_module`'s custom-protocol bridge.

The module holds no tree. Each request is one libp2p exchange, answered from
the zone's JSON API (`GET /roots/{n}`, `GET /merkle_proof/{leaf_index}`),
translated field for field into the protobuf reply. The roots window is
cached for `roots_cache_ms` (every member polls it every 10 s); proofs are
never cached. A zone refusal passes through with its status code; a zone that
does not answer a usable body is a `502` to the member, a registry this
service does not serve a `404`, a frame that is not a request a `400`.

## Running it

Load `libp2p_module` (a declared dependency, installed and loaded with this
module) and this module, then:

```sh
logoscore call liblogos_rln_data_service_module start \
  '{"zone":{"url":"http://127.0.0.1:3000"},"listen":["/ip4/0.0.0.0/tcp/9100"]}'
# -> {"started":true,"peer_id":"16Uiu2…","multiaddrs":["/ip4/…/tcp/9100"],
#     "protocol":"/logos/rln/zone-query/1.0.0","zone_url":"http://127.0.0.1:3000"}
logoscore call liblogos_rln_data_service_module status
logoscore call liblogos_rln_data_service_module stop
```

`start`'s config (`{}` is allowed when the environment carries it):

| key | meaning |
|---|---|
| `zone.url` | the zone for every registry `registries` does not name; env `LOGOS_RLN_ZONE_URL` |
| `registries` | `{"<config account>": {"url": …}}` per registry, the account as hex or base58 |
| `listen` | `createNode` + `start` libp2p on these multiaddrs; env `LOGOS_RLN_DATA_SERVICE_LISTEN` (comma-separated). Absent: the node is someone else's to bring up, only `start` is called |
| `roots_cache_ms` | roots window cache, default 2000 |
| `max_request_bytes` | largest request frame read, default 4096 |

Members are told the reply's `peer_id` and one of its `multiaddrs`: the rln
module's `start()` `zone_service` (`{"peer_id":…,"multiaddrs":[…]}`), or its
daemon's `LOGOS_RLN_ZONE_PEER_ID` + `LOGOS_RLN_ZONE_MULTIADDR`. A member node
must have brought its own libp2p node up (`libp2p_module` `start`) before
its rln module dials.

`stop` stops answering; the protocol stays mounted (libp2p_module has no
unmount), so inbound streams queue — 1024 per protocol — and are then
dropped until the next `start`.

## Design constraints

- **libp2p_module serves every caller from one thread.** The accept poll
  waits 500 ms inside it and sleeps 100 ms between polls; every other call is
  capped at a few seconds. A long poll would stall every module on the node
  that uses libp2p.
- **One worker thread, one exchange at a time.** A zone read is capped at
  5 s; the member waits 20 s end to end. Nothing here runs on the host's Qt
  thread but the client's creation (`on_context_ready`).
- **Never close a stream from the server side.** Write, then
  `streamReleaseJson`; the dialer closes (the gifter's lesson).
- `rust-lib/src/zone_wire.rs` is a copy of the rln module's codec with the
  service side compiled in; both pin the same byte vectors. Keep them
  identical.

## Build

```sh
nix run .#generate          # stage the SDK + regenerate the scaffold (gitignored)
cd rust-lib && cargo test   # 17 tests, no network beyond loopback
nix build .#lgx             # the bundle; .#lgx-portable for another Linux box
```
