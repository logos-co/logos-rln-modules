# logos-rln-data-service-module — working notes

- The staged SDK (`logos-rust-sdk-src/`) and the scaffold
  (`rust-lib/generated/provider_gen.rs`) are gitignored and come from
  `nix run .#generate`. Re-run it after any `flake.lock` or `.lidl` change
  (`rust-lib/liblogos_rln_data_service_module.lidl` or
  `rust-lib/deps/libp2p_module.lidl`); a stale stage fails `cargo --locked`.
- `rust-lib/src/zone_wire.rs` is a copy of
  `../logos-rln-module/rust-lib/src/zone_wire.rs` minus nine `#[cfg(test)]`
  gates (the request decoder and the response encoders) plus the header.
  A wire change lands in both files; both test modules pin the same bytes.
- `rust-lib/deps/libp2p_module.lidl` is a hand-written subset of
  libp2p_module 1.1.0 (it ships no lidl; the builder derives one from
  `plugin.h`). Every method takes one `tstr` and returns `result`; the JSON
  shapes are in the file's header comment.
- libp2p_module dispatches calls on one thread (builder default
  `concurrency: single`). Keep every timeout given to it short; the accept
  poll is 500 ms. The gifter module's one-hour accept is the anti-pattern.
- A worker thread may not create an SDK client. `lp::init_client` runs in
  `on_context_ready` (owner thread); the worker only calls
  `*_async_with_timeout` and waits on a channel.
