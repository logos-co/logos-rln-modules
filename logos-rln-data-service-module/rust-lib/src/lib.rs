//! liblogos_rln_data_service_module — the RLN data service.
//!
//! One node per deployment runs it next to a membership zone
//! (logos-rln-membership-zone's Zone indexer, reachable over HTTP) and serves
//! the zone's roots and Merkle proofs to every other node's
//! liblogos_rln_module over libp2p: the `/logos/rln/zone-query/1.0.0`
//! protocol of `logos-rln-module/docs/zone-query.md`, mounted on
//! libp2p_module's custom-protocol bridge. The module holds no tree: each
//! request is answered from the zone's JSON API, translated field for field
//! into the protobuf reply (`zone_http.rs` → `zone_wire.rs`), with a short
//! cache on the roots window (`server.rs`).
//!
//! Concurrency is "multi" (metadata.json): `status` answers while `start`
//! brings libp2p up. The serving itself is one worker thread (`server.rs`);
//! every libp2p_module call from it is the SDK's async twin with a channel
//! wait (`lp.rs`).

// `deny(unsafe_code)` everywhere but the generated scaffold's C-ABI surface.
#![deny(unsafe_code)]

use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

mod lp;
mod server;
mod zone_http;
mod zone_wire;

mod generated {
    #![allow(unsafe_code)]
    #![allow(dead_code)]
    #![allow(clippy::all)]
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/generated/provider_gen.rs"));
}
pub(crate) use generated::*;

/// A poisoned lock still holds consistent data for what this module keeps
/// (counters, a cache, the running flag): take it anyway.
pub(crate) fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Wall-clock UNIX seconds; a clock before the epoch reads as 0.
pub(crate) fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[derive(Default)]
pub struct LogosRlnDataServiceModuleImpl;

impl LiblogosRlnDataServiceModule for LogosRlnDataServiceModuleImpl {
    fn on_context_ready(&self, _ctx: &RustModuleContext) {
        // The libp2p_module client is made on this (the host's main Qt)
        // thread; the worker only calls through it.
        lp::init_client();
    }

    fn start(&self, config_json: String) -> Result<serde_json::Value, String> {
        server::start(&config_json)
    }

    fn stop(&self) -> Result<serde_json::Value, String> {
        server::stop()
    }

    fn status(&self) -> Result<serde_json::Value, String> {
        Ok(server::status())
    }
}

// The one `no_mangle` the scaffold contract requires of author code: the
// generated `__logos_install_hook` resolves this symbol by linkage.
#[allow(unsafe_code)]
#[no_mangle]
pub extern "Rust" fn logos_module_install() {
    install::<LogosRlnDataServiceModuleImpl>();
}
