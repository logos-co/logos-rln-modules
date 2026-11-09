//! liblogos_rln_module — the RLN Module.
//!
//! Implements the RLN Module API (RLN-API) and the RLN-MEMBERSHIP-MANAGEMENT
//! spec (logos-lips docs/anoncomms/raw/): registry-agnostic membership
//! management — with the identity credential generated IN-MODULE at register
//! and never released — plus RLN rate limiting: proof generation over the
//! encrypted credential and hot-path verification from a locally maintained
//! valid-root window. Every call is scoped by (registry_id, rln_identifier).
//!
//! Architecture (spec concept → crate):
//! - registry_id (CAIP-10) parse/canonicalize/route → `registry_id.rs`
//! - storage backend → `sealed_store/` (the sealed keystore: crypto,
//!   on-disk format, durable files, runtime Store with persist-before-issue
//!   message_id reservation) and `lifecycle.rs` (the state machine, merged
//!   view)
//! - registry provider → `provider.rs` (trait + the lez-rln provider over
//!   the SDK's generated client of the liblogos_lez_rln_module; also
//!   the gifter client for delegated registration)
//! - Pending confirmation window + involuntary-removal detection →
//!   `poller.rs` (a `worker.rs`-supervised worker)
//! - selection (per-scope RoundRobin etc.; public view only) → `select.rs`
//! - proof engine (zerokit, witness assembly, canonical RateLimitProof,
//!   in-module identity generation) → `proof.rs`
//! - epoch + message_id allocation → `rate_limit.rs`
//! - valid-root window (no registry access on the verify path) → `roots.rs`
//! - per-membership Merkle proof-path cache (background-maintained, no
//!   registry access on `generate_proof`'s hot path) → `path_cache.rs`
//! - method bodies → `membership_api.rs` (state, selection, listing,
//!   `ensure_membership`), `register.rs` (registration and its submit
//!   callbacks), `proof_api.rs` (rate limiting); scope parsing and resolution
//!   → `scope.rs`; delegated-registration options → `delegated.rs`;
//!   `start()`'s configuration in force → `config.rs`
//!
//! Wire conventions: every method returns a compact JSON object (serde_json
//! ⇒ alphabetical keys); failures are
//! `{"error":{"class":…,"kind":…,"message":…}}` — consumers switch on
//! `class` (see `ErrorKind::class`) and log `kind`. The lez
//! module's ""-on-error convention is not used here.
//!
//! Concurrency is "multi" (metadata.json): handlers take `&self` and
//! overlap, so one call blocked in a registry read (the register bounds
//! pre-check, get_membership_state, get_merkle_proof, get_valid_roots — up
//! to ~70s) does not serialize the rest. Registration itself stays
//! fire-and-record (the SDK's async twin); the poller thread does the
//! periodic reads.

// Author code is unsafe-free: every outbound call goes through the SDK's
// safe surface (`modules()`, `PluginProxy`). Three sites are exempted from
// `deny(unsafe_code)`, all C-ABI boundaries rather than logic: the generated
// module-impl scaffold, the panic-hook install it wraps, and the test-only
// link stubs that stand in for the host's `lp_*` symbols.
#![deny(unsafe_code)]

use std::sync::{Arc, Mutex};

mod config;
mod delegated;
mod ensure;
mod error;
mod keychain;
mod lifecycle;
mod membership_api;
mod nullifier_log;
mod panic_hook;
mod path_cache;
mod poller;
mod proof;
mod proof_api;
mod provider;
mod rate_limit;
mod register;
mod registry_id;
mod roots;
mod scope;
mod sealed_store;
mod select;
#[cfg(test)]
mod test_support;
mod tree;
mod util;
mod views;
mod wallet_home;
mod worker;

mod generated {
    #![allow(warnings)]
    #![allow(clippy::all)]
    #![allow(unsafe_code)]
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/generated/provider_gen.rs"
    ));
}
use generated::*;
pub(crate) use util::lock;

use config::{
    epoch_binding_warning, ModuleConfig, RegistryConfig, DEFAULT_MAX_EPOCH_GAP, DEFAULT_RATE_LIMIT,
};
use delegated::DelegatedOptions;
use error::{ApiError, ErrorKind};
use membership_api::{
    ensure_membership_impl, get_membership_state_impl, get_memberships_impl, select_membership_impl,
};
use proof_api::{
    generate_proof_impl, generate_proof_with, get_epoch_quota_impl, get_registry_parameters_impl,
    validate_proof_impl, validate_proof_with, SignalArg,
};
use register::register_impl;
use scope::{backend_of, parse_registry};
use sealed_store::store::Store;
use zeroize::Zeroize;

// -------------------------------------------------------------------- errors

/// Flatten a handler result into the wire string (the tstr-method dialect):
/// the Ok value, or the in-band {"error":{…}} envelope.
pub(crate) fn reply(result: Result<serde_json::Value, ApiError>) -> String {
    match result {
        Ok(value) => value.to_string(),
        Err(e) => e.to_json(),
    }
}

/// Flatten a handler result into a `-> result` (LogosResult) return: the
/// generated dispatch wraps Ok into {"success":true,"value":…} and Err into
/// {"success":false,"error":<this string>}, so the error string is the
/// JSON-encoded typed object {"class":…,"kind":…,"message":…}.
pub(crate) fn reply_result(
    result: Result<serde_json::Value, ApiError>,
) -> Result<serde_json::Value, String> {
    result.map_err(|e| e.body().to_string())
}

/// Serialize a typed reply view (`views.rs`) into its wire `Value`.
fn ok_json<T: serde::Serialize>(v: T) -> Result<serde_json::Value, ApiError> {
    serde_json::to_value(v).map_err(|e| ApiError::internal(format!("serialize reply: {e}")))
}

/// start/stop bodies span several supervisor critical sections; interleaving
/// two of them can strand freshly spawned workers behind a stop's generation
/// bump. Neither is a hot path.
// OWNERSHIP: a unit token serializing start and stop across handler threads.
static LIFECYCLE: Mutex<()> = Mutex::new(());

/// Spec start(): apply configuration, warm the configured registries' root
/// windows, begin maintenance, and clear any prior stop(). Idempotent —
/// safe to call again to reconfigure. config_json:
/// {"epoch_size_sec":N (required — the instance default), "max_epoch_gap"?:N,
/// "rate_limit"?:N, "provision"?:bool, "registries"?:[<entry>,…]} where an
/// entry is a CAIP-10 string, or an object {"registry_id":caip10,
/// "epoch_size_sec"?:N, "max_epoch_gap"?:N, "rate_limit"?:N}.
///
/// A call sets the registries it names and leaves every other registry's
/// configuration in force: an object entry sets its registry's values
/// (absent fields take this call's defaults); a plain string pins this
/// call's defaults for a registry nothing has configured yet and leaves a
/// configured one alone. The instance defaults apply to registries no call
/// has named. Two consumers sharing this instance — delivery naming its
/// registry, a host naming the mix registry at its own epoch — therefore
/// never undo each other.
fn start_impl(config_json: &str) -> Result<serde_json::Value, ApiError> {
    let _lifecycle = lock(&LIFECYCLE);
    panic_hook::install_once();
    let cfg: serde_json::Value = if config_json.trim().is_empty() {
        serde_json::json!({})
    } else {
        serde_json::from_str(config_json)
            .map_err(|e| ApiError::new(ErrorKind::InvalidArgument, format!("config_json: {e}")))?
    };

    let epoch_size_sec = cfg
        .get("epoch_size_sec")
        .and_then(|x| x.as_u64())
        .filter(|n| *n > 0)
        .ok_or_else(|| {
            ApiError::new(
                ErrorKind::InvalidArgument,
                "config_json.epoch_size_sec is required (a positive integer all \
                 validators of the application share)",
            )
        })?;
    let max_epoch_gap = cfg
        .get("max_epoch_gap")
        .and_then(|x| x.as_u64())
        .filter(|n| *n > 0)
        .unwrap_or(DEFAULT_MAX_EPOCH_GAP);

    // The rate a provisioned membership asks for. The registry declares no
    // default yet, so this is the module's, and a caller that wants another
    // says so here rather than registering by hand.
    let default_rate = cfg
        .get("rate_limit")
        .and_then(serde_json::Value::as_u64)
        .filter(|n| *n > 0)
        .unwrap_or(DEFAULT_RATE_LIMIT);
    // The allocator provisioning asks first (the RLN Membership Allocation
    // Protocol), for every registry this call names unless an entry carries
    // its own block (or `null`, which opts that registry out). Without one,
    // provisioning is the funded registration alone.
    let default_allocator =
        DelegatedOptions::from_allocator_block(cfg.get("allocator"), "config_json.allocator")?;

    // Merge into the table in force; unparseable entries are skipped.
    let (mut registries, mut per_registry) = config::registries_snapshot();
    let mut track = |raw: &str, set: Option<RegistryConfig>| {
        if let Ok(registry) = registry_id::parse(raw) {
            roots::track(&registry);
            match set {
                Some(c) => {
                    // OWNERSHIP: the map key and the `registries` list each own the id.
                    per_registry.insert(registry.canonical.clone(), c);
                }
                None => {
                    // OWNERSHIP: the map key and the `registries` list each own the
                    // id; every registry's config owns its copy of the default.
                    per_registry
                        .entry(registry.canonical.clone())
                        .or_insert(RegistryConfig {
                            epoch_size_sec,
                            max_epoch_gap,
                            rate_limit: default_rate,
                            allocator: default_allocator.clone(),
                        });
                }
            }
            if !registries.contains(&registry.canonical) {
                registries.push(registry.canonical);
            }
        }
    };
    if let Some(arr) = cfg.get("registries").and_then(|x| x.as_array()) {
        for entry in arr {
            match entry {
                serde_json::Value::String(raw) => track(raw, None),
                serde_json::Value::Object(o) => {
                    let raw = o
                        .get("registry_id")
                        .and_then(|x| x.as_str())
                        .unwrap_or_default();
                    let positive =
                        |key: &str| o.get(key).and_then(|x| x.as_u64()).filter(|n| *n > 0);
                    // An entry's own block wins; an explicit null opts out.
                    let allocator = match o.get("allocator") {
                        // OWNERSHIP: every registry's config owns its copy of the default.
                        None => default_allocator.clone(),
                        Some(v) => DelegatedOptions::from_allocator_block(
                            Some(v),
                            &format!("registries[{raw}].allocator"),
                        )?,
                    };
                    let set = RegistryConfig {
                        epoch_size_sec: positive("epoch_size_sec").unwrap_or(epoch_size_sec),
                        max_epoch_gap: positive("max_epoch_gap").unwrap_or(max_epoch_gap),
                        rate_limit: positive("rate_limit").unwrap_or(default_rate),
                        allocator,
                    };
                    track(raw, Some(set));
                }
                _ => {}
            }
        }
    }

    let overrides_view = (!per_registry.is_empty())
        .then(|| serde_json::to_value(&per_registry).unwrap_or(serde_json::Value::Null));
    // A membership bound to a DIFFERENT epoch size than its registry's can no
    // longer generate proofs; surface that at configure time. Warn-only —
    // rejecting start() would DoS validate_proof for every scope over one
    // stale local membership.
    if let Some(store) = sealed_store::store::current() {
        for (hash, registry, bound) in store.epoch_size_bindings() {
            let canonical = registry_id::parse(&registry)
                .map(|r| r.canonical)
                .unwrap_or(registry);
            let configured = per_registry
                .get(&canonical)
                .map(|c| c.epoch_size_sec)
                .unwrap_or(epoch_size_sec);
            if bound != 0 && bound != configured {
                eprintln!(
                    "{}",
                    epoch_binding_warning(&hash, &canonical, bound, configured)
                );
            }
        }
    }
    // Permit + (re)spawn the maintenance workers, and warm the tracked
    // registries' root windows and every usable membership's Merkle path in
    // the background — must not block start() itself.
    let warm_roots = !registries.is_empty();
    // Provisioning rides the same one-shot pass, after the warm-up: it may
    // wait minutes for a wallet and for funding, and start() must not.
    // Opt out with {"provision": false}; on by default because a config that
    // names registries is a node that intends to prove against them, and
    // every attempt is idempotent per scope. Nothing is spent when no call
    // named a registry. Every registry in force is passed, not only this
    // call's: a membership already present stands the pass down at once, so
    // a reconfigure never abandons another consumer's registry.
    let provision = cfg
        .get("provision")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(true);
    let provision_registries: Vec<ensure::Provision> = if provision {
        registries
            .iter()
            .map(|r| {
                let c = per_registry.get(r);
                // OWNERSHIP: the pass moves into the worker thread's closure;
                // config::install keeps the originals.
                ensure::Provision {
                    registry: r.clone(),
                    rate_limit: c.map(|c| c.rate_limit).unwrap_or(default_rate),
                    allocator: c.and_then(|c| c.allocator.clone()),
                }
            })
            .collect()
    } else {
        Vec::new()
    };
    // OWNERSHIP: moved into the worker thread's closure; config::install takes the original.
    let selection_order = registries.clone();
    // Serialized before `install` takes the list; returned after every effect below.
    let reply = ok_json(views::StartReply::new(
        epoch_size_sec,
        max_epoch_gap,
        overrides_view,
        &registries,
    ));
    config::install(ModuleConfig {
        epoch_size_sec,
        max_epoch_gap,
        registries,
        per_registry,
    });
    // Every pass in flight ends here, provisioning or not: a start that turns
    // provisioning off must not leave an earlier pass funding and registering
    // at a configuration it replaced.
    let ticket = ensure::supersede();
    worker::start(
        move || {
            // First, before anything reaches the registry module: the first
            // `logos` registry id is what binds its wallet to a network when
            // nothing else configured one, and that must be the first one
            // configured, not whichever the warm-up happens to reach first.
            provider::select_networks(&selection_order);
            if warm_roots {
                roots::refresh_all();
            }
            poller::refresh_paths();
            if !provision_registries.is_empty() {
                ensure::run_with(provision_registries, ticket);
            }
        },
        &[poller::ensure_running, roots::ensure_refresher],
    );

    reply
}

/// Spec stop(): halt the maintenance tasks. Sleeping workers are joined
/// within a short grace; a worker blocked in an in-flight registry read
/// (≤80s) is DETACHED — it performs at most that one read, observes it is
/// superseded, and exits. Nothing spawns again until the next start(); the
/// supervisor's generation counter keeps a detached straggler from ever
/// duplicating a worker.
fn stop_impl() -> Result<serde_json::Value, ApiError> {
    let _lifecycle = lock(&LIFECYCLE);
    worker::stop();
    // A pass blocked in a registry read outlives the stop; the next start()
    // clears the stopped flag, so the ticket is what ends it.
    ensure::supersede();
    ok_json(views::StopReply::new())
}

// -------------------------------------------------------------------- module

/// The module instance. Stateless: concurrency:"multi" dispatch shares it as
/// Arc<Self> and every handler takes &self; the store lives in
/// `sealed_store::store`'s one current-store cell. Braced, not a unit struct:
/// the generated loader and the tests construct it through `Default`.
#[derive(Default)]
struct LogosRlnModuleImpl {}

impl LogosRlnModuleImpl {
    /// The open store (cloned out), or `internal` naming why there is none.
    // OWNERSHIP: a handle cloned out of the cell, so no lock spans the handler.
    fn store(&self) -> Result<Arc<Store>, ApiError> {
        sealed_store::store::current_or_cause()
    }
}

impl LiblogosRlnModule for LogosRlnModuleImpl {
    fn on_context_ready(&self, ctx: &RustModuleContext) {
        panic_hook::install_once();
        // The lp client to the lez module must be created on this
        // (the host's main Qt) thread — see provider.rs.
        provider::init_client();
        if ctx.instance_persistence_path.is_empty() {
            // No cwd fallback: a keystore in an unknown directory is worse
            // than a hard error at the first keystore op (see README).
            eprintln!(
                "membership module: host provided no instance_persistence_path — keystore ops will fail"
            );
            sealed_store::store::close_current(
                "no instance persistence path from the host — keystore ops are \
                 disabled (no silent cwd fallback; see README)"
                    .to_string(),
            );
        } else {
            sealed_store::store::open_current(std::path::PathBuf::from(
                &ctx.instance_persistence_path,
            ));
            // Resume confirmation polling for records that were pending at
            // the last shutdown. The handle is cloned out: the auto-unlock
            // reads the current store itself.
            if let Some(store) = sealed_store::store::current() {
                if store.has_pending() {
                    poller::ensure_running();
                }
                keychain::lazy_auto_unlock();
            }
        }
    }

    fn unlock_keystore(&self, mut password: String) -> String {
        let result = self
            .store()
            .and_then(|s| s.unlock(&password))
            .and_then(|count| ok_json(views::UnlockKeystoreReply::new(count as u64)));
        password.zeroize();
        reply(result)
    }

    fn lock_keystore(&self) -> String {
        reply(self.store().map(|s| {
            s.lock();
            serde_json::json!({ "locked": true })
        }))
    }

    fn provision_wallet_home(&self, options_json: String) -> String {
        reply(wallet_home::provision_impl(&options_json))
    }

    fn unlock_keystore_auto(&self) -> String {
        reply(keychain::auto_unlock_impl())
    }

    fn remember_keystore_password(&self) -> String {
        reply(keychain::remember_impl())
    }

    fn register_membership(
        &self,
        registry_id: String,
        rln_identifier_hex: String,
        options_json: String,
    ) -> String {
        reply(register_impl(
            self.store(),
            &registry_id,
            &rln_identifier_hex,
            &options_json,
        ))
    }

    fn ensure_membership(&self, registry_id: String, options_json: String) -> String {
        reply(ensure_membership_impl(
            self.store(),
            &registry_id,
            &options_json,
        ))
    }

    fn get_membership_state(&self, registry_id: String, rln_identifier_hex: String) -> String {
        reply(get_membership_state_impl(
            self.store(),
            &registry_id,
            &rln_identifier_hex,
        ))
    }

    fn get_memberships(&self, registry_id: String) -> String {
        reply(get_memberships_impl(self.store(), &registry_id))
    }

    fn select_membership(
        &self,
        registry_id: String,
        rln_identifier_hex: String,
        selector_json: String,
    ) -> String {
        reply(select_membership_impl(
            self.store(),
            &registry_id,
            &rln_identifier_hex,
            &selector_json,
        ))
    }

    fn get_merkle_proof(&self, registry_id: String, leaf_index: i64) -> String {
        reply((|| {
            let registry = parse_registry(&registry_id)?;
            let backend = backend_of(&registry)?;
            if leaf_index < 0 {
                return Err(ApiError::new(
                    ErrorKind::InvalidArgument,
                    "leaf_index must be non-negative",
                ));
            }
            Ok(backend
                .tree
                .merkle_proof(&registry, leaf_index as u64)?
                .to_wire())
        })())
    }

    fn get_valid_roots(&self, registry_id: String) -> String {
        reply((|| {
            let registry = parse_registry(&registry_id)?;
            let backend = backend_of(&registry)?;
            let roots: Vec<String> = backend
                .tree
                .valid_roots(&registry)?
                .lifted()
                .iter()
                .map(|r| registry_id::bytes_to_hex(r))
                .collect();
            Ok(serde_json::json!({ "valid_roots": roots }))
        })())
    }

    fn generate_proof(
        &self,
        registry_id: String,
        rln_identifier_hex: String,
        signal_hex: String,
        timestamp: String,
    ) -> Result<serde_json::Value, String> {
        reply_result(generate_proof_impl(
            self.store(),
            &registry_id,
            &rln_identifier_hex,
            &signal_hex,
            &timestamp,
        ))
    }

    fn validate_proof(
        &self,
        registry_id: String,
        rln_identifier_hex: String,
        signal_hex: String,
        timestamp: String,
        proof_json: String,
    ) -> Result<serde_json::Value, String> {
        reply_result(validate_proof_impl(
            &registry_id,
            &rln_identifier_hex,
            &signal_hex,
            &timestamp,
            &proof_json,
        ))
    }

    fn generate_proof_prehashed(
        &self,
        registry_id: String,
        rln_identifier_hex: String,
        signal_hash_hex: String,
        timestamp: String,
    ) -> Result<serde_json::Value, String> {
        reply_result(generate_proof_with(
            self.store(),
            &registry_id,
            &rln_identifier_hex,
            SignalArg::Prehashed(&signal_hash_hex),
            &timestamp,
        ))
    }

    fn validate_proof_prehashed(
        &self,
        registry_id: String,
        rln_identifier_hex: String,
        signal_hash_hex: String,
        timestamp: String,
        proof_json: String,
    ) -> Result<serde_json::Value, String> {
        reply_result(validate_proof_with(
            &registry_id,
            &rln_identifier_hex,
            SignalArg::Prehashed(&signal_hash_hex),
            &timestamp,
            &proof_json,
        ))
    }

    fn get_epoch_quota(
        &self,
        registry_id: String,
        rln_identifier_hex: String,
        timestamp: String,
    ) -> Result<serde_json::Value, String> {
        reply_result(get_epoch_quota_impl(
            self.store(),
            &registry_id,
            &rln_identifier_hex,
            &timestamp,
        ))
    }

    fn get_registry_parameters(
        &self,
        registry_id: String,
        rln_identifier_hex: String,
    ) -> Result<serde_json::Value, String> {
        reply_result(get_registry_parameters_impl(
            &registry_id,
            &rln_identifier_hex,
        ))
    }

    fn start(&self, config_json: String) -> Result<serde_json::Value, String> {
        reply_result(start_impl(&config_json))
    }

    fn stop(&self) -> Result<serde_json::Value, String> {
        reply_result(stop_impl())
    }
}

// The one `no_mangle` the scaffold contract requires of author code: the
// generated `__logos_install_hook` resolves this symbol by linkage.
#[allow(unsafe_code)]
#[no_mangle]
pub extern "Rust" fn logos_module_install() {
    install::<LogosRlnModuleImpl>();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{allocator_for, epoch_params_for, reset_config_for_test};
    use crate::register::parse_registry_options;
    use crate::test_support::TEST_GLOBAL_LOCK;

    // Pins the error envelope's byte shape (alphabetical keys), including
    // the coarse RLN-API class.
    #[test]
    fn error_envelope_shape() {
        let e = ApiError::new(ErrorKind::UnknownRegistry, "no provider for namespace");
        assert_eq!(
            e.to_json(),
            r#"{"error":{"class":"permanent","kind":"unknown_registry","message":"no provider for namespace"}}"#
        );
        // The quartet mapping the shim relies on.
        assert_eq!(ErrorKind::Locked.class(), "not_ready");
        assert_eq!(ErrorKind::NotReady.class(), "not_ready");
        assert_eq!(ErrorKind::ProviderFailure.class(), "transient");
        assert_eq!(ErrorKind::BudgetExhausted.class(), "budget_exhausted");
        assert_eq!(ErrorKind::InvalidArgument.class(), "permanent");
    }

    // The `-> result` dialect: the generated dispatch wraps Ok/Err into the
    // LogosResult envelope, and the Err string is the JSON-encoded typed
    // error object.
    #[test]
    fn result_dialect_error_carries_typed_body() {
        // stop() tears down the global worker supervisor; serialize with the
        // other global-state tests and reset it after.
        let _serial = crate::lock(&TEST_GLOBAL_LOCK);
        let imp = LogosRlnModuleImpl::default();
        let err = imp
            .validate_proof(
                "not-caip10".into(),
                "ef".repeat(32),
                "00".into(),
                "0".into(),
                "{}".into(),
            )
            .unwrap_err();
        assert_eq!(
            err,
            r#"{"class":"permanent","kind":"invalid_argument","message":"registry_id must be namespace:reference:account_address (CAIP-10), got 1 segment(s)"}"#
        );
        let ok = imp.stop().unwrap();
        assert_eq!(ok, serde_json::json!({ "stopped": true }));
        worker::reset_for_test();
    }

    #[test]
    fn start_configures_epoch_and_stop_tears_down() {
        // CONFIG is process-global; serialize with the other tests that read
        // or write it (the store lock is the crate's global-state lock).
        let _serial = crate::lock(&TEST_GLOBAL_LOCK);
        let out = start_impl(r#"{"epoch_size_sec": 600, "max_epoch_gap": 3}"#).unwrap();
        assert_eq!(out["started"], serde_json::json!(true));
        assert_eq!(out["epoch_size_sec"], serde_json::json!(600));
        assert_eq!(out["max_epoch_gap"], serde_json::json!(3));
        assert_eq!(epoch_params_for("").unwrap(), (600, 3));
        assert!(!worker::is_stopped());

        let out = stop_impl().unwrap();
        assert_eq!(out["stopped"], serde_json::json!(true));
        assert!(worker::is_stopped());

        // The gap defaults when omitted; the epoch size is required.
        let out = start_impl(r#"{"epoch_size_sec": 600}"#).unwrap();
        assert!(!worker::is_stopped());
        assert_eq!(out["epoch_size_sec"], serde_json::json!(600));
        assert_eq!(
            out["max_epoch_gap"],
            serde_json::json!(DEFAULT_MAX_EPOCH_GAP)
        );
        let err = start_impl(r#"{"max_epoch_gap": 2}"#).unwrap_err();
        assert_eq!(err.kind, ErrorKind::InvalidArgument);
        assert!(
            err.message.contains("epoch_size_sec"),
            "got: {}",
            err.message
        );
    }

    // Spec: epoch size and max gap are per-REGISTRY configuration — an
    // object registries entry sets them, a plain string takes the call's
    // defaults; the reply's overrides object is the table in force.
    #[test]
    fn start_per_registry_overrides_select_epoch_config() {
        let _serial = crate::lock(&TEST_GLOBAL_LOCK);
        reset_config_for_test();
        let reg_a = format!("logos:local:{}", "ab".repeat(32));
        let reg_b = format!("logos:local:{}", "cd".repeat(32));
        let cfg = serde_json::json!({
            "epoch_size_sec": 600,
            "max_epoch_gap": 2,
            "registries": [
                reg_a,
                {"registry_id": reg_b, "epoch_size_sec": 60, "max_epoch_gap": 5},
            ],
        })
        .to_string();
        let out = start_impl(&cfg).unwrap();
        // Exact wire shape: sorted keys, both values always present.
        assert_eq!(
            out["overrides"].to_string(),
            format!(
                r#"{{"{reg_a}":{{"epoch_size_sec":600,"max_epoch_gap":2}},"{reg_b}":{{"epoch_size_sec":60,"max_epoch_gap":5}}}}"#
            ),
            "got: {out}"
        );
        assert_eq!(out["registries"], serde_json::json!([reg_a, reg_b]));
        assert_eq!(epoch_params_for(&reg_a).unwrap(), (600, 2));
        assert_eq!(epoch_params_for(&reg_b).unwrap(), (60, 5));
        // A registry no call named takes the instance defaults.
        assert_eq!(epoch_params_for("logos:local:other").unwrap(), (600, 2));

        // No registries at all: no overrides key.
        reset_config_for_test();
        let out = start_impl(r#"{"epoch_size_sec": 600}"#).unwrap();
        assert!(
            out.get("overrides").is_none(),
            "no overrides key when none are set: {out}"
        );
        reset_config_for_test();
    }

    // A reconfigure names what it sets and leaves the rest alone: delivery's
    // start (its own registry only) must not undo the host's mix registry
    // epoch, and vice versa.
    #[test]
    fn start_keeps_registries_it_does_not_name() {
        let _serial = crate::lock(&TEST_GLOBAL_LOCK);
        reset_config_for_test();
        let deliv = format!("logos:local:{}", "ab".repeat(32));
        let mix = format!("logos:local:{}", "cd".repeat(32));
        let host = serde_json::json!({
            "epoch_size_sec": 600,
            "registries": [deliv, {"registry_id": mix, "epoch_size_sec": 10, "max_epoch_gap": 3}],
        })
        .to_string();
        start_impl(&host).unwrap();
        assert_eq!(epoch_params_for(&mix).unwrap(), (10, 3));

        // Delivery names only its registry, as a plain string.
        let out = start_impl(
            &serde_json::json!({"epoch_size_sec": 600, "registries": [deliv]}).to_string(),
        )
        .unwrap();
        assert_eq!(
            epoch_params_for(&mix).unwrap(),
            (10, 3),
            "the mix registry lost its epoch: {out}"
        );
        assert_eq!(
            epoch_params_for(&deliv).unwrap(),
            (600, DEFAULT_MAX_EPOCH_GAP)
        );
        assert_eq!(
            out["registries"],
            serde_json::json!([deliv, mix]),
            "every registry in force is reported"
        );

        // A plain string under other defaults leaves a configured registry
        // alone; the instance defaults still move for unnamed registries.
        start_impl(
            &serde_json::json!({"epoch_size_sec": 10, "max_epoch_gap": 3, "registries": [mix]})
                .to_string(),
        )
        .unwrap();
        assert_eq!(epoch_params_for(&mix).unwrap(), (10, 3));
        assert_eq!(
            epoch_params_for(&deliv).unwrap(),
            (600, DEFAULT_MAX_EPOCH_GAP)
        );
        assert_eq!(epoch_params_for("logos:local:other").unwrap(), (10, 3));

        // An object entry sets: absent fields take this call's defaults.
        start_impl(
            &serde_json::json!({"epoch_size_sec": 600, "registries": [{"registry_id": mix}]})
                .to_string(),
        )
        .unwrap();
        assert_eq!(
            epoch_params_for(&mix).unwrap(),
            (600, DEFAULT_MAX_EPOCH_GAP)
        );
        reset_config_for_test();
    }

    #[test]
    fn keystore_ops_without_store_report_internal() {
        // With no store initialized (host provided no persistence path),
        // every keystore op fails with the internal error, never panics.
        let _serial = crate::lock(&TEST_GLOBAL_LOCK);
        let imp = LogosRlnModuleImpl::default();
        let out = imp.lock_keystore();
        assert!(out.contains(r#""kind":"internal""#), "got: {out}");
    }

    // start()'s allocator block becomes each registry's delegated options:
    // the global one for every entry without a block, an entry's own one
    // over it, null to opt out; a malformed block fails start().
    #[test]
    fn start_configures_the_allocator_per_registry() {
        let _serial = crate::lock(&TEST_GLOBAL_LOCK);
        let (a, b, c) = (
            format!("logos:local:{}", "a7".repeat(32)),
            format!("logos:local:{}", "b7".repeat(32)),
            format!("logos:local:{}", "c7".repeat(32)),
        );
        let cfg = serde_json::json!({
            "epoch_size_sec": 600, "provision": false,
            "allocator": { "peer_id": "16Uiu2Peer", "multiaddr": "/ip4/127.0.0.1/tcp/1",
                           "auth_type": "peer-any", "auth_payload": "026400000000000000" },
            "registries": [
                a,
                { "registry_id": b, "epoch_size_sec": 10,
                  "allocator": { "peer_id": "16Uiu2Other", "multiaddr": "/ip4/127.0.0.1/tcp/2" } },
                { "registry_id": c, "allocator": null },
            ],
        });
        let out = start_impl(&cfg.to_string()).unwrap();
        assert_eq!(out["started"], serde_json::json!(true), "got: {out}");
        let canonical = |r: &str| registry_id::parse(r).unwrap().canonical;
        let a_alloc = allocator_for(&canonical(&a)).expect("a takes the global allocator");
        assert_eq!(a_alloc.gifter_peer_id, "16Uiu2Peer");
        assert_eq!(a_alloc.auth_type.as_deref(), Some("peer-any"));
        assert_eq!(a_alloc.auth_payload.as_deref(), Some("026400000000000000"));
        let b_alloc = allocator_for(&canonical(&b)).expect("b has its own");
        assert_eq!(b_alloc.gifter_peer_id, "16Uiu2Other");
        assert!(
            b_alloc.auth_type.is_none(),
            "an own block does not inherit the global auth"
        );
        assert!(allocator_for(&canonical(&c)).is_none(), "null opts out");

        // The wire method's flat vocabulary decodes to the same options.
        let (rate, flat) = parse_registry_options(
            &serde_json::json!([
                { "key": "rate_limit", "value": "42" },
                { "key": "delegated", "value": "true" },
                { "key": "gifter_peer_id", "value": "16Uiu2Peer" },
                { "key": "gifter_multiaddr", "value": "/ip4/127.0.0.1/tcp/1" },
                { "key": "auth_type", "value": "peer-any" },
                { "key": "auth_payload", "value": "026400000000000000" },
            ])
            .to_string(),
        )
        .unwrap();
        assert_eq!(rate, 42);
        assert_eq!(
            DelegatedOptions::from_registry_options(&flat).unwrap(),
            Some(a_alloc)
        );

        for (bad, needle) in [
            (
                serde_json::json!({ "multiaddr": "/ip4/1/tcp/1" }),
                "go together",
            ),
            (
                serde_json::json!({ "discover": false }),
                "needs discover or gifter_peer_id",
            ),
            (
                serde_json::json!({ "discover": "yes" }),
                "discover must be a boolean",
            ),
            (
                serde_json::json!({ "peer_id": "p", "multiaddr": "/m", "auth_payload": "00" }),
                "need auth_type",
            ),
            (
                serde_json::json!({ "peer_id": "p", "multiaddr": "/m", "auth_type": "t" }),
                "needs auth_payload or auth_provider",
            ),
            (
                serde_json::json!({ "peer_id": "p", "multiaddr": "/m", "auth_type": "t", "auth_payload": "zz" }),
                "hex",
            ),
            (
                serde_json::json!({ "peer_id": 7, "multiaddr": "/m" }),
                "must be a string",
            ),
            (serde_json::json!("16Uiu2Peer"), "must be an object"),
        ] {
            let cfg = serde_json::json!({ "epoch_size_sec": 600, "provision": false, "allocator": bad, "registries": [a] });
            let e = start_impl(&cfg.to_string()).unwrap_err();
            assert_eq!(e.kind, ErrorKind::InvalidArgument, "{bad}: {}", e.message);
            assert!(e.message.contains(needle), "{bad}: {}", e.message);
            assert!(
                e.message.starts_with("config_json.allocator"),
                "{bad}: {}",
                e.message
            );
        }
        stop_impl().unwrap();
    }
}
