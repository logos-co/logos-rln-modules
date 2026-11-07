//! Test-only shared state and fixtures: the global-state test lock, store
//! publication, and the seeded-membership helpers the module tests share.

use std::sync::{Arc, Mutex};

use crate::error::ApiError;
use crate::lifecycle::{MembershipState, StoredCredential};
use crate::provider::Backend;
use crate::sealed_store::{self, store::Store};
use crate::util::now_unix;
use crate::LogosRlnModuleImpl;

/// Tests touching process-global subsystems (the worker supervisor, CONFIG,
/// the nullifier log, root windows, the path cache, the keychain backend,
/// the published store slot, event emission) serialize on this.
pub(crate) static TEST_GLOBAL_LOCK: Mutex<()> = Mutex::new(());

/// The backend `provider::backend_for("fakens")` serves.
pub(crate) static INSTALLED_BACKEND: Mutex<Option<Backend>> = Mutex::new(None);

/// Serve `backend` under the `fakens` namespace. Callers hold
/// `TEST_GLOBAL_LOCK`.
pub(crate) fn install_backend(backend: Backend) {
    *crate::util::lock(&INSTALLED_BACKEND) = Some(backend);
}

/// Open a store in `dir` and publish it in the worker-loop slot — the tests'
/// stand-in for `on_context_ready`'s store wiring.
pub(crate) fn publish_test_store(dir: std::path::PathBuf) -> Arc<Store> {
    sealed_store::store::publish(None);
    let store = Store::open(dir).expect("test store open");
    sealed_store::store::publish(Some(&store));
    store
}

/// The "no store" argument for `_impl` fns whose store access must never
/// be reached (or must surface the uninitialized internal error).
pub(crate) fn no_store() -> Result<Arc<Store>, ApiError> {
    Err(ApiError::internal(sealed_store::store::UNINIT_MSG))
}

/// The wire's RegistryOptions array from (key, value) pairs.
pub(crate) fn opts_arr(pairs: &[(&str, &str)]) -> String {
    serde_json::Value::Array(
        pairs
            .iter()
            .map(|(k, v)| serde_json::json!({"key": k, "value": v}))
            .collect(),
    )
    .to_string()
}

/// Seed one membership: insert (Pending), then push the cache row to
/// the wanted state/leaf/rate. Needs the store unlocked.
#[allow(clippy::too_many_arguments)]
pub(crate) fn seed_membership(
    store: &Store,
    hash: &str,
    registry: &str,
    commitment_hex: &str,
    rln_identifier: &str,
    secret_hex: &str,
    state: MembershipState,
    leaf_index: u64,
    rate_limit: u64,
) {
    let identity = sealed_store::format::IdentityBlock {
        registry_id: registry.to_string(),
        rln_identifier: rln_identifier.to_string(),
        identity_commitment: commitment_hex.to_string(),
        submitted_at: now_unix(),
    };
    let credential = StoredCredential {
        identity_commitment: commitment_hex.to_string(),
        identity_secret_hash: secret_hex.to_string(),
        registry_id: registry.to_string(),
    };
    store.insert(hash, identity, &credential, 100).expect("seed insert");
    store
        .update_cache(hash, |m| {
            m.state = state;
            m.leaf_index = Some(leaf_index);
            m.rate_limit = Some(rate_limit);
        })
        .expect("seed cache");
}

/// A module instance wired to a fresh store in `dir` (the tests'
/// on_context_ready stand-in), plus the store for direct seeding.
pub(crate) fn imp_with_store(dir: std::path::PathBuf) -> (LogosRlnModuleImpl, Arc<Store>) {
    let imp = LogosRlnModuleImpl::default();
    imp.open_store(dir);
    let store = imp.store().expect("test store open").clone();
    (imp, store)
}
