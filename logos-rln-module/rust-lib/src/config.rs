//! The configuration `start()` puts in force: instance defaults, the
//! per-registry table (epoch parameters, provisioning rate and allocator), and
//! its readers.

use std::collections::BTreeMap;
use std::sync::Mutex;

use crate::delegated::DelegatedOptions;
use crate::error::{ApiError, ErrorKind};
use crate::util::lock;

/// Applied when the common "rate_limit" option key is absent (spec: "absent,
/// the registry … applies its default"); the lez registry declares no default
/// yet, so the module supplies one.
pub(crate) const DEFAULT_RATE_LIMIT: u64 = 100;

/// Default `max_epoch_gap` (see [`epoch_params_for`]) when `start()` sets none.
pub(crate) const DEFAULT_MAX_EPOCH_GAP: u64 = 1;

/// One registry's configuration in force (spec: epoch size and max gap are
/// per-REGISTRY configuration). Every registry a `start()` names has one;
/// the start reply's `overrides` object is this table.
#[derive(Clone, serde::Serialize)]
pub(crate) struct RegistryConfig {
    pub(crate) epoch_size_sec: u64,
    pub(crate) max_epoch_gap: u64,
    /// The rate a membership provisioned on this registry asks for.
    #[serde(skip)]
    pub(crate) rate_limit: u64,
    /// The allocator provisioning asks first, before a funded registration.
    #[serde(skip)]
    pub(crate) allocator: Option<DelegatedOptions>,
}

/// Runtime configuration applied by `start()`: instance defaults for
/// registries no call has named, plus the per-registry table keyed by
/// canonical registry_id. `registries` keeps first-named order — the first
/// `logos` registry binds the wallet network.
pub(crate) struct ModuleConfig {
    pub(crate) epoch_size_sec: u64,
    pub(crate) max_epoch_gap: u64,
    pub(crate) registries: Vec<String>,
    pub(crate) per_registry: std::collections::BTreeMap<String, RegistryConfig>,
}

static CONFIG: Mutex<Option<ModuleConfig>> = Mutex::new(None);

/// Replace the configuration in force with `start()`'s merged table.
pub(crate) fn install(config: ModuleConfig) {
    *lock(&CONFIG) = Some(config);
}

/// The configuration in force as `start()` merges into it: the registries in
/// first-named order and the per-registry table, both empty before any start.
pub(crate) fn registries_snapshot() -> (Vec<String>, BTreeMap<String, RegistryConfig>) {
    match lock(&CONFIG).as_ref() {
        Some(c) => (c.registries.clone(), c.per_registry.clone()),
        None => (Vec::new(), BTreeMap::new()),
    }
}

/// The sole reader of the epoch configuration: `(epoch_size_sec,
/// max_epoch_gap)` for one registry — its start() override, else the instance
/// default — under ONE lock acquisition, so a concurrent reconfigure cannot
/// hand a handler a mixed pair. No default on purpose: the size is an
/// application parameter every prover and verifier must share, so before
/// start() the epoch-dependent methods fail `not_ready`. start() filters both
/// values to positives, so neither component is ever 0 here.
pub(crate) fn epoch_params_for(registry_canonical: &str) -> Result<(u64, u64), ApiError> {
    let cfg = lock(&CONFIG);
    let c = cfg.as_ref().ok_or_else(|| {
        ApiError::new(
            ErrorKind::NotReady,
            "start() has not configured epoch_size_sec; rate limiting is not ready",
        )
    })?;
    Ok(match c.per_registry.get(registry_canonical) {
        Some(r) => (r.epoch_size_sec, r.max_epoch_gap),
        None => (c.epoch_size_sec, c.max_epoch_gap),
    })
}

#[cfg(test)]
pub(crate) fn epoch_size() -> Result<u64, ApiError> {
    epoch_params_for("").map(|(size, _)| size)
}

/// start()'s stale-binding warning: the membership's own registry's
/// configured size, which is what the check compared against.
pub(crate) fn epoch_binding_warning(hash: &str, registry: &str, bound: u64, configured: u64) -> String {
    format!(
        "membership start: entry {hash} on {registry} allocations are bound to \
         epoch_size_sec={bound}, configured size is {configured}; \
         generate_proof for it will fail permanent"
    )
}

/// The allocator `start()` configured for a registry, if any.
pub(crate) fn allocator_for(registry_canonical: &str) -> Option<DelegatedOptions> {
    lock(&CONFIG)
        .as_ref()
        .and_then(|c| c.per_registry.get(registry_canonical))
        .and_then(|c| c.allocator.clone())
}

#[cfg(test)]
pub(crate) fn reset_config_for_test() {
    *lock(&CONFIG) = None;
}

#[cfg(test)]
mod tests {
    use super::*;

    // The warning names the membership's registry and that registry's
    // configured size — the value the check compared against.
    #[test]
    fn epoch_binding_warning_names_the_registry_size() {
        let msg = epoch_binding_warning("abc123", "logos:local:d", 300, 600);
        assert!(msg.contains("on logos:local:d"), "got: {msg}");
        assert!(msg.contains("epoch_size_sec=300"), "got: {msg}");
        assert!(msg.contains("configured size is 600"), "got: {msg}");
    }
}
