//! Process-wide helpers with no crate dependencies.

use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Poison-recovering lock: a poisoned mutex is a bug elsewhere, not a
/// reason to wedge every future call.
pub(crate) fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Wall-clock UNIX seconds; a clock before the epoch reads as 0 rather
/// than panicking.
pub(crate) fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
