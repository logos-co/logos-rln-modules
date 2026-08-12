//! Panic hook installed on first host contact.
//!
//! Release builds set `panic = "abort"` (unwinding across the C ABI into
//! the host would be UB), so a panic aborts the whole `logos_host_qt`
//! subprocess before any `catch_unwind` can run. The panic hook still runs
//! first: it prints the location and payload to stderr so a crash inside
//! this module is locatable in the host log instead of an opaque SIGABRT.

use std::panic;
use std::sync::Once;

static INSTALL: Once = Once::new();

pub(crate) fn install_once() {
    INSTALL.call_once(|| {
        let previous = panic::take_hook();
        panic::set_hook(Box::new(move |info| {
            let payload = info.payload();
            let msg = payload
                .downcast_ref::<&str>()
                .copied()
                .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
                .unwrap_or("<non-string panic payload>");
            match info.location() {
                Some(loc) => eprintln!(
                    "rln_membership: panic at {}:{}:{}: {msg}",
                    loc.file(),
                    loc.line(),
                    loc.column()
                ),
                None => eprintln!("rln_membership: panic at <unknown location>: {msg}"),
            }
            previous(info);
        }));
    });
}
