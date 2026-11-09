//! Reply-envelope error type.

/// Reply-envelope error kinds. The spec's RLN Module API mandates
/// distinguishing at least NOT_READY / TRANSIENT / BUDGET_EXHAUSTED /
/// PERMANENT (the rate-limiting portion), plus this crate's management kinds
/// unknown_registry / unknown_membership / provider_failure.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum ErrorKind {
    UnknownRegistry,
    UnknownMembership,
    ProviderFailure,
    Locked,
    BadPassword,
    NoUsableMembership,
    AmbiguousSelection,
    InvalidArgument,
    KeychainUnavailable,
    Internal,
    /// Module cannot serve the call yet (registry view not warm) — retry.
    NotReady,
    /// A recoverable failure (registry/RPC/engine hiccup) — the caller MAY retry.
    Transient,
    /// The epoch's rate-limit budget is spent — retry next epoch.
    BudgetExhausted,
    /// Retrying as-is cannot succeed. Constructed by the message-id
    /// allocator's floor/epoch-size guards (`store::reserve_message_id`):
    /// an epoch below the persisted allocation floor, or a configured
    /// `epoch_size_sec` this membership's allocations are not bound to.
    Permanent,
}

impl ErrorKind {
    // OWNERSHIP: every kind name is a string literal.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            ErrorKind::UnknownRegistry => "unknown_registry",
            ErrorKind::UnknownMembership => "unknown_membership",
            ErrorKind::ProviderFailure => "provider_failure",
            ErrorKind::Locked => "locked",
            ErrorKind::BadPassword => "bad_password",
            ErrorKind::NoUsableMembership => "no_usable_membership",
            ErrorKind::AmbiguousSelection => "ambiguous_selection",
            ErrorKind::InvalidArgument => "invalid_argument",
            ErrorKind::KeychainUnavailable => "keychain_unavailable",
            ErrorKind::Internal => "internal",
            ErrorKind::NotReady => "not_ready",
            ErrorKind::Transient => "transient",
            ErrorKind::BudgetExhausted => "budget_exhausted",
            ErrorKind::Permanent => "permanent",
        }
    }

    /// The coarse RLN-API error class (the spec's RlnErrorKind quartet),
    /// carried in every error envelope. `locked` maps to not_ready: the
    /// keystore password is invisible to the spec surface, so the caller
    /// retries after the app's unlock flow.
    // OWNERSHIP: every class name is a string literal.
    pub(crate) fn class(self) -> &'static str {
        match self {
            ErrorKind::NotReady | ErrorKind::Locked => "not_ready",
            ErrorKind::Transient | ErrorKind::ProviderFailure => "transient",
            ErrorKind::BudgetExhausted => "budget_exhausted",
            ErrorKind::UnknownRegistry
            | ErrorKind::UnknownMembership
            | ErrorKind::BadPassword
            | ErrorKind::NoUsableMembership
            | ErrorKind::AmbiguousSelection
            | ErrorKind::InvalidArgument
            | ErrorKind::KeychainUnavailable
            | ErrorKind::Internal
            | ErrorKind::Permanent => "permanent",
        }
    }
}

#[derive(Debug)]
pub(crate) struct ApiError {
    pub(crate) kind: ErrorKind,
    pub(crate) message: String,
}

impl ApiError {
    pub(crate) fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        ApiError {
            kind,
            message: message.into(),
        }
    }

    pub(crate) fn internal(message: impl Into<String>) -> Self {
        ApiError::new(ErrorKind::Internal, message)
    }

    /// The typed error object: {"class":…,"kind":…,"message":…}, in
    /// alphabetical wire order (see `views.rs`).
    pub(crate) fn body(&self) -> serde_json::Value {
        serde_json::to_value(crate::views::ErrorBody::new(
            self.kind.class(),
            self.kind.as_str(),
            &self.message,
        ))
        .unwrap_or(serde_json::Value::Null)
    }

    pub(crate) fn to_json(&self) -> String {
        serde_json::json!({ "error": self.body() }).to_string()
    }
}
