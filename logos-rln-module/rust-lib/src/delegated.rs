//! Delegated-registration options: the RegistryOptions flat keys and
//! `start()`'s allocator block, their shape rules, and the gifter request
//! args they produce.

use crate::error::{ApiError, ErrorKind};

/// Delegated-registration options (the RegistryOptions FLAT
/// "discover"/"gifter_peer_id"/"gifter_multiaddr"/"auth_*" keys, selected
/// by "delegated":"true"). The auth surface is vector-agnostic: "auth_type"
/// and its payload material pass to the gifter verbatim. Allocators that
/// advertise the (registry, auth_type) pair through libp2p service
/// discovery are asked first (`discover`, default true); the configured
/// pair, empty when none, comes after them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DelegatedOptions {
    pub(crate) discover: bool,
    pub(crate) gifter_peer_id: String,
    pub(crate) gifter_multiaddr: String,
    pub(crate) auth_type: Option<String>,
    pub(crate) auth_payload: Option<String>,
    pub(crate) auth_provider: Option<String>,
    pub(crate) auth_args: Option<String>,
}

/// The shape rules a delegated registration's options must meet, checked
/// BEFORE a credential is minted (the auth_type vocabulary itself is OPEN):
/// a way to find a gifter (discovery or a pair to dial), payload material
/// only with a named vector, and exactly one payload source for a named
/// vector.
pub(crate) fn validate_delegated(d: &DelegatedOptions) -> Result<(), ApiError> {
    if d.gifter_peer_id.is_empty() != d.gifter_multiaddr.is_empty() {
        return Err(ApiError::new(
            ErrorKind::InvalidArgument,
            "gifter_peer_id and gifter_multiaddr go together",
        ));
    }
    if !d.discover && d.gifter_peer_id.is_empty() {
        return Err(ApiError::new(
            ErrorKind::InvalidArgument,
            "delegated registration needs discover or gifter_peer_id and gifter_multiaddr",
        ));
    }
    if d.auth_type.is_none()
        && (d.auth_payload.is_some() || d.auth_provider.is_some() || d.auth_args.is_some())
    {
        return Err(ApiError::new(
            ErrorKind::InvalidArgument,
            "auth_payload/auth_provider/auth_args need auth_type",
        ));
    }
    if let Some(t) = d.auth_type.as_deref() {
        match (&d.auth_payload, &d.auth_provider) {
            (Some(_), Some(_)) => {
                return Err(ApiError::new(
                    ErrorKind::InvalidArgument,
                    "auth_payload and auth_provider are mutually exclusive",
                ))
            }
            (None, None) => {
                return Err(ApiError::new(
                    ErrorKind::InvalidArgument,
                    format!("auth_type '{t}' needs auth_payload or auth_provider"),
                ))
            }
            _ => {}
        }
    }
    if let Some(p) = &d.auth_payload {
        let h = p.trim_start_matches("0x");
        if h.is_empty() || h.len() % 2 != 0 || !h.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(ApiError::new(
                ErrorKind::InvalidArgument,
                "auth_payload must be hex-encoded bytes",
            ));
        }
    }
    Ok(())
}

impl DelegatedOptions {
    /// `start()`'s `allocator` block — `{"discover"?,"peer_id"?,"multiaddr"?,
    /// "auth_type"?,"auth_payload"?|"auth_provider"?,"auth_args"?}` — as the
    /// delegated options provisioning registers with. `None`/`null` = no
    /// allocator; `{}` = discovery alone.
    pub(crate) fn from_allocator_block(
        v: Option<&serde_json::Value>,
        what: &str,
    ) -> Result<Option<Self>, ApiError> {
        let obj = match v {
            None | Some(serde_json::Value::Null) => return Ok(None),
            Some(serde_json::Value::Object(o)) => o,
            Some(_) => {
                return Err(ApiError::new(
                    ErrorKind::InvalidArgument,
                    format!("{what} must be an object {{discover?, peer_id?, multiaddr?, auth_type?, auth_payload?|auth_provider?, auth_args?}}"),
                ))
            }
        };
        let discover = match obj.get("discover") {
            None | Some(serde_json::Value::Null) => true,
            Some(serde_json::Value::Bool(b)) => *b,
            Some(other) => {
                return Err(ApiError::new(
                    ErrorKind::InvalidArgument,
                    format!("{what}.discover must be a boolean, got {other}"),
                ))
            }
        };
        let text = |key: &str| -> Result<Option<String>, ApiError> {
            match obj.get(key) {
                None | Some(serde_json::Value::Null) => Ok(None),
                Some(serde_json::Value::String(s)) if s.trim().is_empty() => Ok(None),
                // OWNERSHIP: the options own their trimmed text; the request is borrowed.
                Some(serde_json::Value::String(s)) => Ok(Some(s.trim().to_string())),
                Some(other) => Err(ApiError::new(
                    ErrorKind::InvalidArgument,
                    format!("{what}.{key} must be a string, got {other}"),
                )),
            }
        };
        let d = Self {
            discover,
            gifter_peer_id: text("peer_id")?.unwrap_or_default(),
            gifter_multiaddr: text("multiaddr")?.unwrap_or_default(),
            auth_type: text("auth_type")?,
            auth_payload: text("auth_payload")?,
            auth_provider: text("auth_provider")?,
            auth_args: text("auth_args")?,
        };
        validate_delegated(&d)
            .map_err(|e| ApiError::new(e.kind, format!("{what}: {}", e.message)))?;
        Ok(Some(d))
    }

    /// The RegistryOptions flat pairs `parse_registry_options` leaves
    /// (rate_limit removed) — `register_membership`'s delegated vocabulary.
    /// `None` = a funded registration, which takes no auth material. The
    /// option texts move out of `opts`.
    pub(crate) fn from_registry_options(
        mut opts: serde_json::Value,
    ) -> Result<Option<Self>, ApiError> {
        if !flat_bool_option(&opts, "delegated") {
            if ["auth_type", "auth_payload", "auth_provider", "auth_args"]
                .iter()
                .any(|k| opts.get(*k).is_some())
            {
                // Auth material on the funded path is a caller mistake, not a no-op.
                return Err(ApiError::new(
                    ErrorKind::InvalidArgument,
                    "auth_* options apply to delegated registration only — set \"delegated\":\"true\"",
                ));
            }
            return Ok(None);
        }
        let d = Self {
            discover: match opts.get("discover") {
                None => true,
                Some(_) => flat_bool_option(&opts, "discover"),
            },
            gifter_peer_id: flat_str_option(&mut opts, "gifter_peer_id").unwrap_or_default(),
            gifter_multiaddr: flat_str_option(&mut opts, "gifter_multiaddr").unwrap_or_default(),
            auth_type: flat_str_option(&mut opts, "auth_type"),
            auth_payload: flat_str_option(&mut opts, "auth_payload"),
            auth_provider: flat_str_option(&mut opts, "auth_provider"),
            auth_args: flat_str_option(&mut opts, "auth_args"),
        };
        validate_delegated(&d)?;
        Ok(Some(d))
    }
}

/// Read a RegistryOptions flat boolean field. `parse_registry_options` has
/// already rejected every non-string value and stored each pair as a
/// `Value::String`, so the only question left is which string: the spec's
/// char* pairs make "true" the one truthy spelling.
pub(crate) fn flat_bool_option(options: &serde_json::Value, key: &str) -> bool {
    options.get(key).and_then(|v| v.as_str()) == Some("true")
}

/// Take a RegistryOptions flat string field out of `options`; absent and ""
/// both mean unset. String-typed by construction — see `flat_bool_option`.
pub(crate) fn flat_str_option(options: &mut serde_json::Value, key: &str) -> Option<String> {
    match options.get_mut(key).map(serde_json::Value::take) {
        Some(serde_json::Value::String(s)) if !s.is_empty() => Some(s),
        _ => None,
    }
}

/// Gifter `request` args for a delegated registration: the scope's registry
/// (its config account, so a gifter serving another refuses at once instead
/// of registering an orphan), the module-generated commitment (never the
/// secret) plus the caller's gifter and auth-vector selection, passed through
/// verbatim. With an auth_provider the gifter client produces the payload
/// bound to exactly this commitment.
pub(crate) fn delegated_request_args(
    d: &DelegatedOptions,
    commitment_hex: &str,
    rate_limit: u64,
    registry_account: &str,
) -> String {
    let mut args = serde_json::json!({
        "discover": d.discover,
        "config": registry_account,
        "identityCommitment": commitment_hex,
        "rate": rate_limit,
    });
    if !d.gifter_peer_id.is_empty() {
        args["gifterPeerId"] = d.gifter_peer_id.as_str().into();
        args["gifterMultiaddr"] = d.gifter_multiaddr.as_str().into();
    }
    if let Some(t) = &d.auth_type {
        args["authType"] = t.as_str().into();
    }
    if let Some(p) = &d.auth_payload {
        args["authPayload"] = p.as_str().into();
    }
    if let Some(module) = &d.auth_provider {
        args["authProvider"] = module.as_str().into();
    }
    if let Some(extra) = &d.auth_args {
        args["authArgs"] = extra.as_str().into();
    }
    args.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    // The gifter request args carry the auth selection verbatim, and an
    // unspecified vector stays ABSENT rather than defaulting here.
    #[test]
    fn delegated_request_args_pass_auth_selection_through_verbatim() {
        let mut d = DelegatedOptions {
            discover: true,
            gifter_peer_id: "p".into(),
            gifter_multiaddr: "/ip4/127.0.0.1/tcp/1".into(),
            auth_type: None,
            auth_payload: None,
            auth_provider: None,
            auth_args: None,
        };
        let v: serde_json::Value =
            serde_json::from_str(&delegated_request_args(&d, "ab", 300, "cf")).unwrap();
        for key in ["authType", "authPayload", "authProvider", "authArgs"] {
            assert!(
                v.get(key).is_none(),
                "unset {key} must stay absent, got: {v}"
            );
        }
        assert_eq!(v["config"], "cf", "the scope's registry rides along: {v}");
        assert_eq!(v["identityCommitment"], "ab", "got: {v}");
        assert_eq!(v["rate"], 300, "got: {v}");

        d.auth_type = Some("voucher-v1".into());
        d.auth_provider = Some("voucher_module".into());
        d.auth_args = Some(r#"{"campaign":"launch"}"#.into());
        let v: serde_json::Value =
            serde_json::from_str(&delegated_request_args(&d, "ab", 300, "cf")).unwrap();
        assert_eq!(v["authType"], "voucher-v1", "got: {v}");
        assert_eq!(v["authProvider"], "voucher_module", "got: {v}");
        assert_eq!(v["authArgs"], r#"{"campaign":"launch"}"#, "got: {v}");
        assert!(v.get("authPayload").is_none(), "got: {v}");

        d.auth_provider = None;
        d.auth_args = None;
        d.auth_payload = Some("deadbeef".into());
        let v: serde_json::Value =
            serde_json::from_str(&delegated_request_args(&d, "ab", 300, "cf")).unwrap();
        assert_eq!(v["authPayload"], "deadbeef", "got: {v}");
    }
}
