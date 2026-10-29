//! libp2p_module, driven from the worker thread.
//!
//! libp2p_module is a universal (C++) module reached through the typed
//! client generated from `deps/libp2p_module.lidl`. Its replies are
//! `{success, error, value}` envelopes, sometimes as a JSON string, whose
//! `value` may itself be a JSON string. Every call here is the client's
//! `*_async_with_timeout` twin with an mpsc wait: the sync twins would block
//! the Qt event loop that delivers the reply when called from the host's
//! thread, and a worker thread may not create a client, so the one client is
//! made on the owner thread at `on_context_ready` (`init_client`).
//!
//! libp2p_module dispatches every call on one thread: a long
//! `protocolAcceptStream` would stall every other caller of the module on
//! this node, so the server polls with short timeouts (`server.rs`).

use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;

use crate::libp2p_module::Libp2pModuleClient;
use crate::lock;

/// Dispatch margin on top of what the call itself is allowed.
const CALL_MARGIN: Duration = Duration::from_secs(5);

static CLIENT: Mutex<Option<Arc<Libp2pModuleClient>>> = Mutex::new(None);

/// Warm the shared client at load (owner thread).
pub(crate) fn init_client() {
    let _ = client();
}

fn client() -> Arc<Libp2pModuleClient> {
    let mut slot = lock(&CLIENT);
    Arc::clone(slot.get_or_insert_with(|| Arc::new(Libp2pModuleClient::new())))
}

type Reply = Result<serde_json::Value, logos_rust_sdk::LogosError>;

/// Run one client call and wait for its reply: `call` receives the client,
/// the call timeout and the callback to hand the SDK.
fn wait(
    what: &str,
    timeout: Duration,
    call: impl FnOnce(&Libp2pModuleClient, Duration, Box<dyn FnOnce(Reply) + Send + 'static>),
) -> Result<serde_json::Value, String> {
    let (tx, rx) = mpsc::channel();
    call(
        &client(),
        timeout,
        Box::new(move |result| {
            let _ = tx.send(result);
        }),
    );
    let reply = match rx.recv_timeout(timeout + CALL_MARGIN) {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => return Err(format!("{what}: {e}")),
        Err(_) => return Err(format!("{what}: reply channel timed out")),
    };
    unwrap_envelope(what, reply)
}

/// The `value` of a universal module's reply, through the envelope.
pub(crate) fn unwrap_envelope(what: &str, reply: serde_json::Value) -> Result<serde_json::Value, String> {
    let env = match reply {
        serde_json::Value::String(s) if !s.is_empty() => {
            serde_json::from_str(&s).map_err(|e| format!("{what}: reply parse: {e}"))?
        }
        other => other,
    };
    let value = if env.get("success").is_some() {
        if env.get("success").and_then(serde_json::Value::as_bool) == Some(false) {
            let e = env
                .get("error")
                .and_then(serde_json::Value::as_str)
                .filter(|s| !s.is_empty())
                .unwrap_or("libp2p call failed");
            return Err(format!("{what}: {e}"));
        }
        env.get("value").cloned().unwrap_or(serde_json::Value::Null)
    } else {
        env
    };
    Ok(match value {
        serde_json::Value::String(s) => serde_json::from_str(&s).unwrap_or(serde_json::Value::String(s)),
        other => other,
    })
}

/// Is this failure libp2p_module's accept-poll timeout (no stream arrived)?
pub(crate) fn is_accept_timeout(e: &str) -> bool {
    e.contains("timeout waiting for inbound stream")
}

pub(crate) fn mount_protocol(proto: &str) -> Result<(), String> {
    wait("mountProtocol", Duration::from_secs(5), |c, t, cb| c.mount_protocol_async_with_timeout(proto, t, cb))
        .map(|_| ())
}

/// One inbound stream of `proto`, waiting at most `timeout_ms` inside
/// libp2p_module: its `streamId` and the dialing `peerId`.
pub(crate) fn accept_stream(proto: &str, timeout_ms: u64) -> Result<(u64, String), String> {
    let args = serde_json::json!({ "proto": proto, "timeoutMs": timeout_ms }).to_string();
    let v = wait("protocolAcceptStream", Duration::from_millis(timeout_ms) + Duration::from_secs(5), |c, t, cb| {
        c.protocol_accept_stream_async_with_timeout(&args, t, cb)
    })?;
    let stream_id = v
        .get("streamId")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| format!("protocolAcceptStream: no streamId in {v}"))?;
    let peer_id = v.get("peerId").and_then(serde_json::Value::as_str).unwrap_or_default().to_owned();
    Ok((stream_id, peer_id))
}

/// One length-prefixed frame from the stream, at most `max_size` bytes.
pub(crate) fn read_frame(stream_id: u64, max_size: u64, timeout_ms: u64) -> Result<Vec<u8>, String> {
    let args = serde_json::json!({ "streamId": stream_id, "maxSize": max_size, "timeoutMs": timeout_ms }).to_string();
    let v = wait("streamReadLpJson", Duration::from_millis(timeout_ms) + Duration::from_secs(5), |c, t, cb| {
        c.stream_read_lp_json_async_with_timeout(&args, t, cb)
    })?;
    let b64 = v
        .get("dataB64")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("streamReadLpJson: no dataB64 in {v}"))?;
    base64::engine::general_purpose::STANDARD.decode(b64).map_err(|e| format!("streamReadLpJson: dataB64: {e}"))
}

/// One length-prefixed frame onto the stream.
pub(crate) fn write_frame(stream_id: u64, data: &[u8]) -> Result<(), String> {
    let args = serde_json::json!({
        "streamId": stream_id,
        "dataB64": base64::engine::general_purpose::STANDARD.encode(data),
    })
    .to_string();
    wait("streamWriteLpJson", Duration::from_secs(10), |c, t, cb| c.stream_write_lp_json_async_with_timeout(&args, t, cb))
        .map(|_| ())
}

/// Hand the stream back. Never close or send EOF from the server side: the
/// dialer reads the reply and closes; a server-side close races yamux's
/// cleanup (the gifter learned this).
pub(crate) fn release_stream(stream_id: u64) -> Result<(), String> {
    let args = serde_json::json!({ "streamId": stream_id }).to_string();
    wait("streamReleaseJson", Duration::from_secs(5), |c, t, cb| c.stream_release_json_async_with_timeout(&args, t, cb))
        .map(|_| ())
}

/// Rebuild the node listening on `addrs` (before `start`).
pub(crate) fn create_node(addrs: &[String]) -> Result<(), String> {
    let config = serde_json::json!({ "addrs": addrs }).to_string();
    wait("createNode", Duration::from_secs(20), |c, t, cb| c.create_node_async_with_timeout(&config, t, cb)).map(|_| ())
}

/// Start the node. An already-running node answers an error naming that,
/// which is success here.
pub(crate) fn start_node() -> Result<(), String> {
    match wait("start", Duration::from_secs(30), |c, t, cb| c.start_async_with_timeout(t, cb)) {
        Ok(_) => Ok(()),
        Err(e) if e.to_ascii_lowercase().contains("already") => Ok(()),
        Err(e) => Err(e),
    }
}

/// `getNodeInfo(field)`: `"PeerId"` (a string) or `"Multiaddrs"` (strings).
pub(crate) fn node_info(field: &str) -> Result<serde_json::Value, String> {
    wait("getNodeInfo", Duration::from_secs(5), |c, t, cb| c.get_node_info_async_with_timeout(field, t, cb))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelopes_unwrap_to_their_value() {
        let v = unwrap_envelope("t", serde_json::json!({"success": true, "value": {"streamId": 7}})).unwrap();
        assert_eq!(v["streamId"], 7);
        let v = unwrap_envelope("t", serde_json::json!(r#"{"success":true,"value":"{\"dataB64\":\"AQ==\"}"}"#)).unwrap();
        assert_eq!(v["dataB64"], "AQ==");
        let v = unwrap_envelope("t", serde_json::json!({"peerId": "p"})).unwrap();
        assert_eq!(v["peerId"], "p", "a bare value passes through");
        let v = unwrap_envelope("t", serde_json::json!({"success": true, "value": "16Uiu2HAm"})).unwrap();
        assert_eq!(v, "16Uiu2HAm", "a plain string value stays a string");
        let e = unwrap_envelope("t", serde_json::json!({"success": false, "error": "timeout waiting for inbound stream"}))
            .unwrap_err();
        assert!(is_accept_timeout(&e), "{e}");
    }
}
