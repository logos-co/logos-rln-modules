//! Wallet-home provisioning under the module's persistence dir.
//!
//! Sandboxed ui_qml views cannot create files and the external wallet
//! module cannot provision its own config, so this module — owner of the
//! host-stamped writable dir the keystore lives in — provisions a
//! `wallet-home/` sibling: mkdir -p, write `wallet_config.json` once (the
//! shape tools/deployments/stage.sh emits, with the caller's
//! sequencer_addr), and report where `storage.json` would live. Creating
//! storage stays the wallet module's job (`create_new`), and an existing
//! config is never rewritten — a second call with a different
//! sequencer_addr must not silently re-point a wallet.

use crate::{store, ApiError, ErrorKind};

pub(crate) fn provision_impl(options_json: &str) -> Result<serde_json::Value, ApiError> {
    let raw = options_json.trim();
    let opts: serde_json::Value = serde_json::from_str(if raw.is_empty() { "{}" } else { raw })
        .map_err(|e| ApiError::new(ErrorKind::InvalidArgument, &format!("options_json: {e}")))?;
    let sequencer = opts
        .get("sequencer_addr")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if sequencer.is_empty() {
        return Err(ApiError::new(
            ErrorKind::InvalidArgument,
            "options_json.sequencer_addr is required",
        ));
    }

    let home = store::with_store(|s| Ok(s.base_dir().join("wallet-home")))?;
    std::fs::create_dir_all(&home)
        .map_err(|e| ApiError::internal(&format!("create {}: {e}", home.display())))?;

    let config_path = home.join("wallet_config.json");
    let storage_path = home.join("storage.json");
    let config_existed = config_path.exists();
    if !config_existed {
        let config = serde_json::json!({
            "sequencer_addr": sequencer,
            "seq_poll_timeout": "30s",
            "seq_tx_poll_max_blocks": 15,
            "seq_poll_max_retries": 10,
            "seq_block_poll_max_amount": 100,
        });
        // Atomic tmp+rename: the wallet module reads this file from another
        // process.
        let tmp = home.join("wallet_config.json.tmp");
        std::fs::write(&tmp, config.to_string())
            .and_then(|()| std::fs::rename(&tmp, &config_path))
            .map_err(|e| ApiError::internal(&format!("write {}: {e}", config_path.display())))?;
    }

    Ok(serde_json::json!({
        "config_existed": config_existed,
        "config_path": config_path.to_string_lossy(),
        "storage_exists": storage_path.exists(),
        "storage_path": storage_path.to_string_lossy(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store_dir(tag: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("rln-ms-wallet-home-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn missing_sequencer_is_invalid_argument_before_any_io() {
        // Argument validation precedes the store lookup, so this holds even
        // with no store initialized.
        for options in ["", "{}", r#"{"sequencer_addr":""}"#] {
            let err = provision_impl(options).unwrap_err();
            assert!(
                err.to_json().contains(r#""kind":"invalid_argument""#),
                "options {options:?} got: {}",
                err.to_json()
            );
        }
        let err = provision_impl("not json").unwrap_err();
        assert!(err.to_json().contains(r#""kind":"invalid_argument""#));
    }

    #[test]
    fn no_persistence_path_reports_internal() {
        let _serial = crate::lock(&store::TEST_STORE_LOCK);
        store::reset_for_tests();
        let err = provision_impl(r#"{"sequencer_addr":"https://seq.example/"}"#).unwrap_err();
        assert!(err.to_json().contains(r#""kind":"internal""#), "got: {}", err.to_json());
    }

    #[test]
    fn provisions_once_and_never_rewrites_the_config() {
        let _serial = crate::lock(&store::TEST_STORE_LOCK);
        let dir = temp_store_dir("once");
        store::init(dir.clone());

        let first = provision_impl(r#"{"sequencer_addr":"https://seq.example/"}"#).unwrap();
        // Reply-shape pin: compact alphabetical keys, storage NOT created.
        let text = first.to_string();
        assert!(
            text.starts_with(r#"{"config_existed":false,"config_path":"#),
            "got: {text}"
        );
        assert_eq!(first["storage_exists"], false);
        let config_path = std::path::PathBuf::from(first["config_path"].as_str().unwrap());
        let storage_path = std::path::PathBuf::from(first["storage_path"].as_str().unwrap());
        assert_eq!(config_path, dir.join("wallet-home").join("wallet_config.json"));
        assert_eq!(storage_path, dir.join("wallet-home").join("storage.json"));
        assert!(!storage_path.exists(), "provision must not create storage.json");

        // The written config is field-for-field the staged fixtures' shape.
        let on_disk: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&config_path).unwrap()).unwrap();
        assert_eq!(
            on_disk,
            serde_json::json!({
                "sequencer_addr": "https://seq.example/",
                "seq_poll_timeout": "30s",
                "seq_tx_poll_max_blocks": 15,
                "seq_poll_max_retries": 10,
                "seq_block_poll_max_amount": 100,
            })
        );

        // Second call — different sequencer — must report config_existed and
        // leave the file byte-identical (never silently re-point a wallet).
        let before = std::fs::read(&config_path).unwrap();
        let second = provision_impl(r#"{"sequencer_addr":"https://other.example/"}"#).unwrap();
        assert_eq!(second["config_existed"], true);
        assert_eq!(std::fs::read(&config_path).unwrap(), before);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn storage_exists_reflects_the_file() {
        let _serial = crate::lock(&store::TEST_STORE_LOCK);
        let dir = temp_store_dir("storage");
        store::init(dir.clone());

        let opts = r#"{"sequencer_addr":"https://seq.example/"}"#;
        assert_eq!(provision_impl(opts).unwrap()["storage_exists"], false);
        std::fs::write(dir.join("wallet-home").join("storage.json"), b"{}").unwrap();
        assert_eq!(provision_impl(opts).unwrap()["storage_exists"], true);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
