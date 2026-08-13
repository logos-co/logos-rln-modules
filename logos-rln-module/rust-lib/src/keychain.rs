//! OS-keychain auto-unlock: generate-or-fetch the keystore password from the
//! macOS Keychain so a GUI can unlock without prompting. The keystore itself
//! is untouched — `Store::unlock` stays the single verification seam
//! (BadPassword on MAC mismatch, adopt-on-empty), this module only decides
//! WHERE the password comes from.
//!
//! Backend: the `/usr/bin/security` CLI (absolute path — env -i'd daemons
//! strip PATH; env otherwise inherited because the login keychain needs
//! HOME). Reads pass only service/account on argv; writes go through
//! `security -i` stdin batch mode so the secret NEVER appears in argv. The
//! item is written with `-U` (update in place) and `-T /usr/bin/security`
//! (any same-user process can read it via the security tool). Payloads are
//! hex(password_bytes) uniformly: quoting-proof in the batch line and
//! deterministic to read back.
//!
//! The account is the sha256 of the VERBATIM persistence dir string (not
//! canonicalized — macOS /var<->/private/var churn would orphan items), so
//! each module instance owns exactly one item. Missing item + credentials
//! present maps to keychain_unavailable (never invent a secret over an
//! existing keystore). Caveat: deleting an auto-created account's item
//! orphans its credentials — the user never saw the secret.

use crate::registry_id;
use crate::{store, ApiError, ErrorKind};
use sha2::{Digest, Sha256};
use std::sync::Mutex;
use zeroize::Zeroizing;

const SERVICE: &str = "org.logos.rln-membership.keystore";
#[cfg(target_os = "macos")]
const LABEL: &str = "logos-rln-membership-keystore";
#[cfg(target_os = "macos")]
const SECURITY_BIN: &str = "/usr/bin/security";

/// The injectable backend seam: cargo tests NEVER touch the live keychain.
pub(crate) trait Keychain: Send {
    /// Ok(None) = no item (the security CLI's errSecItemNotFound, exit 44).
    fn read(&self, service: &str, account: &str) -> Result<Option<Zeroizing<String>>, String>;
    fn write(&self, service: &str, account: &str, payload_hex: &str) -> Result<(), String>;
}

#[cfg(target_os = "macos")]
struct SecurityCli;

#[cfg(target_os = "macos")]
impl Keychain for SecurityCli {
    fn read(&self, service: &str, account: &str) -> Result<Option<Zeroizing<String>>, String> {
        let out = std::process::Command::new(SECURITY_BIN)
            .args(["find-generic-password", "-s", service, "-a", account, "-w"])
            .output()
            .map_err(|e| format!("spawn {SECURITY_BIN}: {e}"))?;
        if out.status.success() {
            let mut payload = String::from_utf8(out.stdout)
                .map_err(|_| "keychain payload is not utf-8".to_string())?;
            while payload.ends_with('\n') || payload.ends_with('\r') {
                payload.pop();
            }
            return Ok(Some(Zeroizing::new(payload)));
        }
        if out.status.code() == Some(44) {
            return Ok(None);
        }
        Err(format!(
            "find-generic-password exit {:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).chars().take(200).collect::<String>()
        ))
    }

    fn write(&self, service: &str, account: &str, payload_hex: &str) -> Result<(), String> {
        // One batch line over stdin — the secret never appears in argv.
        let line = Zeroizing::new(format!(
            "add-generic-password -U -s {service} -a {account} -l {LABEL} -T {SECURITY_BIN} -w {payload_hex}\n"
        ));
        if run_security_batch(&line).is_ok() {
            return Ok(());
        }
        // -U can fail on an item with a foreign ACL: delete and re-add once.
        let _ = std::process::Command::new(SECURITY_BIN)
            .args(["delete-generic-password", "-s", service, "-a", account])
            .output();
        run_security_batch(&line)
    }
}

#[cfg(target_os = "macos")]
fn run_security_batch(line: &str) -> Result<(), String> {
    use std::io::Write;
    let mut child = std::process::Command::new(SECURITY_BIN)
        .arg("-i")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn {SECURITY_BIN} -i: {e}"))?;
    child
        .stdin
        .take()
        .ok_or_else(|| "no stdin pipe".to_string())?
        .write_all(line.as_bytes())
        .map_err(|e| format!("write batch line: {e}"))?;
    let out = child
        .wait_with_output()
        .map_err(|e| format!("wait {SECURITY_BIN}: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "security -i exit {:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).chars().take(200).collect::<String>()
        ))
    }
}

/// Non-macOS: no OS keychain backend — every call maps to
/// keychain_unavailable and the UI falls back to the password screen.
#[cfg(not(target_os = "macos"))]
struct Unavailable;

#[cfg(not(target_os = "macos"))]
impl Keychain for Unavailable {
    fn read(&self, _: &str, _: &str) -> Result<Option<Zeroizing<String>>, String> {
        Err("no OS keychain backend on this platform".to_string())
    }
    fn write(&self, _: &str, _: &str, _: &str) -> Result<(), String> {
        Err("no OS keychain backend on this platform".to_string())
    }
}

fn default_backend() -> Box<dyn Keychain + Send> {
    #[cfg(target_os = "macos")]
    {
        Box::new(SecurityCli)
    }
    #[cfg(not(target_os = "macos"))]
    {
        Box::new(Unavailable)
    }
}

static BACKEND: Mutex<Option<Box<dyn Keychain + Send>>> = Mutex::new(None);

fn with_backend<R>(f: impl FnOnce(&dyn Keychain) -> R) -> R {
    let mut guard = crate::lock(&BACKEND);
    if guard.is_none() {
        *guard = Some(default_backend());
    }
    f(guard.as_ref().expect("backend just installed").as_ref())
}

#[cfg(test)]
pub(crate) fn set_backend_for_tests(backend: Box<dyn Keychain + Send>) {
    *crate::lock(&BACKEND) = Some(backend);
}

#[cfg(test)]
pub(crate) fn reset_backend_for_tests() {
    *crate::lock(&BACKEND) = None;
}

/// One keychain account per module instance: sha256 of the verbatim
/// persistence dir string.
fn account_for_dir(dir: &str) -> String {
    registry_id::bytes_to_hex(&Sha256::digest(dir.as_bytes()))
}

fn keychain_err(message: &str) -> ApiError {
    ApiError::new(ErrorKind::KeychainUnavailable, message)
}

/// unlock_keystore_auto(): fetch (or, for a fresh keystore, generate and
/// persist FIRST) the session password from the keychain, then unlock
/// through the store's normal verification seam.
pub(crate) fn auto_unlock_impl() -> Result<serde_json::Value, ApiError> {
    let dir = store::with_store(|s| Ok(s.base_dir().to_string_lossy().into_owned()))?;
    let account = account_for_dir(&dir);

    let existing = with_backend(|k| k.read(SERVICE, &account)).map_err(|e| keychain_err(&e))?;
    if let Some(payload) = existing {
        let bytes = Zeroizing::new(
            registry_id::hex_to_vec(&payload)
                .ok_or_else(|| keychain_err("keychain item payload is not hex — foreign item?"))?,
        );
        let password = Zeroizing::new(
            String::from_utf8(bytes.to_vec())
                .map_err(|_| keychain_err("keychain item payload is not a utf-8 password"))?,
        );
        let count = store::with_store(|s| s.unlock(&password))?;
        return Ok(serde_json::json!({
            "membership_count": count,
            "secret": password.as_str(),
            "source": "existing",
            "unlocked": true,
        }));
    }

    // No item. Inventing a secret over an existing keystore would guarantee
    // bad_password forever — require one manual unlock instead (which then
    // remembers itself).
    if store::with_store(|s| Ok(s.has_credentials()))? {
        return Err(keychain_err(
            "no keychain item, but the keystore already has credentials — unlock manually once and it will be remembered",
        ));
    }

    let mut raw = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(raw.as_mut())
        .map_err(|e| ApiError::internal(&format!("no entropy for secret: {e}")))?;
    let secret = Zeroizing::new(registry_id::bytes_to_hex(&raw[..]));
    let payload = Zeroizing::new(registry_id::bytes_to_hex(secret.as_bytes()));
    // Item BEFORE unlock: an unlocked keystore keyed by a secret that never
    // reached the keychain would be a guaranteed future lockout.
    with_backend(|k| k.write(SERVICE, &account, &payload))
        .map_err(|e| keychain_err(&format!("could not save the generated secret: {e}")))?;
    let count = store::with_store(|s| s.unlock(&secret))?;
    Ok(serde_json::json!({
        "membership_count": count,
        "secret": secret.as_str(),
        "source": "created",
        "unlocked": true,
    }))
}

/// remember_keystore_password(): persist the CURRENT session password so the
/// next launch unlocks silently — the manual-to-auto migration hook. The
/// plaintext never re-crosses the wire; it is read from the store here.
pub(crate) fn remember_impl() -> Result<serde_json::Value, ApiError> {
    let (dir, password) = store::with_store(|s| {
        Ok((s.base_dir().to_string_lossy().into_owned(), s.session_password()))
    })?;
    let password = password.ok_or_else(|| {
        ApiError::new(ErrorKind::Locked, "keystore is locked — unlock before remembering")
    })?;
    let account = account_for_dir(&dir);
    let payload = Zeroizing::new(registry_id::bytes_to_hex(password.as_bytes()));
    with_backend(|k| k.write(SERVICE, &account, &payload)).map_err(|e| keychain_err(&e))?;
    Ok(serde_json::json!({ "remembered": true }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    /// In-memory fake sharing state with the test through Arcs — the live
    /// keychain is never touched by cargo tests.
    struct FakeKeychain {
        items: Arc<Mutex<HashMap<String, String>>>,
        fail_writes: Arc<AtomicBool>,
    }

    impl Keychain for FakeKeychain {
        fn read(&self, service: &str, account: &str) -> Result<Option<Zeroizing<String>>, String> {
            let key = format!("{service}/{account}");
            Ok(crate::lock(&self.items).get(&key).cloned().map(Zeroizing::new))
        }
        fn write(&self, service: &str, account: &str, payload_hex: &str) -> Result<(), String> {
            if self.fail_writes.load(Ordering::SeqCst) {
                return Err("simulated keychain write denial".to_string());
            }
            let key = format!("{service}/{account}");
            crate::lock(&self.items).insert(key, payload_hex.to_string());
            Ok(())
        }
    }

    struct Fixture {
        items: Arc<Mutex<HashMap<String, String>>>,
        fail_writes: Arc<AtomicBool>,
        dir: std::path::PathBuf,
    }

    fn setup(tag: &str) -> Fixture {
        let items = Arc::new(Mutex::new(HashMap::new()));
        let fail_writes = Arc::new(AtomicBool::new(false));
        set_backend_for_tests(Box::new(FakeKeychain {
            items: items.clone(),
            fail_writes: fail_writes.clone(),
        }));
        let dir = std::env::temp_dir().join(format!("rln-ms-keychain-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        store::init(dir.clone());
        Fixture { items, fail_writes, dir }
    }

    fn teardown(fixture: &Fixture) {
        reset_backend_for_tests();
        let _ = std::fs::remove_dir_all(&fixture.dir);
    }

    fn seed_item(fixture: &Fixture, password: &str) {
        let account = account_for_dir(&fixture.dir.to_string_lossy());
        crate::lock(&fixture.items).insert(
            format!("{SERVICE}/{account}"),
            registry_id::bytes_to_hex(password.as_bytes()),
        );
    }

    fn item_payload(fixture: &Fixture) -> Option<String> {
        let account = account_for_dir(&fixture.dir.to_string_lossy());
        crate::lock(&fixture.items).get(&format!("{SERVICE}/{account}")).cloned()
    }

    /// A stored credential so unlock() actually verifies (empty keystores
    /// adopt any password).
    fn store_credential(password: &str) {
        store::with_store(|s| {
            s.unlock(password)?;
            let meta = store::MembershipMeta {
                allocations: Vec::new(),
                allocations_mac: None,
                epoch_size_sec: 0,
                failed_reason: None,
                identity_commitment: "11".repeat(32),
                leaf_index: 7,
                prune_floor: 0,
                rate_limit: 300,
                registry_id: format!("logos:local:{}", "ab".repeat(32)),
                retryable: None,
                rln_identifier: String::new(),
                state: store::MembershipState::Active,
                state_history: vec![],
                submitted_at: 1,
                tx_result: None,
            };
            let credential = store::StoredCredential {
                identity_commitment: "11".repeat(32),
                identity_nullifier: None,
                identity_secret_hash: "22".repeat(32),
                identity_trapdoor: None,
                registry_id: format!("logos:local:{}", "ab".repeat(32)),
            };
            s.insert(&"cd".repeat(32), meta, &credential)?;
            s.lock();
            Ok(())
        })
        .expect("fixture credential");
    }

    #[test]
    fn fresh_create_then_relaunch_reuses_the_item() {
        let _serial = crate::lock(&store::TEST_STORE_LOCK);
        let fixture = setup("fresh");

        let first = auto_unlock_impl().expect("fresh auto-unlock");
        assert!(first.to_string().starts_with(r#"{"membership_count":"#), "got: {first}");
        assert_eq!(first["source"], "created");
        assert_eq!(first["unlocked"], true);
        let secret = first["secret"].as_str().expect("secret in reply").to_string();
        assert_eq!(secret.len(), 64, "32 random bytes as hex");
        assert_eq!(
            item_payload(&fixture).expect("item written"),
            registry_id::bytes_to_hex(secret.as_bytes()),
            "payload is hex(password bytes)"
        );

        // Relaunch: same dir, fresh store — the item is reused, not recreated.
        store::reset_for_tests();
        store::init(fixture.dir.clone());
        let second = auto_unlock_impl().expect("relaunch auto-unlock");
        assert_eq!(second["source"], "existing");
        assert_eq!(second["secret"].as_str(), Some(secret.as_str()));

        teardown(&fixture);
    }

    #[test]
    fn existing_item_unlocks_a_matching_keystore() {
        let _serial = crate::lock(&store::TEST_STORE_LOCK);
        let fixture = setup("match");
        store_credential("pw-manual");
        seed_item(&fixture, "pw-manual");

        let out = auto_unlock_impl().expect("matching secret");
        assert_eq!(out["source"], "existing");
        assert_eq!(out["membership_count"], 1);
        assert_eq!(out["secret"], "pw-manual");

        teardown(&fixture);
    }

    #[test]
    fn mismatched_item_is_bad_password_and_stays_locked() {
        let _serial = crate::lock(&store::TEST_STORE_LOCK);
        let fixture = setup("mismatch");
        store_credential("pw-real");
        seed_item(&fixture, "pw-wrong");

        let err = auto_unlock_impl().unwrap_err();
        assert!(err.to_json().contains(r#""kind":"bad_password""#), "got: {}", err.to_json());
        let locked = store::with_store(|s| Ok(s.session_password().is_none())).unwrap();
        assert!(locked, "a failed auto-unlock must leave the store locked");

        teardown(&fixture);
    }

    #[test]
    fn missing_item_with_credentials_never_invents_a_secret() {
        let _serial = crate::lock(&store::TEST_STORE_LOCK);
        let fixture = setup("no-item");
        store_credential("pw-manual");

        let err = auto_unlock_impl().unwrap_err();
        assert!(
            err.to_json().contains(r#""kind":"keychain_unavailable""#),
            "got: {}",
            err.to_json()
        );
        assert!(item_payload(&fixture).is_none(), "must not write an invented secret");

        teardown(&fixture);
    }

    #[test]
    fn foreign_payload_is_keychain_unavailable() {
        let _serial = crate::lock(&store::TEST_STORE_LOCK);
        let fixture = setup("foreign");
        let account = account_for_dir(&fixture.dir.to_string_lossy());
        crate::lock(&fixture.items)
            .insert(format!("{SERVICE}/{account}"), "not hex at all".to_string());

        let err = auto_unlock_impl().unwrap_err();
        assert!(
            err.to_json().contains(r#""kind":"keychain_unavailable""#),
            "got: {}",
            err.to_json()
        );

        teardown(&fixture);
    }

    #[test]
    fn remember_requires_unlock_then_persists_and_overwrites() {
        let _serial = crate::lock(&store::TEST_STORE_LOCK);
        let fixture = setup("remember");

        let err = remember_impl().unwrap_err();
        assert!(err.to_json().contains(r#""kind":"locked""#), "got: {}", err.to_json());

        store::with_store(|s| s.unlock("pw-one")).unwrap();
        assert_eq!(remember_impl().unwrap().to_string(), r#"{"remembered":true}"#);
        assert_eq!(
            item_payload(&fixture).unwrap(),
            registry_id::bytes_to_hex("pw-one".as_bytes())
        );

        store::with_store(|s| s.unlock("pw-two")).unwrap();
        remember_impl().unwrap();
        assert_eq!(
            item_payload(&fixture).unwrap(),
            registry_id::bytes_to_hex("pw-two".as_bytes()),
            "second remember overwrites"
        );

        teardown(&fixture);
    }

    #[test]
    fn no_store_reports_internal() {
        let _serial = crate::lock(&store::TEST_STORE_LOCK);
        reset_backend_for_tests();
        store::reset_for_tests();
        let err = auto_unlock_impl().unwrap_err();
        assert!(err.to_json().contains(r#""kind":"internal""#), "got: {}", err.to_json());
        let err = remember_impl().unwrap_err();
        assert!(err.to_json().contains(r#""kind":"internal""#), "got: {}", err.to_json());
    }

    #[test]
    fn backend_failure_maps_to_keychain_unavailable() {
        let _serial = crate::lock(&store::TEST_STORE_LOCK);
        let fixture = setup("denied");
        fixture.fail_writes.store(true, Ordering::SeqCst);

        // Fresh keystore, no item: the generated secret cannot be saved —
        // the whole unlock fails (write-before-unlock) and nothing unlocks.
        let err = auto_unlock_impl().unwrap_err();
        assert!(
            err.to_json().contains(r#""kind":"keychain_unavailable""#),
            "got: {}",
            err.to_json()
        );
        let locked = store::with_store(|s| Ok(s.session_password().is_none())).unwrap();
        assert!(locked, "write-before-unlock: denied write must not unlock");

        teardown(&fixture);
    }
}
