//! Auto-unlock: module-owned keystore-password custody. Two stored
//! sources, resolved file-first: the `rln_autounlock.secret` FILE in the
//! keystore dir (the module-owned marker — self-provisioned, all
//! platforms) and the macOS Keychain (the UI-owned / legacy marker;
//! remember_keystore_password's target). By default the module
//! self-provisions at init (`lazy_auto_unlock`, gated on
//! LOGOS_RLN_DISABLE_AUTO_UNLOCK), so a fresh store needs ZERO unlock
//! calls; a store with credentials but no stored secret is USER-owned and
//! stays locked. The keystore itself is untouched — `Store::unlock` stays
//! the single verification seam (bad_password from the constant-time
//! verifier, adopt-on-empty), this module only decides WHERE the password
//! comes from.
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
use crate::sealed_store::store as sealed;
use crate::{ApiError, ErrorKind};
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

/// The module-owned auto-unlock secret file, stored INSIDE the keystore
/// dir at 0600 and written durably (tmp → fsync → rename) BEFORE the
/// store adopts the password. Presence = the module custodies its own
/// keystore password (the full-lazy default); at-rest confidentiality
/// then reduces to filesystem ACLs, while the ledger's integrity
/// machinery is unaffected. The OS keychain stays a read-compatible
/// source and the remember_keystore_password target; self-provisioned
/// secrets always land in the FILE, uniformly across platforms — no
/// keychain writes without an explicit user action.
pub(crate) const AUTO_SECRET_FILE: &str = "rln_autounlock.secret";

fn read_file_secret(dir: &std::path::Path) -> Option<Zeroizing<String>> {
    let raw = std::fs::read_to_string(dir.join(AUTO_SECRET_FILE)).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(Zeroizing::new(trimmed.to_string()))
    }
}

/// Resolve the stored auto-unlock password: the secret FILE wins (the
/// module-owned marker), then the OS keychain (the UI-owned / legacy
/// marker). A keychain BACKEND failure is a miss with a note, never a
/// hard stop — the file path and manual unlock both remain; a PRESENT
/// but undecodable keychain item stays a hard error (foreign item —
/// generating over it would mask a real misconfiguration).
fn read_auto_password(
    dir: &std::path::Path,
    account: &str,
) -> Result<(Option<Zeroizing<String>>, Option<String>), ApiError> {
    if let Some(secret) = read_file_secret(dir) {
        return Ok((Some(secret), None));
    }
    match with_backend(|k| k.read(SERVICE, account)) {
        Ok(Some(payload)) => {
            let bytes = Zeroizing::new(
                registry_id::hex_to_vec(&payload)
                    .ok_or_else(|| keychain_err("keychain item payload is not hex — foreign item?"))?,
            );
            let password = Zeroizing::new(
                String::from_utf8(bytes.to_vec())
                    .map_err(|_| keychain_err("keychain item payload is not a utf-8 password"))?,
            );
            Ok((Some(password), None))
        }
        Ok(None) => Ok((None, None)),
        Err(e) => Ok((None, Some(e))),
    }
}

/// The shared auto-unlock walk (wire and init-time lazy path alike):
/// stored secret (file, then keychain) → unlock; no secret + credentials
/// → refuse (USER-owned store; inventing a secret would guarantee
/// bad_password forever); no secret + fresh store → generate, persist the
/// FILE durably FIRST (an unlocked keystore keyed by a secret that never
/// reached disk would be a guaranteed future lockout), then unlock.
fn auto_unlock_core(
    store: &std::sync::Arc<sealed::Store>,
) -> Result<(usize, &'static str, Zeroizing<String>), ApiError> {
    let dir = store.base_dir().to_path_buf();
    let account = account_for_dir(&dir.to_string_lossy());
    let (found, keychain_note) = read_auto_password(&dir, &account)?;
    if let Some(password) = found {
        let count = store.unlock(&password)?;
        return Ok((count, "existing", password));
    }
    if store.has_credentials() {
        let note = keychain_note.map(|e| format!(" (keychain: {e})")).unwrap_or_default();
        return Err(keychain_err(&format!(
            "no stored auto-unlock secret, but the keystore already has credentials — unlock \
             manually once (restoring the keystore files from a backup first if entries are \
             quarantined) and it will be remembered{note}",
        )));
    }
    let mut raw = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(raw.as_mut())
        .map_err(|e| ApiError::internal(&format!("no entropy for secret: {e}")))?;
    let secret = Zeroizing::new(registry_id::bytes_to_hex(&raw[..]));
    crate::sealed_store::fs::write_durable(&dir, AUTO_SECRET_FILE, secret.as_bytes())
        .map_err(|e| ApiError::internal(&format!("could not persist the generated secret: {e}")))?;
    let count = store.unlock(&secret)?;
    Ok((count, "created", secret))
}

/// unlock_keystore_auto(): the wire surface over `auto_unlock_core`.
pub(crate) fn auto_unlock_impl() -> Result<serde_json::Value, ApiError> {
    let store = sealed::current_or_uninit()?;
    let (count, source, secret) = auto_unlock_core(&store)?;
    Ok(serde_json::json!({
        "membership_count": count,
        "secret": secret.as_str(),
        "source": source,
        "unlocked": true,
    }))
}

/// Full-lazy module-owned custody, run once at module init: resume the
/// auto-owned session, or — for a store with no credentials and no stored
/// secret — self-provision one, so the keystore works with ZERO unlock
/// calls (the caller gates on LOGOS_RLN_DISABLE_AUTO_UNLOCK). A store
/// whose credentials exist without a stored secret is USER-owned and
/// stays locked. Failures log and leave the store locked; the wire
/// unlock paths remain authoritative.
pub(crate) fn lazy_auto_unlock() {
    let Some(store) = sealed::current() else { return };
    if store.session_password().is_some() {
        return;
    }
    match auto_unlock_core(&store) {
        Ok((count, source, _)) => {
            eprintln!("keystore auto-unlock at init: {source} ({count} membership(s))");
        }
        Err(e) => eprintln!("keystore auto-unlock at init: staying locked — {}", e.message),
    }
}

/// remember_keystore_password(): persist the CURRENT session password so the
/// next launch unlocks silently — the manual-to-auto migration hook. The
/// plaintext never re-crosses the wire; it is read from the store here.
pub(crate) fn remember_impl() -> Result<serde_json::Value, ApiError> {
    let store = sealed::current_or_uninit()?;
    let dir = store.base_dir().to_string_lossy().into_owned();
    let password = store.session_password().ok_or_else(|| {
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
        fail_reads: Arc<AtomicBool>,
    }

    impl Keychain for FakeKeychain {
        fn read(&self, service: &str, account: &str) -> Result<Option<Zeroizing<String>>, String> {
            if self.fail_reads.load(Ordering::SeqCst) {
                return Err("simulated keychain read denial".to_string());
            }
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
        fail_reads: Arc<AtomicBool>,
        dir: std::path::PathBuf,
        store: Arc<sealed::Store>,
    }

    fn setup(tag: &str) -> Fixture {
        let items = Arc::new(Mutex::new(HashMap::new()));
        let fail_writes = Arc::new(AtomicBool::new(false));
        let fail_reads = Arc::new(AtomicBool::new(false));
        set_backend_for_tests(Box::new(FakeKeychain {
            items: items.clone(),
            fail_writes: fail_writes.clone(),
            fail_reads: fail_reads.clone(),
        }));
        let dir = std::env::temp_dir().join(format!("rln-ms-keychain-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = crate::publish_test_store(dir.clone());
        Fixture { items, fail_writes, fail_reads, dir, store }
    }

    fn file_secret(fixture: &Fixture) -> Option<String> {
        std::fs::read_to_string(fixture.dir.join(AUTO_SECRET_FILE)).ok()
    }

    fn teardown(fixture: &Fixture) {
        reset_backend_for_tests();
        sealed::publish(None);
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
        let store = sealed::current().expect("published test store");
        store.unlock(password).expect("fixture unlock");
        let registry = format!("logos:local:{}", "ab".repeat(32));
        let identity = crate::sealed_store::format::IdentityBlock {
            registry_id: registry.clone(),
            rln_identifier: String::new(),
            identity_commitment: "11".repeat(32),
            submitted_at: 1,
        };
        let credential = crate::lifecycle::StoredCredential {
            identity_commitment: "11".repeat(32),
            identity_nullifier: None,
            identity_secret_hash: "22".repeat(32),
            identity_trapdoor: None,
            registry_id: registry,
        };
        store.insert(&"cd".repeat(32), identity, &credential).expect("fixture credential");
        store.lock();
    }

    #[test]
    fn fresh_create_writes_the_file_then_relaunch_reuses_it() {
        let _serial = crate::lock(&crate::TEST_GLOBAL_LOCK);
        let fixture = setup("fresh");

        let first = auto_unlock_impl().expect("fresh auto-unlock");
        assert!(first.to_string().starts_with(r#"{"membership_count":"#), "got: {first}");
        assert_eq!(first["source"], "created");
        assert_eq!(first["unlocked"], true);
        let secret = first["secret"].as_str().expect("secret in reply").to_string();
        assert_eq!(secret.len(), 64, "32 random bytes as hex");
        // The self-provisioned secret lands in the FILE, never the keychain
        // (keychain writes require an explicit user action).
        assert_eq!(file_secret(&fixture).expect("secret file written"), secret);
        assert!(item_payload(&fixture).is_none(), "self-provision must not touch the keychain");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(fixture.dir.join(AUTO_SECRET_FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "the secret file must be private to the owner");
        }

        // Relaunch: same dir, fresh store — the file is reused, not recreated.
        fixture.store.close();
        let _relaunched = crate::publish_test_store(fixture.dir.clone());
        let second = auto_unlock_impl().expect("relaunch auto-unlock");
        assert_eq!(second["source"], "existing");
        assert_eq!(second["secret"].as_str(), Some(secret.as_str()));

        teardown(&fixture);
    }

    #[test]
    fn file_secret_wins_over_keychain_item() {
        let _serial = crate::lock(&crate::TEST_GLOBAL_LOCK);
        let fixture = setup("file-wins");
        store_credential("pw-file");
        crate::sealed_store::fs::write_durable(&fixture.dir, AUTO_SECRET_FILE, b"pw-file")
            .expect("seed file secret");
        seed_item(&fixture, "pw-keychain");

        let out = auto_unlock_impl().expect("file-first resolution");
        assert_eq!(out["source"], "existing");
        assert_eq!(out["secret"], "pw-file", "the file is the module-owned marker and wins");

        teardown(&fixture);
    }

    #[test]
    fn lazy_auto_unlock_provisions_resumes_and_respects_user_ownership() {
        let _serial = crate::lock(&crate::TEST_GLOBAL_LOCK);
        let fixture = setup("lazy");

        // Fresh store: lazy self-provisions and unlocks — zero calls needed.
        lazy_auto_unlock();
        assert!(fixture.store.session_password().is_some(), "lazy must unlock a fresh store");
        assert!(file_secret(&fixture).is_some(), "lazy must persist the secret file");

        // Relock; lazy resumes from the file.
        fixture.store.lock();
        lazy_auto_unlock();
        assert!(fixture.store.session_password().is_some(), "lazy must resume from the file");

        // A USER-owned store (credentials, no stored secret) stays locked.
        fixture.store.lock();
        std::fs::remove_file(fixture.dir.join(AUTO_SECRET_FILE)).unwrap();
        // Re-key the store to a manual password so the file secret is gone
        // for good: fresh dir, manual credential, no sources.
        teardown(&fixture);
        let fixture2 = setup("lazy-user");
        store_credential("pw-user");
        lazy_auto_unlock();
        assert!(
            fixture2.store.session_password().is_none(),
            "lazy must never invent a secret over a user-owned store"
        );
        assert!(file_secret(&fixture2).is_none(), "and must not write a file either");

        teardown(&fixture2);
    }

    #[test]
    fn existing_item_unlocks_a_matching_keystore() {
        let _serial = crate::lock(&crate::TEST_GLOBAL_LOCK);
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
        let _serial = crate::lock(&crate::TEST_GLOBAL_LOCK);
        let fixture = setup("mismatch");
        store_credential("pw-real");
        seed_item(&fixture, "pw-wrong");

        let err = auto_unlock_impl().unwrap_err();
        assert!(err.to_json().contains(r#""kind":"bad_password""#), "got: {}", err.to_json());
        let locked = fixture.store.session_password().is_none();
        assert!(locked, "a failed auto-unlock must leave the store locked");

        teardown(&fixture);
    }

    #[test]
    fn missing_item_with_credentials_never_invents_a_secret() {
        let _serial = crate::lock(&crate::TEST_GLOBAL_LOCK);
        let fixture = setup("no-item");
        store_credential("pw-manual");

        let err = auto_unlock_impl().unwrap_err();
        assert!(
            err.to_json().contains(r#""kind":"keychain_unavailable""#),
            "got: {}",
            err.to_json()
        );
        assert!(item_payload(&fixture).is_none(), "must not write an invented secret");
        assert!(file_secret(&fixture).is_none(), "must not write an invented secret file");

        teardown(&fixture);
    }

    #[test]
    fn foreign_payload_is_keychain_unavailable() {
        let _serial = crate::lock(&crate::TEST_GLOBAL_LOCK);
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
        let _serial = crate::lock(&crate::TEST_GLOBAL_LOCK);
        let fixture = setup("remember");

        let err = remember_impl().unwrap_err();
        assert!(err.to_json().contains(r#""kind":"locked""#), "got: {}", err.to_json());

        fixture.store.unlock("pw-one").unwrap();
        assert_eq!(remember_impl().unwrap().to_string(), r#"{"remembered":true}"#);
        assert_eq!(
            item_payload(&fixture).unwrap(),
            registry_id::bytes_to_hex("pw-one".as_bytes())
        );

        fixture.store.unlock("pw-two").unwrap();
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
        let _serial = crate::lock(&crate::TEST_GLOBAL_LOCK);
        reset_backend_for_tests();
        sealed::publish(None);
        let err = auto_unlock_impl().unwrap_err();
        assert!(err.to_json().contains(r#""kind":"internal""#), "got: {}", err.to_json());
        let err = remember_impl().unwrap_err();
        assert!(err.to_json().contains(r#""kind":"internal""#), "got: {}", err.to_json());
    }

    #[test]
    fn keychain_read_failure_is_a_miss_not_a_stop() {
        let _serial = crate::lock(&crate::TEST_GLOBAL_LOCK);
        let fixture = setup("read-denied");
        fixture.fail_reads.store(true, Ordering::SeqCst);

        // Fresh keystore + broken keychain backend: the file path still
        // provisions — a keychain outage must not block module-owned custody.
        let out = auto_unlock_impl().expect("file provision despite keychain failure");
        assert_eq!(out["source"], "created");
        assert!(file_secret(&fixture).is_some());

        // With credentials and no sources, the refusal carries the keychain
        // note so the outage is diagnosable.
        fixture.store.lock();
        std::fs::remove_file(fixture.dir.join(AUTO_SECRET_FILE)).unwrap();
        teardown(&fixture);
        let fixture2 = setup("read-denied-creds");
        fixture2.fail_reads.store(true, Ordering::SeqCst);
        store_credential("pw-manual");
        let err = auto_unlock_impl().unwrap_err();
        let json = err.to_json();
        assert!(json.contains(r#""kind":"keychain_unavailable""#), "got: {json}");
        assert!(json.contains("keychain:"), "the keychain outage must be noted: {json}");

        teardown(&fixture2);
    }

    #[test]
    fn remember_write_denial_maps_to_keychain_unavailable() {
        let _serial = crate::lock(&crate::TEST_GLOBAL_LOCK);
        let fixture = setup("remember-denied");
        fixture.store.unlock("pw-one").unwrap();
        fixture.fail_writes.store(true, Ordering::SeqCst);
        let err = remember_impl().unwrap_err();
        assert!(
            err.to_json().contains(r#""kind":"keychain_unavailable""#),
            "got: {}",
            err.to_json()
        );
        teardown(&fixture);
    }

    #[test]
    fn unwritable_dir_fails_closed_before_unlock() {
        let _serial = crate::lock(&crate::TEST_GLOBAL_LOCK);
        let fixture = setup("no-write");
        // Fresh keystore whose dir cannot take the secret file: the whole
        // unlock fails (persist-before-unlock) and nothing unlocks.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&fixture.dir, std::fs::Permissions::from_mode(0o500)).unwrap();
            let err = auto_unlock_impl().unwrap_err();
            assert!(err.to_json().contains(r#""kind":"internal""#), "got: {}", err.to_json());
            assert!(
                fixture.store.session_password().is_none(),
                "persist-before-unlock: a failed secret write must not unlock"
            );
            std::fs::set_permissions(&fixture.dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        teardown(&fixture);
    }
}
