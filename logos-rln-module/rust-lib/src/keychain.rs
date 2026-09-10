//! Auto-unlock: module-owned keystore-password custody. Two stored
//! sources, resolved file-first: the `rln_autounlock.secret` FILE in the
//! keystore dir (the module-owned marker — self-provisioned, all
//! platforms) and the macOS Keychain (the UI-owned / legacy marker;
//! remember_keystore_password's target). By default the module
//! self-provisions at init (`lazy_auto_unlock`), so a fresh store needs
//! ZERO unlock calls; LOGOS_RLN_DISABLE_AUTO_UNLOCK opts out of BOTH that
//! and the wire op. An already provisioned store with no stored secret is
//! USER-owned and stays locked. The keystore itself is untouched —
//! `Store::unlock` stays
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
//! existing keystore). Self-provisioning does NOT write a keychain item: it
//! writes the module-owned `rln_autounlock.secret`, and deleting THAT file
//! orphans the credentials it unlocks — the user never saw the secret.

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

/// Non-macOS: no OS keychain backend. `remember_keystore_password` answers
/// keychain_unavailable and the UI falls back to the password screen; a READ
/// folds to a noted miss instead, so a not-yet-provisioned store still
/// self-provisions from its own secret file.
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

pub(crate) const AUTO_SECRET_FILE: &str = "rln_autounlock.secret";

pub(crate) const DISABLE_ENV: &str = "LOGOS_RLN_DISABLE_AUTO_UNLOCK";

#[cfg(target_os = "macos")]
const REMEMBER_HINT: &str = "unlock manually once and it will be remembered";
#[cfg(not(target_os = "macos"))]
const REMEMBER_HINT: &str = "unlock manually — this platform has no keychain sink, so \
                             remember_keystore_password cannot persist the password for the \
                             next launch";

pub(crate) fn auto_unlock_disabled() -> bool {
    std::env::var_os(DISABLE_ENV).is_some()
}

fn read_file_secret(dir: &std::path::Path) -> (Option<Zeroizing<String>>, Option<String>) {
    match std::fs::read_to_string(dir.join(AUTO_SECRET_FILE)) {
        Ok(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                (None, Some(format!("{AUTO_SECRET_FILE} is present but empty")))
            } else {
                (Some(Zeroizing::new(trimmed.to_string())), None)
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (None, None),
        Err(e) => (None, Some(format!("{AUTO_SECRET_FILE}: {e}"))),
    }
}

fn note_suffix(file: Option<&str>, keychain: Option<&str>) -> String {
    let mut parts = Vec::new();
    if let Some(file) = file {
        parts.push(file.to_string());
    }
    if let Some(keychain) = keychain {
        parts.push(format!("keychain: {keychain}"));
    }
    if parts.is_empty() {
        String::new()
    } else {
        format!(" ({})", parts.join("; "))
    }
}

fn read_keychain_secret(
    account: &str,
) -> Result<(Option<Zeroizing<String>>, Option<String>), ApiError> {
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

fn quarantine_secret_file(dir: &std::path::Path) {
    let bad = dir.join(format!("{AUTO_SECRET_FILE}.bad.{}", crate::now_unix()));
    eprintln!(
        "keystore auto-unlock: {AUTO_SECRET_FILE} does not open this keystore; attempting to \
         move it aside to {}",
        bad.display()
    );
    if let Err(e) = std::fs::rename(dir.join(AUTO_SECRET_FILE), &bad) {
        eprintln!("keystore auto-unlock: quarantine rename failed ({e}); bad file left in place");
    }
}

/// Serializes the read -> maybe-generate+persist -> unlock walk: two
/// concurrent auto-unlocks on a fresh store would otherwise both generate,
/// race the durable secret-file write, and leave one caller's session keyed
/// to a secret the file no longer holds.
static AUTO_UNLOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn auto_unlock_core(
    store: &std::sync::Arc<sealed::Store>,
) -> Result<(usize, &'static str, Zeroizing<String>), ApiError> {
    let _walk = AUTO_UNLOCK.lock().unwrap();
    let dir = store.base_dir().to_path_buf();
    let account = account_for_dir(&dir.to_string_lossy());
    let (file_secret, file_note) = read_file_secret(&dir);
    let mut rejected_file: Option<ApiError> = None;
    if let Some(password) = file_secret {
        match store.unlock(&password) {
            Ok(count) => return Ok((count, "existing", password)),
            Err(e) if e.kind == ErrorKind::BadPassword => {
                quarantine_secret_file(&dir);
                rejected_file = Some(e);
            }
            Err(e) => return Err(e),
        }
    }
    let (found, keychain_note) = read_keychain_secret(&account)?;
    if let Some(password) = found {
        let count = store.unlock(&password)?;
        return Ok((count, "existing", password));
    }
    let note = note_suffix(file_note.as_deref(), keychain_note.as_deref());
    if let Some(e) = rejected_file {
        return Err(ApiError::new(
            ErrorKind::BadPassword,
            &format!(
                "{} — the {AUTO_SECRET_FILE} that held it was moved aside; {REMEMBER_HINT}{note}",
                e.message
            ),
        ));
    }
    if store.is_provisioned() {
        let what = if store.has_credentials() {
            "already has credentials"
        } else {
            "is already provisioned with a password (no credentials yet)"
        };
        return Err(keychain_err(&format!(
            "no stored auto-unlock secret, but the keystore {what} — {REMEMBER_HINT} (restoring \
             the keystore files from a backup first if entries are quarantined){note}",
        )));
    }
    if file_note.is_some() {
        return Err(keychain_err(&format!(
            "the auto-unlock secret file cannot be read, so the module will not self-provision \
             over it — move it aside or repair it first{note}",
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

pub(crate) fn auto_unlock_impl() -> Result<serde_json::Value, ApiError> {
    if auto_unlock_disabled() {
        return Err(keychain_err(&format!(
            "module-owned auto-unlock is disabled on this deployment ({DISABLE_ENV} is set) — \
             unlock with the user's password instead"
        )));
    }
    let store = sealed::current_or_uninit()?;
    let (count, source, secret) = auto_unlock_core(&store)?;
    let mut reply = serde_json::json!({
        "membership_count": count,
        "source": source,
        "unlocked": true,
    });
    if source == "created" {
        reply["secret"] = serde_json::Value::String(secret.as_str().to_string());
    }
    Ok(reply)
}

pub(crate) fn lazy_auto_unlock() {
    if auto_unlock_disabled() {
        return;
    }
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

    fn session_secret() -> Option<String> {
        sealed::current()?.session_password().map(|p| p.to_string())
    }

    fn assert_kind(err: &ApiError, kind: &str) {
        let json = err.to_json();
        assert!(json.contains(&format!(r#""kind":"{kind}""#)), "expected {kind}, got: {json}");
    }

    fn quarantined_secrets(fixture: &Fixture) -> Vec<String> {
        let prefix = format!("{AUTO_SECRET_FILE}.bad.");
        let mut names: Vec<String> = std::fs::read_dir(&fixture.dir)
            .expect("keystore dir")
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with(&prefix))
            .collect();
        names.sort();
        names
    }

    fn sealed_verifier(fixture: &Fixture) -> Option<String> {
        let raw =
            std::fs::read_to_string(fixture.dir.join(crate::sealed_store::format::SEALED_FILE))
                .ok()?;
        let parsed: serde_json::Value = serde_json::from_str(&raw).ok()?;
        parsed.get("verifier")?.as_str().map(str::to_string)
    }

    struct EnvGuard;

    impl EnvGuard {
        fn set() -> EnvGuard {
            std::env::set_var(DISABLE_ENV, "1");
            EnvGuard
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            std::env::remove_var(DISABLE_ENV);
        }
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
        store.insert(&"cd".repeat(32), identity, &credential, 100).expect("fixture credential");
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
        assert!(
            second.get("secret").is_none(),
            "a resume must not re-release the live secret: {second}"
        );
        assert_eq!(file_secret(&fixture).as_deref(), Some(secret.as_str()), "reused, not recreated");
        assert_eq!(session_secret(), Some(secret.clone()), "and it is what unlocked the store");

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
        assert_eq!(
            session_secret().as_deref(),
            Some("pw-file"),
            "the file is the module-owned marker and wins"
        );

        teardown(&fixture);
    }

    #[test]
    fn lazy_auto_unlock_provisions_resumes_and_respects_user_ownership() {
        let _serial = crate::lock(&crate::TEST_GLOBAL_LOCK);
        let fixture = setup("lazy");

        lazy_auto_unlock();
        assert!(fixture.store.session_password().is_some(), "lazy must unlock a fresh store");
        assert!(file_secret(&fixture).is_some(), "lazy must persist the secret file");

        fixture.store.lock();
        lazy_auto_unlock();
        assert!(fixture.store.session_password().is_some(), "lazy must resume from the file");

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
        assert_eq!(session_secret().as_deref(), Some("pw-manual"));

        teardown(&fixture);
    }

    #[test]
    fn mismatched_item_is_bad_password_and_stays_locked() {
        let _serial = crate::lock(&crate::TEST_GLOBAL_LOCK);
        let fixture = setup("mismatch");
        store_credential("pw-real");
        seed_item(&fixture, "pw-wrong");

        let err = auto_unlock_impl().unwrap_err();
        assert_kind(&err, "bad_password");
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
        assert_kind(&err, "keychain_unavailable");
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
        assert_kind(&err, "keychain_unavailable");

        teardown(&fixture);
    }

    #[test]
    fn remember_requires_unlock_then_persists_and_overwrites() {
        let _serial = crate::lock(&crate::TEST_GLOBAL_LOCK);
        let fixture = setup("remember");

        let err = remember_impl().unwrap_err();
        assert_kind(&err, "locked");

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
        assert_kind(&err, "internal");
        let err = remember_impl().unwrap_err();
        assert_kind(&err, "internal");
    }

    #[test]
    fn keychain_read_failure_is_a_miss_not_a_stop() {
        let _serial = crate::lock(&crate::TEST_GLOBAL_LOCK);
        let fixture = setup("read-denied");
        fixture.fail_reads.store(true, Ordering::SeqCst);

        let out = auto_unlock_impl().expect("file provision despite keychain failure");
        assert_eq!(out["source"], "created");
        assert!(file_secret(&fixture).is_some());

        teardown(&fixture);
        let fixture2 = setup("read-denied-creds");
        fixture2.fail_reads.store(true, Ordering::SeqCst);
        store_credential("pw-manual");
        let err = auto_unlock_impl().unwrap_err();
        assert_kind(&err, "keychain_unavailable");
        let json = err.to_json();
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
        assert_kind(&err, "keychain_unavailable");
        teardown(&fixture);
    }

    #[test]
    fn unwritable_dir_fails_closed_before_unlock() {
        let _serial = crate::lock(&crate::TEST_GLOBAL_LOCK);
        let fixture = setup("no-write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&fixture.dir, std::fs::Permissions::from_mode(0o500)).unwrap();
            let err = auto_unlock_impl().unwrap_err();
            assert_kind(&err, "internal");
            assert!(
                fixture.store.session_password().is_none(),
                "persist-before-unlock: a failed secret write must not unlock"
            );
            std::fs::set_permissions(&fixture.dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        teardown(&fixture);
    }

    #[test]
    fn the_opt_out_env_var_binds_both_surfaces() {
        let _serial = crate::lock(&crate::TEST_GLOBAL_LOCK);
        let fixture = setup("opted-out");
        let env = EnvGuard::set();

        let err = auto_unlock_impl().unwrap_err();
        assert_kind(&err, "keychain_unavailable");
        assert!(err.message.contains(DISABLE_ENV), "the refusal must name it: {}", err.message);
        assert!(file_secret(&fixture).is_none(), "an opted-out deployment provisions no secret");
        assert!(sealed_verifier(&fixture).is_none(), "and never touches the sealed header");
        assert!(fixture.store.session_password().is_none());

        lazy_auto_unlock();
        assert!(fixture.store.session_password().is_none(), "opted out: init must not unlock");
        assert!(file_secret(&fixture).is_none(), "opted out: init must not self-provision");
        assert!(sealed_verifier(&fixture).is_none());
        teardown(&fixture);

        let fixture2 = setup("opted-out-remembered");
        store_credential("pw-file");
        crate::sealed_store::fs::write_durable(&fixture2.dir, AUTO_SECRET_FILE, b"pw-file")
            .expect("seed a stored secret");
        assert!(auto_unlock_impl().is_err(), "a stored secret stays unused while opted out");
        assert!(fixture2.store.session_password().is_none());

        drop(env);
        let out = auto_unlock_impl().expect("auto-unlock once the opt-out is cleared");
        assert_eq!(out["source"], "existing");
        assert_eq!(session_secret().as_deref(), Some("pw-file"));

        teardown(&fixture2);
    }

    #[test]
    fn a_provisioned_but_empty_store_is_never_self_provisioned_over() {
        let _serial = crate::lock(&crate::TEST_GLOBAL_LOCK);
        let fixture = setup("provisioned-empty");
        fixture.store.unlock("pw-user").expect("user provisions the empty store");
        fixture.store.lock();
        let verifier = sealed_verifier(&fixture).expect("header provisioned");

        let err = auto_unlock_impl().unwrap_err();
        assert_kind(&err, "keychain_unavailable");
        assert!(file_secret(&fixture).is_none(), "must not invent a secret over a user password");
        assert!(fixture.store.session_password().is_none());
        assert_eq!(
            sealed_verifier(&fixture).as_deref(),
            Some(verifier.as_str()),
            "the header must not be rekeyed"
        );

        lazy_auto_unlock();
        assert!(fixture.store.session_password().is_none(), "lazy must leave it locked");
        assert_eq!(sealed_verifier(&fixture).as_deref(), Some(verifier.as_str()));

        assert_eq!(fixture.store.unlock("pw-user").expect("user password survives"), 0);

        teardown(&fixture);
    }

    #[test]
    fn a_bad_file_secret_is_quarantined_and_the_keychain_takes_over() {
        let _serial = crate::lock(&crate::TEST_GLOBAL_LOCK);
        let fixture = setup("bad-file");
        store_credential("pw-real");
        crate::sealed_store::fs::write_durable(&fixture.dir, AUTO_SECRET_FILE, b"pw-stale")
            .expect("seed a stale file secret");
        seed_item(&fixture, "pw-real");

        let out = auto_unlock_impl().expect("the keychain takes over once the file is aside");
        assert_eq!(out["source"], "existing");
        assert_eq!(out["membership_count"], 1);
        assert_eq!(session_secret().as_deref(), Some("pw-real"));
        assert!(file_secret(&fixture).is_none(), "the bad file must stop shadowing the keychain");
        let quarantined = quarantined_secrets(&fixture);
        assert_eq!(quarantined.len(), 1, "exactly one quarantined file: {quarantined:?}");
        assert_eq!(
            std::fs::read_to_string(fixture.dir.join(&quarantined[0])).unwrap(),
            "pw-stale",
            "the evidence is preserved verbatim"
        );

        teardown(&fixture);
    }

    #[test]
    fn a_bad_file_secret_never_bricks_the_documented_recovery() {
        let _serial = crate::lock(&crate::TEST_GLOBAL_LOCK);
        let fixture = setup("bad-file-only");
        store_credential("pw-real");
        crate::sealed_store::fs::write_durable(&fixture.dir, AUTO_SECRET_FILE, b"pw-stale")
            .expect("seed a stale file secret");

        let err = auto_unlock_impl().unwrap_err();
        assert_kind(&err, "bad_password");
        assert!(err.message.contains(REMEMBER_HINT), "got: {}", err.message);
        assert!(fixture.store.session_password().is_none());
        assert!(file_secret(&fixture).is_none());
        assert_eq!(quarantined_secrets(&fixture).len(), 1);

        fixture.store.unlock("pw-real").expect("manual unlock");
        remember_impl().expect("remember the manual password");
        fixture.store.lock();
        let out = auto_unlock_impl().expect("the remembered password is no longer shadowed");
        assert_eq!(out["source"], "existing");
        assert_eq!(session_secret().as_deref(), Some("pw-real"));
        assert_eq!(quarantined_secrets(&fixture).len(), 1, "the evidence survives the recovery");

        teardown(&fixture);
    }

    #[test]
    fn an_unreadable_secret_file_is_diagnosed_and_never_provisioned_over() {
        let _serial = crate::lock(&crate::TEST_GLOBAL_LOCK);
        let fixture = setup("unreadable");
        std::fs::create_dir_all(fixture.dir.join(AUTO_SECRET_FILE)).expect("unreadable secret");

        let err = auto_unlock_impl().unwrap_err();
        assert_kind(&err, "keychain_unavailable");
        assert!(
            err.message.contains(AUTO_SECRET_FILE),
            "the refusal must name the unreadable file: {}",
            err.message
        );
        assert!(fixture.store.session_password().is_none());
        assert!(sealed_verifier(&fixture).is_none(), "the header must not be provisioned");
        assert!(fixture.dir.join(AUTO_SECRET_FILE).is_dir(), "the file must survive untouched");

        teardown(&fixture);
        let fixture2 = setup("unreadable-creds");
        store_credential("pw-manual");
        std::fs::create_dir_all(fixture2.dir.join(AUTO_SECRET_FILE)).expect("unreadable secret");
        let err = auto_unlock_impl().unwrap_err();
        assert_kind(&err, "keychain_unavailable");
        assert!(err.message.contains(AUTO_SECRET_FILE), "got: {}", err.message);
        assert!(fixture2.store.session_password().is_none());

        teardown(&fixture2);
    }

    #[test]
    fn the_recovery_hint_is_platform_honest() {
        let _serial = crate::lock(&crate::TEST_GLOBAL_LOCK);
        let fixture = setup("hint");
        store_credential("pw-manual");

        let err = auto_unlock_impl().unwrap_err();
        assert!(err.message.contains(REMEMBER_HINT), "got: {}", err.message);
        assert_eq!(
            err.message.contains("it will be remembered"),
            cfg!(target_os = "macos"),
            "the promise must match the platform's keychain sink: {}",
            err.message
        );

        teardown(&fixture);
    }
}
