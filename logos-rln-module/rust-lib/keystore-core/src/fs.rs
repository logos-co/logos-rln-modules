//! The durable-file layer: fsync-atomic private writes, fail-closed loads
//! with corrupt-file evidence preservation, and an exclusive per-directory
//! process lock.

use std::fs;
use std::io;
use std::path::Path;

/// tmp + fsync + rename + dir-fsync write of `bytes` to `dir/file_name`;
/// creates `dir` if needed. 0600 perms. The write → fsync(tmp) → rename →
/// fsync(dir) ordering is power-loss-durability-critical and untestable in
/// CI — do not reorder or drop a sync.
pub fn write_durable(dir: &Path, file_name: &str, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    fs::create_dir_all(dir)?;
    let tmp = dir.join(format!("{file_name}.tmp"));
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp)?;
    #[cfg(unix)]
    {
        // mode() applies only at creation; force 0600 if tmp pre-existed.
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    f.write_all(bytes)?;
    sync_or_warn(&f, file_name)?;
    drop(f);
    fs::rename(&tmp, dir.join(file_name))?;
    #[cfg(unix)]
    sync_or_warn(&fs::File::open(dir)?, "parent dir")?;
    Ok(())
}

/// `write_durable` of a pretty-printed JSON serialization.
pub fn write_durable_json<T: serde::Serialize>(
    dir: &Path,
    file_name: &str,
    value: &T,
) -> io::Result<()> {
    let json = serde_json::to_string_pretty(value).map_err(io::Error::other)?;
    write_durable(dir, file_name, json.as_bytes())
}

/// fsync, tolerating filesystems that cannot (`ErrorKind::Unsupported` —
/// network/FUSE mounts): there durability degrades to a stderr warning
/// rather than failing the save; any other error still fails it.
fn sync_or_warn(f: &fs::File, what: &str) -> io::Result<()> {
    match f.sync_all() {
        Err(e) if e.kind() == io::ErrorKind::Unsupported => {
            eprintln!(
                "keystore: {what} fsync unsupported on this filesystem ({e}); continuing \
                 WITHOUT power-loss durability — prefer a local persistence path"
            );
            Ok(())
        }
        r => r,
    }
}

/// Load `dir/file_name` as JSON. A missing file is a fresh (`Default`) one;
/// an unparseable file is quarantined to `.bad.<ts>` and replaced. A file
/// that EXISTS but cannot be read (EIO/EACCES/…) returns `Err`: the caller
/// MUST fail closed — treating "unreadable" as "empty" would invent fresh
/// state over, then clobber, data that was merely temporarily unreadable.
pub fn load_json<T: serde::de::DeserializeOwned + Default>(
    dir: &Path,
    file_name: &str,
) -> io::Result<T> {
    let path = dir.join(file_name);
    let raw = match fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(T::default()),
        Err(e) => return Err(e),
    };
    match serde_json::from_str::<T>(&raw) {
        Ok(file) => Ok(file),
        Err(e) => {
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let bad = dir.join(format!("{file_name}.bad.{ts}"));
            eprintln!(
                "keystore: {file_name} unparseable ({e}); attempting to move aside to {}",
                bad.display()
            );
            if let Err(re) = fs::rename(&path, &bad) {
                eprintln!("keystore: quarantine rename failed ({re}); bad file left in place");
            }
            Ok(T::default())
        }
    }
}

/// Exclusive advisory lock on `dir`, via the `sentinel` file inside it.
/// Advisory: it stops a second WELL-BEHAVED process, not an arbitrary
/// writer, and network/shared-volume filesystems may not honor it. The lock
/// lives as long as the returned `File` (released on drop).
pub fn acquire_dir_lock(dir: &Path, sentinel: &str) -> io::Result<fs::File> {
    fs::create_dir_all(dir)?;
    let f = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(dir.join(sentinel))?;
    match f.try_lock() {
        Ok(()) => Ok(f),
        Err(fs::TryLockError::WouldBlock) => Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            format!("another process holds the lock on {sentinel}"),
        )),
        Err(fs::TryLockError::Error(e)) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, Default, PartialEq, Debug)]
    struct Toy {
        n: u64,
        s: String,
    }

    fn tmp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "keystore-core-test-{tag}-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn missing_is_default_write_roundtrips_and_is_private() {
        let dir = tmp_dir("roundtrip");
        let fresh: Toy = load_json(&dir, "toy.json").unwrap();
        assert_eq!(fresh, Toy::default());

        let value = Toy { n: 7, s: "seven".into() };
        write_durable_json(&dir, "toy.json", &value).unwrap();
        let reloaded: Toy = load_json(&dir, "toy.json").unwrap();
        assert_eq!(reloaded, value);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(dir.join("toy.json")).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "durable writes must be private to the owner");
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn unparseable_is_quarantined_not_overwritten() {
        let dir = tmp_dir("quarantine");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("toy.json"), b"{not json").unwrap();
        let fresh: Toy = load_json(&dir, "toy.json").unwrap();
        assert_eq!(fresh, Toy::default());
        let quarantined = fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .any(|e| e.file_name().to_string_lossy().contains(".bad."));
        assert!(quarantined, "corrupt file must be moved aside as evidence");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn second_locker_is_refused_until_release() {
        let dir = tmp_dir("lock");
        let first = acquire_dir_lock(&dir, "test.lock").unwrap();
        let denied = acquire_dir_lock(&dir, "test.lock");
        assert!(matches!(denied, Err(ref e) if e.kind() == io::ErrorKind::WouldBlock));
        drop(first);
        acquire_dir_lock(&dir, "test.lock").unwrap();
        let _ = fs::remove_dir_all(&dir);
    }
}
