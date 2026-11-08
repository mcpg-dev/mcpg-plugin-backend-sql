//! Run-time loadable SQLite extensions.
//!
//! An extension is native code that runs inside the gateway process with
//! the gateway's privileges, so a binding's config alone cannot load one.
//! Two parties must agree:
//!
//! * whoever starts the gateway names the approved directories in
//!   [`EXTENSION_DIRS_ENV`] (absent or empty: loading is off); and
//! * the binding names each file and pins its SHA-256.
//!
//! Before the pool opens, and again before every new connection loads
//! the files, each file must pass all of these checks:
//!
//! 1. Its canonical path (symbolic links resolved) is inside a canonical
//!    approved directory.
//! 2. It is a regular file of at most [`MAX_EXTENSION_BYTES`].
//! 3. The file and every directory above it are owned by root or by the
//!    gateway's effective user. None is writable by group or others, except
//!    a directory with the sticky bit (such as `/tmp`): there only an
//!    entry's owner can rename or remove it.
//! 4. Its SHA-256 equals the pin. A new connection hashes the file again
//!    only when its device, inode, size, mtime or ctime changed.
//!
//! The load turns on only the C entry point (`SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION`)
//! and turns it off again before the connection serves a query. The SQL
//! function `load_extension()` stays off on every connection.
//!
//! The checks run before `dlopen`. Whoever can write the file as its owner
//! can still replace it between the check and the load, so the owner
//! should be root. A process keeps a library that it has loaded: a changed
//! file at the same path can go on running the old code until the gateway
//! restarts.
//!
//! Supported on Unix only; on other platforms every load is refused.

use std::ffi::{CStr, CString, c_char, c_int};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use parking_lot::Mutex;
use sqlx::sqlite::{LockedSqliteHandle, SqliteConnection};

use crate::config::SqliteExtension;
use crate::errors::SqlError;

/// Environment variable that lists the directories extensions may load
/// from, separated like `PATH`.
pub const EXTENSION_DIRS_ENV: &str = "MCPG_SQLITE_EXTENSION_DIRS";

/// Largest extension file accepted.
pub const MAX_EXTENSION_BYTES: u64 = 256 * 1024 * 1024;

const TRACE_TARGET: &str = "mcpg::sql::sqlite_ext";

/// Where extensions may load from, fixed when the driver is built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtensionPolicy {
    /// No directory is approved; every load is refused.
    Off,
    /// The approved directories, as given (absolute, not yet canonical).
    Dirs(Vec<PathBuf>),
    /// The approved-directory list is malformed; every load is refused
    /// with this reason.
    Invalid(String),
}

impl ExtensionPolicy {
    /// Read [`EXTENSION_DIRS_ENV`] from the process environment.
    pub fn from_env() -> Self {
        match std::env::var_os(EXTENSION_DIRS_ENV) {
            None => Self::Off,
            Some(list) => Self::from_dirs(std::env::split_paths(&list).collect()),
        }
    }

    /// Build a policy from a directory list. Empty entries are dropped;
    /// a relative entry makes the whole list invalid.
    pub fn from_dirs(dirs: Vec<PathBuf>) -> Self {
        let dirs: Vec<PathBuf> = dirs
            .into_iter()
            .filter(|d| !d.as_os_str().is_empty())
            .collect();
        if dirs.is_empty() {
            return Self::Off;
        }
        if let Some(rel) = dirs.iter().find(|d| !d.is_absolute()) {
            return Self::Invalid(format!(
                "{EXTENSION_DIRS_ENV} entry '{}' is not an absolute path",
                rel.display()
            ));
        }
        Self::Dirs(dirs)
    }
}

/// The identity of a file's content as the file system reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Fingerprint {
    dev: u64,
    ino: u64,
    size: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}

/// An extension that passed every check, ready to load.
#[derive(Debug)]
pub struct ApprovedExtension {
    /// As the binding wrote it.
    configured: PathBuf,
    /// Canonical; the path every load uses.
    path: PathBuf,
    c_path: CString,
    entrypoint: Option<CString>,
    sha256: [u8; 32],
    /// The file state whose content last matched the pin.
    verified: Mutex<Fingerprint>,
}

impl ApprovedExtension {
    /// The canonical path the extension loads from.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Repeat the checks before a new connection loads the file. Hashes
    /// again only when the file changed since it last matched.
    fn recheck(&self) -> Result<(), String> {
        let now = std::fs::canonicalize(&self.configured)
            .map_err(|e| format!("'{}': {e}", self.configured.display()))?;
        if now != self.path {
            return Err(format!(
                "'{}' now resolves to '{}', not the approved '{}'",
                self.configured.display(),
                now.display(),
                self.path.display()
            ));
        }
        platform::check_parents(&self.path)?;
        let known = *self.verified.lock();
        let seen = platform::check_and_hash(&self.path, &self.sha256, Some(known))?;
        if seen != known {
            tracing::info!(
                target: TRACE_TARGET,
                path = %self.path.display(),
                "SQLite extension file changed on disk and still matches its sha256"
            );
            *self.verified.lock() = seen;
        }
        Ok(())
    }
}

/// Approve every extension of a binding, in order. Blocking: it reads
/// and hashes each file.
pub fn approve_all(
    policy: &ExtensionPolicy,
    extensions: &[SqliteExtension],
) -> Result<Vec<Arc<ApprovedExtension>>, SqlError> {
    let mut out: Vec<Arc<ApprovedExtension>> = Vec::with_capacity(extensions.len());
    for ext in extensions {
        let approved = approve(policy, ext).map_err(|why| {
            SqlError::InvalidSpec(format!("sqlite extension '{}': {why}", ext.path.display()))
        })?;
        if out.iter().any(|a| a.path == approved.path) {
            return Err(SqlError::InvalidSpec(format!(
                "sqlite extension '{}': resolves to '{}', which another entry loads already",
                ext.path.display(),
                approved.path.display()
            )));
        }
        tracing::info!(
            target: TRACE_TARGET,
            path = %approved.path.display(),
            sha256 = %hex::encode(approved.sha256),
            entrypoint = ext.entrypoint.as_deref().unwrap_or("(default)"),
            "approved SQLite extension"
        );
        out.push(Arc::new(approved));
    }
    Ok(out)
}

fn approve(policy: &ExtensionPolicy, ext: &SqliteExtension) -> Result<ApprovedExtension, String> {
    let dirs = match policy {
        ExtensionPolicy::Off => {
            return Err(format!(
                "loading SQLite extensions is off: the gateway's environment does not set \
                 {EXTENSION_DIRS_ENV} to the directories that hold approved extensions"
            ));
        }
        ExtensionPolicy::Invalid(why) => return Err(why.clone()),
        ExtensionPolicy::Dirs(dirs) => dirs,
    };
    platform::supported()?;
    let sha256 = ext.sha256_bytes().map_err(|e| e.to_string())?;

    let mut approved_dirs = Vec::with_capacity(dirs.len());
    for dir in dirs {
        let canonical = std::fs::canonicalize(dir)
            .map_err(|e| format!("{EXTENSION_DIRS_ENV} entry '{}': {e}", dir.display()))?;
        approved_dirs.push(canonical);
    }

    let path = std::fs::canonicalize(&ext.path).map_err(|e| e.to_string())?;
    if !approved_dirs
        .iter()
        .any(|dir| path != *dir && path.starts_with(dir))
    {
        let list = approved_dirs
            .iter()
            .map(|d| d.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        return Err(format!(
            "'{}' is not inside a directory that {EXTENSION_DIRS_ENV} approves ({list})",
            path.display()
        ));
    }

    platform::check_parents(&path)?;
    let fingerprint = platform::check_and_hash(&path, &sha256, None)?;

    let c_path = platform::c_path(&path)?;
    let entrypoint = ext
        .entrypoint
        .as_deref()
        .map(CString::new)
        .transpose()
        .map_err(|_| "entrypoint contains a NUL byte".to_owned())?;

    Ok(ApprovedExtension {
        configured: ext.path.clone(),
        path,
        c_path,
        entrypoint,
        sha256,
        verified: Mutex::new(fingerprint),
    })
}

/// Check the files again, then load them into `conn`.
pub async fn load_into_connection(
    conn: &mut SqliteConnection,
    extensions: Arc<Vec<Arc<ApprovedExtension>>>,
) -> Result<(), String> {
    let checked = Arc::clone(&extensions);
    tokio::task::spawn_blocking(move || {
        checked.iter().try_for_each(|ext| {
            ext.recheck()
                .map_err(|why| format!("sqlite extension '{}': {why}", ext.configured.display()))
        })
    })
    .await
    .map_err(|e| format!("sqlite extension check did not finish: {e}"))??;

    let mut handle = conn
        .lock_handle()
        .await
        .map_err(|e| format!("sqlite extension load: {e}"))?;
    load_locked(&mut handle, &extensions)
}

/// The pool's `after_connect` hook. The pool retries a failed connection
/// until its acquire timeout and then reports only the timeout, so the
/// reason is logged here.
pub async fn after_connect(
    conn: &mut SqliteConnection,
    extensions: Arc<Vec<Arc<ApprovedExtension>>>,
) -> Result<(), sqlx::Error> {
    load_into_connection(conn, extensions).await.map_err(|why| {
        tracing::warn!(target: TRACE_TARGET, reason = %why, "refused a new SQLite connection");
        sqlx::Error::Configuration(why.into())
    })
}

fn load_locked(
    handle: &mut LockedSqliteHandle<'_>,
    extensions: &[Arc<ApprovedExtension>],
) -> Result<(), String> {
    let db = handle.as_raw_handle().as_ptr();
    set_c_loading(db, true)?;
    let loaded = extensions.iter().try_for_each(|ext| load_one(db, ext));
    let closed = set_c_loading(db, false);
    loaded?;
    closed
}

#[allow(unsafe_code)]
fn set_c_loading(db: *mut libsqlite3_sys::sqlite3, on: bool) -> Result<(), String> {
    let mut now: c_int = -1;
    // SAFETY: `db` is the open connection the caller holds locked; the
    // option takes an int and an int out-pointer.
    let rc = unsafe {
        libsqlite3_sys::sqlite3_db_config(
            db,
            libsqlite3_sys::SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION,
            c_int::from(on),
            &mut now as *mut c_int,
        )
    };
    if rc != libsqlite3_sys::SQLITE_OK || now != c_int::from(on) {
        return Err(format!(
            "could not turn SQLite extension loading {} (code {rc})",
            if on { "on" } else { "off" }
        ));
    }
    Ok(())
}

#[allow(unsafe_code)]
fn load_one(db: *mut libsqlite3_sys::sqlite3, ext: &ApprovedExtension) -> Result<(), String> {
    let mut message: *mut c_char = std::ptr::null_mut();
    // SAFETY: `db` is the open connection the caller holds locked; both
    // strings are NUL-terminated and outlive the call; SQLite allocates
    // `message`, which is freed below with `sqlite3_free`.
    let rc = unsafe {
        libsqlite3_sys::sqlite3_load_extension(
            db,
            ext.c_path.as_ptr(),
            ext.entrypoint
                .as_ref()
                .map_or(std::ptr::null(), |e| e.as_ptr()),
            &mut message,
        )
    };
    if rc == libsqlite3_sys::SQLITE_OK {
        return Ok(());
    }
    let detail = if message.is_null() {
        format!("code {rc}")
    } else {
        // SAFETY: SQLite set `message` to a NUL-terminated string it
        // allocated; it is read once and then freed.
        unsafe {
            let text = CStr::from_ptr(message).to_string_lossy().into_owned();
            libsqlite3_sys::sqlite3_free(message.cast());
            text
        }
    };
    Err(format!("loading '{}': {detail}", ext.path.display()))
}

#[cfg(unix)]
mod platform {
    use std::fs::{File, Metadata};
    use std::io::Read;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::Path;

    use super::{Fingerprint, MAX_EXTENSION_BYTES};

    #[allow(unsafe_code)]
    unsafe extern "C" {
        fn geteuid() -> u32;
    }

    const GROUP_OR_OTHER_WRITE: u32 = 0o022;
    const STICKY: u32 = 0o1000;

    pub(super) fn supported() -> Result<(), String> {
        Ok(())
    }

    pub(super) fn c_path(path: &Path) -> Result<std::ffi::CString, String> {
        std::ffi::CString::new(path.as_os_str().as_bytes())
            .map_err(|_| "path contains a NUL byte".to_owned())
    }

    #[allow(unsafe_code)]
    fn owner_allowed(uid: u32) -> bool {
        // SAFETY: geteuid has no preconditions and cannot fail.
        uid == 0 || uid == unsafe { geteuid() }
    }

    /// Every directory from the file's parent up to `/`.
    pub(super) fn check_parents(file: &Path) -> Result<(), String> {
        for dir in file.ancestors().skip(1) {
            let md = std::fs::metadata(dir).map_err(|e| format!("'{}': {e}", dir.display()))?;
            if !owner_allowed(md.uid()) {
                return Err(format!(
                    "directory '{}' is owned by uid {}, not by root or the gateway's user",
                    dir.display(),
                    md.uid()
                ));
            }
            let mode = md.permissions().mode();
            if mode & GROUP_OR_OTHER_WRITE != 0 && mode & STICKY == 0 {
                return Err(format!(
                    "directory '{}' is writable by group or others (mode {:o})",
                    dir.display(),
                    mode & 0o7777
                ));
            }
        }
        Ok(())
    }

    fn fingerprint(md: &Metadata) -> Fingerprint {
        Fingerprint {
            dev: md.dev(),
            ino: md.ino(),
            size: md.size(),
            mtime: (md.mtime(), md.mtime_nsec()),
            ctime: (md.ctime(), md.ctime_nsec()),
        }
    }

    /// Check the file's type, owner, mode and size from the open file, and
    /// compare its SHA-256 with the pin unless it still matches `known`.
    pub(super) fn check_and_hash(
        path: &Path,
        expected: &[u8; 32],
        known: Option<Fingerprint>,
    ) -> Result<Fingerprint, String> {
        let mut file = File::open(path).map_err(|e| e.to_string())?;
        let before = file.metadata().map_err(|e| e.to_string())?;
        if !before.is_file() {
            return Err("not a regular file".into());
        }
        if !owner_allowed(before.uid()) {
            return Err(format!(
                "owned by uid {}, not by root or the gateway's user",
                before.uid()
            ));
        }
        let mode = before.permissions().mode();
        if mode & GROUP_OR_OTHER_WRITE != 0 {
            return Err(format!(
                "writable by group or others (mode {:o})",
                mode & 0o7777
            ));
        }
        if before.size() > MAX_EXTENSION_BYTES {
            return Err(format!(
                "{} bytes; the limit is {MAX_EXTENSION_BYTES}",
                before.size()
            ));
        }
        let seen = fingerprint(&before);
        if known == Some(seen) {
            return Ok(seen);
        }

        let mut hasher = hmac_sha256::Hash::new();
        let mut buf = vec![0u8; 64 * 1024];
        let mut total: u64 = 0;
        loop {
            let n = file.read(&mut buf).map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            total += n as u64;
            if total > MAX_EXTENSION_BYTES {
                return Err(format!(
                    "larger than the limit of {MAX_EXTENSION_BYTES} bytes"
                ));
            }
            hasher.update(&buf[..n]);
        }
        let after = file.metadata().map_err(|e| e.to_string())?;
        if fingerprint(&after) != seen || total != seen.size {
            return Err("the file changed while it was read".into());
        }
        let actual = hasher.finalize();
        if &actual != expected {
            return Err(format!(
                "sha256 is {}, but the binding pins {}",
                hex::encode(actual),
                hex::encode(expected)
            ));
        }
        Ok(seen)
    }
}

#[cfg(not(unix))]
mod platform {
    use std::path::Path;

    use super::Fingerprint;

    const UNSUPPORTED: &str = "SQLite extensions load only on Linux and macOS";

    pub(super) fn supported() -> Result<(), String> {
        Err(UNSUPPORTED.into())
    }

    pub(super) fn c_path(_path: &Path) -> Result<std::ffi::CString, String> {
        Err(UNSUPPORTED.into())
    }

    pub(super) fn check_parents(_file: &Path) -> Result<(), String> {
        Err(UNSUPPORTED.into())
    }

    pub(super) fn check_and_hash(
        _path: &Path,
        _expected: &[u8; 32],
        _known: Option<Fingerprint>,
    ) -> Result<Fingerprint, String> {
        Err(UNSUPPORTED.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_is_off_without_directories() {
        assert_eq!(ExtensionPolicy::from_dirs(vec![]), ExtensionPolicy::Off);
        assert_eq!(
            ExtensionPolicy::from_dirs(vec![PathBuf::new(), PathBuf::new()]),
            ExtensionPolicy::Off
        );
    }

    #[test]
    fn policy_refuses_a_relative_directory() {
        let policy =
            ExtensionPolicy::from_dirs(vec![PathBuf::from("/opt/ext"), PathBuf::from("ext")]);
        assert!(
            matches!(&policy, ExtensionPolicy::Invalid(why) if why.contains("'ext'")),
            "{policy:?}"
        );
    }

    #[test]
    fn policy_keeps_absolute_directories_in_order() {
        assert_eq!(
            ExtensionPolicy::from_dirs(vec![PathBuf::from("/a"), PathBuf::from("/b")]),
            ExtensionPolicy::Dirs(vec![PathBuf::from("/a"), PathBuf::from("/b")])
        );
    }

    #[test]
    fn an_off_policy_refuses_every_extension() {
        let ext = SqliteExtension {
            path: PathBuf::from("/opt/ext/vec0.so"),
            sha256: "0".repeat(64),
            entrypoint: None,
        };
        let err = approve_all(&ExtensionPolicy::Off, &[ext]).unwrap_err();
        assert!(err.to_string().contains(EXTENSION_DIRS_ENV), "{err}");
    }
}
