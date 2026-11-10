// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Deployment contract (adr 0034, doc/ops/deploy.md): ceph.conf reading, the OSD data dir
//! (`/var/lib/ceph/osd/<cluster>-<id>/`), host precondition probes and the translation of both into the
//! `croit-flashstore-osd` daemon argument list. Shared by `croit-flashstore-osd run` and `croit-flashstore-tool prepare|activate|list|inspect`.
//! Cold path only; std only.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub use cephconf::{DEFAULT_CLUSTER, conf_path};

pub const DEFAULT_ROOT: &str = "/var/lib/ceph/osd";
/// Default hugepage budget per daemon (MB) when the conf does not say.
pub const DEFAULT_HUGEPAGES_MB: u64 = 2048;

/// Parsed ceph.conf (ini): the shared `cephconf` reader, with the daemon's
/// section views (`[global]` < `[osd]` < `[osd.<id>]`).
#[derive(Clone, Debug, Default)]
pub struct Conf(cephconf::Conf);

impl Conf {
    /// Parse ceph.conf text with the daemon's lenient line rules (the shared
    /// `cephconf` reader: a line without `=` is ignored, the daemon's comment
    /// rule and key normalisation apply).
    pub fn parse(text: &str) -> Conf {
        Conf(cephconf::Conf::parse_lenient(text))
    }

    /// Read and parse the conf at `path`; the error names the path.
    pub fn load(path: &Path) -> Result<Conf, String> {
        cephconf::Conf::load_lenient(path).map(Conf)
    }

    /// [`Conf::load`] with the `io::Error` kept, for callers that must tell "no such file" from "cannot read it".
    fn load_io(path: &Path) -> std::io::Result<Conf> {
        cephconf::Conf::load_io_lenient(path).map(Conf)
    }

    /// Keys of `sections` merged in order (later wins).
    pub fn merged(&self, sections: &[&str]) -> BTreeMap<String, String> {
        self.0.merged(sections)
    }

    /// Value of `key` with `sections` merged in order (later wins), e.g. `["global", "client", "client.admin"]`
    /// for a client option. The key is normalised like every ceph option (spaces and dashes are underscores);
    /// `None` when no section in the list sets it.
    pub fn value(&self, sections: &[&str], key: &str) -> Option<&str> {
        self.0.value(sections, key)
    }

    /// Effective options of `osd.<id>`: `[global]` < `[osd]` < `[osd.<id>]`.
    pub fn for_osd(&self, id: i64) -> BTreeMap<String, String> {
        self.merged(&["global", "osd", &format!("osd.{id}")])
    }

    /// `mon_host` of `osd.<id>` (`[global]` < `[osd]` < `[osd.<id>]`, any key spelling); `None` when unset or empty.
    pub fn mon_host(&self, id: Option<i64>) -> Option<String> {
        let own = id.map(|i| format!("osd.{i}"));
        let mut secs = vec!["global", "osd"];
        if let Some(s) = &own {
            secs.push(s);
        }
        self.merged(&secs)
            .remove("mon_host")
            .filter(|h| !h.is_empty())
    }
}

/// Cluster name that is a path component (`/etc/ceph/<cluster>.conf`, `<root>/<cluster>-<id>`).
fn valid_cluster(c: &str) -> Result<(), String> {
    if c.is_empty()
        || c == "."
        || c == ".."
        || !c
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(format!(
            "bad cluster name {c:?}: letters, digits, `.`, `_`, `-` only, not `.` or `..`"
        ));
    }
    Ok(())
}

/// Value of `--k VALUE`: a trailing `--k` or one followed by another flag/empty value is a usage error, never a silent
/// fallback to a default and never the next flag taken as the value.
fn flag<'a>(a: &'a [String], k: &str) -> Result<Option<&'a str>, String> {
    let Some(i) = a.iter().position(|x| x == k) else {
        return Ok(None);
    };
    match a.get(i + 1) {
        None => Err(format!("{k}: missing value")),
        Some(v) if v.is_empty() => Err(format!("{k}: empty value")),
        Some(v) if v.starts_with("--") => Err(format!("{k}: missing value (got the flag {v})")),
        Some(v) => Ok(Some(v)),
    }
}

/// Cluster name of a command line: `--cluster`, else the last `--set cluster=`, else `$CLUSTER`, else `ceph`.
/// `Err` = usage message ([`valid_cluster`]: the name is a path component).
pub fn cluster_from_args(a: &[String]) -> Result<String, String> {
    let c = flag(a, "--cluster")?
        .map(str::to_owned)
        .or_else(|| {
            a.windows(2)
                .filter(|w| w[0] == "--set")
                .filter_map(|w| w[1].strip_prefix("cluster=").map(str::to_owned))
                .next_back()
        })
        .or_else(|| std::env::var("CLUSTER").ok().filter(|c| !c.is_empty()))
        .unwrap_or_else(|| DEFAULT_CLUSTER.into());
    valid_cluster(&c)?;
    Ok(c)
}

const NO_MON_HOST: &str = "no mon_host: --mon-host ADDR or mon_host in the ceph conf";

/// Mon addresses of a command line: `--mon-host ADDR`, else `mon_host` of its conf file for `--id` ([`conf_file`],
/// [`Conf::mon_host`]). A conf file that exists but cannot be read is reported with its path, not as "no mon_host".
/// `Err` = usage message.
pub fn mon_host_from_args(a: &[String]) -> Result<String, String> {
    if let Some(h) = flag(a, "--mon-host")? {
        return Ok(h.to_owned());
    }
    let path = conf_file(a, &cluster_from_args(a)?)?;
    let id = flag(a, "--id")?.and_then(|s| s.parse::<i64>().ok());
    let conf = match Conf::load_io(&path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(NO_MON_HOST.into()),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    conf.mon_host(id).ok_or_else(|| NO_MON_HOST.into())
}

/// Conf file of a command line: `--conf FILE`, else `/etc/ceph/<cluster>.conf`.
pub fn conf_file(a: &[String], cluster: &str) -> Result<PathBuf, String> {
    Ok(flag(a, "--conf")?.map_or_else(|| conf_path(cluster), PathBuf::from))
}

/// Atomic file replace: `<path>.tmp` is written and fsynced, renamed over `path`, then the parent dir is fsynced.
pub fn write_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
    write_atomic_mode(path, data, 0o666)
}

/// [`write_atomic`] with the file mode (before the umask) the new file is created with, e.g. `0o600` for keys.
/// The temp name is unlinked first and then created with `O_CREAT|O_EXCL|O_NOFOLLOW`: an entry planted at the
/// predictable `<name>.tmp` (symlink, hard link, stale file) is never written through, and a race loses with `EEXIST`.
/// The rename replaces any symlink at `path` itself.
pub fn write_atomic_mode(path: &Path, data: &[u8], mode: u32) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let res = (|| {
        // a stale temp file from a crash keeps its old mode: remove it, then create with `mode` (no reuse).
        // `create_new` refuses an entry planted at the name (symlink or hard link) instead of following it.
        match std::fs::remove_file(&tmp) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .mode(mode)
            .open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
        return res;
    }
    // the rename is only durable with the parent entry on disk: its fsync error is the caller's (not "written")
    if let Some(p) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        use std::os::unix::fs::OpenOptionsExt as _;
        let at = |e: std::io::Error| std::io::Error::new(e.kind(), format!("{}: {e}", p.display()));
        let d = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(p)
            .map_err(at)?;
        d.sync_all().map_err(at)?;
    }
    Ok(())
}

/// Open a directory without following a symlink in the final component and refuse anything that is not a directory.
fn open_dir(dir: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::ffi::OsStrExt as _;
    let c = std::ffi::CString::new(dir.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    // SAFETY: NUL-terminated path; the fd is owned by the returned File.
    let fd = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: fd is open and owned by the File from here on.
    Ok(unsafe { <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(fd) })
}

/// NUL-terminated file name for the `*at` calls; an interior NUL is `InvalidInput`.
fn cstr(s: &str) -> std::io::Result<std::ffi::CString> {
    std::ffi::CString::new(s).map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))
}

// Directory fsyncs of `write_in` on this thread (test seam: the durability ordering has no other observable effect).
#[cfg(test)]
thread_local! {
    static DIR_SYNCS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Write `data` to `name` inside the open directory `dir`: `openat` a new `<name>.tmp` (`O_EXCL|O_NOFOLLOW`), give it the
/// owner and group of `dir` (root `prepare` writes into a dir the daemon user owns), set the mode on the descriptor
/// (`fchmod`, exact, never a path `chmod`), fsync, `renameat` it over `name` (`rename` replaces a symlink at the name
/// itself, never writes through it), then fsync `dir` so the rename is on disk. A stale temp file from a crash is
/// unlinked first.
fn write_in(dir: &std::fs::File, name: &str, data: &[u8], mode: u32) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    let named = |e: std::io::Error| std::io::Error::new(e.kind(), format!("{name}: {e}"));
    let own = dir.metadata().map_err(named)?;
    let tmp = format!("{name}.tmp");
    let (ct, cn) = (cstr(&tmp).map_err(named)?, cstr(name).map_err(named)?);
    // a stale temp file from a crash keeps its old mode: unlink (never follows), then create with `mode`
    // SAFETY: dirfd is open for the life of `dir`; the name is NUL-terminated.
    if unsafe { libc::unlinkat(dir.as_raw_fd(), ct.as_ptr(), 0) } != 0 {
        let e = std::io::Error::last_os_error();
        if e.kind() != std::io::ErrorKind::NotFound {
            return Err(named(e));
        }
    }
    // SAFETY: dirfd is open for the life of `dir`; the name is NUL-terminated.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            ct.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode,
        )
    };
    if fd < 0 {
        return Err(named(std::io::Error::last_os_error()));
    }
    // SAFETY: fd is open and owned by the File from here on.
    let mut f = unsafe { <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(fd) };
    // exact mode at creation (an older file keeps nothing wider): the keyring is a secret
    f.set_permissions(std::fs::Permissions::from_mode(mode))
        .map_err(named)?;
    // same owner as the data dir: the daemon user must be able to read what root `prepare` rewrites
    let got = f.metadata().map_err(named)?;
    if (got.uid(), got.gid()) != (own.uid(), own.gid()) {
        // SAFETY: fd is open; the ids come from the directory that holds the file.
        if unsafe { libc::fchown(fd, own.uid(), own.gid()) } != 0 {
            return Err(named(std::io::Error::last_os_error()));
        }
    }
    f.write_all(data).map_err(named)?;
    f.sync_all().map_err(named)?;
    drop(f);
    // SAFETY: both names are NUL-terminated and relative to the open directory.
    if unsafe { libc::renameat(dir.as_raw_fd(), ct.as_ptr(), dir.as_raw_fd(), cn.as_ptr()) } != 0 {
        return Err(named(std::io::Error::last_os_error()));
    }
    // the rename is only durable with the directory entry on disk (`ready` last is worth nothing otherwise)
    dir.sync_all().map_err(named)?;
    #[cfg(test)]
    DIR_SYNCS.with(|c| c.set(c.get() + 1));
    Ok(())
}

/// Unlink `name` inside the open directory (never follows a symlink; a missing file is fine).
fn remove_in(dir: &std::fs::File, name: &str) -> std::io::Result<()> {
    use std::os::fd::AsRawFd as _;
    let c = cstr(name)?;
    // SAFETY: dirfd is open for the life of `dir`; the name is NUL-terminated.
    if unsafe { libc::unlinkat(dir.as_raw_fd(), c.as_ptr(), 0) } != 0 {
        let e = std::io::Error::last_os_error();
        if e.kind() != std::io::ErrorKind::NotFound {
            return Err(e);
        }
    }
    Ok(())
}

/// UTC civil time of unix seconds: `(year, month, day, hour, minute, second)` (proleptic Gregorian, Hinnant).
pub fn civil_from_secs(secs: u64) -> (u64, u64, u64, u64, u64, u64) {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    (
        y as u64,
        m as u64,
        d as u64,
        rem / 3600,
        rem % 3600 / 60,
        rem % 60,
    )
}

/// Expand ceph metavariables in one pass: `$name` / `${name}`, only the names in `vars`; anything else stays as
/// written (a `$` that does not start a known metavariable is copied, not interpreted twice).
pub fn expand_vars(s: &str, vars: &[(&str, &str)]) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('$') {
        out.push_str(&rest[..i]);
        let after = &rest[i + 1..];
        let (name, used) = if let Some(b) = after.strip_prefix('{') {
            match b.find('}') {
                Some(e) => (&b[..e], e + 2),
                None => ("", 0),
            }
        } else {
            let n = after
                .bytes()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == b'_')
                .count();
            (&after[..n], n)
        };
        match vars.iter().find(|(k, _)| *k == name) {
            Some((_, v)) if used > 0 => {
                out.push_str(v);
                rest = &after[used..];
            }
            _ => {
                out.push('$');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// Expand the metavariables of an OSD path value: `$cluster`, `$type` (`osd`), `$id`, `$name` (`osd.<id>`), also as
/// `${..}`. The same set the daemon expands in `osd_data` (spec cephx.md s2.2): tool and daemon must agree on the path.
pub fn expand(s: &str, cluster: &str, id: i64) -> String {
    let id = id.to_string();
    let name = format!("osd.{id}");
    expand_vars(
        s,
        &[
            ("cluster", cluster),
            ("type", "osd"),
            ("id", &id),
            ("name", &name),
        ],
    )
}

/// Data dir of an OSD: `FLASHSTORE_DATA_DIR` > conf `osd_data` > `/var/lib/ceph/osd/<cluster>-<id>`.
pub fn data_dir(opts: &BTreeMap<String, String>, cluster: &str, id: i64) -> PathBuf {
    if let Ok(d) = std::env::var("FLASHSTORE_DATA_DIR")
        && !d.is_empty()
    {
        return PathBuf::from(d);
    }
    match opts.get("osd_data") {
        Some(d) if !d.is_empty() => PathBuf::from(expand(d, cluster, id)),
        _ => PathBuf::from(format!("{DEFAULT_ROOT}/{cluster}-{id}")),
    }
}

/// Directory that holds the OSD data dirs (`<root>/<cluster>-<id>`): the parent of [`data_dir`] of `id` (`osd_data`,
/// `FLASHSTORE_DATA_DIR`). `prepare`'s one-OSD-per-controller check and `list` scan it ([`scan`]: dirs named
/// `<cluster>-<id>`), so the id in the value is the caller's id, never a placeholder, and an `osd_data` whose parent
/// changes with the id (a `$id`/`$name` in a directory component) is refused instead of scanned at a guess.
pub fn data_root(
    opts: &BTreeMap<String, String>,
    cluster: &str,
    id: i64,
) -> Result<PathBuf, String> {
    let parent = |i: i64| {
        data_dir(opts, cluster, i)
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(Path::to_path_buf)
    };
    let root = parent(id).ok_or_else(|| {
        format!(
            "osd_data {}: no parent directory to scan for the OSD dirs",
            data_dir(opts, cluster, id).display()
        )
    })?;
    if parent(id.saturating_add(1)).as_ref() != Some(&root) {
        return Err(format!(
            "osd_data {}: the OSD dir parent depends on the OSD id, so the controller check and `list` cannot scan \
             the OSD dirs of the cluster (put the OSD dirs under one <root>/<cluster>-<id>)",
            data_dir(opts, cluster, id).display()
        ));
    }
    Ok(root)
}

/// Contents of the OSD data dir.
#[derive(Clone, PartialEq, Eq)]
pub struct OsdDir {
    pub whoami: i64,
    pub osd_uuid: String,
    pub cluster_fsid: String,
    /// `spdk:0000:03:00.0[,ns=N]`
    pub dev: String,
    pub crush_device_class: String,
    /// `[osd.N]\n\tkey = ...` text.
    pub keyring: String,
}

impl OsdDir {
    /// Files: `whoami`, `fsid` (OSD uuid, as classic), `ceph_fsid` (cluster), `keyring` (0600, created that way),
    /// `type` (`bluestore`, adr 0019), `croit-flashstore-osd` (JSON marker: device spec), `ready`. Idempotent, `ready` written last
    /// and removed first (a failed rewrite leaves a dir that is explicitly incomplete, never one with a stale `ready`).
    ///
    /// `prepare` runs as root while the directory belongs to the daemon user: the directory is opened `O_NOFOLLOW` and
    /// every file is written relative to that descriptor (`<name>.tmp` created `O_EXCL|O_NOFOLLOW`, owner/group of the
    /// directory, mode set with `fchmod`, then `renameat` over the name, then the directory is fsynced). A symlink
    /// planted under a fixed name (or for the directory) is never written through; the rename replaces it. The
    /// directory mode is 0750 with the setgid bit kept (files keep inheriting the daemon group).
    pub fn write(&self, dir: &Path) -> Result<(), String> {
        let io = |e: std::io::Error| format!("{}: {e}", dir.display());
        let d = Self::setup(dir)?;
        remove_in(&d, "ready").map_err(io)?;
        // an OSD of an auth-none cluster has no key and no keyring file
        if self.keyring.is_empty() {
            remove_in(&d, "keyring").map_err(io)?;
        }
        for (n, t, m) in self.files() {
            write_in(&d, n, t.as_bytes(), m).map_err(io)?;
        }
        write_in(&d, "ready", b"ready\n", 0o644).map_err(io)
    }

    /// The dir of [`write`]/[`complete`]: created, opened `O_NOFOLLOW`, exclusively locked until the
    /// returned descriptor closes, mode 0750 (setgid kept). Concurrent writers fail without changing files.
    fn setup(dir: &Path) -> Result<std::fs::File, String> {
        use std::os::fd::AsRawFd as _;
        use std::os::unix::fs::PermissionsExt as _;
        let io = |e: std::io::Error| format!("{}: {e}", dir.display());
        std::fs::create_dir_all(dir).map_err(io)?;
        let d = open_dir(dir).map_err(|e| {
            format!(
                "{}: {e} (a data dir that is not a plain directory is refused)",
                dir.display()
            )
        })?;
        // Lock the directory inode: no removable lock-file name can split ownership. The descriptor
        // stays alive across all file checks, temporary writes and the final ready publication.
        // SAFETY: d owns an open directory descriptor.
        if unsafe { libc::flock(d.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(format!(
                "{}: directory writer in use: {}",
                dir.display(),
                std::io::Error::last_os_error()
            ));
        }
        let setgid = d.metadata().map_err(io)?.permissions().mode() & 0o2000;
        d.set_permissions(std::fs::Permissions::from_mode(0o750 | setgid))
            .map_err(io)?;
        Ok(d)
    }

    /// The files of the dir (all except `ready`, which is written last) with their canonical content and mode.
    /// The keyring (0600) is part of the set only when the OSD has a key.
    fn files(&self) -> Vec<(&'static str, String, u32)> {
        let marker = serde_json::json!({
            "dev": self.dev, "osd_id": self.whoami, "osd_uuid": self.osd_uuid,
            "cluster_fsid": self.cluster_fsid, "crush_device_class": self.crush_device_class,
        });
        let mut v = vec![
            ("whoami", format!("{}\n", self.whoami), 0o644),
            ("fsid", format!("{}\n", self.osd_uuid), 0o644),
            ("ceph_fsid", format!("{}\n", self.cluster_fsid), 0o644),
            ("type", "bluestore\n".into(), 0o644),
            ("croit-flashstore-osd", format!("{marker}\n"), 0o644),
        ];
        if !self.keyring.is_empty() {
            v.push(("keyring", self.keyring.clone(), 0o600));
        }
        v
    }

    /// Complete the dir from `self` without touching what is already right: a file that exists with the same
    /// content is left alone, a file that exists with a different content is refused (never overwritten: the
    /// operator must see the difference, e.g. a foreign `whoami` or a keyring of another OSD), a missing file is
    /// written. `ready` is written last, as in [`write`]. Returns the names written (empty = the dir was already
    /// complete).
    pub fn complete(&self, dir: &Path) -> Result<Vec<String>, String> {
        let io = |e: std::io::Error| format!("{}: {e}", dir.display());
        let d = Self::setup(dir)?;
        // an auth-none dir must not carry a keyring file (removing it is a content change we do not make)
        if self.keyring.is_empty() && dir.join("keyring").exists() {
            return Err(format!(
                "{}/keyring: the dir has a keyring file but this OSD has no key: refused (never overwritten)",
                dir.display()
            ));
        }
        let mut written = Vec::new();
        for (n, t, m) in self.files() {
            match std::fs::read(dir.join(n)) {
                Ok(x) if x == t.as_bytes() => continue,
                Ok(_) => {
                    return Err(format!(
                        "{}/{n}: existing file differs from the device identity: refused (never overwritten)",
                        dir.display()
                    ));
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(io(e)),
            }
            write_in(&d, n, t.as_bytes(), m).map_err(io)?;
            written.push(n.to_owned());
        }
        if !dir.join("ready").exists() {
            write_in(&d, "ready", b"ready\n", 0o644).map_err(io)?;
            written.push("ready".into());
        }
        Ok(written)
    }

    /// Decide, without writing, whether `prepare` may publish OSD `whoami` into `dir`: the same decision
    /// [`write`]/[`complete`] make later, taken before anything else is touched. An absent dir is fine; a dir that is
    /// no plain directory, a broken marker, or a marker/file of another identity is refused (`cluster_fsid` and
    /// `keyring` are only compared when already known).
    pub fn admit(
        dir: &Path,
        whoami: i64,
        osd_uuid: &str,
        cluster_fsid: Option<&str>,
        keyring: Option<&str>,
    ) -> Result<(), String> {
        let hint = "move or remove it, or choose another --osd-data-root, then re-run";
        match std::fs::symlink_metadata(dir) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(format!("{}: {e}", dir.display())),
            Ok(m) if !m.is_dir() => {
                return Err(format!(
                    "{}: not a plain directory (a symlink or file is never written through); {hint}",
                    dir.display()
                ));
            }
            Ok(_) => {}
        }
        if dir.join("croit-flashstore-osd").exists() {
            let e = Self::read(dir).map_err(|e| format!("{e}; the dir is broken: {hint}"))?;
            return if e.whoami == whoami
                && e.osd_uuid == osd_uuid
                && cluster_fsid.is_none_or(|f| f == e.cluster_fsid)
            {
                Ok(())
            } else {
                Err(format!(
                    "{}: holds osd.{} (uuid {}, cluster {}), not this OSD (osd.{whoami}, uuid {osd_uuid}): {hint}",
                    dir.display(),
                    e.whoami,
                    e.osd_uuid,
                    e.cluster_fsid
                ))
            };
        }
        let mut want = vec![
            ("whoami", format!("{whoami}\n")),
            ("fsid", format!("{osd_uuid}\n")),
        ];
        if let Some(f) = cluster_fsid {
            want.push(("ceph_fsid", format!("{f}\n")));
        }
        for (n, t) in want {
            match std::fs::read(dir.join(n)) {
                Ok(x) if x != t.as_bytes() => {
                    return Err(format!(
                        "{}/{n}: existing file differs from this OSD: {hint}",
                        dir.display()
                    ));
                }
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                    return Err(format!("{}/{n}: {e}", dir.display()));
                }
                _ => {}
            }
        }
        if let Some(k) = keyring {
            let kp = dir.join("keyring");
            match std::fs::read(&kp) {
                Ok(x) if x != k.as_bytes() || k.is_empty() => {
                    return Err(format!(
                        "{}: existing keyring differs from this OSD: {hint}",
                        kp.display()
                    ));
                }
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                    return Err(format!("{}: {e}", kp.display()));
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Read + validate a dir (marker, whoami consistency, device spec, keyring present). `ready` is not required here.
    /// The OSD id is an `i32` (doc/spec/osd-lifecycle.md 1.1) and a `spdk:` device spec must carry a BDF (adr 0652):
    /// both come from a file the daemon user can write, so neither reaches an argv or a sysfs path unchecked.
    pub fn read(dir: &Path) -> Result<OsdDir, String> {
        let at = |n: &str| format!("{}/{n}", dir.display());
        let rd =
            |n: &str| std::fs::read_to_string(dir.join(n)).map_err(|e| format!("{}: {e}", at(n)));
        let m: serde_json::Value = serde_json::from_str(&rd("croit-flashstore-osd")?)
            .map_err(|e| format!("{}: {e}", at("croit-flashstore-osd")))?;
        let s = |k: &str| {
            m[k].as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| format!("{}: missing {k}", at("croit-flashstore-osd")))
        };
        let whoami = i64::from(
            rd("whoami")?
                .trim()
                .parse::<i32>()
                .ok()
                .filter(|i| *i >= 0)
                .ok_or_else(|| format!("{}: not an OSD id (0..=i32::MAX)", at("whoami")))?,
        );
        if m["osd_id"].as_i64() != Some(whoami) {
            return Err(format!(
                "{}: whoami disagrees with croit-flashstore-osd marker",
                dir.display()
            ));
        }
        let dev = s("dev")?;
        spec_pci(&dev).map_err(|e| format!("{}: {e}", at("croit-flashstore-osd")))?;
        let d = OsdDir {
            whoami,
            osd_uuid: s("osd_uuid")?,
            cluster_fsid: s("cluster_fsid")?,
            dev,
            crush_device_class: m["crush_device_class"]
                .as_str()
                .unwrap_or("nvme")
                .to_owned(),
            // no keyring file = an OSD without a key (auth none)
            keyring: match std::fs::read_to_string(dir.join("keyring")) {
                Ok(t) => t,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
                Err(e) => return Err(format!("{}: {e}", at("keyring"))),
            },
        };
        if rd("fsid")?.trim() != d.osd_uuid {
            return Err(format!(
                "{}: fsid file disagrees with croit-flashstore-osd marker",
                dir.display()
            ));
        }
        Ok(d)
    }

    pub fn is_ready(dir: &Path) -> bool {
        dir.join("ready").exists()
    }

    /// PCI address of the device spec (`spdk:<pci>[,ns=N]`); `None` for a spec that is not `spdk:`. [`OsdDir::read`]
    /// has validated it ([`spec_pci`]).
    pub fn pci(&self) -> Option<&str> {
        self.dev
            .strip_prefix("spdk:")?
            .split(',')
            .next()
            .filter(|s| !s.is_empty())
    }
}

/// Never print the keyring (a cephx secret): set/none only.
impl std::fmt::Debug for OsdDir {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OsdDir")
            .field("whoami", &self.whoami)
            .field("osd_uuid", &self.osd_uuid)
            .field("cluster_fsid", &self.cluster_fsid)
            .field("dev", &self.dev)
            .field("crush_device_class", &self.crush_device_class)
            .field(
                "keyring",
                &if self.keyring.is_empty() {
                    "<none>"
                } else {
                    "<set>"
                },
            )
            .finish()
    }
}

/// A hex PCI domain above 0xffff: an Intel VMD domain. The SPDK integration never initialises the VMD driver and
/// `nvme::pciallow::canonical_bdf` refuses such addresses, so every BDF check here refuses them as well.
fn vmd_domain(domain: &str) -> bool {
    u32::from_str_radix(domain, 16).is_ok_and(|d| d > 0xffff)
}

/// BDF shape `[dddd:]bb:dd.f` (adr 0652): the address is interpolated into `/sys/bus/pci/devices/<pci>/...`.
fn is_bdf(s: &str) -> bool {
    let hex = |p: &str, n: usize| p.len() == n && p.bytes().all(|c| c.is_ascii_hexdigit());
    let parts: Vec<&str> = s.split(':').collect();
    let (domain, bus, dev) = match parts.as_slice() {
        [d, b, f] => (Some(*d), *b, *f),
        [b, f] => (None, *b, *f),
        _ => return false,
    };
    // the kernel prints the domain as `%04x`; leading zeros are accepted, the value must fit SPDK's 16-bit domain
    // (`nvme::pciallow::canonical_bdf`: same rule; Intel VMD domains 10000+ are not addressable, see [`vmd_domain`])
    if let Some(d) = domain
        && (!(4..=8).any(|n| hex(d, n)) || vmd_domain(d))
    {
        return false;
    }
    let Some((dev, func)) = dev.split_once('.') else {
        return false;
    };
    hex(bus, 2) && hex(dev, 2) && matches!(func.as_bytes(), [b'0'..=b'7'])
}

/// The kernel's sysfs spelling of a BDF (`[dddd:]bb:dd.f`, any case): lowercase, domain of at least four hex digits
/// (wider for Intel VMD domains). `None` = not a BDF. Every identity comparison and sysfs path uses this form.
pub fn canonical_pci(pci: &str) -> Option<String> {
    if !is_bdf(pci) {
        return None;
    }
    let (domain, rest) = match pci.split_once(':')? {
        (domain, rest) if rest.contains(':') => (u32::from_str_radix(domain, 16).ok()?, rest),
        _ => (0, pci),
    };
    Some(format!("{domain:04x}:{}", rest.to_ascii_lowercase()))
}

fn same_pci(a: &str, b: &str) -> bool {
    matches!((canonical_pci(a), canonical_pci(b)), (Some(a), Some(b)) if a == b)
}

/// PCI address of a `spdk:` device spec: `Ok(None)` = not a `spdk:` spec, `Err` = a `spdk:` spec whose address is not a
/// BDF (`[dddd:]bb:dd.f`, adr 0652) and must never reach a sysfs path, `chown` or `chmod`.
pub fn spec_pci(spec: &str) -> Result<Option<&str>, String> {
    let Some(rest) = spec.strip_prefix("spdk:") else {
        return Ok(None);
    };
    let pci = rest.split(',').next().unwrap_or_default();
    if let Some((domain, tail)) = pci.split_once(':')
        && tail.contains(':')
        && vmd_domain(domain)
    {
        return Err(format!(
            "PCI domain {domain} in {spec:?} is above 0xffff: the device sits behind Intel VMD, which the SPDK tier cannot address; \
             disable VMD in the BIOS or use the kernel tier (kernel:/dev/nvmeXnY)"
        ));
    }
    if !is_bdf(pci) {
        return Err(format!(
            "bad PCI address {pci:?} in {spec:?} (expected [dddd:]bb:dd.f)"
        ));
    }
    Ok(Some(pci))
}

/// NSID of a `spdk:` device spec (`ns=N`, default 1); `None` for other specs or an invalid NSID.
/// Options apply in order, matching the device parser: the last `ns=` selects the namespace.
pub fn spec_ns(spec: &str) -> Option<u32> {
    let mut nsid = 1;
    for v in spec
        .strip_prefix("spdk:")?
        .split(',')
        .skip(1)
        .filter_map(|o| o.strip_prefix("ns="))
    {
        nsid = v
            .parse::<u32>()
            .ok()
            .filter(|n| (1..u32::MAX).contains(n))?;
    }
    Some(nsid)
}

/// Same store device? `spdk:` = same canonical PCI address AND namespace; other specs compare as written. A malformed `ns=` is
/// never the same device (two unparsable namespaces are not equal either).
pub fn same_dev(a: &str, b: &str) -> bool {
    match (spec_pci(a), spec_pci(b)) {
        (Ok(Some(x)), Ok(Some(y))) => {
            same_pci(x, y) && matches!((spec_ns(a), spec_ns(b)), (Some(x), Some(y)) if x == y)
        }
        _ => a == b,
    }
}

/// Prepared OSDs under `root` (cluster `cl`) whose device sits on the same NVMe controller as `spec` but is not that very
/// device (another namespace): `(id, dev)`. One process owns a whole controller (adr 0103), so such an OSD and one on
/// `spec` could never run side by side. A root or an OSD dir that cannot be read is an error: the check must not pass
/// because it could not see the other OSDs.
pub fn controller_neighbours(
    root: &Path,
    cl: &str,
    spec: &str,
) -> Result<Vec<(i64, String)>, String> {
    let Some(pci) = spec_pci(spec)? else {
        return Ok(Vec::new());
    };
    let mut v = Vec::new();
    for (c, id, dir) in scan(root)? {
        if c != cl {
            continue;
        }
        let d = OsdDir::read(&dir)?;
        if d.pci().is_some_and(|other| same_pci(other, pci)) && !same_dev(&d.dev, spec) {
            v.push((id, d.dev));
        }
    }
    Ok(v)
}

/// `[osd.N]\n\tkey = K\n`; empty for an OSD without a key (auth none).
pub fn keyring_text(id: i64, key: &str) -> String {
    if key.is_empty() {
        return String::new();
    }
    format!("[osd.{id}]\n\tkey = {key}\n")
}

/// `<cluster>-<id>` dirs under `root` that hold an `croit-flashstore-osd` marker (no deeper scan). A missing root is an empty root; a
/// root that cannot be read is an error (an unreadable directory is not an empty cluster).
pub fn scan(root: &Path) -> Result<Vec<(String, i64, PathBuf)>, String> {
    let rd = match std::fs::read_dir(root) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("{}: {e}", root.display())),
    };
    let mut v = Vec::new();
    for e in rd {
        let e = e.map_err(|e| format!("{}: {e}", root.display()))?;
        let n = e.file_name().to_string_lossy().into_owned();
        if let Some((c, i)) = n.rsplit_once('-')
            && let Ok(i) = i.parse::<i32>()
            && e.path().join("croit-flashstore-osd").exists()
        {
            v.push((c.to_owned(), i64::from(i), e.path()));
        }
    }
    v.sort_by(|a, b| (&a.0, a.1).cmp(&(&b.0, b.1)));
    Ok(v)
}

// ---- host probes (activate)

/// Kernel driver a PCI device is bound to (`None` = unbound, absent, or not a BDF: no sysfs path is built from a value
/// that is not a PCI address, adr 0652).
pub fn pci_driver(pci: &str) -> Option<String> {
    let pci = canonical_pci(pci)?;
    std::fs::read_link(format!("/sys/bus/pci/devices/{pci}/driver"))
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
}

/// The PCI device exists in sysfs (`false` for a value that is not a BDF, adr 0652).
pub fn pci_exists(pci: &str) -> bool {
    canonical_pci(pci).is_some_and(|pci| Path::new(&format!("/sys/bus/pci/devices/{pci}")).exists())
}

/// Free hugepage memory in MB over all page sizes, without pages reserved by existing mappings (counted free until
/// faulted, but promised).
pub fn hugepages_free_mb() -> u64 {
    hugepages_free_mb_at(Path::new("/sys/kernel/mm/hugepages"))
}

fn hugepages_free_mb_at(dir: &Path) -> u64 {
    let num = |p: std::path::PathBuf| -> u64 {
        std::fs::read_to_string(p)
            .ok()
            .and_then(|t| t.trim().parse().ok())
            .unwrap_or(0)
    };
    let mut mb = 0;
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().into_owned();
            let kb: u64 = n
                .strip_prefix("hugepages-")
                .and_then(|r| r.strip_suffix("kB"))
                .and_then(|r| r.parse().ok())
                .unwrap_or(0);
            let free = num(e.path().join("free_hugepages"))
                .saturating_sub(num(e.path().join("resv_hugepages")));
            mb += kb * free / 1024;
        }
    }
    mb
}

/// Soft `Max locked memory` limit field of `/proc/self/limits`; `None` = no such line or field.
fn memlock_soft(limits: &str) -> Option<&str> {
    limits
        .lines()
        .find(|l| l.starts_with("Max locked memory"))
        .and_then(|l| l.split_whitespace().nth(3))
}

/// `Max locked memory` soft limit is unlimited.
pub fn memlock_unlimited() -> bool {
    std::fs::read_to_string("/proc/self/limits")
        .is_ok_and(|t| memlock_soft(&t) == Some("unlimited"))
}

/// Parse a size option: plain bytes or with a K/M/G/T suffix (powers of 1024).
pub fn parse_size(s: &str) -> Option<u64> {
    cephconf::size_with_units(s)
}

/// Can this process pin `need` bytes (RDMA memory registration)? The soft `RLIMIT_MEMLOCK` must cover it, unless the process
/// holds CAP_IPC_LOCK (then the limit does not apply). `Err` = the startup error with the fix.
pub fn memlock_covers(need: u64) -> Result<(), String> {
    let read = |p: &str| std::fs::read_to_string(p).unwrap_or_default();
    memlock_check(&read("/proc/self/limits"), &read("/proc/self/status"), need)
}

/// [`memlock_covers`] on the text of `/proc/self/limits` and `/proc/self/status`; an unreadable limit counts as unlimited
/// (nothing to compare, the registration reports a real failure).
fn memlock_check(limits: &str, status: &str, need: u64) -> Result<(), String> {
    const CAP_IPC_LOCK: u32 = 14;
    let limit = match memlock_soft(limits) {
        None | Some("unlimited") => return Ok(()),
        Some(v) => v.parse::<u64>().unwrap_or(u64::MAX),
    };
    let cap_ipc_lock = status
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:"))
        .and_then(|v| u64::from_str_radix(v.trim(), 16).ok())
        .is_some_and(|m| (m >> CAP_IPC_LOCK) & 1 == 1);
    if limit >= need || cap_ipc_lock {
        return Ok(());
    }
    Err(format!(
        "memlock limit {} MiB is below the {} MiB of RDMA memory to register (flashstore_rdma): systemd LimitMEMLOCK=infinity, \
         docker --ulimit memlock=-1, shell ulimit -l unlimited",
        limit >> 20,
        need.div_ceil(1 << 20)
    ))
}

/// Is `driver` one SPDK can drive without the kernel (`vfio-pci`, `uio_pci_generic`, `igb_uio`)?
pub fn is_userspace_driver(d: &str) -> bool {
    matches!(d, "vfio-pci" | "uio_pci_generic" | "igb_uio")
}

// ---- run args

fn push(a: &mut Vec<String>, k: &str, v: &str) {
    a.push(k.to_owned());
    a.push(v.to_owned());
}

/// `flashstore_lcores` (`FIRST[-LAST]`) -> `(first core, core count)`; `None` for a malformed or reversed range.
fn lcore_range(v: &str) -> Option<(usize, usize)> {
    let (f, l) = v.split_once('-').unwrap_or((v, v));
    let (f, l): (usize, usize) = (f.trim().parse().ok()?, l.trim().parse().ok()?);
    Some((f, l.checked_sub(f)?.checked_add(1)?))
}

/// Translate `[osd]`/`[osd.N]` options + the data dir into the `croit-flashstore-osd` daemon flags. Conf keys:
/// `flashstore_dev` (default: the dir's device), `flashstore_ip`, `flashstore_lcores` (`FIRST[-LAST]`), `flashstore_hugepages_mb` (alias
/// `flashstore_mem`, both MB, K/M/G/T suffix ok), `flashstore_hugepages` (bare flag), `flashstore_cores`,
/// `flashstore_idle`, `flashstore_hostname`, `flashstore_port_base`, `flashstore_huge_dir`; `mon_host`
/// (an empty value is unset, as in [`Conf::mon_host`]). Unknown `flashstore_<k>` keys become `--<k-with-dashes> value`.
pub fn run_args(
    opts: &BTreeMap<String, String>,
    dir: Option<&OsdDir>,
    data_dir: &Path,
) -> Result<Vec<String>, String> {
    let mut a: Vec<String> = Vec::new();
    let dev = opts
        .get("flashstore_dev")
        .cloned()
        .or_else(|| dir.map(|d| d.dev.clone()))
        .ok_or("no device: set flashstore_dev in the conf or prepare the OSD dir")?;
    if let Some(c) = opts.get("flashstore_dev")
        && let Some(d) = dir
        && !same_dev(c, &d.dev)
    {
        return Err(format!(
            "conf flashstore_dev {c:?} disagrees with {}/croit-flashstore-osd ({:?})",
            data_dir.display(),
            d.dev
        ));
    }
    push(&mut a, "--dev", &dev);
    if let Some(h) = opts.get("mon_host").filter(|h| !h.is_empty()) {
        push(&mut a, "--mon-host", h);
    }
    for (k, v) in opts {
        let Some(k) = k.strip_prefix("flashstore_") else {
            continue;
        };
        match k {
            "dev" => {}
            "lcores" => {
                let (f, c) =
                    lcore_range(v).ok_or_else(|| format!("bad flashstore_lcores {v:?}"))?;
                push(&mut a, "--lcore", &f.to_string());
                push(&mut a, "--cores", &c.to_string());
            }
            // one budget, one parse: both spellings are read by `hugepages_need_mb` (emitted below)
            "hugepages_mb" | "mem" => {}
            // read by croit-flashstore-prep.sh only
            "set" | "driver" | "hugepage_kb" | "nic_bind" => {}
            // `flashstore_store_*` (`store_shards` is a prepare/mkfs option): `croit-flashstore-osd run` forwards them as `--set k=v`
            _ if k.starts_with("store_") => {}
            _ => {
                let flag = format!("--{}", k.replace('_', "-"));
                match v.as_str() {
                    "true" | "yes" | "1" if k == "hugepages" => a.push(flag),
                    "false" | "no" | "0" if k == "hugepages" => {}
                    _ => {
                        a.push(flag);
                        a.push(v.clone());
                    }
                }
            }
        }
    }
    a.extend(["--mem".into(), hugepages_need_mb(opts)?.to_string()]);
    Ok(a)
}

/// mkfs inputs from the conf (adr 0160): `flashstore_store_shards` (`auto` | N) and the core count the OSD will run with
/// (`flashstore_cores`, else the length of the `flashstore_lcores` range).
pub fn mkfs_shard_opts(opts: &BTreeMap<String, String>) -> (Option<String>, Option<usize>) {
    let cores = opts
        .get("flashstore_cores")
        .and_then(|v| v.trim().parse().ok())
        .or_else(|| lcore_range(opts.get("flashstore_lcores")?).map(|(_, c)| c));
    (opts.get("flashstore_store_shards").cloned(), cores)
}

/// A hugepage budget value in MB: a bare number is MB, a `K`/`M`/`G`/`T` suffix is bytes and must be a whole number of
/// MB. `Err` = a value nobody can act on (never silently replaced by the default).
fn mem_mb(key: &str, v: &str) -> Result<u64, String> {
    let t = v.trim();
    if !t.is_empty() && t.bytes().all(|c| c.is_ascii_digit()) {
        return t.parse().map_err(|_| format!("bad {key} {v:?} (MB)"));
    }
    let b = parse_size(t).ok_or_else(|| format!("bad {key} {v:?} (MB, or a K/M/G/T suffix)"))?;
    if b < (1 << 20) || b % (1 << 20) != 0 {
        return Err(format!("bad {key} {v:?}: not a whole number of MB"));
    }
    Ok(b >> 20)
}

/// Hugepage budget in MB the daemon is started with and the `activate` precheck compares against: `flashstore_hugepages_mb`,
/// alias `flashstore_mem` (both spellings must agree), default [`DEFAULT_HUGEPAGES_MB`]. `Err` = a value that does not parse.
pub fn hugepages_need_mb(opts: &BTreeMap<String, String>) -> Result<u64, String> {
    let a = opts
        .get("flashstore_hugepages_mb")
        .map(|v| mem_mb("flashstore_hugepages_mb", v))
        .transpose()?;
    let b = opts
        .get("flashstore_mem")
        .map(|v| mem_mb("flashstore_mem", v))
        .transpose()?;
    match (a, b) {
        (Some(x), Some(y)) if x != y => Err(format!(
            "flashstore_hugepages_mb = {x} and flashstore_mem = {y} disagree (one hugepage budget)"
        )),
        (Some(x), _) | (_, Some(x)) => Ok(x),
        (None, None) => Ok(DEFAULT_HUGEPAGES_MB),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir_of(id: i64, uuid: &str, fsid: &str) -> OsdDir {
        OsdDir {
            whoami: id,
            osd_uuid: uuid.into(),
            cluster_fsid: fsid.into(),
            dev: "file:/x".into(),
            crush_device_class: "nvme".into(),
            keyring: keyring_text(id, "k"),
        }
    }

    /// `admit` takes the decision of `write`/`complete` before anything is touched.
    #[test]
    fn admit_matches_what_publishing_would_refuse() {
        let t = std::env::temp_dir().join(format!("osddir-admit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&t);
        std::fs::create_dir_all(&t).unwrap();
        let d = t.join("ceph-4");
        let key = keyring_text(4, "k");
        // absent and empty dirs are fine
        OsdDir::admit(&d, 4, "u1", None, Some(&key)).unwrap();
        std::fs::create_dir_all(&d).unwrap();
        OsdDir::admit(&d, 4, "u1", Some("c1"), Some(&key)).unwrap();
        // the same OSD (marker) is rewritten; another uuid, id or cluster is refused
        dir_of(4, "u1", "c1").write(&d).unwrap();
        OsdDir::admit(&d, 4, "u1", Some("c1"), Some(&key)).unwrap();
        OsdDir::admit(&d, 4, "u1", None, None).unwrap();
        for (id, u, c) in [(4, "u2", None), (5, "u1", None), (4, "u1", Some("c2"))] {
            let e = OsdDir::admit(&d, id, u, c, None).unwrap_err();
            assert!(e.contains("not this OSD") && e.contains("re-run"), "{e}");
        }
        // a broken marker is refused
        std::fs::write(d.join("whoami"), "9\n").unwrap();
        assert!(
            OsdDir::admit(&d, 4, "u1", None, None)
                .unwrap_err()
                .contains("broken")
        );
        // marker-less dir with a foreign file is refused, with only matching files it is fine
        std::fs::remove_file(d.join("croit-flashstore-osd")).unwrap();
        assert!(
            OsdDir::admit(&d, 4, "u1", None, None)
                .unwrap_err()
                .contains("whoami")
        );
        std::fs::write(d.join("whoami"), "4\n").unwrap();
        OsdDir::admit(&d, 4, "u1", None, None).unwrap();
        std::fs::write(d.join("keyring"), "[osd.4]\n\tkey = other\n").unwrap();
        assert!(
            OsdDir::admit(&d, 4, "u1", None, Some(&key))
                .unwrap_err()
                .contains("keyring")
        );
        // not a plain directory
        let f = t.join("file");
        std::fs::write(&f, "x").unwrap();
        assert!(
            OsdDir::admit(&f, 4, "u1", None, None)
                .unwrap_err()
                .contains("not a plain directory")
        );
        std::fs::remove_dir_all(&t).unwrap();
    }

    #[test]
    fn size_suffixes() {
        assert_eq!(parse_size("256M"), Some(256 << 20));
        assert_eq!(parse_size(" 1g "), Some(1 << 30));
        assert_eq!(parse_size("4096"), Some(4096));
        assert_eq!(parse_size("x"), None);
        assert_eq!(parse_size(""), None);
    }

    /// Pages reserved by an existing mapping are still in `free_hugepages` but not available to a new OSD.
    #[test]
    fn reserved_hugepages_are_not_free() {
        let d = std::env::temp_dir().join(format!("osddir-hp-{}", std::process::id()));
        for (sz, free, resv) in [("2048kB", "1024", Some("512")), ("1048576kB", "2", None)] {
            let s = d.join(format!("hugepages-{sz}"));
            std::fs::create_dir_all(&s).unwrap();
            std::fs::write(s.join("free_hugepages"), free).unwrap();
            if let Some(r) = resv {
                std::fs::write(s.join("resv_hugepages"), r).unwrap();
            }
        }
        assert_eq!(hugepages_free_mb_at(&d), 1024 + 2048);
        // a snapshot with more reservations than free pages does not underflow
        std::fs::write(d.join("hugepages-2048kB/resv_hugepages"), "2000").unwrap();
        assert_eq!(hugepages_free_mb_at(&d), 2048);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// OD12: one hugepage option, one parse, and the precheck compares the value the daemon is started with.
    #[test]
    fn one_hugepage_budget_one_parse() {
        let o = |k: &str, v: &str| {
            BTreeMap::from([
                (
                    "flashstore_dev".to_string(),
                    "spdk:0000:03:00.0".to_string(),
                ),
                (k.to_string(), v.to_string()),
            ])
        };
        let mem = |a: &[String]| {
            a.windows(2)
                .filter(|w| w[0] == "--mem")
                .map(|w| w[1].clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            hugepages_need_mb(&BTreeMap::new()),
            Ok(DEFAULT_HUGEPAGES_MB)
        );
        assert_eq!(
            hugepages_need_mb(&o("flashstore_hugepages_mb", "4096")),
            Ok(4096)
        );
        assert_eq!(
            hugepages_need_mb(&o("flashstore_hugepages_mb", "4G")),
            Ok(4096)
        );
        assert_eq!(hugepages_need_mb(&o("flashstore_mem", "8192")), Ok(8192));
        assert!(hugepages_need_mb(&o("flashstore_hugepages_mb", "4Gx")).is_err());
        assert!(hugepages_need_mb(&o("flashstore_hugepages_mb", "1K")).is_err());
        let both = BTreeMap::from([
            (
                "flashstore_dev".to_string(),
                "spdk:0000:03:00.0".to_string(),
            ),
            ("flashstore_hugepages_mb".to_string(), "4096".to_string()),
            ("flashstore_mem".to_string(), "8192".to_string()),
        ]);
        assert!(hugepages_need_mb(&both).is_err());
        assert!(run_args(&both, None, Path::new("/x")).is_err());
        // the alias is the same option: one `--mem` with the parsed value, no second default appended
        assert_eq!(
            mem(&run_args(&o("flashstore_mem", "8192"), None, Path::new("/x")).unwrap()),
            ["8192"]
        );
        assert_eq!(
            mem(&run_args(&o("flashstore_hugepages_mb", "4G"), None, Path::new("/x")).unwrap()),
            ["4096"]
        );
        assert_eq!(
            mem(&run_args(
                &o("flashstore_dev", "spdk:0000:03:00.0"),
                None,
                Path::new("/x")
            )
            .unwrap()),
            [DEFAULT_HUGEPAGES_MB.to_string()]
        );
        assert!(run_args(&o("flashstore_hugepages_mb", "x"), None, Path::new("/x")).is_err());
    }

    /// OD11: an empty `mon_host` is unset (it cannot be a usable address), never `--mon-host ""`.
    #[test]
    fn empty_mon_host_is_not_forwarded() {
        let c = Conf::parse(
            "[global]\nmon host = v2:192.0.2.14:3300\n[osd.3]\nflashstore_dev = spdk:0000:03:00.0\nmon host =\n",
        );
        let a = run_args(&c.for_osd(3), None, Path::new("/x")).unwrap();
        assert!(!a.iter().any(|x| x == "--mon-host"), "{a:?}");
        let a = run_args(
            &BTreeMap::from([
                (
                    "flashstore_dev".to_string(),
                    "spdk:0000:03:00.0".to_string(),
                ),
                ("mon_host".to_string(), String::new()),
            ]),
            None,
            Path::new("/x"),
        )
        .unwrap();
        assert!(!a.iter().any(|x| x == "--mon-host"), "{a:?}");
        assert_eq!(c.mon_host(Some(3)), None);
    }

    /// OD14: `[osd.N] mon host` wins over `[osd]`/`[global]` for that OSD, like every other option.
    #[test]
    fn osd_section_mon_host_wins() {
        let c = Conf::parse(
            "[global]\nmon host = v2:192.0.2.11:3300\n[osd]\nmon host = v2:192.0.2.12:3300\n[osd.3]\nmon host = v2:192.0.2.13:3300\n",
        );
        assert_eq!(c.mon_host(None).as_deref(), Some("v2:192.0.2.12:3300"));
        assert_eq!(c.mon_host(Some(3)).as_deref(), Some("v2:192.0.2.13:3300"));
        assert_eq!(c.mon_host(Some(4)).as_deref(), Some("v2:192.0.2.12:3300"));
        // the direct daemon start (`croit-flashstore-osd --id 3`, no `run`) finds it too
        let p = std::env::temp_dir().join(format!("osddir-monhost-{}", std::process::id()));
        std::fs::write(&p, "[osd.3]\nmon host = v2:192.0.2.13:3300\n").unwrap();
        let p = p.to_str().unwrap();
        assert_eq!(
            mon_host_from_args(&["--conf".into(), p.into(), "--id".into(), "3".into()]),
            Ok("v2:192.0.2.13:3300".into())
        );
        assert!(
            mon_host_from_args(&["--conf".into(), p.into(), "--id".into(), "4".into()]).is_err()
        );
        let _ = std::fs::remove_file(p);
    }

    /// A client option is read across the client sections like the daemon reads one across the OSD sections.
    #[test]
    fn value_merges_the_named_sections_in_order() {
        let c = Conf::parse(
            "[global]\nmon host = v2:192.0.2.11:3300\nrustyrados_rdma = no\n\
             [client]\nrustyrados rdma = yes\n\
             [client.admin]\nmon_host = v2:192.0.2.13:3300\n",
        );
        let sections = ["global", "client", "client.admin"];
        assert_eq!(c.value(&sections, "mon_host"), Some("v2:192.0.2.13:3300"));
        assert_eq!(
            c.value(&["global", "client"], "mon_host"),
            Some("v2:192.0.2.11:3300")
        );
        assert_eq!(c.value(&sections, "rustyrados_rdma"), Some("yes"));
        assert_eq!(c.value(&["global"], "rustyrados_rdma"), Some("no"));
        assert_eq!(c.value(&["global"], "absent"), None);
    }

    /// OD3: the cluster name becomes a path component; a path is refused.
    #[test]
    fn cluster_name_is_a_path_component() {
        let v = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(cluster_from_args(&v(&[])), Ok("ceph".into()));
        assert_eq!(
            cluster_from_args(&v(&["--cluster", "c-1"])),
            Ok("c-1".into())
        );
        assert_eq!(
            cluster_from_args(&v(&["--set", "cluster=c-1"])),
            Ok("c-1".into())
        );
        for bad in ["../../tmp/x", "a/b", ".", "..", "", "a b"] {
            assert!(
                cluster_from_args(&v(&["--cluster", bad])).is_err(),
                "{bad:?} accepted"
            );
            assert!(
                cluster_from_args(&v(&["--set", &format!("cluster={bad}")])).is_err(),
                "{bad:?} accepted via --set"
            );
        }
    }

    /// OD15: a flag without its value is a usage error, never a silent default and never the next flag as the value.
    #[test]
    fn flags_need_their_value() {
        let v = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(cluster_from_args(&v(&["--cluster"])).is_err());
        assert!(mon_host_from_args(&v(&["--mon-host"])).is_err());
        assert!(conf_file(&v(&["--conf"]), "ceph").is_err());
        assert!(cluster_from_args(&v(&["--cluster", "--conf", "x"])).is_err());
        assert!(mon_host_from_args(&v(&["--mon-host", "--conf", "x"])).is_err());
        assert!(mon_host_from_args(&v(&["--mon-host", ""])).is_err());
        assert_eq!(conf_file(&v(&[]), "ceph").unwrap(), conf_path("ceph"));
        assert_eq!(
            conf_file(&v(&["--conf", "/x/y.conf"]), "ceph").unwrap(),
            PathBuf::from("/x/y.conf")
        );
    }

    /// OD13: a conf that exists but cannot be read is reported with its path, not as "no mon_host".
    #[test]
    fn unreadable_conf_is_reported() {
        let v = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        // a directory: the file exists, reading it fails (EISDIR)
        let d = std::env::temp_dir().join(format!("osddir-conf-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let p = d.to_str().unwrap();
        let e = mon_host_from_args(&v(&["--conf", p])).unwrap_err();
        assert!(e.contains(p) && !e.contains("no mon_host"), "{e}");
        // a missing conf still says what is missing
        let missing = d.join("nope.conf");
        let e = mon_host_from_args(&v(&["--conf", missing.to_str().unwrap()])).unwrap_err();
        assert!(e.contains("no mon_host"), "{e}");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// OD8: one single-pass expansion for `$cluster`, `$type`, `$id`, `$name` (and `${..}`), the set the daemon expands
    /// in `osd_data`; an unknown name stays, and a substituted value is never expanded again.
    #[test]
    fn metavariables_expand_in_one_pass() {
        assert_eq!(expand("/x/$cluster-$id/k", "c1", 3), "/x/c1-3/k");
        assert_eq!(expand("/x/${cluster}/$type.$id", "c1", 3), "/x/c1/osd.3");
        assert_eq!(expand("$name.keyring", "c1", 3), "osd.3.keyring");
        assert_eq!(expand("$unknown/$", "c1", 3), "$unknown/$");
        assert_eq!(expand("${cluster", "c1", 3), "${cluster");
        assert_eq!(
            expand("$cluster", "$id", 5),
            "$id",
            "a substituted value is not expanded again"
        );
    }

    /// OD10: the scan root is the parent of the OSD dir of the id the caller resolves; an `osd_data` whose parent
    /// changes with the id cannot be scanned and is refused (never scanned at a guessed id).
    #[test]
    fn data_root_is_the_parent_of_the_resolved_dir() {
        let o = |v: &str| BTreeMap::from([("osd_data".to_string(), v.to_string())]);
        assert_eq!(
            data_root(&o("/srv/ceph/$cluster-$id"), "ceph", 5),
            Ok(PathBuf::from("/srv/ceph"))
        );
        assert_eq!(
            data_root(&o("/data/$cluster/osd.$id"), "ceph", 5),
            Ok(PathBuf::from("/data/ceph"))
        );
        assert_eq!(
            data_root(&BTreeMap::new(), "ceph", 5),
            Ok(PathBuf::from(DEFAULT_ROOT))
        );
        // the parent moves with the id: no single root holds the OSD dirs
        for v in ["/data/$id/osd", "/data/$name/osd"] {
            let e = data_root(&o(v), "ceph", 5).unwrap_err();
            assert!(e.contains("depends on the OSD id"), "{v}: {e}");
        }
        // no parent: nothing to scan (never a silent DEFAULT_ROOT)
        assert!(data_root(&o("osd"), "ceph", 5).is_err());
    }

    #[test]
    fn memlock_check_limit_capability_unlimited() {
        let lim = |s: &str| {
            format!("Max locked memory         {s}              {s}              bytes\n")
        };
        let st = |cap: &str| format!("Name:\tx\nCapEff:\t{cap}\n");
        let none = st("0000000000000000");
        assert!(memlock_check(&lim("unlimited"), &none, 1 << 40).is_ok());
        assert!(
            memlock_check(&lim("536870912"), &none, 512 << 20).is_ok(),
            "exactly covered"
        );
        let e = memlock_check(&lim("8388608"), &none, 512 << 20).unwrap_err();
        assert!(
            e.contains("8 MiB") && e.contains("512 MiB") && e.contains("ulimit -l"),
            "{e}"
        );
        // CAP_IPC_LOCK (bit 14) lifts the limit
        assert!(memlock_check(&lim("8388608"), &st("0000000000004000"), 512 << 20).is_ok());
        assert!(
            memlock_check("", "", 1 << 30).is_ok(),
            "unreadable: nothing to compare"
        );
    }

    const CONF: &str = "\
# c
[global]
fsid = 11111111-2222-3333-4444-555555555555
mon host = [v2:192.0.2.1:3300,v1:192.0.2.1:6789] ; trailing
public_network = 192.0.2.0/24
[osd]
flashstore_hugepages_mb = 4096
flashstore_ip = 192.0.2.5/24
[osd.3]
flashstore_dev = spdk:0000:03:00.0
flashstore_lcores = 4-7
flashstore_driver = uio_pci_generic
[osd.4]
flashstore_ip = 192.0.2.6/24
";

    #[test]
    fn conf_sections_merge() {
        let c = Conf::parse(CONF);
        let o = c.for_osd(3);
        assert_eq!(o["fsid"], "11111111-2222-3333-4444-555555555555");
        assert_eq!(o["mon_host"], "[v2:192.0.2.1:3300,v1:192.0.2.1:6789]");
        assert_eq!(o["flashstore_ip"], "192.0.2.5/24");
        assert_eq!(c.for_osd(4)["flashstore_ip"], "192.0.2.6/24");
    }

    #[test]
    fn args_from_conf() {
        let o = Conf::parse(CONF).for_osd(3);
        let a = run_args(&o, None, Path::new("/x")).unwrap();
        let s = a.join(" ");
        assert!(
            s.starts_with("--dev spdk:0000:03:00.0 --mon-host [v2"),
            "{s}"
        );
        assert!(s.contains("--lcore 4 --cores 4"), "{s}");
        assert!(s.contains("--mem 4096"), "{s}");
        assert!(s.contains("--ip 192.0.2.5/24"), "{s}");
        assert!(!s.contains("--driver"), "{s}");
        // osd.4 has no device and no dir
        assert!(run_args(&Conf::parse(CONF).for_osd(4), None, Path::new("/x")).is_err());
    }

    #[test]
    fn store_shards_is_a_mkfs_option_only() {
        let c = Conf::parse(&format!(
            "{CONF}[osd.5]\nflashstore_dev = spdk:0000:04:00.0\nflashstore_store_shards = 6\nflashstore_cores = 3\n"
        ));
        let o = c.for_osd(5);
        let s = run_args(&o, None, Path::new("/x")).unwrap().join(" ");
        assert!(!s.contains("store-shards"), "{s}");
        assert_eq!(mkfs_shard_opts(&o), (Some("6".into()), Some(3)));
        // cores from the lcores range when flashstore_cores is unset; no store_shards = None (prepare: auto)
        assert_eq!(mkfs_shard_opts(&c.for_osd(3)), (None, Some(4)));
        assert_eq!(mkfs_shard_opts(&c.for_osd(4)), (None, None));
    }

    #[test]
    fn dir_without_a_key_has_no_keyring_file() {
        let t = std::env::temp_dir().join(format!("osddir-nokey-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&t);
        let d = OsdDir {
            whoami: 2,
            osd_uuid: "u-2".into(),
            cluster_fsid: "c-2".into(),
            dev: "spdk:0000:03:00.0".into(),
            crush_device_class: "nvme".into(),
            keyring: keyring_text(2, ""),
        };
        assert!(d.keyring.is_empty());
        d.write(&t).unwrap();
        assert!(!t.join("keyring").exists());
        assert_eq!(OsdDir::read(&t).unwrap(), d);
        // a key added later is written, and removing it again removes the file
        let keyed = OsdDir {
            keyring: keyring_text(2, "K"),
            ..d.clone()
        };
        keyed.write(&t).unwrap();
        assert!(t.join("keyring").exists());
        d.write(&t).unwrap();
        assert!(!t.join("keyring").exists());
        let _ = std::fs::remove_dir_all(&t);
    }

    #[test]
    fn directory_writers_refuse_an_active_writer() {
        use std::os::fd::AsRawFd as _;
        let t = std::env::temp_dir().join(format!("osddir-writer-{}", std::process::id()));
        std::fs::create_dir_all(&t).unwrap();
        let held = open_dir(&t).unwrap();
        // A separate open description models another activation process without scheduling races.
        // SAFETY: held owns an open directory descriptor.
        assert_eq!(
            unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        let d = OsdDir {
            whoami: 9,
            osd_uuid: "u-9".into(),
            cluster_fsid: "c-9".into(),
            dev: "spdk:0000:09:00.0".into(),
            crush_device_class: "nvme".into(),
            keyring: String::new(),
        };
        assert!(d.write(&t).unwrap_err().contains("in use"));
        assert!(d.complete(&t).unwrap_err().contains("in use"));
        assert!(!t.join("whoami").exists());
        drop(held);
        d.complete(&t).unwrap();
        assert_eq!(OsdDir::read(&t).unwrap(), d);
        std::fs::remove_dir_all(t).unwrap();
    }

    /// `complete` (activate --from-device, OS disk lost): a missing dir is created whole, a complete dir is
    /// left untouched, only missing files are written, and a file with other content is refused, never overwritten.
    #[test]
    fn complete_fills_in_without_overwriting() {
        let t = std::env::temp_dir().join(format!("osddir-complete-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&t);
        let d = OsdDir {
            whoami: 9,
            osd_uuid: "u-9".into(),
            cluster_fsid: "c-9".into(),
            dev: "spdk:0000:09:00.0".into(),
            crush_device_class: "nvme".into(),
            keyring: keyring_text(9, "K"),
        };
        assert_eq!(
            d.complete(&t).unwrap(),
            vec![
                "whoami",
                "fsid",
                "ceph_fsid",
                "type",
                "croit-flashstore-osd",
                "keyring",
                "ready"
            ]
        );
        assert!(OsdDir::is_ready(&t));
        assert_eq!(OsdDir::read(&t).unwrap(), d);
        // a complete dir changes nothing
        assert_eq!(d.complete(&t).unwrap(), Vec::<String>::new());
        // only the missing files are written
        std::fs::remove_file(t.join("ready")).unwrap();
        std::fs::remove_file(t.join("keyring")).unwrap();
        assert_eq!(d.complete(&t).unwrap(), vec!["keyring", "ready"]);
        // a file with other content is refused, never overwritten, and nothing else is written
        std::fs::remove_file(t.join("ready")).unwrap();
        std::fs::write(t.join("whoami"), "10\n").unwrap();
        let e = d.complete(&t).unwrap_err();
        assert!(
            e.contains("whoami") && e.contains("never overwritten"),
            "{e}"
        );
        assert_eq!(std::fs::read_to_string(t.join("whoami")).unwrap(), "10\n");
        assert!(!OsdDir::is_ready(&t));
        let _ = std::fs::remove_dir_all(&t);
    }

    /// `complete` never removes a keyring file an auth-none OSD does not carry (removing is a content change).
    #[test]
    fn complete_refuses_a_stale_keyring_of_a_keyless_osd() {
        let t = std::env::temp_dir().join(format!("osddir-complete-nokey-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&t);
        let keyed = OsdDir {
            whoami: 3,
            osd_uuid: "u-3".into(),
            cluster_fsid: "c-3".into(),
            dev: "spdk:0000:03:00.0".into(),
            crush_device_class: "nvme".into(),
            keyring: keyring_text(3, "K"),
        };
        keyed.write(&t).unwrap();
        let keyless = OsdDir {
            keyring: String::new(),
            ..keyed
        };
        let e = keyless.complete(&t).unwrap_err();
        assert!(
            e.contains("keyring") && e.contains("never overwritten"),
            "{e}"
        );
        assert!(t.join("keyring").exists());
        let _ = std::fs::remove_dir_all(&t);
    }

    /// The keyring is created 0600 (no window with a wider mode), also over a stale wide temp file.
    #[test]
    fn keyring_written_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let t = std::env::temp_dir().join(format!("osddir-mode-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&t);
        std::fs::create_dir_all(&t).unwrap();
        let stale = t.join("keyring.tmp");
        std::fs::write(&stale, "old").unwrap();
        std::fs::set_permissions(&stale, std::fs::Permissions::from_mode(0o666)).unwrap();
        let d = OsdDir {
            whoami: 4,
            osd_uuid: "u-4".into(),
            cluster_fsid: "c-4".into(),
            dev: "spdk:0000:03:00.0".into(),
            crush_device_class: "nvme".into(),
            keyring: keyring_text(4, "K"),
        };
        d.write(&t).unwrap();
        let mode = std::fs::metadata(t.join("keyring"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        assert!(!stale.exists());
        let _ = std::fs::remove_dir_all(&t);
    }

    /// OD6: a rewrite that fails half-way leaves a dir that is explicitly incomplete, never one with a stale `ready`.
    #[test]
    fn failed_rewrite_clears_ready() {
        let t = std::env::temp_dir().join(format!("osddir-ready-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&t);
        let d = OsdDir {
            whoami: 4,
            osd_uuid: "u-4".into(),
            cluster_fsid: "c-4".into(),
            dev: "spdk:0000:03:00.0".into(),
            crush_device_class: "nvme".into(),
            keyring: keyring_text(4, "K"),
        };
        d.write(&t).unwrap();
        assert!(OsdDir::is_ready(&t));
        // the keyring write fails: a directory occupies its temp name (unlinkat refuses it)
        std::fs::create_dir_all(t.join("keyring.tmp")).unwrap();
        let changed = OsdDir {
            osd_uuid: "u-4b".into(),
            ..d
        };
        assert!(changed.write(&t).is_err());
        assert!(
            !OsdDir::is_ready(&t),
            "a half-written dir still claims to be ready"
        );
        let _ = std::fs::remove_dir_all(&t);
    }

    /// OD5: every file write of an [`OsdDir`] fsyncs the directory, so `ready` last is also the order on disk.
    #[test]
    fn every_file_write_fsyncs_the_directory() {
        let t = std::env::temp_dir().join(format!("osddir-dsync-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&t);
        let d = OsdDir {
            whoami: 6,
            osd_uuid: "u-6".into(),
            cluster_fsid: "c-6".into(),
            dev: "spdk:0000:03:00.0".into(),
            crush_device_class: "nvme".into(),
            keyring: keyring_text(6, "K"),
        };
        let before = DIR_SYNCS.with(std::cell::Cell::get);
        d.write(&t).unwrap();
        let after = DIR_SYNCS.with(std::cell::Cell::get);
        assert_eq!(
            after - before,
            7,
            "whoami fsid ceph_fsid type croit-flashstore-osd keyring ready"
        );
        let _ = std::fs::remove_dir_all(&t);
    }

    /// OD1: the files belong to the owner and group of the data dir (`prepare` runs as root, the dir belongs to the
    /// daemon user), and the setgid bit an operator set is kept (files keep inheriting the daemon group).
    #[test]
    fn files_belong_to_the_data_dir_and_setgid_is_kept() {
        use std::os::unix::fs::MetadataExt as _;
        use std::os::unix::fs::PermissionsExt as _;
        let t = std::env::temp_dir().join(format!("osddir-own-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&t);
        std::fs::create_dir_all(&t).unwrap();
        let d = OsdDir {
            whoami: 5,
            osd_uuid: "u-5".into(),
            cluster_fsid: "c-5".into(),
            dev: "spdk:0000:03:00.0".into(),
            crush_device_class: "nvme".into(),
            keyring: keyring_text(5, "K"),
        };
        // setgid on the dir: the mode rewrite keeps it
        std::fs::set_permissions(&t, std::fs::Permissions::from_mode(0o2750)).unwrap();
        // Linux uses setgid for group inheritance. Some macOS filesystems discard that bit at chmod;
        // BSD group inheritance still applies there. Preserve the bit the filesystem actually accepted.
        let setgid = std::fs::metadata(&t).unwrap().permissions().mode() & 0o2000;
        #[cfg(target_os = "linux")]
        assert_ne!(setgid, 0, "fixture did not enable setgid");
        d.write(&t).unwrap();
        let mode = std::fs::metadata(&t).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o750, "dir mode");
        assert_eq!(mode & 0o2000, setgid, "setgid changed");
        // a dir handed to another group: the files take that group (root prepare into a daemon-user dir)
        let mut groups = vec![0 as libc::gid_t; 64];
        // SAFETY: the buffer is `groups.len()` gids and the return is the count written.
        let n = unsafe { libc::getgroups(groups.len() as libc::c_int, groups.as_mut_ptr()) };
        assert!(n > 0, "getgroups failed");
        let egid = unsafe { libc::getegid() };
        let Some(other) = groups[..n as usize].iter().find(|g| **g != egid).copied() else {
            eprintln!("skip: the test user is in one group only");
            let _ = std::fs::remove_dir_all(&t);
            return;
        };
        // SAFETY: an open path; `-1` keeps the owner, the group is one the test user belongs to.
        assert_eq!(
            unsafe { libc::chown(cstr(t.to_str().unwrap()).unwrap().as_ptr(), !0, other) },
            0
        );
        d.write(&t).unwrap();
        let dir = std::fs::metadata(&t).unwrap();
        for f in [
            "whoami",
            "fsid",
            "ceph_fsid",
            "type",
            "croit-flashstore-osd",
            "keyring",
            "ready",
        ] {
            let m = std::fs::metadata(t.join(f)).unwrap();
            assert_eq!((m.uid(), m.gid()), (dir.uid(), dir.gid()), "{f}");
        }
        let _ = std::fs::remove_dir_all(&t);
    }

    /// OD1 on a real root prepare (Linux lab/CI): root rewrites a dir the daemon user owns; the files must change hands.
    #[test]
    fn root_prepare_gives_the_files_to_the_daemon_user() {
        use std::os::unix::fs::MetadataExt as _;
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("skip: needs root (the Linux lab gate runs this)");
            return;
        }
        let t = std::env::temp_dir().join(format!("osddir-root-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&t);
        std::fs::create_dir_all(&t).unwrap();
        let daemon = 65534; // nobody
        // SAFETY: an existing path; both ids are explicit.
        assert_eq!(
            unsafe { libc::chown(cstr(t.to_str().unwrap()).unwrap().as_ptr(), daemon, daemon) },
            0
        );
        let d = OsdDir {
            whoami: 5,
            osd_uuid: "u-5".into(),
            cluster_fsid: "c-5".into(),
            dev: "spdk:0000:03:00.0".into(),
            crush_device_class: "nvme".into(),
            keyring: keyring_text(5, "K"),
        };
        d.write(&t).unwrap();
        let dir = std::fs::metadata(&t).unwrap();
        assert_eq!(dir.uid(), daemon, "the dir keeps its owner");
        for f in ["whoami", "keyring", "ready"] {
            let m = std::fs::metadata(t.join(f)).unwrap();
            assert_eq!((m.uid(), m.gid()), (daemon, daemon), "{f}");
        }
        let _ = std::fs::remove_dir_all(&t);
    }

    /// OD7: a parent that cannot be opened/fsynced after the rename is an error (the caller must not report "durable").
    #[test]
    fn dir_roundtrip_and_mismatch() {
        let t = std::env::temp_dir().join(format!("osddir-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&t);
        let d = OsdDir {
            whoami: 7,
            osd_uuid: "u-1".into(),
            cluster_fsid: "c-1".into(),
            dev: "spdk:0000:03:00.0,ns=1".into(),
            crush_device_class: "nvme".into(),
            keyring: keyring_text(7, "KEY"),
        };
        d.write(&t).unwrap();
        d.write(&t).unwrap(); // idempotent
        assert_eq!(OsdDir::read(&t).unwrap(), d);
        assert!(OsdDir::is_ready(&t));
        assert_eq!(d.pci(), Some("0000:03:00.0"));
        let mut o = BTreeMap::new();
        o.insert("flashstore_dev".to_owned(), "spdk:0000:04:00.0".to_owned());
        assert!(run_args(&o, Some(&d), &t).is_err());
        // same controller, other namespace: a different device
        o.insert(
            "flashstore_dev".to_owned(),
            "spdk:0000:03:00.0,ns=2".to_owned(),
        );
        assert!(run_args(&o, Some(&d), &t).is_err());
        o.insert("flashstore_dev".to_owned(), "spdk:0000:03:00.0".to_owned()); // ns=1 implied
        assert!(run_args(&o, Some(&d), &t).is_ok());
        std::fs::write(t.join("whoami"), "8\n").unwrap();
        assert!(OsdDir::read(&t).is_err());

        let _ = std::fs::remove_dir_all(&t);
    }

    #[test]
    fn write_refuses_symlinks_and_keeps_the_keyring_private() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let root = std::env::temp_dir().join(format!("osddir-sym-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let d = OsdDir {
            whoami: 3,
            osd_uuid: "u-3".into(),
            cluster_fsid: "c-3".into(),
            dev: "spdk:0000:03:00.0".into(),
            crush_device_class: "nvme".into(),
            keyring: keyring_text(3, "SECRET"),
        };
        // a symlink under a fixed file name is replaced by the rename, its target keeps content and mode
        let victim = root.join("victim");
        std::fs::write(&victim, "untouched").unwrap();
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&victim, root.join("whoami")).unwrap();
        d.write(&root).unwrap();
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "untouched");
        assert!(
            !std::fs::symlink_metadata(root.join("whoami"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            std::fs::metadata(&victim).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::remove_file(root.join("whoami")).unwrap();
        // a data dir that is a symlink is refused too (root would chmod the target)
        let real = root.join("real");
        let link = root.join("link");
        d.write(&real).unwrap();
        symlink(&real, &link).unwrap();
        assert!(
            d.write(&link).is_err(),
            "symlinked data dir written through"
        );
        assert_eq!(OsdDir::read(&real).unwrap(), d);
        // the keyring mode is set at open time, also over an existing wider file
        let kr = real.join("keyring");
        std::fs::set_permissions(&kr, std::fs::Permissions::from_mode(0o644)).unwrap();
        d.write(&real).unwrap();
        assert_eq!(
            std::fs::metadata(&kr).unwrap().permissions().mode() & 0o777,
            0o600,
            "keyring is not 0600"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn write_atomic_never_writes_through_a_planted_temp_name() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};
        let root = std::env::temp_dir().join(format!("osddir-atom-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let victim = root.join("victim");
        std::fs::write(&victim, "untouched").unwrap();
        let path = root.join("keyring");
        // a symlink planted at the predictable temp name is removed, not followed
        symlink(&victim, root.join("keyring.tmp")).unwrap();
        write_atomic_mode(&path, b"SECRET", 0o600).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "SECRET");
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "untouched");
        // a hard link at the temp name is unlinked, the shared inode keeps its content
        std::fs::hard_link(&victim, root.join("keyring.tmp")).unwrap();
        write_atomic_mode(&path, b"AGAIN", 0o600).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "AGAIN");
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "untouched");
        // a symlink at the destination is replaced by the rename, never written through
        std::fs::remove_file(&path).unwrap();
        symlink(&victim, &path).unwrap();
        write_atomic_mode(&path, b"SECRET", 0o600).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "SECRET");
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "untouched");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn controller_neighbours_are_other_namespaces() {
        let r = std::env::temp_dir().join(format!("osddir-nb-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&r);
        let d = OsdDir {
            whoami: 1,
            osd_uuid: "u-1".into(),
            cluster_fsid: "c-1".into(),
            dev: "spdk:0000:03:00.0".into(),
            crush_device_class: "nvme".into(),
            keyring: keyring_text(1, "KEY"),
        };
        d.write(&r.join("ceph-1")).unwrap();
        let nb = |s: &str| controller_neighbours(&r, "ceph", s).unwrap();
        assert_eq!(
            nb("spdk:0000:03:00.0,ns=2"),
            vec![(1, "spdk:0000:03:00.0".to_owned())]
        );
        assert!(nb("spdk:0000:03:00.0,ns=1").is_empty()); // the very device (re-prepare)
        assert!(nb("spdk:0000:04:00.0,ns=2").is_empty());
        assert!(
            controller_neighbours(&r, "other", "spdk:0000:03:00.0,ns=2")
                .unwrap()
                .is_empty()
        );
        // a spec that is not a BDF is refused, never scanned against a sysfs path
        assert!(controller_neighbours(&r, "ceph", "spdk:../../x").is_err());
        let _ = std::fs::remove_dir_all(&r);
    }

    #[test]
    fn spdk_device_identity() {
        assert_eq!(spec_ns("spdk:0000:03:00.0"), Some(1));
        assert_eq!(spec_ns("spdk:0000:03:00.0,ns=2"), Some(2));
        assert_eq!(spec_ns("spdk:0000:03:00.0,ns=x"), None);
        assert_eq!(spec_ns("file:/x"), None);
        assert!(same_dev("spdk:0000:03:00.0", "spdk:0000:03:00.0,ns=1"));
        assert!(!same_dev(
            "spdk:0000:03:00.0,ns=1",
            "spdk:0000:03:00.0,ns=2"
        ));
        assert!(!same_dev("spdk:0000:03:00.0", "spdk:0000:04:00.0"));
        assert!(same_dev("file:/a", "file:/a") && !same_dev("file:/a", "file:/b"));
    }

    #[test]
    fn pci_aliases_identify_the_same_device() {
        for alias in ["AF:00.0", "0000:AF:00.0", "00000000:af:00.0"] {
            // The same spelling is used by sysfs probes, not just device comparisons.
            assert_eq!(canonical_pci(alias).as_deref(), Some("0000:af:00.0"));
            let dev = format!("spdk:{alias},ns=1");
            assert!(same_dev("spdk:0000:af:00.0", &dev), "{alias}");
            assert!(!same_dev("spdk:0000:af:00.0,ns=2", &dev), "{alias}");
        }
        // SPDK domains are 16 bit: ffff is the largest, VMD domains (10000+) are refused with a VMD hint
        assert_eq!(
            canonical_pci("ffff:af:00.0").as_deref(),
            Some("ffff:af:00.0")
        );
        assert_eq!(
            canonical_pci("00000000:af:00.0").as_deref(),
            Some("0000:af:00.0")
        );
        assert_eq!(canonical_pci("10000:af:00.0"), None);
        assert_eq!(canonical_pci("00010000:af:00.0"), None);
        let e = spec_pci("spdk:10000:af:00.0,ns=1").unwrap_err();
        assert!(e.contains("VMD") && e.contains("kernel:"), "{e}");
        assert!(spec_pci("spdk:ffff:af:00.0").is_ok());
        let dir = OsdDir {
            whoami: 7,
            osd_uuid: "u-7".into(),
            cluster_fsid: "c-7".into(),
            dev: "spdk:0000:af:00.0".into(),
            crush_device_class: "nvme".into(),
            keyring: String::new(),
        };
        let opts = BTreeMap::from([("flashstore_dev".into(), "spdk:AF:00.0".into())]);
        assert!(run_args(&opts, Some(&dir), Path::new("/unused")).is_ok());
    }

    #[test]
    fn pci_aliases_cannot_hide_controller_neighbours() {
        let root = std::env::temp_dir().join(format!("osddir-pci-alias-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let dir = OsdDir {
            whoami: 1,
            osd_uuid: "u-1".into(),
            cluster_fsid: "c-1".into(),
            dev: "spdk:0000:af:00.0,ns=1".into(),
            crush_device_class: "nvme".into(),
            keyring: String::new(),
        };
        dir.write(&root.join("ceph-1")).unwrap();
        for alias in ["AF:00.0", "0000:AF:00.0", "00000000:af:00.0"] {
            assert_eq!(
                controller_neighbours(&root, "ceph", &format!("spdk:{alias},ns=2")).unwrap(),
                vec![(1, dir.dev.clone())],
                "{alias}"
            );
            assert!(
                controller_neighbours(&root, "ceph", &format!("spdk:{alias},ns=1"))
                    .unwrap()
                    .is_empty()
            );
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn namespace_comparison_uses_the_namespace_the_device_parser_opens() {
        let dir = OsdDir {
            whoami: 7,
            osd_uuid: "u-1".into(),
            cluster_fsid: "c-1".into(),
            dev: "spdk:0000:03:00.0,ns=1".into(),
            crush_device_class: "nvme".into(),
            keyring: String::new(),
        };
        // DevSpec::parse applies ns= options in order; the last one selects the device.
        let opts = BTreeMap::from([(
            "flashstore_dev".into(),
            "spdk:0000:03:00.0,ns=1,ns=2".into(),
        )]);
        assert!(run_args(&opts, Some(&dir), Path::new("/unused")).is_err());
        assert_eq!(spec_ns("spdk:0000:03:00.0,ns=1,ns=2"), Some(2));
        assert_eq!(spec_ns("spdk:0000:03:00.0,ns=0"), None);
        assert_eq!(spec_ns("spdk:0000:03:00.0,ns=4294967295"), None);
    }

    #[test]
    fn lcore_range_refuses_reversed_and_overflowing_ranges() {
        assert_eq!(lcore_range("7-4"), None);
        assert_eq!(lcore_range(&format!("0-{}", usize::MAX)), None);
        assert_eq!(lcore_range("4-7"), Some((4, 4)));
    }

    /// OD9: two unparsable namespaces are not the same namespace.
    #[test]
    fn a_malformed_namespace_is_never_the_same_device() {
        assert!(!same_dev(
            "spdk:0000:03:00.0,ns=x",
            "spdk:0000:03:00.0,ns=y"
        ));
        assert!(!same_dev(
            "spdk:0000:03:00.0,ns=",
            "spdk:0000:03:00.0,ns=nonsense"
        ));
    }

    /// OD2: only `[dddd:]bb:dd.f` reaches a sysfs path (adr 0652).
    #[test]
    fn only_bdf_pci_addresses_are_accepted() {
        assert_eq!(spec_pci("spdk:0000:03:00.0"), Ok(Some("0000:03:00.0")));
        assert_eq!(spec_pci("spdk:03:00.0,ns=2"), Ok(Some("03:00.0")));
        assert_eq!(spec_pci("file:/x"), Ok(None));
        for bad in [
            "spdk:../../../../etc",
            "spdk:0000:03:00.8",
            "spdk:0000:03:0.0",
            "spdk:",
            "spdk:0000:03:00.0/../../x",
        ] {
            assert!(spec_pci(bad).is_err(), "{bad} accepted");
        }
        assert!(!pci_exists("../../..") && pci_driver("../../..").is_none());
        assert!(!is_bdf("0000:03:00.0x") && !is_bdf("0000:03:00"));
        // up to 8 domain digits with leading zeros; a VMD domain (10000+) is refused, a 3- or 9-digit domain is not a BDF
        assert!(is_bdf("00000000:01:00.0") && !is_bdf("10000:01:00.0"));
        assert!(!is_bdf("000:03:00.0") && !is_bdf("000000000:03:00.0"));
    }

    /// OD2: a marker the daemon user can write must not carry a path into sysfs.
    #[test]
    fn read_refuses_a_marker_with_a_path_like_device() {
        let t = std::env::temp_dir().join(format!("osddir-badd-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&t);
        let d = OsdDir {
            whoami: 1,
            osd_uuid: "u-1".into(),
            cluster_fsid: "c-1".into(),
            dev: "spdk:0000:03:00.0".into(),
            crush_device_class: "nvme".into(),
            keyring: keyring_text(1, "K"),
        };
        d.write(&t).unwrap();
        assert_eq!(OsdDir::read(&t).unwrap().dev, d.dev);
        let planted = OsdDir {
            dev: "spdk:../../../../etc".into(),
            ..d
        };
        planted.write(&t).unwrap();
        assert!(OsdDir::read(&t).is_err());
        let _ = std::fs::remove_dir_all(&t);
    }

    /// OD16: the OSD id is an i32 (doc/spec/osd-lifecycle.md 1.1); a planted marker with any other id is not an OSD.
    #[test]
    fn osd_ids_outside_i32_are_refused() {
        let t = std::env::temp_dir().join(format!("osddir-id-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&t);
        let d = OsdDir {
            whoami: 3,
            osd_uuid: "u-3".into(),
            cluster_fsid: "c-3".into(),
            dev: "spdk:0000:03:00.0".into(),
            crush_device_class: "nvme".into(),
            keyring: keyring_text(3, "K"),
        };
        d.write(&t).unwrap();
        assert_eq!(OsdDir::read(&t).unwrap().whoami, 3);
        for bad in ["-5", "2150000000", "x"] {
            let mut m: serde_json::Value = serde_json::from_str(
                &std::fs::read_to_string(t.join("croit-flashstore-osd")).unwrap(),
            )
            .unwrap();
            m["osd_id"] = serde_json::json!(bad.parse::<i64>().unwrap_or(0));
            std::fs::write(t.join("croit-flashstore-osd"), m.to_string()).unwrap();
            std::fs::write(t.join("whoami"), format!("{bad}\n")).unwrap();
            assert!(OsdDir::read(&t).is_err(), "id {bad} accepted");
        }
        // scan lists only in-range ids (the dir name is the id)
        let r = std::env::temp_dir().join(format!("osddir-idscan-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&r);
        for n in ["ceph-1", "ceph-2150000000"] {
            std::fs::create_dir_all(r.join(n)).unwrap();
            std::fs::write(r.join(n).join("croit-flashstore-osd"), "{}").unwrap();
        }
        assert_eq!(scan(&r).unwrap().len(), 1);
        let _ = std::fs::remove_dir_all(&r);
        let _ = std::fs::remove_dir_all(&t);
    }

    /// OD17: the keyring is a secret and never printed by `{:?}`.
    #[test]
    fn debug_never_prints_the_keyring() {
        let d = OsdDir {
            whoami: 3,
            osd_uuid: "u-3".into(),
            cluster_fsid: "c-3".into(),
            dev: "spdk:0000:03:00.0".into(),
            crush_device_class: "nvme".into(),
            keyring: keyring_text(3, "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="),
        };
        let s = format!("{d:?}");
        assert!(!s.contains("AQAA"), "{s}");
        assert!(s.contains("<set>"), "{s}");
        assert!(
            format!(
                "{:?}",
                OsdDir {
                    keyring: String::new(),
                    ..d
                }
            )
            .contains("<none>")
        );
    }

    #[test]
    fn scan_finds_marker_dirs() {
        let r = std::env::temp_dir().join(format!("osddir-scan-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&r);
        std::fs::create_dir_all(r.join("ceph-2")).unwrap();
        std::fs::write(r.join("ceph-2/croit-flashstore-osd"), "{}").unwrap();
        std::fs::create_dir_all(r.join("ceph-5")).unwrap(); // classic dir: ignored
        let v = scan(&r).unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!((v[0].0.as_str(), v[0].1), ("ceph", 2));
        let _ = std::fs::remove_dir_all(&r);
    }

    /// OD4: a root that cannot be read is an error, not an empty cluster: the one-OSD-per-controller check must not pass
    /// because it could not see the other OSDs.
    #[test]
    fn unreadable_osd_roots_are_errors() {
        let r = std::env::temp_dir().join(format!("osddir-scanerr-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&r);
        std::fs::create_dir_all(&r).unwrap();
        // a missing root is an empty root
        assert!(scan(&r.join("nonexistent")).unwrap().is_empty());
        // a root that is a file cannot be listed
        std::fs::write(r.join("file"), "").unwrap();
        assert!(scan(&r.join("file")).is_err());
        assert!(controller_neighbours(&r.join("file"), "ceph", "spdk:0000:03:00.0").is_err());
        // a marker dir that does not read blocks the check instead of being skipped
        std::fs::create_dir_all(r.join("ceph-1")).unwrap();
        std::fs::write(r.join("ceph-1/croit-flashstore-osd"), "{}").unwrap();
        let e = controller_neighbours(&r, "ceph", "spdk:0000:03:00.0,ns=2").unwrap_err();
        assert!(e.contains("ceph-1"), "{e}");
        // a marker dir of another cluster is not read at all
        assert!(
            controller_neighbours(&r, "other", "spdk:0000:03:00.0,ns=2")
                .unwrap()
                .is_empty()
        );
        let _ = std::fs::remove_dir_all(&r);
    }
}
