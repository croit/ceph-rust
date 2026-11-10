// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Classic `--setuser` / `--setgroup` privilege drop (spec osd-lifecycle.md 3.1a, adr 0056 am. 3): started as root by
//! a classic unit (`--setuser ceph --setgroup ceph`), the daemon becomes that user before it opens the store, a socket
//! or a file. Tiers that need root (SPDK storage) stay root with a startup WARNING.
use crate::args::{arg, set_opt};

/// A passwd entry: uid, primary gid, login name.
pub(crate) struct User {
    pub uid: u32,
    pub gid: u32,
    pub name: String,
}

/// The system lookups the decision needs (a test double in the tests).
pub(crate) trait Sys {
    fn user_by_name(&self, name: &str) -> Option<User>;
    fn user_by_id(&self, uid: u32) -> Option<User>;
    fn group_by_name(&self, name: &str) -> Option<u32>;
    /// Owner `(uid, gid)` of `path`.
    fn owner(&self, path: &str) -> Result<(u32, u32), String>;
}

/// What start-up does about the flags.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Plan {
    /// Nothing to change; the optional note is printed.
    Keep(Option<String>),
    /// Stay root; the WARNING line is printed.
    StayRoot(String),
    /// Become `uid:gid`; `user` (login name) gives the supplementary groups, `None` = only `gid`.
    Drop {
        uid: u32,
        gid: u32,
        user: Option<String>,
    },
}

/// `setuser_match_path` with the meta variables of this daemon expanded.
fn match_path(a: &[String]) -> Option<String> {
    let p = arg(a, "--setuser-match-path")
        .or_else(|| set_opt(a, "setuser_match_path"))
        .filter(|p| !p.is_empty())?;
    let cluster = set_opt(a, "cluster").unwrap_or_else(|| "ceph".into());
    let id = arg(a, "--place-id").or_else(|| arg(a, "--id"));
    let mut p = p.replace("$cluster", &cluster).replace("$type", "osd");
    if let Some(id) = id {
        p = p.replace("$name", &format!("osd.{id}")).replace("$id", &id);
    }
    Some(p)
}

/// Why this start needs root (no drop), `None` = it runs unprivileged.
pub(crate) fn root_reason(a: &[String]) -> Option<String> {
    let dev = arg(a, "--dev")?;
    #[cfg(feature = "kernel-nvme")]
    let kernel = matches!(
        crate::args::store_backend(a).as_deref(),
        Some("kernel" | "kernel-cmd")
    );
    #[cfg(not(feature = "kernel-nvme"))]
    let kernel = false;
    (dev.starts_with("spdk:") && !kernel).then(|| {
        "the SPDK storage tier drives the NVMe through vfio with hugepage DMA memory (needs root)".to_owned()
    })
}

/// Decide what to do (spec 3.1a). `Err` = start fails (exit 1, classic).
pub(crate) fn plan(
    a: &[String],
    am_root: bool,
    root_needed: Option<String>,
    sys: &impl Sys,
) -> Result<Plan, String> {
    let user = arg(a, "--setuser").filter(|v| !v.is_empty());
    let group = arg(a, "--setgroup").filter(|v| !v.is_empty());
    if user.is_none() && group.is_none() {
        return Ok(Plan::Keep(None));
    }
    if !am_root {
        let mut n = Vec::new();
        for (f, v) in [("--setuser", &user), ("--setgroup", &group)] {
            if let Some(v) = v {
                n.push(format!("ignoring {f} {v} since I am not root"));
            }
        }
        return Ok(Plan::Keep(Some(n.join("; "))));
    }
    let (mut uid, mut gid, mut name) = (0, 0, None);
    if let Some(u) = &user {
        let e = match u.parse::<u32>() {
            // Never a drop to gid 0: without a passwd entry the primary group is unknown (a numeric --setuser would
            // carry the root group for the life of the daemon).
            Ok(n) if n != 0 => match sys.user_by_id(n) {
                Some(e) => e,
                None if group.is_none() => {
                    return Err(format!(
                        "--setuser {n}: no passwd entry for uid {n}; add --setgroup G (never drop with group 0)"
                    ));
                }
                None => User {
                    uid: n,
                    gid: 0,
                    name: String::new(),
                },
            },
            _ => sys
                .user_by_name(u)
                .ok_or_else(|| format!("unable to look up user '{u}'"))?,
        };
        uid = e.uid;
        gid = e.gid;
        name = Some(e.name).filter(|n| !n.is_empty());
    }
    if let Some(g) = &group {
        gid = match g.parse::<u32>() {
            Ok(n) if n != 0 => n,
            _ => sys
                .group_by_name(g)
                .ok_or_else(|| format!("unable to look up group '{g}'"))?,
        };
    }
    if uid == 0 && gid == 0 {
        return Ok(Plan::Keep(None));
    }
    if let Some(p) = match_path(a) {
        let (ou, og) = sys
            .owner(&p)
            .map_err(|e| format!("unable to stat setuser_match_path {p}: {e}"))?;
        if (uid != 0 && uid != ou) || (gid != 0 && gid != og) {
            return Ok(Plan::StayRoot(format!(
                "WARNING: will not setuid/gid: {p} owned by {ou}:{og} and not requested {uid}:{gid}"
            )));
        }
    }
    if let Some(why) = root_needed {
        return Ok(Plan::StayRoot(format!(
            "WARNING: --setuser/--setgroup {uid}:{gid} not applied, running as root: {why} (adr 0056)"
        )));
    }
    Ok(Plan::Drop {
        uid,
        gid,
        user: name,
    })
}

/// The real system databases.
pub(crate) struct RealSys;

fn pw(name: Option<&std::ffi::CStr>, uid: u32) -> Option<User> {
    let mut buf = vec![0 as libc::c_char; 16 << 10];
    // SAFETY: reentrant lookup into our own buffer and out struct; the result pointer is checked before use and the
    // name it points to lives in `buf`.
    unsafe {
        let mut p: libc::passwd = std::mem::zeroed();
        let mut r: *mut libc::passwd = std::ptr::null_mut();
        let e = match name {
            Some(n) => libc::getpwnam_r(n.as_ptr(), &mut p, buf.as_mut_ptr(), buf.len(), &mut r),
            None => libc::getpwuid_r(uid, &mut p, buf.as_mut_ptr(), buf.len(), &mut r),
        };
        (e == 0 && !r.is_null()).then(|| User {
            uid: p.pw_uid,
            gid: p.pw_gid,
            name: std::ffi::CStr::from_ptr(p.pw_name)
                .to_string_lossy()
                .into_owned(),
        })
    }
}

impl Sys for RealSys {
    fn user_by_name(&self, name: &str) -> Option<User> {
        pw(Some(&std::ffi::CString::new(name).ok()?), 0)
    }
    fn user_by_id(&self, uid: u32) -> Option<User> {
        pw(None, uid)
    }
    fn group_by_name(&self, name: &str) -> Option<u32> {
        let c = std::ffi::CString::new(name).ok()?;
        let mut buf = vec![0 as libc::c_char; 64 << 10];
        // SAFETY: reentrant lookup into our own buffer and out struct; the result pointer is checked before use.
        unsafe {
            let mut g: libc::group = std::mem::zeroed();
            let mut r: *mut libc::group = std::ptr::null_mut();
            let e = libc::getgrnam_r(c.as_ptr(), &mut g, buf.as_mut_ptr(), buf.len(), &mut r);
            (e == 0 && !r.is_null()).then_some(g.gr_gid)
        }
    }
    fn owner(&self, path: &str) -> Result<(u32, u32), String> {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(path)
            .map(|m| (m.uid(), m.gid()))
            .map_err(|e| e.to_string())
    }
}

fn os_err(what: &str) -> String {
    format!("{what}: {}", std::io::Error::last_os_error())
}

/// Become `uid:gid` (spec 3.1a): pinned-memory limit lifted while root, supplementary groups of the user, gid, keep-caps
/// flag on `set_keepcaps`, uid, core dumps disabled; then the paths the daemon opens read-write are checked as the new user.
/// `Err` = start fails (exit 1).
pub(crate) fn drop_to(
    uid: u32,
    gid: u32,
    user: Option<&str>,
    keepcaps: bool,
    rw_paths: &[String],
) -> Result<String, String> {
    let inf = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    // SAFETY: plain syscalls on this process with valid arguments; still before any thread the daemon starts, and the
    // id changes apply to every thread (libc broadcasts them).
    unsafe {
        if libc::setrlimit(libc::RLIMIT_MEMLOCK, &inf) != 0 {
            return Err(os_err("unable to lift RLIMIT_MEMLOCK before dropping root"));
        }
        let groups_ok = match user {
            Some(u) => {
                let c = std::ffi::CString::new(u).map_err(|e| e.to_string())?;
                libc::initgroups(c.as_ptr(), gid as _) == 0
            }
            None => libc::setgroups(1, &gid) == 0,
        };
        if !groups_ok {
            return Err(os_err("unable to set the supplementary groups"));
        }
        if libc::setgid(gid) != 0 {
            return Err(os_err(&format!("unable to setgid {gid}")));
        }
        if keepcaps && libc::prctl(libc::PR_SET_KEEPCAPS, 1, 0, 0, 0) != 0 {
            eprintln!(
                "croit-flashstore-osd: warning: {}",
                os_err("unable to set keepcaps flag")
            );
        }
        if libc::setuid(uid) != 0 {
            return Err(os_err(&format!("unable to setuid {uid}")));
        }
    }
    disable_core_dumps()?;
    for p in rw_paths {
        let c = std::ffi::CString::new(p.as_str()).map_err(|e| e.to_string())?;
        // SAFETY: access(2) on a NUL-terminated path.
        if unsafe { libc::access(c.as_ptr(), libc::R_OK | libc::W_OK) } != 0 {
            let err = std::io::Error::last_os_error();
            let owner = {
                use std::os::unix::fs::MetadataExt;
                std::fs::metadata(p)
                    .map(|m| format!("owner {}:{} mode {:o}", m.uid(), m.gid(), m.mode() & 0o7777))
                    .unwrap_or_else(|e| e.to_string())
            };
            return Err(format!(
                "after --setuser/--setgroup {uid}:{gid}: {p} is not readable+writable ({err}; {owner}): give it to \
                 the user (chown {uid}:{gid} {p}, croit-flashstore-prep@ / ceph-volume udev rule) or add the user to its group"
            ));
        }
    }
    Ok(format!(
        "set uid:gid to {uid}:{gid} ({})",
        user.unwrap_or("")
    ))
}

/// Paths the kernel tier opens read-write: the device node of a kernel-driven NVMe or a file store, and the data dir.
pub(crate) fn rw_paths(a: &[String]) -> Vec<String> {
    let mut v = Vec::new();
    if let Some(d) = arg(a, "--dev") {
        #[cfg(feature = "kernel-nvme")]
        let d = match crate::args::store_backend(a) {
            Some(b) => nvme::any::resolve_backend(&d, &b).unwrap_or(d),
            None => d,
        };
        for pre in ["kernel:", "file:"] {
            if let Some(p) = d.strip_prefix(pre) {
                v.push(p.split(',').next().unwrap_or(p).to_owned());
            }
        }
    }
    v.extend(arg(a, "--data"));
    v
}

/// Option `set_keepcaps` (any `_` / `-` / space spelling): capabilities survive the uid change.
fn keepcaps(a: &[String]) -> bool {
    set_opt(a, "set_keepcaps").is_some_and(|v| v == "true")
}

/// The start-up step: decide and apply (spec 3.1a). `Err` = exit 1.
pub(crate) fn apply(a: &[String]) -> Result<(), String> {
    // SAFETY: getuid has no preconditions.
    let am_root = unsafe { libc::getuid() } == 0;
    match plan(a, am_root, root_reason(a), &RealSys)? {
        Plan::Keep(None) => {}
        Plan::Keep(Some(n)) => eprintln!("croit-flashstore-osd: {n}"),
        Plan::StayRoot(w) => eprintln!("croit-flashstore-osd: {w}"),
        Plan::Drop { uid, gid, user } => {
            let msg = drop_to(uid, gid, user.as_deref(), keepcaps(a), &rw_paths(a))?;
            eprintln!("croit-flashstore-osd: {msg}");
        }
    }
    Ok(())
}

/// `PR_SET_DUMPABLE=0`: no native core of this process (keys, client data), also not through a piped `core_pattern`
/// collector, which ignores `RLIMIT_CORE` (`LimitCORE=0` alone is not enough). `main` calls it first; a uid/gid change
/// resets the flag, so [`drop_to`] calls it again. `Err` = start fails.
pub(crate) fn disable_core_dumps() -> Result<(), String> {
    // SAFETY: process-local prctl with scalar arguments; no pointers.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(os_err("unable to disable core dumps"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fake;
    impl Sys for Fake {
        fn user_by_name(&self, name: &str) -> Option<User> {
            match name {
                "ceph" => Some(User {
                    uid: 167,
                    gid: 167,
                    name: "ceph".into(),
                }),
                "root" => Some(User {
                    uid: 0,
                    gid: 0,
                    name: "root".into(),
                }),
                _ => None,
            }
        }
        fn user_by_id(&self, uid: u32) -> Option<User> {
            (uid == 167).then(|| User {
                uid,
                gid: 167,
                name: "ceph".into(),
            })
        }
        fn group_by_name(&self, name: &str) -> Option<u32> {
            match name {
                "ceph" => Some(167),
                "disk" => Some(6),
                _ => None,
            }
        }
        fn owner(&self, path: &str) -> Result<(u32, u32), String> {
            match path {
                "/var/lib/ceph/osd/c1-3" => Ok((167, 167)),
                "/var/lib/ceph/osd/c1-4" => Ok((0, 0)),
                _ => Err("No such file or directory".into()),
            }
        }
    }

    fn v(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| (*x).to_owned()).collect()
    }

    fn drop_(uid: u32, gid: u32, user: Option<&str>) -> Plan {
        Plan::Drop {
            uid,
            gid,
            user: user.map(str::to_owned),
        }
    }

    #[test]
    fn classic_unit_flags_drop_to_the_user() {
        let a = v(&["--setuser", "ceph", "--setgroup", "ceph"]);
        assert_eq!(
            plan(&a, true, None, &Fake).unwrap(),
            drop_(167, 167, Some("ceph"))
        );
        assert_eq!(
            plan(
                &v(&["--setuser", "ceph", "--setgroup", "disk"]),
                true,
                None,
                &Fake
            )
            .unwrap(),
            drop_(167, 6, Some("ceph")),
            "the group overrides the primary gid"
        );
        assert_eq!(
            plan(&v(&["--setuser", "167"]), true, None, &Fake).unwrap(),
            drop_(167, 167, Some("ceph"))
        );
        assert_eq!(
            plan(
                &v(&["--setuser", "500", "--setgroup", "500"]),
                true,
                None,
                &Fake
            )
            .unwrap(),
            drop_(500, 500, None),
            "numeric ids without passwd entry"
        );
        assert_eq!(
            plan(&v(&["--setgroup", "ceph"]), true, None, &Fake).unwrap(),
            drop_(0, 167, None)
        );
        assert_eq!(
            plan(&v(&["--setuser", "root"]), true, None, &Fake).unwrap(),
            Plan::Keep(None)
        );
        // classic: `0` is not a uid but a name to look up
        assert!(plan(&v(&["--setuser", "0"]), true, None, &Fake).is_err());
        assert_eq!(plan(&v(&[]), true, None, &Fake).unwrap(), Plan::Keep(None));
    }

    #[test]
    fn not_root_ignores_with_classic_note() {
        assert_eq!(
            plan(&v(&["--setuser", "ceph", "--setgroup", "ceph"]), false, None, &Fake).unwrap(),
            Plan::Keep(Some(
                "ignoring --setuser ceph since I am not root; ignoring --setgroup ceph since I am not root".into()
            ))
        );
    }

    #[test]
    fn unknown_user_or_group_fails() {
        let e = plan(&v(&["--setuser", "nobody2"]), true, None, &Fake).unwrap_err();
        assert_eq!(e, "unable to look up user 'nobody2'");
        let e = plan(
            &v(&["--setuser", "ceph", "--setgroup", "x"]),
            true,
            None,
            &Fake,
        )
        .unwrap_err();
        assert_eq!(e, "unable to look up group 'x'");
    }

    /// A numeric `--setuser` without a passwd entry has no primary group; the drop needs `--setgroup` instead of
    /// silently keeping group 0.
    #[test]
    fn numeric_user_without_a_passwd_entry_needs_setgroup() {
        let e = plan(&v(&["--setuser", "500"]), true, None, &Fake).unwrap_err();
        assert!(e.contains("--setgroup") && e.contains("500"), "{e}");
        // with an explicit group the drop is well defined (no passwd entry, no supplementary groups)
        assert_eq!(
            plan(
                &v(&["--setuser", "500", "--setgroup", "500"]),
                true,
                None,
                &Fake
            )
            .unwrap(),
            drop_(500, 500, None)
        );
    }

    /// `set_keepcaps` is an option: `--set set-keepcaps=true` must be honoured like the `_` spelling.
    #[test]
    fn keepcaps_key_accepts_both_spellings() {
        assert!(!keepcaps(&v(&[])));
        for k in ["set_keepcaps", "set-keepcaps"] {
            assert!(keepcaps(&v(&["--set", &format!("{k}=true")])), "{k}");
            assert!(!keepcaps(&v(&["--set", &format!("{k}=false")])), "{k}");
        }
        // the last setting wins
        assert!(!keepcaps(&v(&[
            "--set",
            "set_keepcaps=true",
            "--set",
            "set-keepcaps=false",
        ])));
    }

    /// setuser_match_path: meta variables expanded; owner match drops, mismatch stays root with the WARNING, a
    /// missing path fails.
    #[test]
    fn match_path_gates_the_drop() {
        let a = |p: &str, id: &str| {
            v(&[
                "--setuser",
                "ceph",
                "--setgroup",
                "ceph",
                "--set",
                "cluster=c1",
                "--place-id",
                id,
                "--set",
                &format!("setuser_match_path={p}"),
            ])
        };
        let p = "/var/lib/ceph/osd/$cluster-$id";
        assert_eq!(
            plan(&a(p, "3"), true, None, &Fake).unwrap(),
            drop_(167, 167, Some("ceph"))
        );
        assert_eq!(
            plan(&a(p, "4"), true, None, &Fake).unwrap(),
            Plan::StayRoot(
                "WARNING: will not setuid/gid: /var/lib/ceph/osd/c1-4 owned by 0:0 and not requested 167:167".into()
            )
        );
        let e = plan(&a(p, "5"), true, None, &Fake).unwrap_err();
        assert!(
            e.starts_with("unable to stat setuser_match_path /var/lib/ceph/osd/c1-5"),
            "{e}"
        );
        let mut f = a("x", "3");
        f.truncate(8);
        f.extend(v(&[
            "--setuser-match-path",
            "/var/lib/ceph/osd/$cluster-$id",
        ]));
        assert_eq!(
            plan(&f, true, None, &Fake).unwrap(),
            drop_(167, 167, Some("ceph"))
        );
    }

    /// The real drop, in a child process of this test binary (as root only; the runner is root): ids, groups, memlock
    /// limit, dumpable flag, and the access check naming a path the new user cannot write.
    #[test]
    fn real_drop_in_a_child_process() {
        const CHILD: &str = "FLASHSTORE_PRIVDROP_CHILD";
        if let Ok(dir) = std::env::var(CHILD) {
            let ok = format!("{dir}/ok");
            let bad = format!("{dir}/bad");
            let e = drop_to(65534, 65534, None, false, &[ok, bad.clone()]).unwrap_err();
            assert!(e.contains(&bad) && e.contains("owner 0:0 mode 600"), "{e}");
            // SAFETY: plain id / limit / prctl queries.
            unsafe {
                assert_eq!((libc::getuid(), libc::geteuid()), (65534, 65534));
                assert_eq!((libc::getgid(), libc::getegid()), (65534, 65534));
                let mut g = [0 as libc::gid_t; 8];
                assert_eq!(libc::getgroups(8, g.as_mut_ptr()), 1);
                assert_eq!(g[0], 65534);
                let mut r: libc::rlimit = std::mem::zeroed();
                libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut r);
                assert_eq!(r.rlim_cur, libc::RLIM_INFINITY);
                assert_eq!(libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0), 0);
            }
            return;
        }
        // SAFETY: getuid has no preconditions.
        if unsafe { libc::getuid() } != 0 {
            eprintln!("real_drop_in_a_child_process: not root, the drop itself is not exercised");
            return;
        }
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("privdrop-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        for (f, m) in [("ok", 0o666), ("bad", 0o600)] {
            std::fs::write(dir.join(f), b"").unwrap();
            std::fs::set_permissions(dir.join(f), std::fs::Permissions::from_mode(m)).unwrap();
        }
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "privdrop::tests::real_drop_in_a_child_process",
                "--nocapture",
            ])
            .env(CHILD, &dir)
            .output()
            .unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            out.status.success(),
            "child: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[test]
    fn root_tiers_stay_root_with_warning() {
        assert!(
            root_reason(&v(&["--dev", "spdk:0000:03:00.0"])).is_some_and(|r| r.contains("SPDK"))
        );
        assert!(root_reason(&v(&["--dev", "file:/x"])).is_none());
        let a = v(&["--setuser", "ceph", "--dev", "spdk:0000:03:00.0"]);
        let p = plan(&a, true, root_reason(&a), &Fake).unwrap();
        assert!(
            matches!(&p, Plan::StayRoot(w) if w.starts_with("WARNING") && w.contains("SPDK storage tier")),
            "{p:?}"
        );
        assert_eq!(
            rw_paths(&v(&["--dev", "file:/srv/osd.img,size=1G", "--data", "/d"])),
            ["/srv/osd.img", "/d"]
        );
    }
}
