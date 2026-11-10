// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Host io_uring access policy: why `io_uring_setup` is refused and the exact host fix (adr 0053 am. 11, adr 0169 am. 6).
//!
//! The OSD never changes host sysctls (CLAUDE.md "Runs optimally out of the box"): a refused ring is one loud line naming the
//! cause and the command that fixes it; `croit-flashstore-tool host-tune` applies it on request (hwcheck `os.io_uring`).
//!
//! Policy of the kernel (`kernel.io_uring_disabled`, upstream 6.6, backported e.g. to RHEL 9 where the default is 2):
//! 0 = every process, 1 = only CAP_SYS_ADMIN and members of `kernel.io_uring_group`, 2 = nobody. Without the sysctl the
//! kernel has no such policy; a refusal then comes from seccomp (container profiles), an LSM (SELinux/AppArmor) or, for
//! ENOSYS, from a kernel without io_uring (mainline before 5.1). A sysctl that exists but cannot be read is reported as
//! unknown, never as allowing io_uring.
//!
//! Pure file parsing below a root directory (`/` live, a fake tree in tests): no io_uring or sysctl calls.
use std::path::Path;

/// User the OSD runs as (unit `croit-flashstore-osd@.service` `User=`/`Group=`, adr 0056).
pub const OSD_USER: &str = "ceph";

/// Bit of CAP_SYS_ADMIN (21) in the `CapEff:` mask of `/proc/self/status`.
const CAP_SYS_ADMIN: u64 = 1 << 21;

/// Tail of every sysctl fix: where to persist it and the helper that applies it.
const PERSIST: &str = "persist in /etc/sysctl.d/, or run `croit-flashstore-tool host-tune --apply`";

/// One `kernel.io_uring*` sysctl below `/proc/sys/kernel`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Sysctl<T> {
    /// ENOENT: the kernel has no such sysctl (no policy).
    #[default]
    Absent,
    /// Value read.
    Value(T),
    /// Present but unreadable or not a number (procfs hidden, permission error): the policy is not known.
    Unknown,
}

impl Sysctl<i64> {
    /// The gid the sysctl names; `None` for `-1` (no group) and its unsigned view `u32::MAX` (`-1` as `u32`).
    pub fn named_gid(&self) -> Option<i64> {
        match *self {
            Sysctl::Value(g) if (0..i64::from(u32::MAX)).contains(&g) => Some(g),
            _ => None,
        }
    }
}

/// io_uring access state of the host and of the calling process.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Access {
    /// `kernel.io_uring_disabled`.
    pub disabled: Sysctl<u8>,
    /// `kernel.io_uring_group` (`-1` = no group).
    pub group: Sysctl<i64>,
    /// Effective uid of this process (`/proc/self/status` `Uid:` second column).
    pub euid: Option<u32>,
    /// Effective gid of this process (`Gid:` second column).
    pub egid: Option<u32>,
    /// Supplementary groups of this process (`Groups:`).
    pub groups: Vec<u32>,
    /// CAP_SYS_ADMIN in the effective set (passes `io_uring_disabled=1`).
    pub cap_sys_admin: bool,
    /// `Seccomp:` of this process (0 none, 1 strict, 2 filter).
    pub seccomp: Option<u8>,
    /// Primary gid of [`OSD_USER`] (`etc/passwd`).
    pub osd_gid: Option<u32>,
    /// Supplementary groups of [`OSD_USER`] (`etc/group` member lists).
    pub osd_groups: Vec<u32>,
}

/// One file below the root: its text, absent (ENOENT) or present but unreadable.
enum File {
    Text(String),
    Absent,
    Unreadable,
}

/// Lossy on purpose: one undecodable byte (latin-1 in a `/etc/passwd` GECOS field is legal) must not hide the rest of the
/// file.
fn read(root: &Path, rel: &str) -> File {
    match std::fs::read(root.join(rel)) {
        Ok(b) => File::Text(String::from_utf8_lossy(&b).trim().to_owned()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => File::Absent,
        Err(_) => File::Unreadable,
    }
}

impl File {
    fn text(self) -> Option<String> {
        match self {
            File::Text(s) => Some(s),
            File::Absent | File::Unreadable => None,
        }
    }

    /// Sysctl value: ENOENT is "the kernel has no such sysctl", any other error or a non-number is "unknown" (never
    /// "allowed").
    fn sysctl<T: std::str::FromStr>(self) -> Sysctl<T> {
        match self {
            File::Text(s) => s.trim().parse().map_or(Sysctl::Unknown, Sysctl::Value),
            File::Absent => Sysctl::Absent,
            File::Unreadable => Sysctl::Unknown,
        }
    }
}

fn status_field<'a>(status: &'a str, key: &str) -> Option<&'a str> {
    status
        .lines()
        .find_map(|l| l.strip_prefix(key)?.strip_prefix(':').map(str::trim))
}

/// Second column (effective id) of a `Uid:` / `Gid:` status line.
fn effective(v: Option<&str>) -> Option<u32> {
    v?.split_whitespace().nth(1)?.parse().ok()
}

/// Is `gid` (or one of `groups`) the group `named`? `named = None` = the sysctl names no group.
fn in_group(gid: u32, groups: &[u32], named: Option<i64>) -> bool {
    named.is_some_and(|g| i64::from(gid) == g || groups.iter().any(|x| i64::from(*x) == g))
}

impl Access {
    /// Read the state below `root` (`/` on a live host).
    pub fn read(root: &Path) -> Access {
        let status = read(root, "proc/self/status").text().unwrap_or_default();
        let osd_gid = read(root, "etc/passwd").text().and_then(|p| {
            p.lines().find_map(|l| {
                let f: Vec<&str> = l.split(':').collect();
                (f.len() >= 4 && f[0] == OSD_USER)
                    .then(|| f[3].parse().ok())
                    .flatten()
            })
        });
        let osd_groups = read(root, "etc/group")
            .text()
            .map(|g| {
                g.lines()
                    .filter_map(|l| {
                        let f: Vec<&str> = l.split(':').collect();
                        (f.len() >= 4 && f[3].split(',').any(|m| m.trim() == OSD_USER))
                            .then(|| f[2].parse().ok())
                            .flatten()
                    })
                    .collect()
            })
            .unwrap_or_default();
        Access {
            disabled: read(root, "proc/sys/kernel/io_uring_disabled").sysctl(),
            group: read(root, "proc/sys/kernel/io_uring_group").sysctl(),
            euid: effective(status_field(&status, "Uid")),
            egid: effective(status_field(&status, "Gid")),
            groups: status_field(&status, "Groups")
                .map(|g| {
                    g.split_whitespace()
                        .filter_map(|x| x.parse().ok())
                        .collect()
                })
                .unwrap_or_default(),
            cap_sys_admin: status_field(&status, "CapEff")
                .and_then(|c| u64::from_str_radix(c, 16).ok())
                .is_some_and(|c| c & CAP_SYS_ADMIN != 0),
            seccomp: status_field(&status, "Seccomp").and_then(|s| s.parse().ok()),
            osd_gid,
            osd_groups,
        }
    }

    /// State of the live host and this process.
    pub fn live() -> Access {
        Access::read(Path::new("/"))
    }

    /// Does the sysctl policy let [`OSD_USER`] create rings (no CAP_SYS_ADMIN, adr 0056)? `None` = user or policy unknown.
    pub fn osd_user_allowed(&self) -> Option<bool> {
        match self.disabled {
            Sysctl::Absent | Sysctl::Value(0) => Some(true),
            Sysctl::Value(1) => {
                let gid = self.osd_gid?;
                Some(in_group(gid, &self.osd_groups, self.group.named_gid()))
            }
            Sysctl::Value(_) => Some(false),
            Sysctl::Unknown => None,
        }
    }

    /// Does the sysctl policy let this process create rings? An unknown policy does not.
    pub fn self_allowed(&self) -> bool {
        match self.disabled {
            Sysctl::Absent | Sysctl::Value(0) => true,
            Sysctl::Value(1) => {
                self.cap_sys_admin
                    || self
                        .egid
                        .is_some_and(|g| in_group(g, &self.groups, self.group.named_gid()))
            }
            _ => false,
        }
    }

    /// gid the fix grants io_uring to: [`OSD_USER`]'s, else this process's when it is not root, else a shell expansion.
    pub fn osd_gid_text(&self) -> String {
        match (self.osd_gid, self.euid, self.egid) {
            (Some(g), _, _) => g.to_string(),
            (None, Some(u), Some(g)) if u != 0 => g.to_string(),
            _ => format!("$(id -g {OSD_USER})"),
        }
    }

    /// Cause of a refused `io_uring_setup` and the exact host fix, one line (no leading error text).
    pub fn explain(&self) -> String {
        self.explain_kind(None)
    }

    /// [`Access::explain`] knowing the errno class of the refused call: `Unsupported` (ENOSYS) separates a kernel without
    /// io_uring from a filter that only blocks the syscalls.
    fn explain_kind(&self, kind: Option<std::io::ErrorKind>) -> String {
        match self.disabled {
            Sysctl::Value(1) if self.self_allowed() => self.unblocked(kind),
            Sysctl::Value(1) => self.group_only(),
            Sysctl::Value(0) | Sysctl::Absent => self.unblocked(kind),
            Sysctl::Unknown => self.policy_unknown(),
            // the kernel clamps the sysctl to 0..2, so any higher value is off for every process like 2
            Sysctl::Value(d) => self.off_for_everyone(d),
        }
    }

    /// `Seccomp:` of this process as far as an io_uring refusal is concerned.
    fn filter(&self) -> Filter {
        match self.seccomp {
            Some(1) | Some(2) => Filter::Active,
            Some(0) => Filter::None,
            _ => Filter::Unknown,
        }
    }

    /// `kernel.io_uring_disabled` as read, for the messages.
    fn disabled_state(&self) -> String {
        match self.disabled {
            Sysctl::Absent => "kernel.io_uring_disabled is absent (kernel without the sysctl)".to_owned(),
            Sysctl::Value(0) => "kernel.io_uring_disabled=0 allows every process".to_owned(),
            Sysctl::Value(1) => {
                "kernel.io_uring_disabled=1 allows this process (CAP_SYS_ADMIN or group io_uring_group)".to_owned()
            }
            Sysctl::Value(d) => format!("kernel.io_uring_disabled={d}"),
            Sysctl::Unknown => "kernel.io_uring_disabled cannot be read".to_owned(),
        }
    }

    /// `kernel.io_uring_disabled=1` and this process is neither CAP_SYS_ADMIN nor in the sysctl group: only a group the OSD
    /// is in helps.
    fn group_only(&self) -> String {
        let g = self.osd_gid_text();
        let current = match self.group {
            Sysctl::Value(current) => current.to_string(),
            Sysctl::Unknown => "unreadable".to_owned(),
            Sysctl::Absent => "absent".to_owned(),
        };
        let alternative = self.group.named_gid().map_or_else(String::new, |named| {
            format!(" or add the OSD user to group {named}")
        });
        format!(
            "kernel.io_uring_disabled=1 limits io_uring to CAP_SYS_ADMIN and members of kernel.io_uring_group (currently \
             {current}); this process (uid {} gid {} groups {:?}) is in neither. Fix: `sysctl -w \
             kernel.io_uring_group={g}` (the OSD group){alternative}; {PERSIST}",
            self.euid.map_or("?".into(), |u| u.to_string()),
            self.egid.map_or("?".into(), |u| u.to_string()),
            self.groups
        )
    }

    /// `kernel.io_uring_disabled=2` (RHEL 9 default) or above: io_uring off for every process, CAP_SYS_ADMIN included.
    fn off_for_everyone(&self, disabled: u8) -> String {
        let g = self.osd_gid_text();
        if matches!(self.group, Sysctl::Value(_)) {
            format!(
                "kernel.io_uring_disabled={disabled} (io_uring off for every process; RHEL 9 default 2); the OSD does not \
                 change host sysctls. Fix: `sysctl -w kernel.io_uring_group={g} kernel.io_uring_disabled=1` (io_uring for the \
                 OSD group {g} and CAP_SYS_ADMIN only) or `sysctl -w kernel.io_uring_disabled=0` (every process); {PERSIST}"
            )
        } else {
            format!(
                "kernel.io_uring_disabled={disabled} (io_uring off for every process); the OSD does not change host sysctls. \
                 Fix: `sysctl -w kernel.io_uring_disabled=0`; {PERSIST}"
            )
        }
    }

    /// The policy sysctl exists but cannot be read: the state is unknown, never "allows io_uring".
    fn policy_unknown(&self) -> String {
        "kernel.io_uring_disabled cannot be read (procfs hidden, e.g. ProcSubset=pid, or a permission error), so the \
         io_uring policy of this host is unknown; read it on the host (`cat /proc/sys/kernel/io_uring_disabled`) and apply \
         the fix for that value; a syscall filter or an LSM can refuse io_uring_setup as well"
            .to_owned()
    }

    /// The sysctl names no policy or lets this process create rings: the refusal comes from a syscall filter or an LSM or,
    /// for ENOSYS, from a kernel without io_uring. `Seccomp:` decides which cause is named first.
    fn unblocked(&self, kind: Option<std::io::ErrorKind>) -> String {
        let state = self.disabled_state();
        match (self.filter(), kind == Some(std::io::ErrorKind::Unsupported)) {
            (Filter::Active, false) => format!(
                "{state}, so the seccomp profile of this process refuses it (seccomp=filter): allow \
                 io_uring_setup/io_uring_enter/io_uring_register in the container seccomp profile; SELinux: check \
                 `ausearch -m avc -ts recent` for io_uring denials"
            ),
            (Filter::Active, true) => format!(
                "{state} and the seccomp profile of this process refuses io_uring (seccomp=filter, a profile can return \
                 ENOSYS): allow io_uring_setup/io_uring_enter/io_uring_register in the container seccomp profile; if the \
                 profile already allows them, this kernel has no io_uring (mainline before 5.1)"
            ),
            (Filter::None, false) => format!(
                "{state} and Seccomp: 0 (no filter), so an LSM (SELinux/AppArmor) refuses io_uring: SELinux: check \
                 `ausearch -m avc -ts recent` for io_uring denials; AppArmor: check the OSD profile"
            ),
            (Filter::None, true) => format!(
                "{state}, Seccomp: 0 (no filter) and io_uring_setup returns ENOSYS: io_uring is not available in this kernel \
                 (mainline before 5.1, or built with CONFIG_IO_URING=n), which no sysctl or filter can change; use a kernel \
                 with io_uring (adr 0098)"
            ),
            (Filter::Unknown, false) => format!(
                "{state}, so a syscall filter (seccomp unknown) or an LSM refuses it: allow \
                 io_uring_setup/io_uring_enter/io_uring_register in the container seccomp profile; SELinux: check \
                 `ausearch -m avc -ts recent` for io_uring denials"
            ),
            (Filter::Unknown, true) => format!(
                "{state} and io_uring_setup returns ENOSYS: either this kernel has no io_uring (mainline before 5.1) or a \
                 syscall filter returns ENOSYS (seccomp unknown); allow io_uring_setup/io_uring_enter/io_uring_register in the \
                 container seccomp profile if the kernel has io_uring"
            ),
        }
    }
}

/// `Seccomp:` of the calling process.
enum Filter {
    /// A filter (or strict mode) is active and can refuse the io_uring syscalls.
    Active,
    /// `Seccomp: 0`: no filter exists, only an LSM can refuse them.
    None,
    /// `/proc/self/status` says nothing.
    Unknown,
}

/// `err` of `io_uring_setup`: a permission refusal (EPERM/EACCES) or a syscall the kernel does not have (ENOSYS) gets the
/// host cause and fix appended ([`Access::explain`] of the live host); any other error is returned unchanged.
pub fn refused(err: std::io::Error) -> std::io::Error {
    match err.kind() {
        std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::Unsupported => {
            std::io::Error::new(
                err.kind(),
                format!(
                    "io_uring refused ({err}): {}",
                    Access::live().explain_kind(Some(err.kind()))
                ),
            )
        }
        _ => err,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    struct Root(PathBuf);
    impl Drop for Root {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn root(tag: &str, files: &[(&str, &str)]) -> Root {
        let bytes: Vec<(&str, &[u8])> = files.iter().map(|(f, c)| (*f, c.as_bytes())).collect();
        root_bytes(tag, &bytes)
    }

    fn root_bytes(tag: &str, files: &[(&str, &[u8])]) -> Root {
        let p = std::env::temp_dir().join(format!("uring-access-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        for (f, c) in files {
            let path = p.join(f);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, c).unwrap();
        }
        Root(p)
    }

    const STATUS_CEPH: &str = "Name:\tflashstore\nUid:\t167\t167\t167\t167\nGid:\t167\t167\t167\t167\nGroups:\t167 6 \nCapEff:\t0000000000804000\nSeccomp:\t0\n";
    const STATUS_ROOT: &str =
        "Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nGroups:\t\nCapEff:\t000001ffffffffff\nSeccomp:\t0\n";
    const PASSWD: &str = "root:x:0:0:root:/root:/bin/bash\nceph:x:167:167:Ceph daemons:/var/lib/ceph:/sbin/nologin\n";

    #[test]
    fn rhel_default_two_offers_group_and_zero() {
        let r = root(
            "two",
            &[
                ("proc/sys/kernel/io_uring_disabled", "2\n"),
                ("proc/sys/kernel/io_uring_group", "-1\n"),
                ("proc/self/status", STATUS_ROOT),
                ("etc/passwd", PASSWD),
            ],
        );
        let a = Access::read(&r.0);
        assert_eq!(
            (a.disabled, a.group, a.osd_gid),
            (Sysctl::Value(2), Sysctl::Value(-1), Some(167))
        );
        assert!(a.cap_sys_admin && !a.self_allowed());
        assert_eq!(a.osd_user_allowed(), Some(false));
        let e = a.explain();
        assert!(
            e.contains("sysctl -w kernel.io_uring_group=167 kernel.io_uring_disabled=1"),
            "{e}"
        );
        assert!(e.contains("sysctl -w kernel.io_uring_disabled=0"), "{e}");
        assert!(e.contains("host-tune --apply"), "{e}");
    }

    #[test]
    fn two_without_group_sysctl_offers_zero_only() {
        let r = root(
            "twonog",
            &[
                ("proc/sys/kernel/io_uring_disabled", "2\n"),
                ("proc/self/status", STATUS_ROOT),
            ],
        );
        let e = Access::read(&r.0).explain();
        assert!(
            e.contains("sysctl -w kernel.io_uring_disabled=0") && !e.contains("io_uring_group"),
            "{e}"
        );
    }

    #[test]
    fn one_group_membership_decides() {
        let mut files = vec![
            ("proc/sys/kernel/io_uring_disabled", "1\n"),
            ("proc/sys/kernel/io_uring_group", "6\n"),
            ("proc/self/status", STATUS_CEPH),
            ("etc/passwd", PASSWD),
        ];
        let r = root("one", &files);
        let a = Access::read(&r.0);
        assert!(
            !a.cap_sys_admin && a.self_allowed(),
            "supplementary group 6 of the process"
        );
        assert_eq!(
            a.osd_user_allowed(),
            Some(false),
            "etc/group does not list ceph in 6"
        );
        files.push(("etc/group", "disk:x:6:ceph,qemu\n"));
        let r = root("one2", &files);
        assert_eq!(Access::read(&r.0).osd_user_allowed(), Some(true));
        files[1] = ("proc/sys/kernel/io_uring_group", "-1\n"); // no group named: CAP_SYS_ADMIN only
        let r = root("one3", &files);
        let a = Access::read(&r.0);
        assert!(!a.self_allowed());
        assert!(
            a.explain().contains("sysctl -w kernel.io_uring_group=167`"),
            "{}",
            a.explain()
        );
    }

    #[test]
    fn allowed_policy_points_at_seccomp() {
        let r = root(
            "zero",
            &[
                ("proc/sys/kernel/io_uring_disabled", "0\n"),
                ("proc/self/status", "Seccomp:\t2\n"),
            ],
        );
        let a = Access::read(&r.0);
        assert!(a.self_allowed());
        assert!(a.explain().contains("seccomp=filter"), "{}", a.explain());
        let r = root("none", &[]);
        let a = Access::read(&r.0);
        assert_eq!(a.osd_user_allowed(), Some(true));
        assert!(a.explain().contains("io_uring_disabled is absent"));
    }

    #[test]
    fn gid_text_without_passwd() {
        let a = Access {
            euid: Some(0),
            egid: Some(0),
            ..Access::default()
        };
        assert_eq!(a.osd_gid_text(), "$(id -g ceph)");
        let a = Access {
            euid: Some(167),
            egid: Some(167),
            ..Access::default()
        };
        assert_eq!(a.osd_gid_text(), "167");
    }

    #[test]
    fn explain_disabled_one_allowed_points_at_seccomp() {
        let r = root(
            "onecap",
            &[
                ("proc/sys/kernel/io_uring_disabled", "1\n"),
                ("proc/sys/kernel/io_uring_group", "6\n"),
                (
                    "proc/self/status",
                    "Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nGroups:\t\nCapEff:\t0000000000200000\nSeccomp:\t0\n",
                ),
                ("etc/passwd", PASSWD),
            ],
        );
        let a = Access::read(&r.0);
        assert!(a.cap_sys_admin && a.self_allowed());
        let e = a.explain();
        assert!(e.contains("LSM"), "the policy allows this process: {e}");
        assert!(!e.contains("is in neither"), "not a contradiction: {e}");
        assert!(
            !e.contains("sysctl -w kernel.io_uring_group"),
            "no group fix can help: {e}"
        );
    }

    #[test]
    fn explain_disabled_one_without_group_offers_sysctl_only() {
        let status = "Uid:\t167\t167\t167\t167\nGid:\t167\t167\t167\t167\nGroups:\t\nCapEff:\t0\nSeccomp:\t0\n";
        for (tag, group) in [("nogroup", "-1\n"), ("ungroup", "4294967295\n")] {
            let r = root(
                tag,
                &[
                    ("proc/sys/kernel/io_uring_disabled", "1\n"),
                    ("proc/sys/kernel/io_uring_group", group),
                    ("proc/self/status", status),
                    ("etc/passwd", PASSWD),
                ],
            );
            let a = Access::read(&r.0);
            assert!(!a.self_allowed(), "{tag}: the sysctl names no group");
            let e = a.explain();
            assert!(e.contains("sysctl -w kernel.io_uring_group=167"), "{e}");
            assert!(
                !e.contains("add the OSD user to that group"),
                "{tag}: there is no group to join: {e}"
            );
        }
    }

    #[test]
    fn explain_without_filter_names_lsm() {
        let a = Access {
            disabled: Sysctl::Value(0),
            seccomp: Some(0),
            ..Access::default()
        };
        let e = a.explain();
        assert!(e.contains("LSM") && e.contains("ausearch"), "{e}");
        assert!(!e.contains("seccomp profile"), "no filter exists: {e}");
    }

    #[test]
    fn enosys_without_policy_names_missing_io_uring() {
        let enosys = Some(std::io::ErrorKind::Unsupported);
        let a = Access {
            disabled: Sysctl::Absent,
            seccomp: Some(0),
            ..Access::default()
        };
        let e = a.explain_kind(enosys);
        assert!(e.contains("io_uring is not available"), "{e}");
        assert!(!e.contains("seccomp profile"), "no filter exists: {e}");
        // a filter can return ENOSYS itself: the profile stays the first fix there
        let a = Access {
            disabled: Sysctl::Absent,
            seccomp: Some(2),
            ..Access::default()
        };
        let e = a.explain_kind(enosys);
        assert!(e.contains("seccomp profile"), "{e}");
        assert!(
            e.contains("this kernel has no io_uring"),
            "the second cause stays named: {e}"
        );
    }

    #[test]
    fn passwd_non_utf8_keeps_osd_gid() {
        let r = root_bytes(
            "latin1",
            &[
                (
                    "etc/passwd",
                    b"j\xfcrgen:x:1000:1000:J\xfcrgen:/home/j\xfcrgen:/bin/bash\n\
                      ceph:x:167:167:Ceph daemons:/var/lib/ceph:/sbin/nologin\n",
                ),
                ("etc/group", b"disk:x:6:j\xfcrgen\nceph:x:167:ceph\n"),
            ],
        );
        let a = Access::read(&r.0);
        assert_eq!(a.osd_gid, Some(167), "one latin-1 byte must not hide ceph");
        assert_eq!(a.osd_groups, [167]);
    }

    #[test]
    fn unreadable_sysctl_is_not_absent() {
        let r = root("unreadable", &[]);
        fs::create_dir_all(r.0.join("proc/sys/kernel/io_uring_disabled")).unwrap();
        let a = Access::read(&r.0);
        assert_eq!(
            a.disabled,
            Sysctl::Unknown,
            "EISDIR is not a kernel without the sysctl"
        );
        assert_eq!(a.osd_user_allowed(), None, "the policy is unknown");
        let e = a.explain();
        assert!(e.contains("cannot be read"), "{e}");
        assert!(!e.contains("absent"), "{e}");
    }

    #[test]
    fn refused_keeps_other_errors() {
        let e = refused(std::io::Error::from_raw_os_error(12));
        assert_eq!(e.raw_os_error(), Some(12));
        let e = refused(std::io::Error::from_raw_os_error(1));
        assert!(e.to_string().starts_with("io_uring refused ("), "{e}");
    }
}
