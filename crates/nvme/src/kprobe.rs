// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Identity + SMART of a kernel-owned NVMe device (`--dev kernel:/dev/nvme0n1`, and the lab `file:/dev/nvme0n1`
//! path) through the kernel admin passthrough ioctl (`NVME_IOCTL_ADMIN_CMD`). Same output as the SPDK probe;
//! background thread only.
use crate::health::SmartError;
use std::path::PathBuf;

/// `struct nvme_passthru_cmd` (72 bytes).
#[repr(C)]
#[derive(Default)]
struct AdminCmd {
    opcode: u8,
    flags: u8,
    rsvd1: u16,
    nsid: u32,
    cdw2: u32,
    cdw3: u32,
    metadata: u64,
    addr: u64,
    metadata_len: u32,
    data_len: u32,
    cdw10: u32,
    cdw11: u32,
    cdw12: u32,
    cdw13: u32,
    cdw14: u32,
    cdw15: u32,
    timeout_ms: u32,
    result: u32,
}

/// `_IOWR('N', 0x41, struct nvme_passthru_cmd)`.
#[cfg(any(test, target_os = "linux"))]
const IOCTL_ADMIN_CMD: u64 =
    (3 << 30) | ((size_of::<AdminCmd>() as u64) << 16) | (0x4e << 8) | 0x41;

/// Admin-command timeout handed to the kernel (ms): the NVMe admin command timeout of the driver's default.
const ADMIN_TIMEOUT_MS: u32 = 5000;

impl AdminCmd {
    /// A data-in admin command (`opcode`, `nsid`, CDW10) filling `buf`.
    fn data_in(opcode: u8, nsid: u32, cdw10: u32, buf: &mut [u8]) -> AdminCmd {
        AdminCmd {
            opcode,
            nsid,
            addr: buf.as_mut_ptr() as u64,
            data_len: buf.len() as u32,
            cdw10,
            timeout_ms: ADMIN_TIMEOUT_MS,
            ..Default::default()
        }
    }
}

/// Identify Controller (CNS 1) command.
fn identify_cmd(buf: &mut [u8]) -> AdminCmd {
    AdminCmd::data_in(0x06, 0, 1, buf)
}

/// Identify Namespace (CNS 0) for `nsid`.
fn identify_ns_cmd_for(nsid: u32, buf: &mut [u8]) -> AdminCmd {
    AdminCmd::data_in(0x06, nsid, 0, buf)
}

/// Get Log Page 0x02 (SMART / Health, global nsid), 512 bytes.
fn smart_cmd(buf: &mut [u8]) -> AdminCmd {
    // CDW10: log page id 0x02, NUMD = dwords - 1 (0's based)
    AdminCmd::data_in(
        0x02,
        u32::MAX,
        0x02 | ((buf.len() as u32 / 4 - 1) << 16),
        buf,
    )
}

/// One admin passthrough ioctl; `< 0` is the errno, `> 0` the NVMe status.
#[cfg(target_os = "linux")]
fn admin_ioctl(fd: std::os::fd::RawFd, c: &mut AdminCmd) -> std::io::Result<()> {
    // SAFETY: `c` is a valid passthrough command whose buffer outlives the call.
    let r = unsafe { libc::ioctl(fd, IOCTL_ADMIN_CMD as _, c as *mut AdminCmd) };
    if r == 0 {
        Ok(())
    } else if r < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Err(std::io::Error::other(format!("nvme status {r:#x}")))
    }
}

/// The opened node `io` must be the device sysfs describes at `sys` (`block`: a block node, else a char node; same
/// `major:minor`). Admission checks (partitions, namespace, cmd mode's block-node claim) go by name; a node that was
/// renamed or recreated (or mapped under another name into a container) would otherwise do IO on another namespace than
/// the one checked and claimed. A missing or unreadable sysfs entry fails closed.
#[cfg(all(feature = "kernel", any(test, target_os = "linux")))]
pub(crate) fn check_node(
    io: &std::os::fd::OwnedFd,
    sys: &std::path::Path,
    block: bool,
) -> Result<(), String> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let md = std::fs::File::from(io.try_clone().map_err(|e| e.to_string())?)
        .metadata()
        .map_err(|e| e.to_string())?;
    let kind_ok = if block {
        md.file_type().is_block_device()
    } else {
        md.file_type().is_char_device()
    };
    let actual = format!(
        "{}:{}",
        libc::major(md.rdev() as _),
        libc::minor(md.rdev() as _)
    );
    let want = std::fs::read_to_string(sys.join("dev")).unwrap_or_default();
    if !kind_ok || want.trim() != actual {
        return Err(format!(
            "{}: opened device identity does not match sysfs (opened {} {actual}, sysfs dev {:?})",
            sys.display(),
            if block { "block" } else { "char" },
            want.trim()
        ));
    }
    Ok(())
}

/// Model / serial / firmware from an Identify Controller page (bytes 4..24, 24..64, 64..72).
pub fn parse_ident(b: &[u8]) -> Option<crate::health::Ident> {
    if b.len() < 72 {
        return None;
    }
    Some(crate::health::Ident::from_raw(
        &b[24..64],
        &b[4..24],
        &b[64..72],
    ))
}

/// One admin command (`opcode`, `nsid`, CDW10, data in `buf`) on an open NVMe node (controller, namespace block or
/// generic char device): identify of the `kernel:` backend (crate::kdev).
#[cfg(all(feature = "kernel", target_os = "linux"))]
pub(crate) fn admin_fd(
    fd: std::os::fd::RawFd,
    opcode: u8,
    nsid: u32,
    cdw10: u32,
    buf: &mut [u8],
) -> std::io::Result<()> {
    admin_ioctl(fd, &mut AdminCmd::data_in(opcode, nsid, cdw10, buf))
}

/// Error text of a failed admin ioctl: only a refusal (`EPERM`/`EACCES`) is the CAP_SYS_ADMIN hint of adr 0056, so the
/// text agrees with [`SmartError::from_io`]'s classification; every other errno is reported as itself.
#[cfg(any(test, target_os = "linux"))]
fn admin_errno_text(opcode: u8, e: &std::io::Error) -> String {
    if e.kind() == std::io::ErrorKind::PermissionDenied {
        format!(
            "{e}: this kernel allows the NVMe admin command (opcode {opcode:#04x}) to CAP_SYS_ADMIN only; the OSD runs \
             without it (adr 0056)"
        )
    } else {
        format!("{e}: the NVMe admin command (opcode {opcode:#04x}) failed")
    }
}

/// Admin-command handle of a kernel NVMe node.
#[derive(Clone, Debug)]
pub struct KernelProbe(pub PathBuf);

impl KernelProbe {
    fn admin_cmd(&self, c: AdminCmd) -> Result<(), String> {
        self.admin_cmd_denied(c).map_err(|e| e.to_string())
    }

    #[cfg(target_os = "linux")]
    fn admin_cmd_denied(&self, mut c: AdminCmd) -> Result<(), SmartError> {
        use std::os::fd::AsRawFd;
        let f = std::fs::File::open(&self.0)
            .map_err(|e| SmartError::from_io(format!("{}: {e}", self.0.display()), &e))?;
        match admin_ioctl(f.as_raw_fd(), &mut c) {
            Ok(()) => Ok(()),
            // an errno: the ioctl itself was refused or failed; an NVMe status is a plain command failure
            Err(e) if e.raw_os_error().is_some() => {
                Err(SmartError::from_io(admin_errno_text(c.opcode, &e), &e))
            }
            Err(e) => Err(SmartError::Failed(e.to_string())),
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn admin_cmd_denied(&self, _c: AdminCmd) -> Result<(), SmartError> {
        Err(SmartError::Failed(
            "kernel nvme passthrough needs Linux".into(),
        ))
    }

    /// Identity; empty strings when the node is not an NVMe device (plain file, virtio).
    pub fn ident(&self) -> crate::health::Ident {
        let mut b = vec![0u8; 4096];
        match self.admin_cmd(identify_cmd(&mut b)) {
            Ok(()) => parse_ident(&b).unwrap_or_default(),
            Err(_) => crate::health::Ident::default(),
        }
    }

    /// Raw Identify Controller page (4096 bytes; read-only admin command).
    pub fn identify_ctrl_raw(&self) -> Result<Vec<u8>, String> {
        let mut b = vec![0u8; 4096];
        self.admin_cmd(identify_cmd(&mut b))?;
        Ok(b)
    }

    /// Raw Identify Namespace page of the namespace node `nsid` (read-only admin command).
    pub fn identify_ns_raw(&self, nsid: u32) -> Result<Vec<u8>, String> {
        let mut b = vec![0u8; 4096];
        let c = identify_ns_cmd_for(nsid, &mut b);
        self.admin_cmd(c)?;
        Ok(b)
    }

    pub fn smart_log(&self) -> Result<[u8; 512], SmartError> {
        let mut b = [0u8; 512];
        self.admin_cmd_denied(smart_cmd(&mut b))?;
        Ok(b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_and_commands() {
        assert_eq!(size_of::<AdminCmd>(), 72);
        assert_eq!(IOCTL_ADMIN_CMD, 0xC048_4E41);
        let mut b = [0u8; 512];
        let c = smart_cmd(&mut b);
        assert_eq!((c.opcode, c.nsid, c.cdw10), (0x02, u32::MAX, 0x007f_0002));
        let mut b = vec![0u8; 4096];
        let c = identify_cmd(&mut b);
        assert_eq!((c.opcode, c.cdw10, c.data_len), (0x06, 1, 4096));
    }

    #[test]
    fn admin_error_text_blames_cap_sys_admin_only_on_a_refusal() {
        let eperm = std::io::Error::from_raw_os_error(libc::EPERM);
        let t = admin_errno_text(0x02, &eperm);
        assert!(t.contains("CAP_SYS_ADMIN"), "{t}");
        assert!(matches!(
            SmartError::from_io(t, &eperm),
            SmartError::Denied(_)
        ));
        let eio = std::io::Error::from_raw_os_error(libc::EIO);
        let t = admin_errno_text(0x02, &eio);
        assert!(!t.contains("CAP_SYS_ADMIN"), "{t}");
        assert!(t.contains("opcode 0x02"), "{t}");
        assert!(matches!(
            SmartError::from_io(t, &eio),
            SmartError::Failed(_)
        ));
    }

    #[test]
    fn ident_strings() {
        let mut b = vec![b' '; 4096];
        b[4..10].copy_from_slice(b"SN1234");
        b[24..38].copy_from_slice(b"Some Model 123");
        b[64..68].copy_from_slice(b"FW01");
        let i = parse_ident(&b).unwrap();
        assert_eq!(
            (i.serial.as_str(), i.model.as_str(), i.firmware.as_str()),
            ("SN1234", "Some Model 123", "FW01")
        );
        // raw fixed-width fields: 40 B model + `_` + 20 B serial, padding kept (classic devid form)
        assert_eq!(
            i.device_id(),
            format!("Some_Model_123{}_SN1234{}", "_".repeat(26), "_".repeat(14))
        );
        assert!(parse_ident(&b[..10]).is_none());
    }
    /// A renamed/recreated ng node must not pair passthrough IO on one namespace
    /// with an exclusive block-node claim (and fallback IO) on another namespace.
    #[cfg(feature = "kernel")]
    #[test]
    fn opened_node_must_match_the_admitted_sysfs_identity() {
        use std::os::unix::fs::MetadataExt;
        let io: std::os::fd::OwnedFd = std::fs::File::open("/dev/null").unwrap().into();
        let md = std::fs::File::from(io.try_clone().unwrap())
            .metadata()
            .unwrap();
        let actual = format!(
            "{}:{}",
            libc::major(md.rdev() as _),
            libc::minor(md.rdev() as _)
        );
        let d = std::env::temp_dir().join(format!("kprobe-identity-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("dev"), &actual).unwrap();
        assert!(check_node(&io, &d, false).is_ok());
        assert!(
            check_node(&io, &d, true).is_err(),
            "char fd cannot claim a block namespace"
        );
        std::fs::write(d.join("dev"), "0:0\n").unwrap();
        assert!(check_node(&io, &d, false).unwrap_err().contains("identity"));
        std::fs::remove_file(d.join("dev")).unwrap();
        assert!(
            check_node(&io, &d, false).is_err(),
            "missing identity fails closed"
        );
        std::fs::remove_dir_all(d).unwrap();
    }
}
