// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Format NVM scope check (mkfs `--format-lba4k`, adr 0103). Identify Controller FNA bit 0 set = a Format NVM of one
//! namespace formats EVERY namespace of the NVM subsystem; bit 1 = the same for secure erase (we never request one,
//! but treat it the same: conservative). Formatting ns=2 on such a controller would wipe ns=1, which may be another
//! OSD. Rule: format only when it provably touches the target namespace alone; otherwise refuse.

/// Format-all / secure-erase-all bits of FNA.
pub const FNA_ALL_NS: u8 = 0b11;

/// What the controller reports (no SPDK types; filled by the shim).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NsScope {
    /// Identify Controller FNA byte.
    pub fna: u8,
    /// Active namespaces attached to this controller.
    pub active: u32,
    /// Allocated namespaces in the subsystem (Identify CNS 10h); `None` = not queried / failed.
    pub allocated: Option<u32>,
    /// Namespace management supported (OACS bit 3): namespaces may exist that are not attached here.
    pub ns_mgmt: bool,
    /// CMIC: the subsystem may have more controllers (other controllers may see other namespaces).
    pub multi_ctrl: bool,
}

/// `Ok` when a Format NVM of `nsid` touches that namespace alone, else why it must be refused.
pub fn check_format_scope(s: &NsScope, nsid: u32) -> Result<(), String> {
    if s.fna & FNA_ALL_NS == 0 {
        return Ok(()); // per-namespace format: only the target is touched
    }
    let known = match s.allocated {
        Some(a) => Some(a.max(s.active)),
        // without the subsystem-wide list, the attached set is complete only for a single-controller, fixed layout
        None if !s.ns_mgmt && !s.multi_ctrl => Some(s.active),
        None => None,
    };
    match known {
        Some(n) if n <= 1 => Ok(()),
        k => Err(format!(
            "refused: Format NVM on this controller applies to ALL namespaces (Identify Controller FNA 0x{:02x}) and the \
             subsystem holds {} namespaces: formatting nsid {nsid} would also wipe the others (possibly other OSDs). \
             Instead create the namespace with a 4096-byte LBA format (kernel driver: `nvme create-ns <ctrl> \
             --flbas=<4096+0 index> ...`, see `nvme id-ns -H`) and run mkfs/prepare without --format-lba4k, or \
             evacuate every namespace first and format with nvme-cli (adr 0103)",
            s.fna,
            k.map_or_else(|| "an unknown number of".to_owned(), |n| n.to_string())
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sc(
        fna: u8,
        active: u32,
        allocated: Option<u32>,
        ns_mgmt: bool,
        multi_ctrl: bool,
    ) -> NsScope {
        NsScope {
            fna,
            active,
            allocated,
            ns_mgmt,
            multi_ctrl,
        }
    }

    #[test]
    fn per_namespace_format_targets_the_nsid() {
        // PM1743 lab drive: FNA 0x04 (crypto erase only), 2 namespaces
        assert_eq!(
            check_format_scope(&sc(0x04, 2, Some(2), true, true), 2),
            Ok(())
        );
        assert_eq!(
            check_format_scope(&sc(0x00, 1, None, false, false), 1),
            Ok(())
        );
    }

    #[test]
    fn format_all_with_other_namespaces_is_refused() {
        for fna in [0x01, 0x02, 0x03, 0x07] {
            let e = check_format_scope(&sc(fna, 2, Some(2), true, false), 2).unwrap_err();
            assert!(e.contains("ALL namespaces") && e.contains("holds 2"), "{e}");
        }
        // attached here: 1, but another namespace is allocated (detached / other controller)
        let e = check_format_scope(&sc(0x01, 1, Some(2), true, true), 1).unwrap_err();
        assert!(e.contains("holds 2"), "{e}");
    }

    #[test]
    fn format_all_with_unknown_namespace_set_is_refused() {
        for (m, c) in [(true, false), (false, true), (true, true)] {
            let e = check_format_scope(&sc(0x01, 1, None, m, c), 1).unwrap_err();
            assert!(e.contains("unknown number"), "{e}");
        }
    }

    #[test]
    fn format_all_on_the_only_namespace_is_allowed() {
        assert_eq!(
            check_format_scope(&sc(0x03, 1, Some(1), true, true), 1),
            Ok(())
        );
        assert_eq!(
            check_format_scope(&sc(0x01, 1, None, false, false), 1),
            Ok(())
        );
        // allocated list empty but one attached (odd firmware): attached count wins
        assert_eq!(
            check_format_scope(&sc(0x01, 1, Some(0), true, false), 1),
            Ok(())
        );
    }
}
