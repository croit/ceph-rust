// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Arguments for the kernel backend's memory-only EAL (payload hugepages, adr 0400).

/// EAL argv for the memory-only EAL: `--huge-dir` = the conf's `flashstore_huge_dir` (the mount prep reserved and
/// mounted), EAL's own mount choice when unset (NT-runtimeenv-02).
pub fn kernel_heap(lcores: &str, mem: &str, huge_dir: Option<&str>) -> Vec<String> {
    let mut args = [
        "croit-flashstore-osd",
        "--lcores",
        lcores,
        "-m",
        mem,
        "--no-pci",
        "--no-telemetry",
        "--in-memory",
        "--iova-mode=va",
        "--log-level=lib.eal:notice",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<Vec<_>>();
    if let Some(dir) = huge_dir {
        args.extend(["--huge-dir".to_owned(), dir.to_owned()]);
    }
    args
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_heap_uses_configured_hugepage_mount() {
        let args = kernel_heap("0@(8,9)", "2048", Some("/mnt/osd hugepages"));
        assert!(
            args.windows(2)
                .any(|a| a == ["--huge-dir", "/mnt/osd hugepages"])
        );
        assert!(args.windows(2).any(|a| a == ["--lcores", "0@(8,9)"]));
        assert!(args.windows(2).any(|a| a == ["-m", "2048"]));
        assert!(
            !kernel_heap("0@(8)", "2048", None)
                .iter()
                .any(|a| a == "--huge-dir")
        );
    }
}
