// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! The one way every subcommand opens a store device: exclusive (a running OSD or another tool holds it ->
//! "device is in use", exit 3), the `spdk:` PCI claim taken before the DPDK environment touches the device.
use nvme::any::{AnyCtrl, DevSpec};

/// Exit code for a refused open ("in use" = held by a running OSD / tool), else 1.
pub fn exit_code(e: &str) -> i32 {
    if e.contains("in use") { 3 } else { 1 }
}

/// A missing default conf is optional; an explicit file or any other read error is fatal.
/// Never select a different backend or data directory after losing its configuration.
pub(crate) fn optional_conf(a: &[String], cluster: &str) -> Result<osddir::Conf, String> {
    let path = osddir::conf_file(a, cluster)?;
    match std::fs::read_to_string(&path) {
        Ok(text) => Ok(osddir::Conf::parse(&text)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && !a.iter().any(|s| s == "--conf") => {
            Ok(osddir::Conf::default())
        }
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// SPDK hugepage pool an offline mount gets (`0` would be the library default, which is too small for a store mount).
pub const MOUNT_HUGEPAGES_MB: u32 = 256;

/// Claim, init the SPDK env (`hugepages_mb`, 0 = default; a `shared` spec joins the controller's spdk-primary as a
/// secondary, adr 0463) and open `spec` exclusively. `create`: a missing `file:` device with `size` is created.
pub fn open(spec: &DevSpec, create: bool, hugepages_mb: u32) -> Result<AnyCtrl, String> {
    AnyCtrl::claim_before_env(spec)?;
    spec.spdk_env_init(
        "croit-flashstore-tool",
        None,
        i32::try_from(hugepages_mb).map_err(|_| "hugepages_mb too large".to_string())?,
    )?;
    AnyCtrl::open_exclusive_create(spec, create)
}

/// The spec to open for an OSD whose device spec comes from its OSD dir or `--dev`: conf `flashstore_store_backend`
/// (`spdk` | `kernel` | `kernel-cmd`, adr 0169) resolved exactly as the daemon does (`nvme::any::resolve_backend`): with
/// `kernel` / `kernel-cmd` an `spdk:BDF[,ns=N]` spec becomes the kernel node of that namespace (the controller stays on
/// the kernel nvme driver), anything else is returned unchanged. The OSD dir keeps the `spdk:` spec; only what is
/// opened changes. A build without the kernel backend never resolves (the daemon ignores the key there too).
pub fn conf_backend_spec(
    spec: &str,
    opts: &std::collections::BTreeMap<String, String>,
) -> Result<String, String> {
    #[cfg(feature = "kernel-nvme")]
    if let Some(b) = opts.get("flashstore_store_backend") {
        return nvme::any::resolve_backend(spec, b.trim())
            .map_err(|e| format!("flashstore_store_backend {b}: {e}"));
    }
    #[cfg(not(feature = "kernel-nvme"))]
    let _ = opts;
    Ok(spec.to_owned())
}

#[cfg(all(test, feature = "kernel-nvme"))]
mod tests {
    use super::conf_backend_spec;
    use std::collections::BTreeMap;

    fn opts(b: &str) -> BTreeMap<String, String> {
        osddir::Conf::parse(&format!("[osd]\nflashstore store-backend = {b}\n")).for_osd(3)
    }

    #[test]
    fn unset_or_spdk_keeps_the_spec() {
        let s = "spdk:0000:03:00.0,ns=1";
        assert_eq!(conf_backend_spec(s, &BTreeMap::new()).unwrap(), s);
        assert_eq!(conf_backend_spec(s, &opts("spdk")).unwrap(), s);
    }

    #[test]
    fn kernel_backends_leave_non_spdk_specs_alone() {
        assert_eq!(
            conf_backend_spec("kernel:/dev/null", &opts("kernel-cmd")).unwrap(),
            "kernel:/dev/null"
        );
        assert_eq!(
            conf_backend_spec("kernel:/dev/nvme0n1", &opts("kernel")).unwrap(),
            "kernel:/dev/nvme0n1"
        );
    }

    #[test]
    fn kernel_cmd_refuses_a_block_node_and_unknown_backends_fail() {
        assert!(conf_backend_spec("kernel:/dev/nvme0n1", &opts("kernel-cmd")).is_err());
        let e = conf_backend_spec("spdk:0000:03:00.0", &opts("bogus")).unwrap_err();
        assert!(e.contains("bogus"), "{e}");
    }

    #[test]
    fn kernel_backend_needs_the_controller_on_the_kernel_driver() {
        // a PCI address that exists nowhere: the sysfs lookup of the kernel node fails (no SPDK fallback)
        assert!(conf_backend_spec("spdk:ffff:ff:1f.7", &opts("kernel-cmd")).is_err());
    }
}
