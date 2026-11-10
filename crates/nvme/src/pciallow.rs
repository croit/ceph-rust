// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! PCI allow-list for every DPDK/SPDK env init (P0 safety: DPDK without an allow-list probes every PCI device of the
//! host, including non-approved NIC ports). Pure helpers, always compiled.

/// SPDK's canonical `dddd:bb:dd.f` form of `0000:03:00.0` / `03:00.0` (hex, lower case).
pub fn canonical_bdf(addr: &str) -> Result<String, String> {
    let bad = || format!("bad PCI address {addr:?} (expected dddd:bb:dd.f)");
    let (rest, func) = addr.rsplit_once('.').ok_or_else(bad)?;
    let parts: Vec<&str> = rest.split(':').collect();
    let (dom, bus, dev) = match parts.as_slice() {
        [d, b, v] => (*d, *b, *v),
        [b, v] => ("0", *b, *v),
        _ => return Err(bad()),
    };
    let h = |s: &str, max: u32| {
        u32::from_str_radix(s, 16)
            .ok()
            .filter(|v| *v <= max)
            .ok_or_else(bad)
    };
    Ok(format!(
        "{:04x}:{:02x}:{:02x}.{:x}",
        h(dom, 0xffff)?,
        h(bus, 0xff)?,
        h(dev, 0x1f)?,
        h(func, 0x7)?
    ))
}

/// Canonical, de-duplicated PCI allow-list for a DPDK/SPDK env init. Never empty: a blank allow-list makes DPDK probe
/// every PCI device on the host (P0 safety rule: only the configured NVMe / NIC ports may be touched).
pub fn allow_list(addrs: &[&str]) -> Result<Vec<String>, String> {
    let mut v: Vec<String> = Vec::new();
    for a in addrs {
        let c = canonical_bdf(a)?;
        if !v.contains(&c) {
            v.push(c);
        }
    }
    if v.is_empty() {
        return Err("empty PCI allow-list: refusing to initialise DPDK/SPDK without one".into());
    }
    Ok(v)
}

/// EAL arguments (`-a ADDR` per device) for an allow-list.
pub fn eal_allow_args(list: &[String]) -> Vec<String> {
    list.iter()
        .flat_map(|a| ["-a".to_owned(), a.clone()])
        .collect()
}

/// PCI devices a DPDK EAL will probe, from its final argument list. DPDK probes EVERY PCI device when neither
/// `--no-pci` nor an allow (`-a`/`--allow`/`-w`) is given (P0 safety: non-approved NIC ports on a production host),
/// so that case is refused. `Ok(vec![])` = `--no-pci`.
pub fn eal_pci_allow(eal: &[String]) -> Result<Vec<String>, String> {
    let mut allow = Vec::new();
    let mut no_pci = false;
    let mut it = eal.iter();
    while let Some(x) = it.next() {
        let v = match x.as_str() {
            "--no-pci" => {
                no_pci = true;
                continue;
            }
            "-a" | "--allow" | "-w" | "--pci-whitelist" => it.next().cloned(),
            s if s.starts_with("--allow=") => Some(s["--allow=".len()..].to_owned()),
            _ => continue,
        };
        // may carry device args (`0000:4b:00.0,rx_vec_en=1`): the address is the part before the first ','
        let v = v.ok_or("EAL -a without a PCI address")?;
        allow.push(v.split(',').next().unwrap_or("").to_owned());
    }
    if allow.is_empty() && !no_pci {
        return Err(
            "EAL without a PCI allow-list would probe every PCI device: pass -a <pci> (or --no-pci)"
                .into(),
        );
    }
    Ok(allow)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn eal_blank_probe_refused() {
        assert!(eal_pci_allow(&v(&["croit-flashstore-osd", "-l", "1", "-m", "512"])).is_err());
        assert!(
            eal_pci_allow(&v(&[
                "croit-flashstore-osd",
                "--vdev",
                "net_af_packet0,iface=x"
            ]))
            .is_err()
        );
        assert!(eal_pci_allow(&v(&["croit-flashstore-osd", "-a"])).is_err());
    }

    #[test]
    fn eal_allow_and_no_pci_accepted() {
        assert_eq!(
            eal_pci_allow(&v(&["n", "--no-pci"])).unwrap(),
            Vec::<String>::new()
        );
        assert_eq!(
            eal_pci_allow(&v(&[
                "n",
                "-a",
                "0000:03:00.0",
                "--allow",
                "0000:4b:00.0,x=1",
                "--allow=0000:4b:00.1"
            ]))
            .unwrap(),
            ["0000:03:00.0", "0000:4b:00.0", "0000:4b:00.1"]
        );
    }

    #[test]
    fn allow_list_only_configured() {
        let l = allow_list(&["03:00.0", "0000:03:00.0", "0000:4B:00.1"]).unwrap();
        assert_eq!(l, ["0000:03:00.0", "0000:4b:00.1"]);
        assert_eq!(
            eal_allow_args(&l),
            ["-a", "0000:03:00.0", "-a", "0000:4b:00.1"]
        );
        assert!(allow_list(&[]).is_err());
        assert!(allow_list(&["junk"]).is_err());
    }

    #[test]
    fn bdf_forms() {
        assert_eq!(canonical_bdf("0000:03:00.0").unwrap(), "0000:03:00.0");
        assert_eq!(canonical_bdf("03:00.0").unwrap(), "0000:03:00.0");
        assert_eq!(canonical_bdf("0000:AF:1f.7").unwrap(), "0000:af:1f.7");
        assert_eq!(canonical_bdf("ffff:03:00.0").unwrap(), "ffff:03:00.0");
        // Intel VMD domains (10000+) are not addressable: SPDK's VMD driver is never initialised
        assert!(canonical_bdf("10000:03:00.0").is_err());
        for b in ["", "03:00", "0000:03:00.8", "x:03:00.0", "1:2:3:4.0"] {
            assert!(canonical_bdf(b).is_err(), "{b}");
        }
    }
}
