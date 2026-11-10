// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! SPDK smoke: attach NVMe by PCI address, print identify data, write+read one LBA on a scratch offset.
//! Usage: spdk_probe <pci-addr> [nsid] [--write-lba N]   (DESTROYS data at the LBA if --write-lba is given)
use nvme::spdk::{SpdkCtrlr, env_init};
use nvme::{BlockDev, Completion, IoBuf};
use std::time::Instant;

/// Drain `n` completions into `out`, bounded: a device that stops completing fails the smoke test with a loud line
/// instead of hanging the lab run.
fn wait<D: BlockDev>(q: &mut D, out: &mut Vec<Completion<D::Buf>>, n: usize) {
    let t = Instant::now();
    while out.len() < n {
        q.poll(0, out);
        if t.elapsed().as_secs() >= 30 {
            eprintln!(
                "WARNING TIMEOUT spdk_probe IO exceeded 30s ({} of {n} completions)",
                out.len()
            );
            std::process::exit(1);
        }
    }
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let addr = a
        .get(1)
        .expect("usage: spdk_probe <pci-addr> [nsid] [--write-lba N]");
    let nsid: u32 = a.get(2).and_then(|s| s.parse().ok()).unwrap_or(1);
    env_init("spdk_probe", None, 0, &[addr.as_str()]).expect("env init");
    let c = SpdkCtrlr::attach_pci(addr, nsid).expect("attach");
    println!("{:#?}", c.geometry());
    let mut q = c.open_queue(128).expect("qpair");
    if let Some(i) = a.iter().position(|s| s == "--write-lba") {
        let lba: u64 = a
            .get(i + 1)
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| {
                eprintln!("spdk_probe: --write-lba needs an LBA number");
                std::process::exit(2)
            });
        let ls = c.geometry().lba_size as usize;
        let mut b = q.alloc_buf(ls);
        b.as_mut_slice().fill(0xA5);
        q.submit_write(lba, b, 1).map_err(|r| r.err).unwrap();
        let mut out = Vec::new();
        wait(&mut q, &mut out, 1);
        println!("write: {:?}", out[0].result);
        let b = q.alloc_buf(ls);
        q.submit_read(lba, b, 2).map_err(|r| r.err).unwrap();
        out.clear();
        wait(&mut q, &mut out, 1);
        println!(
            "read: {:?} ok={}",
            out[0].result,
            out[0]
                .buf
                .as_ref()
                .unwrap()
                .as_slice()
                .iter()
                .all(|&x| x == 0xA5)
        );
    }
}
