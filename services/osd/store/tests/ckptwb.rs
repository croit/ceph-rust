// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Checkpoint write-back per 4 KiB create (doc/perf/store-ckpt-writeback-20261024.md): the OSD write shape of
//! `walks.rs` (4 KiB data + 2 xattrs + PG log entry + `_info` + log trim) spread over `NPG` PGs of one shard with the
//! daemon's cache sizing (`StoreCfg::for_memory`), automatic checkpoints, from a fresh store. Reports per create and
//! window of creates: checkpoint pages written, delta entries, declines by reason, device write bytes, synchronous
//! checkpoint CPU, wall ns, and the delta state at the window's end: how the write-back grows with the store.
#[path = "common/objmodel.rs"]
mod objmodel;

use denc::types::{Ghobject, Hobject, ShardId, SnapId};
use objmodel::pgc;
use std::collections::HashMap;
use store::dev::{SimClock, SimConfig, SimDev, SimDisk};
use store::layout::{MkfsParams, mkfs};
use store::obj::{OTxn, Store, StoreCfg, TOp};

type St = Store<SimDev, SimClock>;

fn obj(i: u64) -> Ghobject {
    Ghobject::new(
        Hobject::new(
            format!("benchmark_data_host1_4242_object{i}").as_bytes(),
            SnapId::NOSNAP,
            (i as u32).wrapping_mul(2654435761),
            1,
            b"",
        ),
        Ghobject::NO_GEN,
        ShardId::NO_SHARD,
    )
}

/// PG log length kept per PG: a create past it trims the PG's oldest entry.
const LOG: u64 = 3000;

fn log_key(v: u64) -> Vec<u8> {
    format!("{:010}.{:020}", 5, v).into_bytes()
}

fn env(k: &str, d: u64) -> u64 {
    std::env::var(k)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(d)
}

type Ctr = HashMap<&'static str, u64>;

fn ctr(st: &St) -> Ctr {
    st.perf_counters()
        .into_iter()
        .map(|(k, _, v)| (k, v))
        .collect()
}

/// Per-create figures of one window (counter deltas / creates) and the delta gauges at its end.
struct Win {
    creates: u64,
    wall_ns: f64,
    c0: Ctr,
    c1: Ctr,
}

impl Win {
    fn per(&self, k: &str) -> f64 {
        (self.c1[k] - self.c0[k]) as f64 / self.creates as f64
    }

    fn print(&self, tag: &str) {
        let why = ["requested", "space", "wal", "dirty", "chunks", "interval"].map(|w| {
            let k = format!("ckpt_why_{w}");
            self.c1[k.as_str()] - self.c0[k.as_str()]
        });
        println!(
            "{tag}: wall {:.0} ns, ckpt sync {:.0} ns, ckpts/1k {:.3}, ckpt pages {:.3}, delta entries {:.3} pages {:.3}, \
             declined chain {:.3} room {:.3}, folded {:.3}, relog chains {:.3} segs/1k {:.3}, whole leaves {:.3} interiors {:.3}, clean {:.3}, dev write {:.0} B; \
             why {why:?}; chains {} KiB, delta pages {}/{}, segments {}",
            self.wall_ns,
            self.per("ckpt_sync_ns"),
            self.per("ckpt_ends") * 1e3,
            self.per("ckpt_pages"),
            self.per("ckpt_delta_entries"),
            self.per("ckpt_delta_pages"),
            self.per("ckpt_declined_chain"),
            self.per("ckpt_declined_room"),
            self.per("ckpt_delta_folded"),
            self.per("ckpt_delta_relog_chains"),
            self.per("ckpt_delta_relog_segs") * 1e3,
            self.per("ckpt_fz_whole_leaves"),
            self.per("ckpt_fz_whole_ints"),
            self.per("ckpt_fz_clean"),
            self.per("dev_write_bytes"),
            self.c1["delta_chain_bytes"] >> 10,
            self.c1["delta_pages"],
            self.c1["delta_max_pages"],
            self.c1["delta_segments"],
        );
        println!(
            "{tag}: dev write B data {:.0} wal {:.0} (unit {:.0} payload {:.0}, txns/unit {:.2}) ckpt {:.0} (blob pages {:.4}) root {:.0}",
            self.per("dev_wr_data"),
            self.per("dev_wr_wal"),
            self.per("wal_unit_bytes"),
            self.per("wal_payload_bytes"),
            1.0 / self.per("wal_units"),
            self.per("dev_wr_ckpt"),
            self.per("ckpt_blob_pages"),
            self.per("dev_wr_root"),
        );
        let wl = [
            "name", "onode", "attr", "ext", "omap", "coll", "bitmap", "other",
        ]
        .map(|t| format!("{t} {:.4}", self.per(&format!("ckpt_wleaf_{t}"))));
        println!(
            "{tag}: whole leaves per create by key space: {}",
            wl.join(", ")
        );
    }
}

/// `nwin` windows of `n` creates from a fresh store; `budget` = the shard's cache share (bytes); `relog` = mkfs
/// `delta_relog` (false: the oldest delta segments are only freed by folding, the format before segment cleaning).
fn run(budget: u64, npg: u32, nwin: u64, n: u64, relog: bool) -> Vec<Win> {
    let sim = SimConfig {
        dedup: true,
        ..SimConfig::new(64 << 30)
    };
    let disk = SimDisk::new(sim);
    let mut dev = disk.queue();
    let mut clk = SimClock::default();
    let p = MkfsParams {
        shards: 1,
        wal_blocks: 65536,
        align_blocks: 1,
        delta_relog: relog,
        ..Default::default()
    };
    mkfs(&mut dev, &mut clk, &p).unwrap();
    let d2 = disk.clone();
    let cfg = StoreCfg::for_memory(budget, 1).unwrap();
    let (mut st, _) = Store::mount(move || d2.queue(), SimClock::default(), cfg).unwrap();
    let pgs: Vec<_> = (0..npg).map(|s| pgc(1, s)).collect();
    let pms: Vec<_> = (0..npg)
        .map(|s| Ghobject::pgmeta(1, s, ShardId::NO_SHARD))
        .collect();
    for (c, pm) in pgs.iter().zip(&pms) {
        let mut t = OTxn::new();
        t.mkcoll(*c);
        t.touch(*c, pm);
        st.commit(&t).unwrap();
    }
    let page = vec![0xC3u8; 4096];
    let (oi, ss) = (vec![7u8; 260], vec![8u8; 40]);
    let (logv, infov) = (vec![1u8; 180], vec![2u8; 600]);
    let mut acked = Vec::new();
    let mut inflight = 0usize;
    let mut out = Vec::new();
    let (mut t0, mut c0) = (std::time::Instant::now(), ctr(&st));
    for i in 0..nwin * n {
        let g = (i % npg as u64) as usize;
        let v = i / npg as u64 + 1; // the PG's log version
        let (c, pm, o, lk) = (pgs[g], &pms[g], obj(i), log_key(v));
        let mut tries = 0;
        while !(st.warm(&c, &o, 0, 4096).unwrap() & st.warm_omap(&c, pm, &[&lk]).unwrap()) {
            tries += 1;
            assert!(tries < 1000, "state load of create {i} never ready");
            st.idle();
            acked.clear();
            st.poll(&mut acked).unwrap();
            inflight -= acked.len();
        }
        let mut t = OTxn::new();
        t.write(c, &o, 0, &page);
        t.setattr(c, &o, b"_", &oi);
        t.setattr(c, &o, b"snapset", &ss);
        t.omap_set(c, pm, &lk, &logv);
        t.omap_set(c, pm, b"_info", &infov);
        if v > LOG {
            t.push(TOp::OmapRmKeys {
                cid: c,
                oid: pm.clone(),
                keys: vec![log_key(v - LOG).into()],
            });
        }
        st.queue(&t, i + 1).unwrap();
        inflight += 1;
        acked.clear();
        st.poll(&mut acked).unwrap();
        inflight -= acked.len();
        while inflight > 16 {
            st.idle();
            acked.clear();
            st.poll(&mut acked).unwrap();
            inflight -= acked.len();
        }
        if (i + 1) % n == 0 {
            let c1 = ctr(&st);
            out.push(Win {
                creates: n,
                wall_ns: t0.elapsed().as_nanos() as f64 / n as f64,
                c0: std::mem::replace(&mut c0, c1.clone()),
                c1,
            });
            t0 = std::time::Instant::now();
        }
    }
    out
}

/// Bounded check (debug-friendly sizes): checkpoints run and write fewer meta pages than one per create.
#[test]
fn ckpt_pages_per_create_bounded() {
    let w = run(160 << 20, 16, 2, 20_000, true);
    w[1].print("second 20k");
    assert!(w[1].per("ckpt_ends") > 0.0, "no checkpoint ran");
    assert!(w[1].per("ckpt_pages") < 1.0);
}

/// Store-level checkpoint write-back as the store grows (release):
/// `cargo test --release -p store --test ckptwb windows -- --ignored --nocapture`; env `BUDGET_MIB` (512), `NPG` (16),
/// `NWIN` (8) windows of `NCREATE` (200000) creates, `RELOG` (1; 0 = store without segment cleaning).
#[test]
#[ignore = "measurement"]
fn windows() {
    let (b, g) = (env("BUDGET_MIB", 512) << 20, env("NPG", 16) as u32);
    let n = env("NCREATE", 200_000);
    for (k, w) in run(b, g, env("NWIN", 8), n, env("RELOG", 1) != 0)
        .iter()
        .enumerate()
    {
        w.print(&format!("objects {:>8}", (k as u64 + 1) * n));
    }
}
