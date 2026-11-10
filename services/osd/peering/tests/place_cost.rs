// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Cost of the control core's placement work at a map gate (adr 0639, `peering::place`) on an e9455-shaped map, per
//! map change: a full membership scan (restart, CRUSH / weight / OSD-set change) and the incremental `Mine::next` for
//! the changes of normal operation, each followed by `arrivals` (what `place_moves` in the osd crate runs per gate).
//!
//! Map: 30 OSDs on 8 hosts (4 x 6 + 3 x 2), equal weights, jewel tunables; the pools of the e9455 stall-diag run:
//! `.mgr` (1 PG, size 3), rbd metadata (8 PGs, size 3), replicated 1024 PGs size 3 (failure domain host), EC 512 PGs
//! 4 positions (host), EC 256 PGs 11 positions (osd). EC rules as classic writes them (chooseleaf / choose tries).
//!
//! Measurement, not a gate: `cargo test -p peering --release --test place_cost -- --ignored --nocapture`.
//! Output: one JSON line per case `{"case","ms_median","ms_max","runs","pgs","arrivals"}` (median / max of `runs`).

use crush::*;
use denc::types::PgT;
use osdmap::consts::osd_state;
use osdmap::pool::{PgPool, TYPE_ERASURE, TYPE_REPLICATED, flags};
use osdmap::{OsdInfo, OsdMap};
use peering::place::{Mine, arrivals};
use std::collections::BTreeSet;
use std::time::Instant;

const OSDS: i32 = 30;
const HOSTS: i32 = 8;
const CORES: usize = 6;
const POOLS: [(i64, u32, u8, u8, u8); 5] = [
    // id, pg_num, size, type, rule
    (1, 1, 3, TYPE_REPLICATED, 0),
    (2, 8, 3, TYPE_REPLICATED, 0),
    (64, 1024, 3, TYPE_REPLICATED, 0),
    (65, 512, 4, TYPE_ERASURE, 1),
    (66, 256, 11, TYPE_ERASURE, 2),
];

fn host_of(o: i32) -> i32 {
    // hosts 0-5 hold 4 OSDs, hosts 6-7 hold 3
    if o < 24 { o / 4 } else { 6 + (o - 24) / 3 }
}

fn e9455_map() -> OsdMap {
    let mut m = OsdMap::default();
    m.epoch = 100;
    m.max_osd = OSDS;
    m.osd_state = vec![osd_state::EXISTS | osd_state::UP; OSDS as usize];
    m.osd_weight = vec![0x10000; OSDS as usize];
    m.osd_info = vec![OsdInfo::default(); OSDS as usize];
    let mut c = CrushMap::new();
    c.type_map = [(0, "osd".into()), (1, "host".into()), (10, "root".into())].into();
    let mut root = Vec::new();
    for h in 0..HOSTS {
        let items: Vec<(i32, u32)> = (0..OSDS)
            .filter(|o| host_of(*o) == h)
            .map(|o| (o, 0x10000))
            .collect();
        root.push((-2 - h, 0x10000 * items.len() as u32));
        c.add_bucket(Bucket::straw2(-2 - h, 1, &items));
    }
    c.add_bucket(Bucket::straw2(-1, 10, &root));
    let take = Step::new(OP_TAKE, -1, 0);
    let emit = Step::new(OP_EMIT, 0, 0);
    c.add_rule(
        0,
        Rule::new(
            RULE_REPLICATED,
            vec![take, Step::new(OP_CHOOSELEAF_FIRSTN, 0, 1), emit],
        ),
    );
    let ec = |choose: Step| {
        Rule::new(
            RULE_ERASURE,
            vec![
                Step::new(OP_SET_CHOOSELEAF_TRIES, 5, 0),
                Step::new(OP_SET_CHOOSE_TRIES, 100, 0),
                take,
                choose,
                emit,
            ],
        )
    };
    c.add_rule(1, ec(Step::new(OP_CHOOSELEAF_INDEP, 0, 1)));
    c.add_rule(2, ec(Step::new(OP_CHOOSE_INDEP, 0, 0)));
    c.finalize();
    m.set_crush(c.encode());
    for (id, pg_num, size, ptype, rule) in POOLS {
        let p = PgPool {
            ptype,
            size,
            min_size: size - 1,
            crush_rule: rule,
            pg_num,
            pgp_num: pg_num,
            flags: flags::HASHPSPOOL,
            ..PgPool::default()
        };
        m.pools.insert(id, p);
    }
    m
}

fn pools() -> BTreeSet<u64> {
    POOLS.iter().map(|p| p.0 as u64).collect()
}

/// Median and max of `runs` timings of `f` in ms, plus `f`'s last result.
fn time<T>(runs: usize, mut f: impl FnMut() -> T) -> (f64, f64, T) {
    let mut v = Vec::with_capacity(runs);
    let mut last = None;
    for _ in 0..runs {
        let t = Instant::now();
        last = Some(std::hint::black_box(f()));
        v.push(t.elapsed().as_secs_f64() * 1e3);
    }
    v.sort_by(f64::total_cmp);
    (v[runs / 2], v[runs - 1], last.unwrap())
}

fn report(case: &str, runs: usize, f: impl FnMut() -> (Mine, usize)) {
    let (med, max, (mine, arr)) = time(runs, f);
    println!(
        "{{\"case\":\"{case}\",\"ms_median\":{med:.4},\"ms_max\":{max:.4},\"runs\":{runs},\"pgs\":{},\"arrivals\":{arr}}}",
        mine.pgs.len()
    );
}

/// One gate of the control core for `old -> new`: `next` from the kept set, then `arrivals` (hash shards).
fn gate(prev: &Mine, old: &OsdMap, new: &OsdMap, me: i32) -> (Mine, usize) {
    let next = prev.next(old, new, me, pools());
    let (places, _) = arrivals(prev, &next, old, new, CORES, CORES as u32, |pg| {
        ((pg.pool + u64::from(pg.seed)) % CORES as u64) as u32
    });
    (next, places.len())
}

#[test]
#[ignore = "measurement: cargo test -p peering --release --test place_cost -- --ignored --nocapture"]
fn gate_placement_cost_on_an_e9455_map() {
    let me = 0;
    let base = e9455_map();
    let mine = Mine::scan(&base, me, pools());
    assert!(
        mine.pgs.len() > 100,
        "osd.{me} holds {} PGs",
        mine.pgs.len()
    );
    let bump = |m: &OsdMap| {
        let mut n = m.clone();
        n.epoch += 1;
        n
    };
    // (a) full scan: restart (no kept set) and every CRUSH-level change
    report("full_scan", 21, || (Mine::scan(&base, me, pools()), 0));
    let mut out = bump(&base);
    out.osd_weight[17] = 0;
    report("osd_out (full scan)", 21, || gate(&mine, &base, &out, me));
    let after_out = Mine::scan(&out, me, pools());
    let mut back_in = bump(&out);
    back_in.osd_weight[17] = 0x10000;
    report("osd_in (full scan)", 21, || {
        gate(&after_out, &out, &back_in, me)
    });
    // (b) incremental changes of normal operation
    let mut down = bump(&base);
    down.osd_state[17] &= !osd_state::UP;
    report("osd_down", 201, || gate(&mine, &base, &down, me));
    let after_down = Mine::scan(&down, me, pools());
    let mut up = bump(&down);
    up.osd_state[17] |= osd_state::UP;
    report("osd_up", 201, || gate(&after_down, &down, &up, me));
    let pg = PgT::new(64, 5);
    let mut temp = bump(&base);
    temp.pg_temp.insert(pg, vec![me, 9, 21]);
    report("pg_temp", 201, || gate(&mine, &base, &temp, me));
    let mut upmap = bump(&base);
    let raw = base.pg_to_up_acting(pg).up;
    let to = (0..OSDS).find(|o| !raw.contains(o)).unwrap();
    upmap.pg_upmap_items.insert(pg, vec![(raw[1], to)]);
    report("pg_upmap_items", 201, || gate(&mine, &base, &upmap, me));
    let same = bump(&base);
    report("epoch_bump", 201, || gate(&mine, &base, &same, me));
    // this OSD's own up state: down = member of nothing (no CRUSH work), up = full scan
    let mut self_down = bump(&base);
    self_down.osd_state[me as usize] &= !osd_state::UP;
    report("self_down", 21, || gate(&mine, &base, &self_down, me));
    // first gate after a restart: no kept set (scan of the applied map, here with this OSD down) and the map that
    // marks this OSD up (full scan)
    let mut self_up = bump(&self_down);
    self_up.osd_state[me as usize] |= osd_state::UP;
    report("boot", 21, || {
        let prev = Mine::scan(&self_down, me, pools());
        gate(&prev, &self_down, &self_up, me)
    });
}
