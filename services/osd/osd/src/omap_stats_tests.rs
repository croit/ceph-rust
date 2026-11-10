// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
//! Last-deep-scrub OMAP reporting: the mgr must use logical primary PG totals, not per-OSD allocation estimates.
use super::*;
use messages::{MPGStats, Message};

fn write(mc: &mut Mc, tid: u64, ops: Vec<OsdOp>) -> SpgT {
    // Fresh fake session: it does not answer messenger keepalives during the intervening scrub/report timers.
    let client = mc.client(0);
    let op = mc.op(1, "omap-stats", ops);
    let spg = op.pgid;
    let replies = mc.call(0, client, tid, op);
    assert_eq!(replies.len(), 1, "write tid {tid}, pg {spg}");
    assert_eq!(replies[0].1.result, 0);
    spg
}

fn set(pairs: &[(&[u8], usize)]) -> OsdOp {
    OsdOp::omap_set_vals(
        &pairs
            .iter()
            .map(|(k, n)| (k.to_vec(), vec![b'v'; *n]))
            .collect(),
    )
}

fn scrub(mc: &mut Mc, spg: SpgT) {
    let core = mc
        .osds
        .iter()
        .position(|o| o.pg.set.pg(spg).is_some())
        .unwrap();
    let before = mc.osds[core].pg.set.pg(spg).unwrap().scrub_counts().0;
    let now = mc.t.as_nanos() as u64;
    let o = &mut mc.osds[core];
    let acts = o.pg.set.request_scrub(now, spg, true, false, &o.pg.store);
    o.pg_exec(acts);
    for _ in 0..100 {
        mc.run_for(Duration::from_millis(100));
        let pg = mc.osds[core].pg.set.pg(spg).unwrap();
        if pg.scrub_counts().0 > before && !pg.scrub_running() {
            mc.run_for(Duration::from_secs(2)); // publish the worker's primary PG stats to the control core
            return;
        }
    }
    panic!("deep-scrub did not finish for {spg}");
}

fn report(mc: &mut Mc, keys: i64, bytes: i64) {
    // Default PG publication is every five seconds, followed by the worker's one-second report.
    mc.run_for(Duration::from_secs(7));
    let mgr = mc.client(0);
    mc.osds[0].t.out.clear();
    mc.osds[0].send_mgr_report(mgr);
    let frame = mc.osds[0]
        .t
        .out
        .iter()
        .find(|f| f.0 == mgr && f.2.0 == 87)
        .unwrap();
    let segs = &frame.3;
    let r = MPGStats::decode(frame.2.1, &segs.front, &segs.middle, &segs.data).unwrap();
    assert_eq!(
        r.osd_stat.num_per_pool_osds, 1,
        "retain per-pool data statistics"
    );
    assert_eq!(
        r.osd_stat.num_per_pool_omap_osds, 0,
        "select mgr's scrub-based OMAP fallback"
    );
    assert_eq!(
        r.osd_stat.statfs.omap_allocated, bytes,
        "OSD-level OMAP column (ceph osd df) carries the hosted PG sum"
    );
    assert_eq!(r.osd_stat.kb_used_omap, bytes >> 10);
    assert!(
        r.pool_stat.values().all(|s| s.omap_allocated == 0),
        "no scrub totals in allocation fields"
    );
    let mut totals = (0, 0);
    for (pgid, enc) in &r.pg_stat {
        if pgid.pool == 1 {
            let pg: pgwire::PgStat = denc::from_slice(enc).unwrap();
            totals.0 += pg.stats.sum.num_omap_keys;
            totals.1 += pg.stats.sum.num_omap_bytes;
        }
    }
    assert_eq!(totals, (keys, bytes));
    // The manager selects the PG totals unless every reporting OSD advertises per-pool OMAP allocation. In this
    // fallback, logical usage is independent of the pool's replication / EC raw-used rate.
    for rate in [1.0, 2.0, 3.0, 1.5] {
        let stored = if r.osd_stat.num_osds == r.osd_stat.num_per_pool_omap_osds {
            (r.pool_stat.values().map(|s| s.omap_allocated).sum::<i64>() as f64 / rate) as i64
        } else {
            totals.1
        };
        assert_eq!(stored, bytes, "raw-used rate {rate}");
    }
    let (_, dump) = super::tellx::ask(mc, serde_json::json!({"prefix": "dump_osd_pg_stats"}));
    assert_eq!(dump["osd_stat"]["num_per_pool_omap_osds"], 0);
}

fn last_deep_scrub_usage(lsm: bool) {
    let mut mc = if lsm {
        Mc::with_olsm(2, 2048)
    } else {
        Mc::new(2)
    };
    mc.up();
    let key = b"seventeen-bytekey";
    let mut tid = 1;
    let spg = write(&mut mc, tid, vec![set(&[(key, 96)])]);
    report(&mut mc, 0, 0);
    scrub(&mut mc, spg);
    report(&mut mc, 1, 113); // 17 key bytes + 96 value bytes; not divided by replica count
    let mut previous = 113;
    for size in [192, 7, 0] {
        tid += 1;
        write(&mut mc, tid, vec![set(&[(key, size)])]);
        report(&mut mc, 1, previous);
        scrub(&mut mc, spg);
        report(&mut mc, 1, key.len() as i64 + size as i64);
        previous = key.len() as i64 + size as i64;
    }
    report(&mut mc, 1, 17); // empty value still contributes its key bytes

    tid += 1;
    write(&mut mc, tid, vec![set(&[(key, 333)]), set(&[(key, 0)])]);
    scrub(&mut mc, spg);
    report(&mut mc, 1, 17); // repeated overwrite counts the final value and one key

    tid += 1;
    let utf8_key = "é".as_bytes();
    let binary_key = b"\x00\xff";
    write(
        &mut mc,
        tid,
        vec![set(&[
            (b"a", 11),
            (b"b", 17),
            (b"c", 23),
            (binary_key, 5),
            (utf8_key, 0),
        ])],
    );
    let cl = mc.client(0);
    let read = mc.op(1, "omap-stats", vec![OsdOp::omap_get_vals(b"", 100, b"")]);
    let replies = mc.call(0, cl, 100, read);
    let values: opwire::OmapValsOut = denc::from_slice(&replies[0].1.ops[0].outdata).unwrap();
    assert_eq!(
        values.vals.len(),
        6,
        "stored OMAP entries before deep-scrub"
    );
    scrub(&mut mc, spg);
    report(&mut mc, 6, 80); // 17 + 12 + 18 + 24 + 7 + 2 key/value bytes
    let mut range = OsdOp::new(opwire::consts::op::OMAP_RM_KEY_RANGE);
    range.indata = denc::to_vec(&opwire::OmapRmKeyRangeIn {
        begin: b"b".to_vec(),
        end: b"d".to_vec(),
    })
    .unwrap()
    .into();
    tid += 1;
    write(&mut mc, tid, vec![range]);
    report(&mut mc, 6, 80);
    scrub(&mut mc, spg);
    report(&mut mc, 4, 38); // retains empty 17-byte key, a (12), binary (7), UTF-8 (2)

    tid += 1;
    write(
        &mut mc,
        tid,
        vec![OsdOp::omap_rm_keys(&BTreeSet::from([b"a".to_vec()]))],
    );
    report(&mut mc, 4, 38);
    scrub(&mut mc, spg);
    report(&mut mc, 3, 26);

    tid += 1;
    write(&mut mc, tid, vec![OsdOp::omap_clear()]);
    report(&mut mc, 3, 26);
    scrub(&mut mc, spg);
    report(&mut mc, 0, 0);
    tid += 1;
    write(&mut mc, tid, vec![set(&[(key, 96)])]);
    scrub(&mut mc, spg);
    report(&mut mc, 1, 113);
    tid += 1;
    write(&mut mc, tid, vec![OsdOp::delete()]);
    report(&mut mc, 1, 113); // purge does not change last-scrub key/value measurements
    mc.restart();
    let map = mc.map(12, 12);
    mc.deliver(map);
    mc.run_for(Duration::from_secs(3));
    report(&mut mc, 1, 113); // last completed scrub survives restart
    scrub(&mut mc, spg);
    report(&mut mc, 0, 0);
}

#[test]
fn btree_omap_usage_changes_only_after_deep_scrub() {
    last_deep_scrub_usage(false);
}

#[test]
fn lsm_omap_usage_changes_only_after_deep_scrub() {
    last_deep_scrub_usage(true);
}
