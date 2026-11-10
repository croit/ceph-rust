// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Actual PgEnv + optimized-EC PG key query; setup and output checks are outside CPU samples.
use super::*;
#[path = "../../peering/tests/common/mod.rs"]
mod sim;
use denc::types::{CollT, Ghobject};
use peering::{WriteEntry, WriteReq};
use pgwire::LogOp;
use replwire::txn::{Transaction, TxnOp};
use std::cell::Cell;
use std::hint::black_box;
use std::time::Instant;

thread_local! {
    static TRACK: Cell<bool> = const { Cell::new(false) };
    static ALLOCS: Cell<usize> = const { Cell::new(0) };
    static BYTES: Cell<usize> = const { Cell::new(0) };
}
#[cfg(feature = "perf4-overlay-allocations")]
pub(crate) fn note_alloc(bytes: usize) {
    if TRACK.try_with(Cell::get).unwrap_or(false) {
        let _ = ALLOCS.try_with(|n| n.set(n.get() + 1));
        let _ = BYTES.try_with(|n| n.set(n.get() + bytes));
    }
}

struct Fixture {
    s: sim::Sim,
    spg: SpgT,
    primary: i32,
    h: Hobject,
}
impl Fixture {
    fn new(value_bytes: usize) -> Self {
        let mut s = sim::Sim::new(741);
        for who in 0..4 {
            s.add_osd_cfg(who, |c| {
                c.ec_enable = ec::EcEnable::All;
                c.ec_enable_optimized = ec::EcEnable::All;
                c.ec_primary = true;
                c.ec_opt_primary = true;
            });
        }
        s.run_for(50 * sim::MS);
        s.create_pool_ec_opt(1, 2, 2, 4096, true, 1);
        s.run_for(2000 * sim::MS);
        s.run_until(60_000 * sim::MS, "optimized EC clean", |s| s.pool_clean(1));
        let spg = s.lead_spg(1, 0);
        let primary = s.primary_of(spg.pgid);
        let h = sim::hobj(1, "projected-keys");
        let version = s.pg(primary, spg).unwrap().next_version();
        let g = Ghobject::head(h.clone(), spg.shard);
        let mut t = Transaction::new();
        let cx = t.coll(&CollT::Pg(spg));
        let ox = t.obj(&g);
        t.push(cx, TxnOp::Touch { oid: ox });
        let puts: Vec<_> = (0..32)
            .map(|i| (format!("z/{i:04}").into_bytes(), vec![0x53; value_bytes]))
            .collect();
        t.push(
            cx,
            TxnOp::OmapSetKeys {
                oid: ox,
                pairs: puts
                    .iter()
                    .map(|(k, v)| (k.as_slice(), v.as_slice()))
                    .collect(),
            },
        );
        let oi = denc::to_vec(&replwire::ObjectInfo {
            soid: h.clone(),
            version,
            flags: replwire::oi::flag::OMAP,
            ..Default::default()
        })
        .unwrap();
        t.push(
            cx,
            TxnOp::SetAttr {
                oid: ox,
                name: b"_",
                value: &oi,
            },
        );
        let _tid = s
            .submit_raw(
                1,
                0,
                WriteReq {
                    entries: vec![WriteEntry {
                        op: LogOp::MODIFY,
                        soid: h.clone(),
                        user_version: version.version,
                        mtime: Default::default(),
                        snaps: Vec::new(),
                        return_code: 0,
                        op_returns: Vec::new(),
                        prior: None,
                    }],
                    txn_data: t.encode_v9().unwrap().into(),
                    ..Default::default()
                },
            )
            .unwrap();
        // A second object's in-flight write keeps the pipeline non-idle while the
        // first object becomes readable, matching a busy primary before roll-forward.
        let sentinel = sim::hobj(1, "pipeline-sentinel");
        let mut next = Transaction::new();
        let cx = next.coll(&CollT::Pg(spg));
        let ox = next.obj(&Ghobject::head(sentinel.clone(), spg.shard));
        next.push(cx, TxnOp::Touch { oid: ox });
        s.submit_raw(
            1,
            0,
            WriteReq {
                entries: vec![WriteEntry {
                    op: LogOp::MODIFY,
                    soid: sentinel,
                    user_version: 2,
                    mtime: Default::default(),
                    snaps: Vec::new(),
                    return_code: 0,
                    op_returns: Vec::new(),
                    prior: None,
                }],
                txn_data: next.encode_v9().unwrap().into(),
                ..Default::default()
            },
        )
        .unwrap();
        s.run_until(30_000 * sim::MS, "committed pending overlay", |s| {
            s.pg(primary, spg)
                .unwrap()
                .ec_omap_overlay(&h)
                .is_ok_and(|o| !o.is_empty())
        });
        assert!(
            !s.pg(primary, spg)
                .unwrap()
                .ec_omap_overlay(&h)
                .unwrap()
                .is_empty(),
            "fixture must exercise pending EC overlay"
        );
        let obj = s
            .nodes
            .get_mut(&primary)
            .unwrap()
            .store
            .pgs
            .get_mut(&spg)
            .unwrap()
            .objects
            .get_mut(&h)
            .unwrap();
        // Stored keys model already rolled-forward data; no writes occur during any sample.
        obj.omap = (0..64)
            .map(|i| (format!("b/{i:04}").into_bytes(), vec![0x37; value_bytes]))
            .collect();
        Self { s, spg, primary, h }
    }
    fn query(
        &mut self,
        after: Option<&[u8]>,
        prefix: &[u8],
        max: usize,
        bytes: usize,
    ) -> (Vec<Vec<u8>>, bool) {
        let node = self.s.nodes.get_mut(&self.primary).unwrap();
        let mut times = crate::perf::PersistTimes::default();
        let mut tracer = crate::trace::Tracer::default();
        let mut refuse_own = None;
        let mut bad_txns = 0;
        let env = PgEnv {
            conn_open: &|_| true,
            facts: Default::default(),
            refuse_own: &mut refuse_own,
            bad_txns: &mut bad_txns,
            set: &mut node.set,
            store: &mut node.store,
            spg: self.spg,
            now: self.s.now,
            wall: UTime::default(),
            map: None,
            whoami: self.primary,
            rest: Vec::new(),
            failed: None,
            notes: Vec::new(),
            persist_t: &mut times,
            tr: &mut tracer,
            eio: Default::default(),
            failsafe: false,
            repairs: 0,
            late_ok: false,
            send_first: false,
            late: None,
            obj_cache: 0,
            share: None,
        };
        env.ov_omap_keys_range(self.spg, &self.h, after, prefix, max, bytes)
            .unwrap()
    }

    fn execute(
        &mut self,
        mut ops: Vec<opwire::OsdOp>,
        max_entries: usize,
        max_bytes: usize,
    ) -> Vec<opwire::OsdOp> {
        let node = self.s.nodes.get_mut(&self.primary).unwrap();
        let mut times = crate::perf::PersistTimes::default();
        let mut tracer = crate::trace::Tracer::default();
        let mut refuse_own = None;
        let mut bad_txns = 0;
        let env = PgEnv {
            conn_open: &|_| true,
            facts: Default::default(),
            refuse_own: &mut refuse_own,
            bad_txns: &mut bad_txns,
            set: &mut node.set,
            store: &mut node.store,
            spg: self.spg,
            now: self.s.now,
            wall: UTime::default(),
            map: None,
            whoami: self.primary,
            rest: Vec::new(),
            failed: None,
            notes: Vec::new(),
            persist_t: &mut times,
            tr: &mut tracer,
            eio: Default::default(),
            failsafe: false,
            repairs: 0,
            late_ok: false,
            send_first: false,
            late: None,
            obj_cache: 0,
            share: None,
        };
        let info = opwire::OpInfo::classify(&ops, opwire::flag::READ, &|c, m| {
            opexec::clsx::lookup(c, m, &opexec::clsx::ClassPolicy::default()).ok()
        })
        .unwrap();
        let msg = opexec::Msg {
            source_pull_error: None,
            spg: self.spg,
            placement_read: false,
            head: self.h.clone(),
            flags: opwire::flag::READ
                | if info.may_write {
                    opwire::flag::WRITE
                } else {
                    0
                },
            snapid: denc::types::SnapId::NOSNAP.0,
            snapc: Default::default(),
            reqid: Default::default(),
            mtime: Default::default(),
            now: Default::default(),
            caller: opexec::Caller {
                name: denc::types::EntityName::client(7),
                addr: Default::default(),
                features: 0,
            },
            at_version: Default::default(),
            last_user_version: 0,
            info,
            limits: opexec::Limits {
                max_omap_entries: max_entries,
                max_omap_bytes: max_bytes,
                ..Default::default()
            },
            connected: Vec::new(),
            pool_full: false,
            pool_full_quota: false,
            no_room: false,
            removed_snaps: Vec::new(),
            ec_pool: true,
            ec_caps: opexec::EcCaps {
                allows_optimizations: true,
                requires_aligned_append: false,
                required_alignment: 0,
            },
            require_osd_release: osdmap::consts::release::UMBRELLA,
            copy: None,
            cls_map: opexec::ClsMap::default(),
        };
        let pre = opexec::exec::load_state(&env, self.spg, &self.h).unwrap();
        let mut exec = opexec::exec::Exec::new(&env, &msg, self.h.clone(), &pre);
        assert_eq!(exec.run(&mut ops), 0);
        ops
    }
}

fn log_trim_input() -> Vec<u8> {
    let mut e = denc::Encoder::new();
    e.versioned(2, 1, |e| {
        denc::Encode::encode(&UTime::default(), e)?;
        denc::Encode::encode(&UTime::default(), e)?;
        e.bytes(b"b/")?;
        e.bytes(b"b/9999")
    })
    .unwrap();
    e.into_vec()
}

#[test]
fn actual_pg_key_pagination_and_wire_results() {
    let mut f = Fixture::new(1);
    let all: Vec<Vec<u8>> = (0..64)
        .map(|i| format!("b/{i:04}").into_bytes())
        .chain((0..32).map(|i| format!("z/{i:04}").into_bytes()))
        .collect();
    for after in [
        None,
        Some(b"b/0000".as_slice()),
        Some(b"b/0063"),
        Some(b"z/0000"),
    ] {
        for prefix in [b"".as_slice(), b"b/", b"z/", b"x/"] {
            for max in [0, 1, 2, 128] {
                for budget in [0usize, 1, 10, 16, 1000] {
                    let matching: Vec<_> = all
                        .iter()
                        .filter(|k| after.is_none_or(|a| k.as_slice() > a) && k.starts_with(prefix))
                        .cloned()
                        .collect();
                    let n = max.min(budget.div_ceil(10)).min(matching.len());
                    assert_eq!(
                        f.query(after, prefix, max, budget),
                        (matching[..n].to_vec(), n < matching.len())
                    );
                }
            }
        }
    }
    let ops = f.execute(vec![opwire::OsdOp::omap_get_keys(b"", 1000)], 2, 16);
    // Independent literal encoding: count2, two six-byte strings, more1.
    assert_eq!(
        ops[0].outdata.as_ref(),
        b"\x02\0\0\0\x06\0\0\0b/0000\x06\0\0\0b/0001\x01"
    );
    let ops = f.execute(vec![opwire::OsdOp::omap_get_keys(b"", 1000)], 2, 0);
    assert_eq!(ops[0].outdata.as_ref(), b"\0\0\0\0\x01");

    let obj =
        f.s.nodes
            .get_mut(&f.primary)
            .unwrap()
            .store
            .pgs
            .get_mut(&f.spg)
            .unwrap()
            .objects
            .get_mut(&f.h)
            .unwrap();
    obj.omap
        .insert(b"snap_seq".to_vec(), 7u64.to_le_bytes().to_vec());
    for id in [1, 2] {
        obj.omap.insert(
            format!("snapshot_{id:016x}").into_bytes(),
            vec![42; 256 << 10],
        );
    }
    let ops = f.execute(
        vec![opwire::OsdOp::call(b"rbd", b"get_snapcontext", b"")],
        1,
        1 << 20,
    );
    // rbd get_snapcontext walks cls key pages, reverses snapshot IDs and reads only snap_seq's value.
    let mut want = 7u64.to_le_bytes().to_vec();
    want.extend(2u32.to_le_bytes());
    want.extend(2u64.to_le_bytes());
    want.extend(1u64.to_le_bytes());
    assert_eq!(ops[0].outdata.as_ref(), want);
    let ops = f.execute(
        vec![opwire::OsdOp::call(b"log", b"trim", &log_trim_input())],
        1,
        1 << 20,
    );
    assert_eq!(ops[0].rval, 0);
    assert!(ops[0].outdata.is_empty());
}

#[test]
fn immutable_listing_reply_keeps_actual_ec_overlay_values_and_keys() {
    let mut f = Fixture::new(1);
    // z/ exists only in the pending optimized-EC overlay, not the base store.
    // Both complete-reply dispatches must still use PgEnv's merged view.
    let out = f.execute(
        vec![
            opwire::OsdOp::omap_get_vals(b"b/0063", 2, b"z/"),
            opwire::OsdOp::omap_get_keys(b"b/0063", 2),
        ],
        2,
        usize::MAX,
    );
    assert_eq!(
        out[0].outdata.as_ref(),
        b"\x02\0\0\0\x06\0\0\0z/0000\x01\0\0\0S\x06\0\0\0z/0001\x01\0\0\0S\x01"
    );
    assert_eq!(
        out[1].outdata.as_ref(),
        b"\x02\0\0\0\x06\0\0\0z/0000\x06\0\0\0z/0001\x01"
    );
    assert!(
        out.iter()
            .all(|op| op.rval == 0 && op.outdata_more.is_empty())
    );
    let held = out[0].outdata.clone();
    drop(f);
    assert_eq!(held, out[0].outdata);
}

#[cfg(feature = "perf4-overlay-allocations")]
#[test]
fn actual_pg_large_values_do_not_allocate_for_key_listing() {
    let mut f = Fixture::new(256 << 10);
    BYTES.set(0);
    ALLOCS.set(0);
    TRACK.set(true);
    let reply = f.query(None, b"", 1, 16);
    TRACK.set(false);
    assert_eq!(reply, (vec![b"b/0000".to_vec()], true));
    assert!(
        BYTES.get() < 64 << 10,
        "key query allocated {} bytes for unused values",
        BYTES.get()
    );
}

#[cfg(feature = "perf4-overlay-allocations")]
#[test]
fn actual_pg_large_values_do_not_allocate_for_op_and_cls_key_listing() {
    let mut f = Fixture::new(256 << 10);
    let mut oversized = Vec::new();
    for op in [
        opwire::OsdOp::omap_get_keys(b"", 1),
        opwire::OsdOp::call(b"log", b"trim", &log_trim_input()),
    ] {
        BYTES.set(0);
        ALLOCS.set(0);
        TRACK.set(true);
        let reply = f.execute(vec![op], 1, 1 << 20);
        TRACK.set(false);
        assert_eq!(reply[0].rval, 0);
        println!(
            "executor_key_listing op={} allocations={} requested_bytes={}",
            reply[0].op,
            ALLOCS.get(),
            BYTES.get()
        );
        if BYTES.get() >= 64 << 10 {
            oversized.push((reply[0].op, BYTES.get()));
        }
    }
    assert!(
        oversized.is_empty(),
        "key-only op/cls allocated unused values: {oversized:?}"
    );
}

#[test]
#[ignore = "paired actual PgEnv CPU probe; run perf4-plain-allocator alone"]
fn perf4_ec_overlay_keys_cpu() {
    assert!(black_box(cfg!(feature = "perf4-plain-allocator")));
    assert!(!black_box(cfg!(feature = "perf4-overlay-allocations")));
    let mut f = Fixture::new(256 << 10);
    let expected = (vec![b"b/0000".to_vec()], true);
    assert_eq!(f.query(None, b"", 1, 16), expected);
    for sample in 0..5 {
        let start = Instant::now();
        for _ in 0..20 {
            black_box(f.query(None, b"", black_box(1), black_box(16)));
        }
        let ns = start.elapsed().as_nanos() / 20;
        assert_eq!(f.query(None, b"", 1, 16), expected);
        println!(
            "ec_overlay_keys_cpu sample={sample} ns_per_query={ns} overlay_keys=32 base_keys=64 value_bytes=262144 allocator=System_uninstrumented"
        );
    }
}

#[test]
#[ignore = "allocation-only actual PgEnv probe; perf4-overlay-allocations, separate from CPU"]
fn perf4_ec_overlay_keys_allocations() {
    assert!(black_box(cfg!(feature = "perf4-overlay-allocations")));
    assert!(!black_box(cfg!(feature = "perf4-plain-allocator")));
    let mut f = Fixture::new(256 << 10);
    for sample in 0..5 {
        ALLOCS.set(0);
        BYTES.set(0);
        TRACK.set(true);
        let result = f.query(None, b"", 1, 16);
        TRACK.set(false);
        assert_eq!(result, (vec![b"b/0000".to_vec()], true));
        println!(
            "ec_overlay_keys_alloc sample={sample} allocations={} requested_bytes={} overlay_keys=32 base_keys=64 value_bytes=262144",
            ALLOCS.get(),
            BYTES.get()
        );
    }
}
