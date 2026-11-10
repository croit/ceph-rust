// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! CephFS-shaped op sequences (doc/spec/cephfs-osd-surface.md, cephfs-gap.md G6-G9): MDS/client messages built from
//! the documented patterns (permission probe, uninline compound, size probe at snapid, hints, unknown ops).
mod common;
use common::*;
use denc::types::{EntityAddr, UTime};
use opexec::caps::Caps;
use opexec::{ClientReq, Engine};
use opwire::{
    MOSDOp, MOSDOpReply, OsdOp, StatOut,
    consts::{cmp, op as code, opflag},
    errno, flag as mflag,
};
use std::sync::Arc;

fn send(pg: &mut TPg, eng: &mut Engine, tid: u64, op: MOSDOp, caps: Option<&str>) -> MOSDOpReply {
    eng.on_op(
        pg,
        ClientReq {
            placement_read: None,
            conn: 1,
            caps: caps.map(|c| Arc::new(Caps::parse(c).unwrap())),
            tid,
            op: Box::new(op),
            who: client(7),
            addr: EntityAddr::v4(EntityAddr::TYPE_MSGR2, 0, [10, 0, 0, 5], 4000),
            peer_addr: EntityAddr::v4(EntityAddr::TYPE_MSGR2, 0, [10, 0, 0, 5], 4000),
            features: 0x3f17_ffff_fffd_ffff,
        },
    );
    let mut outs = settle(pg, eng);
    reply_of(&mut outs, 1, tid).expect("reply")
}

fn app(pg: &mut TPg, key: &str, val: &str) {
    pg.apps
        .entry("cephfs".into())
        .or_default()
        .insert(key.into(), val.into());
}

/// Message flags exactly as the client sends them for the pool permission probe: a read-only `stat` with the
/// WRITE flag (the Objecter marks the whole message as a mutation).
fn probe_stat(oid: &str) -> MOSDOp {
    let mut m = mkop(oid.as_bytes(), vec![OsdOp::stat()]);
    m.flags = (m.flags & !mflag::READ) | mflag::WRITE;
    m
}
fn probe_create(oid: &str) -> MOSDOp {
    mkop(oid.as_bytes(), vec![OsdOp::create(true)])
}

// ---------------------------------------------------------------- G6 caps / pool permission probe

#[test]
fn fs_authorize_caps_probe() {
    // `ceph fs authorize <fs> client.x / rw` -> osd 'allow rw tag cephfs data=<fs>'
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    let rw = "allow rw tag cephfs data=cephfs";
    let ro = "allow r tag cephfs data=cephfs";
    // pool not tagged yet: every probe is EPERM, nothing created
    assert_eq!(
        send(
            &mut pg,
            &mut eng,
            1,
            probe_stat("10000000000.00000000"),
            Some(rw)
        )
        .result,
        -errno::EPERM
    );
    app(&mut pg, "data", "cephfs");
    let o = "10000000000.00000000";
    // stat-with-WRITE-flag under read-only caps: judged by op list -> allowed, ENOENT on a missing object
    assert_eq!(
        send(&mut pg, &mut eng, 2, probe_stat(o), Some(ro)).result,
        -errno::ENOENT
    );
    // create(excl) with read-only caps: plain EPERM, object not created
    let n = pg.entries.len();
    assert_eq!(
        send(&mut pg, &mut eng, 3, probe_create(o), Some(ro)).result,
        -errno::EPERM
    );
    assert_eq!(pg.entries.len(), n);
    assert_eq!(
        send(&mut pg, &mut eng, 4, probe_stat(o), Some(ro)).result,
        -errno::ENOENT
    );
    // rw caps: create succeeds once (creates the empty object), second probe EEXIST = still "write ok"
    assert_eq!(
        send(&mut pg, &mut eng, 5, probe_create(o), Some(rw)).result,
        0
    );
    assert_eq!(
        send(&mut pg, &mut eng, 6, probe_create(o), Some(rw)).result,
        -errno::EEXIST
    );
    let r = send(&mut pg, &mut eng, 7, probe_stat(o), Some(ro));
    assert_eq!(r.result, 0);
    let st: StatOut = denc::from_slice(&r.ops[0].outdata).unwrap();
    assert_eq!(st.size, 0);
    // other filesystem's tag does not match; metadata= tag is a different key
    assert_eq!(
        send(
            &mut pg,
            &mut eng,
            8,
            probe_stat(o),
            Some("allow rw tag cephfs data=other")
        )
        .result,
        -errno::EPERM
    );
    assert_eq!(
        send(
            &mut pg,
            &mut eng,
            9,
            probe_stat(o),
            Some("allow rw tag cephfs metadata=cephfs")
        )
        .result,
        -errno::EPERM
    );
    app(&mut pg, "metadata", "cephfs");
    assert_eq!(
        send(
            &mut pg,
            &mut eng,
            10,
            probe_stat(o),
            Some("allow rw tag cephfs metadata=cephfs")
        )
        .result,
        0
    );
    // comma-joined grants as `fs authorize` prints them for several filesystems; wildcard tag
    let multi = "allow rw tag cephfs data=a, allow rw tag cephfs data=cephfs";
    assert_eq!(
        send(&mut pg, &mut eng, 11, probe_create(o), Some(multi)).result,
        -errno::EEXIST
    );
    assert_eq!(
        send(
            &mut pg,
            &mut eng,
            12,
            probe_create(o),
            Some("allow rw tag cephfs *=*")
        )
        .result,
        -errno::EEXIST
    );
    // `fs authorize ... path` clients get the same osd caps; pool-name caps still work
    assert_eq!(
        send(
            &mut pg,
            &mut eng,
            13,
            probe_create(o),
            Some("allow rw pool=testpool")
        )
        .result,
        -errno::EEXIST
    );
}

#[test]
fn fs_caps_namespaces() {
    // layout `pool_namespace` => locator namespace; caps may pin a namespace
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    app(&mut pg, "data", "cephfs");
    let wr_ns = |ns: &str, oid: &str| {
        let mut m = mkop(oid.as_bytes(), vec![OsdOp::write(0, b"x".to_vec())]);
        m.oloc.nspace = ns.as_bytes().to_vec();
        m
    };
    let c = "allow rw namespace=fsns tag cephfs data=cephfs";
    assert_eq!(
        send(&mut pg, &mut eng, 1, wr_ns("fsns", "o"), Some(c)).result,
        0
    );
    assert_eq!(
        send(&mut pg, &mut eng, 2, wr_ns("", "o"), Some(c)).result,
        -errno::EPERM
    );
    assert_eq!(
        send(&mut pg, &mut eng, 3, wr_ns("other", "o"), Some(c)).result,
        -errno::EPERM
    );
    // same name in two namespaces = two objects
    assert_eq!(
        send(&mut pg, &mut eng, 4, wr_ns("", "o"), Some("allow rw")).result,
        0
    );
    assert_eq!(pg.store.objects(pg.spg).len(), 2);
    let c2 = "allow rw pool=testpool namespace=fsns";
    assert_eq!(
        send(&mut pg, &mut eng, 5, wr_ns("fsns", "o2"), Some(c2)).result,
        0
    );
    assert_eq!(
        send(&mut pg, &mut eng, 6, wr_ns("x", "o2"), Some(c2)).result,
        -errno::EPERM
    );
}

// ---------------------------------------------------------------- G7 uninline compound

fn le64(v: u64) -> Vec<u8> {
    v.to_le_bytes().to_vec()
}

fn uninline(oid: &str, ver: u64, data: &[u8]) -> MOSDOp {
    let mut w = OsdOp::write(0, data.to_vec());
    let mut e = w.extent();
    e.truncate_seq = 1;
    e.truncate_size = 0;
    w.set_extent(e);
    mkop(
        oid.as_bytes(),
        vec![
            OsdOp::cmpxattr(b"inline_version", &le64(ver), cmp::GT, cmp::MODE_U64),
            w,
            OsdOp::setxattr(b"inline_version", ver.to_string().as_bytes()),
        ],
    )
}

#[test]
fn uninline_cmpxattr_u64_gt_compound() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    // the client sends `create(non-excl)` as its own message first; the compound itself needs the object (committed state)
    assert_eq!(
        send(&mut pg, &mut eng, 100, uninline("f", 5, b"x"), None).result,
        -errno::ENOENT
    );
    for (t, o) in [(101, "f"), (102, "g"), (103, "h"), (104, "i")] {
        assert_eq!(
            send(
                &mut pg,
                &mut eng,
                t,
                mkop(o.as_bytes(), vec![OsdOp::create(false)]),
                None
            )
            .result,
            0
        );
    }
    // missing xattr counts as 0: GT true -> data written and version recorded atomically
    let r = send(&mut pg, &mut eng, 1, uninline("f", 5, b"inline-data"), None);
    assert_eq!(r.result, 0);
    let st = pg.store.objects(pg.spg);
    let o = st.values().next().unwrap();
    assert_eq!(o.data, b"inline-data");
    assert_eq!(o.xattrs[b"_inline_version".as_slice()], b"5");
    drop(st);
    // same version again: GT false -> ECANCELED, nothing changes (data not rewritten)
    let r = send(&mut pg, &mut eng, 2, uninline("f", 5, b"XXXXXXXXXXX"), None);
    assert_eq!(r.result, -errno::ECANCELED);
    assert_eq!(r.ops[0].rval, -errno::ECANCELED);
    let st = pg.store.objects(pg.spg);
    assert_eq!(st.values().next().unwrap().data, b"inline-data");
    drop(st);
    // older version: ECANCELED; newer: applies
    assert_eq!(
        send(&mut pg, &mut eng, 3, uninline("f", 4, b"old"), None).result,
        -errno::ECANCELED
    );
    assert_eq!(
        send(&mut pg, &mut eng, 4, uninline("f", 6, b"newer"), None).result,
        0
    );
    let st = pg.store.objects(pg.spg);
    let o = st.values().next().unwrap();
    assert_eq!(&o.data[..5], b"newer");
    assert_eq!(o.xattrs[b"_inline_version".as_slice()], b"6");
    drop(st);
    // empty stored value also counts as 0
    send(
        &mut pg,
        &mut eng,
        5,
        mkop(b"g", vec![OsdOp::setxattr(b"inline_version", b"")]),
        None,
    );
    assert_eq!(
        send(&mut pg, &mut eng, 6, uninline("g", 1, b"d"), None).result,
        0
    );
    // cmpxattr with a non-numeric stored value: EINVAL, nothing applied
    send(
        &mut pg,
        &mut eng,
        7,
        mkop(b"h", vec![OsdOp::setxattr(b"inline_version", b"zz")]),
        None,
    );
    assert_eq!(
        send(&mut pg, &mut eng, 8, uninline("h", 1, b"d"), None).result,
        -errno::EINVAL
    );
    // the MDS "no inline data" marker is u64::MAX-ish: version comparison is unsigned
    assert_eq!(
        send(&mut pg, &mut eng, 9, uninline("i", u64::MAX, b"d"), None).result,
        0
    );
    assert_eq!(
        send(&mut pg, &mut eng, 10, uninline("i", u64::MAX, b"d"), None).result,
        -errno::ECANCELED
    );
}

// ---------------------------------------------------------------- G8 stat / read at snapid

fn at_mtime(mut m: MOSDOp, sec: u32) -> MOSDOp {
    m.mtime = UTime::new(sec, 0);
    m
}
fn snapc(mut m: MOSDOp, seq: u64, snaps: &[u64]) -> MOSDOp {
    m.snap_seq = seq;
    m.snaps = snaps.to_vec();
    m
}
fn stat_at(
    pg: &mut TPg,
    eng: &mut Engine,
    tid: u64,
    oid: &str,
    snapid: u64,
) -> (i32, Option<StatOut>) {
    let mut m = mkop(oid.as_bytes(), vec![OsdOp::stat()]);
    m.flags |= mflag::RWORDERED;
    m.snapid = snapid;
    let r = send(pg, eng, tid, m, None);
    let st = (r.result == 0).then(|| denc::from_slice(&r.ops[0].outdata).unwrap());
    (r.result, st)
}

#[test]
fn stat_and_read_at_snapid_with_gaps() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    let w = |data: &[u8], sec, seq, snaps: &[u64]| {
        snapc(
            at_mtime(mkop(b"s", vec![OsdOp::write(0, data.to_vec())]), sec),
            seq,
            snaps,
        )
    };
    assert_eq!(
        send(&mut pg, &mut eng, 1, w(b"aaaa", 100, 0, &[]), None).result,
        0
    );
    // snaps 3 and 5 exist (4 never existed for this realm: gap); each first write after a snap clones
    assert_eq!(
        send(&mut pg, &mut eng, 2, w(b"bbbbbb", 200, 3, &[3]), None).result,
        0
    );
    assert_eq!(
        send(&mut pg, &mut eng, 3, w(b"cccccccc", 300, 5, &[5, 3]), None).result,
        0
    );
    // probe at the clone ids: size + mtime of the state AT the snap
    let (r, s) = stat_at(&mut pg, &mut eng, 4, "s", 3);
    assert_eq!((r, s.unwrap().size, s.unwrap().mtime.sec), (0, 4, 100));
    let (r, s) = stat_at(&mut pg, &mut eng, 5, "s", 5);
    assert_eq!((r, s.unwrap().size, s.unwrap().mtime.sec), (0, 6, 200));
    // gap: snap 4 is not in any clone's snaps -> ENOENT; snap 2 (before first clone's snaps) -> ENOENT
    assert_eq!(stat_at(&mut pg, &mut eng, 6, "s", 4).0, -errno::ENOENT);
    assert_eq!(stat_at(&mut pg, &mut eng, 7, "s", 2).0, -errno::ENOENT);
    // beyond the object's snapset seq: head
    let (r, s) = stat_at(&mut pg, &mut eng, 8, "s", 9);
    assert_eq!((r, s.unwrap().size, s.unwrap().mtime.sec), (0, 8, 300));
    // data read at snapid: same resolution
    let mut rd = mkop(b"s", vec![OsdOp::read(0, 100)]);
    rd.snapid = 5;
    assert_eq!(
        send(&mut pg, &mut eng, 9, rd, None).ops[0].outdata,
        &b"bbbbbb"[..]
    );
    // snap id removed (rmdir .snap, queue not yet trimmed): reads/stat -> ENOENT even though the clone exists
    pg.removed = vec![(3, 1)];
    assert_eq!(stat_at(&mut pg, &mut eng, 10, "s", 3).0, -errno::ENOENT);
    assert_eq!(stat_at(&mut pg, &mut eng, 11, "s", 5).0, 0);
    // object never written since the snap: snap read = head content
    send(&mut pg, &mut eng, 12, w(b"zz", 400, 0, &[]), None);
    let (r, s) = stat_at(&mut pg, &mut eng, 13, "t", 7);
    assert_eq!((r, s.is_none()), (-errno::ENOENT, true));
    let (r, s) = stat_at(&mut pg, &mut eng, 14, "s", 100);
    assert_eq!(r, 0);
    assert_eq!(s.unwrap().size, 8);
}

// ---------------------------------------------------------------- G9 hints and unknown ops

#[test]
fn flags_and_hints_are_ignored() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    let mut w = OsdOp::write(0, b"hello".to_vec());
    w.flags |= opflag::FADVISE_RANDOM
        | opflag::FADVISE_SEQUENTIAL
        | opflag::FADVISE_WILLNEED
        | opflag::FADVISE_DONTNEED
        | opflag::FADVISE_NOCACHE;
    let mut m = mkop(b"h", vec![w]);
    m.flags |= mflag::RWORDERED
        | mflag::FULL_FORCE
        | mflag::FULL_TRY
        | mflag::SUPPORTSPOOLEIO
        | mflag::IGNORE_OVERLAY;
    assert_eq!(send(&mut pg, &mut eng, 1, m, None).result, 0);
    let mut r = OsdOp::read(0, 10);
    r.flags |= opflag::FADVISE_DONTNEED | opflag::FADVISE_NOCACHE;
    let mut m = mkop(b"h", vec![r]);
    m.flags |=
        mflag::LOCALIZE_READS | mflag::BALANCE_READS | mflag::KNOWN_REDIR | mflag::SUPPORTSPOOLEIO;
    let rep = send(&mut pg, &mut eng, 2, m, None);
    assert_eq!((rep.result, &rep.ops[0].outdata[..]), (0, &b"hello"[..]));
    // alloc-hint (kernel sends it ahead of writes) in a compound
    let m = mkop(
        b"h2",
        vec![
            OsdOp::alloc_hint_op(4 << 20, 4 << 20, 0),
            OsdOp::write(0, b"x".to_vec()),
        ],
    );
    assert_eq!(send(&mut pg, &mut eng, 3, m, None).result, 0);
}

#[test]
fn unknown_and_unsupported_ops_answer_per_op_eopnotsupp() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    send(
        &mut pg,
        &mut eng,
        1,
        mkop(b"u", vec![OsdOp::write(0, b"keep".to_vec())]),
        None,
    );
    let n = pg.entries.len();
    // an unsupported op (tmap2omap) as the 2nd op of a compound (stat first, a mutation after)
    let cf = OsdOp::new(code::TMAP2OMAP);
    let rep = send(
        &mut pg,
        &mut eng,
        2,
        mkop(b"u", vec![OsdOp::write(0, b"XXXX".to_vec()), cf]),
        None,
    );
    assert_eq!(rep.result, -errno::EOPNOTSUPP);
    assert_eq!(rep.ops.len(), 2, "per-op results travel");
    assert_eq!(rep.ops[1].rval, -errno::EOPNOTSUPP);
    // the whole message is atomic: the write before it left no trace
    assert_eq!(
        &pg.store.objects(pg.spg).values().next().unwrap().data[..],
        b"keep"
    );
    assert_eq!(pg.entries.len(), n + 1, "only the error log entry");
    // a code the daemon has never heard of (read-mode and write-mode) -> same
    for (tid, c) in [(3u64, 0x12ffu16), (4, 0x22ff)] {
        let rep = send(
            &mut pg,
            &mut eng,
            tid,
            mkop(b"u", vec![OsdOp::new(c)]),
            None,
        );
        assert_eq!(rep.result, -errno::EOPNOTSUPP, "op {c:#x}");
    }
    // FAILOK on the unsupported op: the compound continues (client's fallback pattern)
    let mut cf = OsdOp::new(code::TMAP2OMAP);
    cf.flags |= opflag::FAILOK;
    let rep = send(
        &mut pg,
        &mut eng,
        5,
        mkop(b"u", vec![cf, OsdOp::write(0, b"YYYY".to_vec())]),
        None,
    );
    assert_eq!(rep.result, 0);
    assert_eq!(rep.ops[0].rval, -errno::EOPNOTSUPP);
    assert_eq!(
        &pg.store.objects(pg.spg).values().next().unwrap().data[..],
        b"YYYY"
    );
}

// ---------------------------------------------------------------- journal object patterns (G4 semantics)

#[test]
fn journal_object_patterns() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    let j = |ops: Vec<OsdOp>| mkop(b"200.00000001", ops);
    // prezero/remove of an object that does not exist: zero = success no-op, delete = ENOENT, both harmless
    assert_eq!(
        send(&mut pg, &mut eng, 1, j(vec![OsdOp::zero(0, 4 << 20)]), None).result,
        0
    );
    assert!(
        pg.store.objects(pg.spg).is_empty(),
        "zero must not create the object"
    );
    assert_eq!(
        send(&mut pg, &mut eng, 2, j(vec![OsdOp::delete()]), None).result,
        -errno::ENOENT
    );
    // stat at the journal probe: ENOENT for the end-of-journal object
    assert_eq!(
        send(&mut pg, &mut eng, 3, j(vec![OsdOp::stat()]), None).result,
        -errno::ENOENT
    );
    // unaligned appends at consecutive offsets, the first one beyond the (empty) end: holes read as zeros
    let mut pos = 1000u64;
    let mut want = vec![0u8; 1000];
    for (i, len) in [100usize, 4000, 4097, 65000, 1].into_iter().enumerate() {
        let d: Vec<u8> = (0..len).map(|k| (i * 31 + k) as u8).collect();
        let r = send(
            &mut pg,
            &mut eng,
            10 + i as u64,
            j(vec![OsdOp::write(pos, d.clone())]),
            None,
        );
        assert_eq!(r.result, 0);
        want.extend_from_slice(&d);
        pos += len as u64;
        // stat size == exact acked end after every append
        let r = send(
            &mut pg,
            &mut eng,
            100 + i as u64,
            j(vec![OsdOp::stat()]),
            None,
        );
        let st: StatOut = denc::from_slice(&r.ops[0].outdata).unwrap();
        assert_eq!(st.size, pos, "append {i}");
    }
    let r = send(&mut pg, &mut eng, 200, j(vec![OsdOp::read(0, 0)]), None);
    assert_eq!(
        r.ops[0].outdata,
        want[..],
        "full read (read 0,0) = everything incl. the leading hole"
    );
    // writes at an offset beyond the end (journal after trim): size jumps, gap is zeros
    let r = send(
        &mut pg,
        &mut eng,
        201,
        j(vec![OsdOp::write(pos + 5000, vec![9; 10])]),
        None,
    );
    assert_eq!(r.result, 0);
    let r = send(
        &mut pg,
        &mut eng,
        202,
        j(vec![OsdOp::read(pos, 5010)]),
        None,
    );
    assert_eq!(r.ops[0].outdata[..5000], vec![0u8; 5000][..]);
    // purge: delete of a full object, then ENOENT again, then the header-style write_full
    assert_eq!(
        send(&mut pg, &mut eng, 203, j(vec![OsdOp::delete()]), None).result,
        0
    );
    assert_eq!(
        send(&mut pg, &mut eng, 204, j(vec![OsdOp::delete()]), None).result,
        -errno::ENOENT
    );
    assert_eq!(
        send(
            &mut pg,
            &mut eng,
            205,
            mkop(b"200.00000000", vec![OsdOp::writefull(vec![1; 100])]),
            None
        )
        .result,
        0
    );
    let r = send(
        &mut pg,
        &mut eng,
        206,
        mkop(b"200.00000000", vec![OsdOp::read(0, 0)]),
        None,
    );
    assert_eq!(r.ops[0].outdata.len(), 100);
}

// ---------------------------------------------------------------- oversized txn (client-ops s5.4 rule 14b)

#[test]
fn oversized_txn_is_refused_without_log_entry() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    pg.max_txn = Some(200_000);
    // a dirfrag commit batch the store cannot take: ~1 MiB of omap in one message
    let big: std::collections::BTreeMap<Vec<u8>, Vec<u8>> = (0..500u32)
        .map(|i| (format!("f{i:05}_head").into_bytes(), vec![7u8; 2000]))
        .collect();
    let n = pg.entries.len();
    let r = send(
        &mut pg,
        &mut eng,
        1,
        mkop(
            b"10000000000.00000000",
            vec![OsdOp::stat(), OsdOp::omap_set_vals(&big)],
        ),
        None,
    );
    // stat on the missing object aborts first: use create so the batch is really executed
    assert_eq!(r.result, -errno::ENOENT);
    let r = send(
        &mut pg,
        &mut eng,
        2,
        mkop(
            b"10000000000.00000000",
            vec![OsdOp::create(false), OsdOp::omap_set_vals(&big)],
        ),
        None,
    );
    assert_eq!(r.result, -errno::EMSGSIZE, "plain per-message errno");
    assert_eq!(
        pg.entries.len(),
        n + 1,
        "only the ENOENT error entry of step 1, nothing for the refused op"
    );
    assert!(pg.store.objects(pg.spg).is_empty(), "no object, no omap");
    assert!(pg.done.is_empty(), "no txn submitted");
    // the engine is healthy: smaller batches go through, the refused op can be retried smaller
    let small: std::collections::BTreeMap<Vec<u8>, Vec<u8>> = big.into_iter().take(20).collect();
    let r = send(
        &mut pg,
        &mut eng,
        3,
        mkop(
            b"10000000000.00000000",
            vec![OsdOp::create(false), OsdOp::omap_set_vals(&small)],
        ),
        None,
    );
    assert_eq!(r.result, 0);
    // same tid resent after the refusal is answered again (nothing was recorded as a dup)
    let r = send(
        &mut pg,
        &mut eng,
        2,
        mkop(
            b"10000000000.00000000",
            vec![
                OsdOp::create(false),
                OsdOp::omap_set_vals(&{
                    (0..500u32)
                        .map(|i| (format!("f{i:05}_head").into_bytes(), vec![7u8; 2000]))
                        .collect()
                }),
            ],
        ),
        None,
    );
    assert_eq!(r.result, -errno::EMSGSIZE);
}
