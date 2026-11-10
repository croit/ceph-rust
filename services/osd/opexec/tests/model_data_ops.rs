// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Randomized single-op sequences of the data ops (write, writefull, append, writesame, zero, truncate, create,
//! delete) against a plain byte-vector model of the classic semantics (client-ops 7.2); every step compares the
//! op result and the full object (stat size + read) afterwards.
mod common;
use common::*;
use opwire::OsdOp;

const EFBIG: i32 = -27;
const ENOENT: i32 = -2;
const EEXIST: i32 = -17;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

fn exec(pg: &mut TPg, eng: &mut opexec::Engine, tid: u64, ops: Vec<OsdOp>) -> opwire::MOSDOpReply {
    let mut out = run(pg, eng, 1, tid, client(7), mkop(b"model", ops));
    out.extend(settle(pg, eng));
    reply_of(&mut out, 1, tid).expect("reply")
}

fn pattern(rng: &mut Rng, n: usize) -> Vec<u8> {
    (0..n).map(|_| 1 + rng.below(250) as u8).collect()
}

#[test]
fn data_ops_match_the_byte_vector_model() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let mut model: Option<Vec<u8>> = None;
    let mut tid = 0u64;
    for step in 0..3000 {
        tid += 1;
        let name;
        let (op, want): (OsdOp, i32) = match rng.below(9) {
            0 => {
                let off = rng.below(300);
                let n = rng.below(120) as usize;
                let d = pattern(&mut rng, n);
                name = "write";
                let m = model.get_or_insert_with(Vec::new);
                if d.is_empty() {
                    if off as usize > m.len() {
                        m.resize(off as usize, 0);
                    }
                } else {
                    if m.len() < off as usize + d.len() {
                        m.resize(off as usize + d.len(), 0);
                    }
                    m[off as usize..off as usize + d.len()].copy_from_slice(&d);
                }
                (OsdOp::write(off, d), 0)
            }
            1 => {
                let n = rng.below(200) as usize;
                let d = pattern(&mut rng, n);
                name = "writefull";
                model = Some(d.clone());
                (OsdOp::writefull(d), 0)
            }
            2 => {
                let n = rng.below(100) as usize;
                let d = pattern(&mut rng, n);
                name = "append";
                model.get_or_insert_with(Vec::new).extend_from_slice(&d);
                (OsdOp::append(d), 0)
            }
            3 => {
                let off = rng.below(300);
                let dl = 1 + rng.below(8) as usize;
                let len = dl as u64 * rng.below(20);
                let pat = pattern(&mut rng, dl);
                name = "writesame";
                if len > 0 {
                    let m = model.get_or_insert_with(Vec::new);
                    if m.len() < (off + len) as usize {
                        m.resize((off + len) as usize, 0);
                    }
                    for i in 0..len as usize {
                        m[off as usize + i] = pat[i % dl];
                    }
                }
                (OsdOp::writesame(off, len, pat), 0)
            }
            4 => {
                let off = rng.below(350);
                let len = rng.below(150);
                name = "zero";
                if let Some(m) = model.as_mut()
                    && len > 0
                    && (off as usize) < m.len()
                {
                    if off + len >= m.len() as u64 {
                        m.truncate(off as usize);
                    } else {
                        m[off as usize..(off + len) as usize].fill(0);
                    }
                }
                (OsdOp::zero(off, len), 0)
            }
            5 => {
                let n = rng.below(350);
                name = "truncate";
                if let Some(m) = model.as_mut() {
                    m.resize(n as usize, 0);
                }
                (OsdOp::truncate(n), 0)
            }
            6 => {
                let excl = rng.below(2) == 0;
                name = "create";
                if model.is_some() && excl {
                    (OsdOp::create(excl), EEXIST)
                } else {
                    model.get_or_insert_with(Vec::new);
                    (OsdOp::create(excl), 0)
                }
            }
            7 => {
                name = "delete";
                if model.take().is_some() {
                    (OsdOp::delete(), 0)
                } else {
                    (OsdOp::delete(), ENOENT)
                }
            }
            _ => {
                // past the object limit: EFBIG, state untouched
                name = "write-efbig";
                let d = pattern(&mut rng, 4);
                (OsdOp::write(u64::MAX - 1, d), EFBIG)
            }
        };
        let r = exec(&mut pg, &mut eng, tid, vec![op]);
        assert_eq!(r.result, want, "step {step} {name}: result");
        tid += 1;
        let r = exec(
            &mut pg,
            &mut eng,
            tid,
            vec![OsdOp::stat(), OsdOp::read(0, 0)],
        );
        match &model {
            None => assert_eq!(r.result, ENOENT, "step {step} {name}: absent"),
            Some(m) => {
                assert_eq!(r.result, 0, "step {step} {name}: read back");
                let size = u64::from_le_bytes(r.ops[0].outdata[..8].try_into().unwrap());
                assert_eq!(size, m.len() as u64, "step {step} {name}: size");
                assert_eq!(
                    r.ops[1].outdata.as_ref(),
                    m.as_slice(),
                    "step {step} {name}: bytes"
                );
            }
        }
    }
}

fn read_back(pg: &mut TPg, eng: &mut opexec::Engine, tid: u64) -> Option<Vec<u8>> {
    let r = exec(pg, eng, tid, vec![OsdOp::read(0, 0)]);
    (r.result == 0).then(|| r.ops[0].outdata.to_vec())
}

/// A failing op aborts the whole message (nothing of the earlier ops is applied, per-op results keep the prefix),
/// except a FAILOK op, whose failure the message survives.
#[test]
fn compound_messages_are_all_or_nothing_and_failok_continues() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    assert_eq!(
        exec(
            &mut pg,
            &mut eng,
            1,
            vec![OsdOp::writefull(b"base".to_vec())]
        )
        .result,
        0
    );
    let efbig = OsdOp::write(u64::MAX - 1, b"x".to_vec());
    let r = exec(
        &mut pg,
        &mut eng,
        2,
        vec![
            OsdOp::writefull(b"changed".to_vec()),
            OsdOp::setxattr(b"a", b"1"),
            efbig.clone(),
        ],
    );
    assert_eq!(r.result, EFBIG);
    assert_eq!(r.ops[0].rval, 0);
    assert_eq!(r.ops[1].rval, 0);
    assert_eq!(r.ops[2].rval, EFBIG);
    assert_eq!(
        read_back(&mut pg, &mut eng, 3).as_deref(),
        Some(&b"base"[..])
    );
    let r = exec(&mut pg, &mut eng, 4, vec![OsdOp::getxattr(b"a")]);
    assert_eq!(r.result, -61, "attr of the aborted message must not exist");
    // create-excl on the existing object after a truncate: aborted, size unchanged
    let r = exec(
        &mut pg,
        &mut eng,
        5,
        vec![OsdOp::truncate(1), OsdOp::create(true)],
    );
    assert_eq!(r.result, EEXIST);
    assert_eq!(
        read_back(&mut pg, &mut eng, 6).as_deref(),
        Some(&b"base"[..])
    );
    // FAILOK: the failing op reports its error, the message continues and commits the rest
    let mut failok = efbig;
    failok.flags |= opwire::opflag::FAILOK;
    let r = exec(
        &mut pg,
        &mut eng,
        7,
        vec![
            OsdOp::write(0, b"A".to_vec()),
            failok,
            OsdOp::write(2, b"B".to_vec()),
        ],
    );
    assert_eq!(r.result, 0);
    assert_eq!(r.ops[1].rval, EFBIG);
    assert_eq!(r.ops[2].rval, 0);
    assert_eq!(
        read_back(&mut pg, &mut eng, 8).as_deref(),
        Some(&b"AaBe"[..])
    );
}

fn head_of(oid: &[u8]) -> denc::types::Hobject {
    let mut h = denc::types::Hobject::new(
        oid,
        denc::types::SnapId::NOSNAP,
        0x1234_5678,
        POOL as i64,
        b"",
    );
    h.set_key(b"");
    h
}

/// With snapshots in play: every clone keeps the bytes the head had when it was made, and the newest clone's
/// overlap only names ranges where head and clone still agree (recovery copies those ranges from the head).
#[test]
fn clone_overlap_never_names_differing_bytes() {
    use denc::types::SnapId;
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    let mut rng = Rng(0x2545_f491_4f6c_dd1d);
    let mut model: Option<Vec<u8>> = None;
    let mut clones: std::collections::BTreeMap<SnapId, Vec<u8>> = Default::default();
    let (mut seq, mut snaps) = (0u64, Vec::<u64>::new());
    let mut tid = 0u64;
    for step in 0..3000 {
        if rng.below(6) == 0 {
            seq += 1;
            snaps.insert(0, seq);
        }
        let pre = model.clone();
        let op = match rng.below(7) {
            0 => {
                let off = rng.below(300);
                let n = rng.below(120) as usize;
                let d = pattern(&mut rng, n);
                let m = model.get_or_insert_with(Vec::new);
                if d.is_empty() {
                    if off as usize > m.len() {
                        m.resize(off as usize, 0);
                    }
                } else {
                    if m.len() < off as usize + d.len() {
                        m.resize(off as usize + d.len(), 0);
                    }
                    m[off as usize..off as usize + d.len()].copy_from_slice(&d);
                }
                OsdOp::write(off, d)
            }
            1 => {
                let n = rng.below(200) as usize;
                let d = pattern(&mut rng, n);
                model = Some(d.clone());
                OsdOp::writefull(d)
            }
            2 => {
                let n = rng.below(100) as usize;
                let d = pattern(&mut rng, n);
                model.get_or_insert_with(Vec::new).extend_from_slice(&d);
                OsdOp::append(d)
            }
            3 => {
                let off = rng.below(350);
                let len = rng.below(150);
                if let Some(m) = model.as_mut()
                    && len > 0
                    && (off as usize) < m.len()
                {
                    if off + len >= m.len() as u64 {
                        m.truncate(off as usize);
                    } else {
                        m[off as usize..(off + len) as usize].fill(0);
                    }
                }
                OsdOp::zero(off, len)
            }
            4 => {
                let n = rng.below(350);
                if let Some(m) = model.as_mut() {
                    m.resize(n as usize, 0);
                }
                OsdOp::truncate(n)
            }
            5 => {
                if model.take().is_none() {
                    OsdOp::create(false)
                } else {
                    OsdOp::delete()
                }
            }
            _ => {
                let off = rng.below(300);
                let dl = 1 + rng.below(8) as usize;
                let len = dl as u64 * rng.below(20);
                let pat = pattern(&mut rng, dl);
                if len > 0 {
                    let m = model.get_or_insert_with(Vec::new);
                    if m.len() < (off + len) as usize {
                        m.resize((off + len) as usize, 0);
                    }
                    for i in 0..len as usize {
                        m[off as usize + i] = pat[i % dl];
                    }
                }
                OsdOp::writesame(off, len, pat)
            }
        };
        let was_create_noop = op.op == opwire::op::CREATE && pre.is_none();
        if was_create_noop {
            model = Some(Vec::new());
        }
        tid += 1;
        let mut m = mkop(b"model", vec![op]);
        m.snap_seq = seq;
        m.snaps = snaps.clone();
        let mut out = run(&mut pg, &mut eng, 1, tid, client(7), m);
        out.extend(settle(&mut pg, &mut eng));
        let r = reply_of(&mut out, 1, tid).expect("reply");
        assert!(
            r.result == 0 || r.result == ENOENT,
            "step {step}: result {}",
            r.result
        );
        // a delete that answered ENOENT left the model absent already
        let objs = pg.store.objects(pg.spg);
        let ss: Option<replwire::SnapSet> = objs
            .get(&head_of(b"model"))
            .and_then(|o| o.xattrs.get(b"snapset".as_slice()))
            .map(|b| denc::from_slice(b).unwrap());
        if let Some(ss) = ss {
            for c in &ss.clones {
                clones
                    .entry(*c)
                    .or_insert_with(|| pre.clone().unwrap_or_default());
                let mut cid = head_of(b"model");
                cid.snap = *c;
                let got = &objs.get(&cid).expect("clone object").data;
                assert_eq!(got, &clones[c], "step {step}: clone {c:?} content changed");
            }
            if let (Some(last), Some(h)) = (ss.clones.last(), model.as_ref()) {
                let c = &clones[last];
                for (a, l) in &ss.clone_overlap[last] {
                    let (a, l) = (*a as usize, *l as usize);
                    assert!(a + l <= c.len(), "step {step}: overlap past the clone size");
                    assert!(a + l <= h.len(), "step {step}: overlap past the head size");
                    assert_eq!(
                        &h[a..a + l],
                        &c[a..a + l],
                        "step {step}: overlap {a}+{l} differs"
                    );
                }
            }
        }
    }
    assert!(clones.len() > 20, "the run made {} clones", clones.len());
}

/// Payloads classic tolerates: a malformed notify body means default timeout and empty payload, a malformed
/// notify-ack body is the legacy ack, the create category may carry trailing bytes, and omap-cmp on a missing
/// object answers ENOENT before it decodes its payload.
#[test]
fn malformed_payloads_behave_like_classic() {
    let mut pg = TPg::new();
    let mut eng = engine(&pg);
    assert_eq!(
        exec(&mut pg, &mut eng, 1, vec![OsdOp::create(false)]).result,
        0
    );
    let mut notify = OsdOp::notify_op(7, 5, b"p");
    notify.indata = vec![1, 0].into(); // short body
    let r = exec(&mut pg, &mut eng, 2, vec![notify]);
    assert_eq!(r.result, 0, "short notify body");
    assert_eq!(r.ops[0].outdata.len(), 8, "notify id returned");
    let mut notify = OsdOp::notify_op(7, 5, b"p");
    let mut body = notify.indata.to_vec();
    body.extend_from_slice(b"trailing");
    notify.indata = body.into();
    assert_eq!(
        exec(&mut pg, &mut eng, 3, vec![notify]).result,
        0,
        "trailing notify bytes"
    );
    let mut ack = OsdOp::notify_ack(1, 2, b"r");
    ack.indata = vec![9, 9, 9].into();
    assert_eq!(
        exec(&mut pg, &mut eng, 4, vec![ack]).result,
        0,
        "short ack body"
    );
    let mut create = OsdOp::create(false);
    let mut cat = denc::to_vec(&b"cat".to_vec()).unwrap();
    cat.extend_from_slice(b"junk");
    create.indata = cat.into();
    assert_eq!(
        exec(&mut pg, &mut eng, 5, vec![create]).result,
        0,
        "create category with trailing bytes"
    );
    let mut cmp = OsdOp::read(0, 0);
    cmp.op = opwire::op::OMAP_CMP;
    cmp.indata = vec![0xff; 3].into();
    assert_eq!(
        exec(&mut pg, &mut eng, 6, vec![cmp.clone()]).result,
        -22,
        "present object: bad payload"
    );
    let mut m = mkop(b"missing", vec![cmp]);
    m.flags |= opwire::flag::WRITE;
    let mut out = run(&mut pg, &mut eng, 1, 7, client(7), m);
    out.extend(settle(&mut pg, &mut eng));
    assert_eq!(
        reply_of(&mut out, 1, 7).unwrap().result,
        ENOENT,
        "missing object"
    );
}
