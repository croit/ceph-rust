// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Replay of REAL librbd / rbd CLI traffic (testdata/opwire, recorded against a classic OSD 21.1.1
//! cluster, see testdata/opwire/README.md) on `MemStore`. For every scenario the client requests are
//! put in time order (per client by tid; clients by first stream number) and executed on one
//! store; each `lock.*` / `rbd.*` call must return the same rval and (normalized) outdata as the
//! captured reply.
//!
//! Known gaps in the capture (streams > 200 KB were dropped, e.g. bulk `rbd bench` writes): object
//! map updates / data-object writes of dropped streams are missing, so affected getters after them
//! can differ. Those are listed in `KNOWN_GAPS` with the reason.
mod common;
use cls::mem::{MemCtx, MemStore};
use cls::registry;
use common::{mask_lock, norm_bytes};
use messages::Header2;
use msgr2::{Banner, Decoder as FrameDecoder};
use opwire::consts::{op as code, opflag};
use opwire::{ClientMsg, MOSDOp, MOSDOpReply, decode_client_parts};
use std::collections::BTreeMap;
use std::path::PathBuf;

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../testdata/opwire")
}

type Frame = (Header2, Vec<u8>, Vec<u8>, Vec<u8>);

fn frames(stream: &[u8]) -> Option<Vec<Frame>> {
    let (b, n) = Banner::parse(stream).ok()??;
    let mut d = FrameDecoder::new(b.revision());
    d.feed(&stream[n..]);
    let mut out = Vec::new();
    loop {
        match d.poll() {
            Ok(Some(f)) => {
                if f.tag != 17 {
                    continue;
                }
                let h = Header2::parse(f.segment(0)).ok()?;
                out.push((
                    h,
                    f.segment(1).to_vec(),
                    f.segment(2).to_vec(),
                    f.segment(3).to_vec(),
                ));
            }
            Ok(None) => break,
            Err(_) => return None,
        }
    }
    Some(out)
}

/// One request with its captured reply.
struct Exchange {
    stream: u32,
    tid: u64,
    /// Synthetic client (CLI process) index: streams are grouped by non-colliding tids.
    client: i64,
    req: MOSDOp,
    rep: MOSDOpReply,
}

/// All exchanges of a scenario in replay order.
fn scenario(prefix: &str) -> Vec<Exchange> {
    let mut files: Vec<(u32, PathBuf)> = std::fs::read_dir(dir())
        .unwrap()
        .filter_map(|e| {
            let p = e.ok()?.path();
            let n = p.file_name()?.to_string_lossy().into_owned();
            let rest = n.strip_prefix(prefix)?.strip_prefix("-s")?;
            let num = rest.strip_suffix("-c2s.bin")?;
            Some((num.parse().ok()?, p))
        })
        .collect();
    files.sort();
    // per stream exchanges
    type StreamEx = (u32, Vec<(u64, MOSDOp, MOSDOpReply)>);
    let mut streams: Vec<StreamEx> = Vec::new();
    for (num, c2s) in files {
        let s2c = PathBuf::from(c2s.to_string_lossy().replace("-c2s.bin", "-s2c.bin"));
        let (Some(req), Some(rep)) = (
            frames(&std::fs::read(&c2s).unwrap()),
            std::fs::read(&s2c).ok().and_then(|b| frames(&b)),
        ) else {
            continue;
        };
        let mut replies: BTreeMap<u64, MOSDOpReply> = BTreeMap::new();
        for (h, f, m, d) in &rep {
            if h.ty == 43
                && let Ok(ClientMsg::OpReply(r)) = decode_client_parts(h.ty, h.version, f, m, d)
            {
                replies.entry(h.tid).or_insert(r);
            }
        }
        let mut v = Vec::new();
        for (h, f, m, d) in &req {
            if h.ty != 42 {
                continue;
            }
            let Ok(ClientMsg::Op(o)) = decode_client_parts(h.ty, h.version, f, m, d) else {
                continue;
            };
            let Some(r) = replies.get(&h.tid) else {
                continue;
            };
            v.push((h.tid, o, r.clone()));
        }
        streams.push((num, v));
    }
    // group streams into client processes: a stream joins the current process unless its tids collide
    let mut procs: Vec<(std::collections::BTreeSet<u64>, Vec<Exchange>)> = Vec::new();
    for (num, v) in streams {
        let collide = procs
            .last()
            .is_none_or(|(t, _)| v.iter().any(|(tid, ..)| t.contains(tid)));
        if collide {
            procs.push((Default::default(), Vec::new()));
        }
        let idx = procs.len() as i64;
        let (t, ex) = procs.last_mut().unwrap();
        for (tid, o, r) in v {
            t.insert(tid);
            ex.push(Exchange {
                stream: num,
                client: idx,
                tid,
                req: o,
                rep: r,
            });
        }
    }
    let mut out = Vec::new();
    for (_, mut ex) in procs {
        ex.sort_by_key(|e| e.tid);
        out.extend(ex);
    }
    out
}

fn is_data_obj(oid: &[u8]) -> bool {
    oid.starts_with(b"rbd_data.")
}

struct Result_ {
    result: i32,
    ops: Vec<(i32, Vec<u8>)>,
}

/// Execute the state-relevant ops of one message; unsupported ops are ignored (no state effect that
/// matters for cls methods) except that they make `exact` false.
fn exec(store: &mut MemStore, key: &str, m: &MOSDOp) -> (Result_, bool) {
    let mut c: MemCtx = store.begin(key);
    let mut exact = true;
    let mut ops = Vec::new();
    let mut result = 0;
    for o in &m.ops {
        let (rv, out): (i32, Vec<u8>) = match o.op {
            code::CALL => match o.cls_call() {
                Ok(cc) => {
                    let r = c.call(
                        &String::from_utf8_lossy(cc.class),
                        &String::from_utf8_lossy(cc.method),
                        cc.input,
                    );
                    (r.ret, r.out)
                }
                Err(_) => (-22, vec![]),
            },
            code::CREATE => match cls::ClsCtx::create(&mut c, o.flags & opflag::EXCL != 0) {
                Ok(()) => (0, vec![]),
                Err(e) => (e, vec![]),
            },
            code::STAT => match cls::ClsCtx::stat(&mut c) {
                Ok(_) => (0, vec![]),
                Err(e) => (e, vec![]),
            },
            code::READ | code::SPARSE_READ | code::SYNC_READ => {
                match cls::ClsCtx::read(&mut c, 0, 1) {
                    Ok(_) => (0, vec![]),
                    Err(e) => (e, vec![]),
                }
            }
            code::WRITE => {
                let off = o.extent().offset;
                (
                    cls::ClsCtx::write(&mut c, off, &o.indata)
                        .err()
                        .unwrap_or(0),
                    vec![],
                )
            }
            code::WRITEFULL => (
                cls::ClsCtx::write_full(&mut c, &o.indata)
                    .err()
                    .unwrap_or(0),
                vec![],
            ),
            code::APPEND => {
                let sz = cls::ClsCtx::stat(&mut c).map_or(0, |s| s.size);
                (
                    cls::ClsCtx::write(&mut c, sz, &o.indata).err().unwrap_or(0),
                    vec![],
                )
            }
            code::TRUNCATE => {
                let sz = o.extent().offset;
                (cls::ClsCtx::truncate(&mut c, sz).err().unwrap_or(0), vec![])
            }
            code::DELETE => (cls::ClsCtx::remove(&mut c).err().unwrap_or(0), vec![]),
            code::SETXATTR => match o.xattr_name_value() {
                Ok((n, v)) => (
                    cls::ClsCtx::setxattr(&mut c, &String::from_utf8_lossy(n), v)
                        .err()
                        .unwrap_or(0),
                    vec![],
                ),
                Err(_) => (-22, vec![]),
            },
            code::OMAP_SET_VALS => match o.indata_as::<BTreeMap<Vec<u8>, Vec<u8>>>() {
                Ok(mm) => {
                    let e: Vec<(&[u8], &[u8])> = mm
                        .iter()
                        .map(|(k, v)| (k.as_slice(), v.as_slice()))
                        .collect();
                    (cls::ClsCtx::omap_set(&mut c, &e).err().unwrap_or(0), vec![])
                }
                Err(_) => (-22, vec![]),
            },
            code::OMAP_SET_HEADER => (
                cls::ClsCtx::omap_set_header(&mut c, &o.indata)
                    .err()
                    .unwrap_or(0),
                vec![],
            ),
            code::OMAP_CLEAR => (cls::ClsCtx::omap_clear(&mut c).err().unwrap_or(0), vec![]),
            code::OMAP_RM_KEYS => match o.indata_as::<std::collections::BTreeSet<Vec<u8>>>() {
                Ok(ks) => {
                    let mut r = 0;
                    for k in ks {
                        r = cls::ClsCtx::omap_remove_key(&mut c, &k).err().unwrap_or(r);
                    }
                    (r, vec![])
                }
                Err(_) => (-22, vec![]),
            },
            code::SET_ALLOC_HINT => (
                cls::ClsCtx::create(&mut c, false).err().unwrap_or(0),
                vec![],
            ),
            code::WRITESAME => {
                let w = o.write_same();
                let pat = &o.indata;
                let mut buf = Vec::with_capacity(w.length as usize);
                while (buf.len() as u64) < w.length && !pat.is_empty() {
                    buf.extend_from_slice(pat);
                }
                buf.truncate(w.length as usize);
                (
                    cls::ClsCtx::write(&mut c, w.offset, &buf)
                        .err()
                        .unwrap_or(0),
                    vec![],
                )
            }
            // pure reads / notifications without effect on the object state we model
            code::GETXATTR
            | code::GETXATTRS
            | code::OMAP_GET_KEYS
            | code::OMAP_GET_VALS
            | code::OMAP_GET_HEADER
            | code::OMAP_GET_VALS_BY_KEYS
            | code::LIST_WATCHERS
            | code::LIST_SNAPS
            | code::WATCH
            | code::NOTIFY
            | code::NOTIFY_ACK => (0, vec![]),
            _ => {
                exact = false;
                (0, vec![])
            }
        };
        ops.push((rv, out));
        if rv < 0 {
            result = rv;
            break;
        }
    }
    if result >= 0 {
        if c.changed() && m.flags & opwire::consts::flag::RETURNVEC == 0 {
            ops.iter_mut().for_each(|o| o.1.clear());
        }
        store.commit(key, c);
    }
    (Result_ { result, ops }, exact)
}

/// State that existed in the lab pool before the capture started (`rbd_mirroring` did NOT exist): the
/// pool-level objects created by earlier runs and the image `test` (id 102f7874fae0) visible in the directory listings.
fn seed(store: &mut MemStore, pool: i64) {
    for o in ["rbd_info", "rbd_trash", "rbd_children"] {
        store.msg(&format!("{pool}//{o}"), |c| {
            (cls::ClsCtx::create(c, false).map_or(-1, |_| 0), ())
        });
    }
    let d = format!("{pool}//rbd_directory");
    let arg = |a: &str, b: &str| {
        [a, b]
            .iter()
            .flat_map(|s| denc::Encode::encode_to_vec(*s).unwrap())
            .collect::<Vec<u8>>()
    };
    let r = store.call(&d, "rbd", "dir_add_image", &arg("test", "102f7874fae0"));
    assert_eq!(r.ret, 0);
}

fn replay(prefix: &str) -> (Vec<String>, usize) {
    let mut store = MemStore::new();
    let mut seeded = false;
    let mut bad = Vec::new();
    let mut compared = 0;
    for ex in scenario(prefix) {
        let m = &ex.req;
        if m.mtime.sec != 0 {
            store.env.now = m.mtime;
        }
        store.env.origin.name = denc::types::EntityName::client(ex.client);
        if !seeded {
            seed(&mut store, m.oloc.pool);
            seeded = true;
        }
        let key = format!(
            "{}/{}/{}",
            m.oloc.pool,
            String::from_utf8_lossy(&m.oloc.nspace),
            String::from_utf8_lossy(&m.oid)
        );
        if is_data_obj(&m.oid) && !m.ops.iter().any(|o| o.op == code::CALL) {
            // plain data traffic: only its existence matters; replay cheaply
        }
        let has_call = m.ops.iter().any(|o| o.op == code::CALL);
        // rule #24: a message without any write op on an absent object fails ENOENT before any op runs
        if !store.objects.contains_key(&key) && !m.ops.iter().any(is_write_op) {
            if has_call && ex.rep.result != -2 {
                bad.push(format!(
                    "{prefix}-s{} tid {}: object {} absent in replay, captured result {}",
                    ex.stream,
                    ex.tid,
                    String::from_utf8_lossy(&m.oid),
                    ex.rep.result
                ));
            }
            continue;
        }
        let (got, exact) = exec(&mut store, &key, m);
        if !has_call {
            continue;
        }
        let center = store.env.now.sec;
        let want = &ex.rep;
        let calls: Vec<String> = m
            .ops
            .iter()
            .filter(|o| o.op == code::CALL)
            .filter_map(|o| o.cls_call().ok())
            .map(|c| {
                format!(
                    "{}.{}",
                    String::from_utf8_lossy(c.class),
                    String::from_utf8_lossy(c.method)
                )
            })
            .collect();
        let tag = format!(
            "{prefix}-s{} tid {} {} on {}",
            ex.stream,
            ex.tid,
            calls.join("+"),
            String::from_utf8_lossy(&m.oid)
        );
        if want.result != got.result && exact {
            bad.push(format!(
                "{tag}: result got {} want {}",
                got.result, want.result
            ));
            continue;
        }
        for (i, o) in m.ops.iter().enumerate() {
            if o.op != code::CALL {
                continue;
            }
            let (Some(g), Some(w)) = (got.ops.get(i), want.ops.get(i)) else {
                continue;
            };
            compared += 1;
            let cc = o.cls_call().unwrap();
            let fix = |b: &[u8]| {
                let b = if cc.class == b"lock" && cc.method == b"get_info" {
                    mask_lock(b)
                } else {
                    b.to_vec()
                };
                norm_bytes(&b, center)
            };
            if g.0 != w.rval || fix(&g.1) != fix(&w.outdata) {
                bad.push(format!(
                    "{tag} op {i}: rval got {} want {}; out got {}B want {}B\n    got  {}\n    want {}",
                    g.0,
                    w.rval,
                    g.1.len(),
                    w.outdata.len(),
                    hex(&fix(&g.1)),
                    hex(&fix(&w.outdata))
                ));
            }
        }
    }
    (bad, compared)
}

fn hex(b: &[u8]) -> String {
    b.iter().take(120).map(|c| format!("{c:02x}")).collect()
}

#[test]
fn registry_covers_every_captured_call() {
    let mut missing = std::collections::BTreeSet::new();
    let mut total = 0;
    for p in [
        "rbd-basic",
        "rbd-clone",
        "rbd-thick",
        "rbd-watch",
        "rados-basic",
        "rados-misc",
        "rados-watch",
    ] {
        for ex in scenario(p) {
            for o in ex.req.ops.iter().filter(|o| o.op == code::CALL) {
                if let Ok(c) = o.cls_call() {
                    total += 1;
                    let (cl, me) = (
                        String::from_utf8_lossy(c.class),
                        String::from_utf8_lossy(c.method),
                    );
                    if registry::lookup(&cl, &me).is_none() {
                        missing.insert(format!("{cl}.{me}"));
                    }
                }
            }
        }
    }
    eprintln!("captured calls: {total}");
    assert!(total > 500);
    assert!(
        missing.is_empty(),
        "captured calls missing from the registry: {missing:?}"
    );
}

/// Mismatches explained by the capture gaps (see module docs): (tag prefix, reason).
const KNOWN_GAPS: &[(&str, &str)] = &[
    (
        "rbd-clone-s9 tid 16 ",
        "object map bits set by dropped bench stream",
    ),
    (
        "rbd-clone-s59 tid 17 ",
        "object map bits set by dropped bench stream",
    ),
    (
        "rbd-clone-s62 tid 17 ",
        "object map bits set by dropped bench stream",
    ),
    (
        "rbd-clone-s62 tid 43 ",
        "object map bits set by dropped bench stream",
    ),
    (
        "rbd-clone-s62 tid 73 ",
        "object map bits set by dropped bench stream",
    ),
    (
        "rbd-clone-s26 tid 7 ",
        "exclusive lock taken in a dropped stream",
    ),
    (
        "rbd-clone-s26 tid 25 ",
        "exclusive lock taken in a dropped stream",
    ),
    (
        "rbd-thick-s39 ",
        "image created by the dropped `rbd import` stream",
    ),
];

#[test]
fn replay_captured_scenarios() {
    let mut all_bad = Vec::new();
    let mut compared = 0;
    for p in ["rbd-basic", "rbd-clone", "rbd-thick", "rados-basic"] {
        let (bad, n) = replay(p);
        compared += n;
        all_bad.extend(bad);
    }
    let (known, unexplained): (Vec<_>, Vec<_>) = all_bad
        .iter()
        .partition(|b| KNOWN_GAPS.iter().any(|(t, _)| b.starts_with(t)));
    eprintln!(
        "replayed captured librbd calls: {compared} compared, {} known-gap mismatches, {} unexplained",
        known.len(),
        unexplained.len()
    );
    for (t, why) in KNOWN_GAPS {
        assert!(
            known.iter().any(|b| b.starts_with(t)),
            "stale KNOWN_GAPS entry {t} ({why})"
        );
    }
    assert!(compared > 1500, "too few compared calls: {compared}");
    assert!(
        unexplained.is_empty(),
        "{} unexplained mismatches vs captured librbd traffic:\n{}",
        unexplained.len(),
        unexplained
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    );
}

fn is_write_op(o: &opwire::OsdOp) -> bool {
    match o.op {
        code::CALL => o
            .cls_call()
            .ok()
            .and_then(|c| {
                registry::lookup(
                    &String::from_utf8_lossy(c.class),
                    &String::from_utf8_lossy(c.method),
                )
            })
            .is_none_or(|m| m.wr()),
        x => x & code::MODE_WR != 0,
    }
}
