// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! `oprobe hash`: per-object content hash + one cross-cluster comparable combined digest, parallel reads, no temp files.

use crate::client::{Opts, Probe, Target};
use crate::omapbench::{flag, num, secs, take, target};
use crate::script::ScriptMsg;
use hashsum::{Alg, Hasher};
use opwire::OsdOp;
use std::collections::VecDeque;
use std::process::ExitCode;
use std::time::{Duration, Instant};

pub const HELP: &str = "\
hash -p POOL [--prefix S] [--names FILE|-] [--image IMG] [options]
  object set: default = all objects of the pool (pgnls, default namespace; --prefix S keeps names starting with S);
              --names FILE|-  = one object name per line;  --image IMG = the RBD image's data objects (rbd_id/header lookup),
              named by object number (rbd-obj-<16 hex>) so two clusters compare equal; absent (sparse) objects are skipped.
  --alg blake3|xxh3 (per-object hash; default blake3 = hashsum::DEFAULT)  --clients N (4)  --qd N (16)  --chunk BYTES (4194304)
  --op-timeout S (60)  --quiet (combined line only)  --format plain|json|json-pretty
output plain: '<hex>  <name>' per object (sorted by name, escaped like b3sum), then
  'combined <hex> objects=N bytes=B alg=A missing=M secs=S'; combined = BLAKE3 over, sorted by name
  (ties by data length, then digest), (u32le len(name), name, u64le len(data), u8 len(digest), per-object digest).
output json: one object {combined, objects, bytes, alg, missing, secs, errors, hashes[] {name, bytes, digest}}. rc 0 ok, 1 read errors.
";

const PAGE: u64 = 1000;

type Item = (String, u64, Vec<u8>);

struct Cfg {
    pool: String,
    alg: Alg,
    chunk: usize,
    qd: usize,
    timeout: Duration,
}

fn ok_reply(d: &crate::client::Done) -> Result<&opwire::MOSDOpReply, String> {
    let r = d.reply.as_ref().ok_or_else(|| d.err.clone())?;
    let rv = r.ops.first().map_or(0, |o| o.rval);
    let res = if r.result < 0 { r.result } else { rv };
    if res < 0 {
        return Err(format!("errno {res}"));
    }
    Ok(r)
}

/// One synchronous compound op; returns the outdata of op `i`.
fn run1(p: &mut Probe, t: &Target, ops: Vec<OsdOp>, i: usize) -> Result<Vec<u8>, String> {
    run1r(p, t, ops, i).map(|x| x.1)
}

/// [`run1`] plus the message result (pgnls: 1 = PG exhausted).
fn run1r(p: &mut Probe, t: &Target, ops: Vec<OsdOp>, i: usize) -> Result<(i32, Vec<u8>), String> {
    let o = p.exec(
        t,
        &ScriptMsg {
            ops,
            ..Default::default()
        },
    )?;
    let r = o.reply.ok_or(o.note)?;
    let rv = r.ops.get(i).map_or(0, |x| x.rval);
    let res = if r.result < 0 { r.result } else { rv };
    if res < 0 {
        return Err(format!("errno {res}"));
    }
    Ok((
        r.result,
        r.ops.get(i).map(|x| x.outdata.to_vec()).unwrap_or_default(),
    ))
}

fn list_pool(p: &mut Probe, pool: i64, prefix: &str) -> Result<Vec<String>, String> {
    let pg_num = p.osdmap().pool(pool).ok_or("pool vanished")?.pg_num;
    let mut names = Vec::new();
    for seed in 0..pg_num {
        p.pg_override = Some(seed);
        let mut cursor = denc::types::Hobject::MIN();
        loop {
            let out = run1r(p, &target(pool, ""), vec![OsdOp::pgnls(PAGE, &cursor)], 0);
            let (res, out) = match out {
                Ok(o) => o,
                Err(e) => {
                    p.pg_override = None;
                    return Err(format!("pgnls pg {pool}.{seed:x}: {e}"));
                }
            };
            let r: opwire::PgNlsResponse =
                denc::from_slice(&out).map_err(|e| format!("pgnls decode: {e:?}"))?;
            names.extend(
                r.entries
                    .iter()
                    .filter_map(|e| String::from_utf8(e.oid.clone()).ok())
                    .filter(|n| n.starts_with(prefix)),
            );
            // result 1 = PG exhausted (the handle then points past the PG: do not request it)
            if res == 1 || r.handle.max || r.entries.is_empty() {
                break;
            }
            cursor = r.handle;
        }
    }
    p.pg_override = None;
    Ok(names)
}

/// RBD image object orders 12..=25 (4 KiB .. 32 MiB): `rbd get_size` reports the image's object order
/// (doc/spec/cls_rbd.md A.2: `order`, object size = 1<<order, default 22), and only an order in this range can
/// describe an RBD image. A corrupt header must fail here, not read one object per image byte.
const RBD_MIN_ORDER: u8 = 12;
const RBD_MAX_ORDER: u8 = 25;

/// Object size of the `rbd get_size` order byte, refused outside the RBD object orders.
fn rbd_object_size(order: u8) -> Result<u64, String> {
    if !(RBD_MIN_ORDER..=RBD_MAX_ORDER).contains(&order) {
        return Err(format!(
            "rbd get_size: object order {order} outside {RBD_MIN_ORDER}..={RBD_MAX_ORDER}"
        ));
    }
    Ok(1u64 << order)
}

/// (object-name prefix "rbd_data.<id>", object size, image size) of an RBD image.
fn image_info(p: &mut Probe, pool: i64, img: &str) -> Result<(String, u64, u64), String> {
    let idb = run1(
        p,
        &target(pool, &format!("rbd_id.{img}")),
        vec![OsdOp::read(0, 4096)],
        0,
    )
    .map_err(|e| format!("rbd_id.{img}: {e}"))?;
    let id = denc::from_slice::<String>(&idb).map_err(|e| format!("rbd_id decode: {e:?}"))?;
    let hdr = target(pool, &format!("rbd_header.{id}"));
    let nosnap = opwire::NOSNAP.to_le_bytes();
    let sz = run1(p, &hdr, vec![OsdOp::call(b"rbd", b"get_size", &nosnap)], 0)?;
    if sz.len() < 9 {
        return Err("short get_size reply".into());
    }
    let order = sz[0];
    let osz = rbd_object_size(order)?;
    let size = u64::from_le_bytes(sz[1..9].try_into().expect("8"));
    let pre = run1(
        p,
        &hdr,
        vec![OsdOp::call(b"rbd", b"get_object_prefix", b"")],
        0,
    )?;
    let prefix = denc::from_slice::<String>(&pre).map_err(|e| format!("prefix decode: {e:?}"))?;
    Ok((prefix, osz, size))
}

struct Slot {
    name: String,
    wire: String,
    off: u64,
    h: Hasher,
}

/// Read + hash `work` = (display name, wire name); returns (items, missing, errors).
fn worker(
    o: Opts,
    c: &Cfg,
    work: Vec<(String, String)>,
) -> Result<(Vec<Item>, u64, Vec<String>), String> {
    let mut o = o;
    o.timeout = c.timeout;
    let mut p = Probe::connect(o)?;
    p.idle_sleep = Duration::from_micros(100);
    let pool = p
        .osdmap()
        .pool_id_by_name(&c.pool)
        .ok_or_else(|| format!("no pool '{}'", c.pool))?;
    let mut todo: VecDeque<(String, String)> = work.into();
    let mut slots: Vec<Option<Slot>> = Vec::new();
    let (mut items, mut missing, mut errs) = (Vec::new(), 0u64, Vec::new());
    let submit = |p: &mut Probe, s: &Slot, tag: u64| {
        let m = ScriptMsg {
            ops: vec![OsdOp::read(s.off, c.chunk as u64)],
            ..Default::default()
        };
        p.submit(target(pool, &s.wire), m, tag)
    };
    loop {
        while p.in_flight() < c.qd && !todo.is_empty() {
            let (name, wire) = todo.pop_front().expect("nonempty");
            let s = Slot {
                name,
                wire,
                off: 0,
                h: Hasher::new(c.alg),
            };
            let tag = slots.iter().position(Option::is_none).unwrap_or_else(|| {
                slots.push(None);
                slots.len() - 1
            });
            match submit(&mut p, &s, tag as u64) {
                Ok(()) => slots[tag] = Some(s),
                Err(e) => errs.push(format!("{}: {e}", s.name)),
            }
        }
        if p.in_flight() == 0 {
            break;
        }
        for d in p.poll() {
            let tag = d.tag as usize;
            let Some(mut s) = slots[tag].take() else {
                continue;
            };
            let r = match ok_reply(&d) {
                Ok(r) => r,
                Err(e) if e == "errno -2" && s.off == 0 => {
                    missing += 1;
                    continue;
                }
                Err(e) => {
                    errs.push(format!("{}: {e}", s.name));
                    continue;
                }
            };
            let data = r.ops.first().map(|x| &x.outdata[..]).unwrap_or_default();
            s.h.update(data);
            s.off += data.len() as u64;
            if data.len() < c.chunk {
                items.push((s.name, s.off, s.h.finish()));
            } else {
                match submit(&mut p, &s, tag as u64) {
                    Ok(()) => slots[tag] = Some(s),
                    Err(e) => errs.push(format!("{}: {e}", s.name)),
                }
            }
        }
    }
    Ok((items, missing, errs))
}

pub fn cli(a: Vec<String>, o: Opts, pool: Option<String>) -> Result<ExitCode, String> {
    let (fmt, mut a) = outfmt::extract(&a, false)?;
    let pool_name = pool.ok_or("hash: -p POOL required")?;
    let alg = match take(&mut a, "--alg")? {
        None => hashsum::DEFAULT,
        Some(s) => Alg::parse(&s).ok_or_else(|| format!("bad --alg '{s}'"))?,
    };
    let clients: usize = num(&mut a, "--clients", 4usize)?.max(1);
    let c = Cfg {
        pool: pool_name.clone(),
        alg,
        chunk: num(&mut a, "--chunk", 4usize << 20)?.max(4096),
        qd: num(&mut a, "--qd", 16usize)?.max(1),
        timeout: secs(&mut a, "--op-timeout", 60.0)?,
    };
    let prefix = take(&mut a, "--prefix")?.unwrap_or_default();
    let names_src = take(&mut a, "--names")?;
    let image = take(&mut a, "--image")?;
    let quiet = flag(&mut a, "--quiet");
    if !a.is_empty() {
        return Err(format!("hash: unknown args {a:?}\n{HELP}"));
    }
    let t0 = Instant::now();
    let mut p = Probe::connect(o.clone())?;
    let pool = p
        .osdmap()
        .pool_id_by_name(&pool_name)
        .ok_or_else(|| format!("no pool '{pool_name}'"))?;
    let work: Vec<(String, String)> = if let Some(img) = image {
        let (pre, osz, size) = image_info(&mut p, pool, &img)?;
        (0..size.div_ceil(osz))
            .map(|n| (format!("rbd-obj-{n:016x}"), format!("{pre}.{n:016x}")))
            .collect()
    } else if let Some(src) = names_src {
        let text = if src == "-" {
            std::io::read_to_string(std::io::stdin()).map_err(|e| e.to_string())?
        } else {
            std::fs::read_to_string(&src).map_err(|e| format!("{src}: {e}"))?
        };
        text.lines()
            .filter(|l| !l.is_empty())
            .map(|l| (l.to_string(), l.to_string()))
            .collect()
    } else {
        list_pool(&mut p, pool, &prefix)?
            .into_iter()
            .map(|n| (n.clone(), n))
            .collect()
    };
    drop(p);
    let mut parts: Vec<Vec<(String, String)>> = vec![Vec::new(); clients];
    for (i, w) in work.into_iter().enumerate() {
        parts[i % clients].push(w);
    }
    let c = std::sync::Arc::new(c);
    let hs: Vec<_> = parts
        .into_iter()
        .filter(|w| !w.is_empty())
        .map(|w| {
            let (o, c) = (o.clone(), c.clone());
            std::thread::spawn(move || worker(o, &c, w))
        })
        .collect();
    let (mut items, mut missing, mut errs) = (Vec::new(), 0u64, Vec::new());
    for h in hs {
        let (i, m, e) = h.join().map_err(|_| "hash: worker panicked")??;
        items.extend(i);
        missing += m;
        errs.extend(e);
    }
    let combined = hashsum::combine(&mut items).map_err(|e| format!("hash: {e}"))?; // sorts
    let bytes: u64 = items.iter().map(|i| i.1).sum();
    let elapsed_s = t0.elapsed().as_secs_f64();
    for e in &errs {
        eprintln!("oprobe hash: {e}");
    }
    if fmt == outfmt::Format::Plain {
        if !quiet {
            for (n, _, d) in &items {
                println!("{}", hashsum::line(&hashsum::hex(d), n));
            }
        }
        println!(
            "combined {combined} objects={} bytes={bytes} alg={} missing={missing} secs={elapsed_s:.1}",
            items.len(),
            alg.name(),
        );
    } else {
        let mut doc = serde_json::json!({
            "combined": combined, "objects": items.len(), "bytes": bytes, "alg": alg.name(),
            "missing": missing, "secs": elapsed_s, "errors": errs,
        });
        if !quiet {
            doc["hashes"] = items
                .iter()
                .map(|(n, len, d)| {
                    serde_json::json!({
                        "name": n, "bytes": len, "digest": hashsum::hex(d),
                    })
                })
                .collect();
        }
        println!("{}", fmt.doc(&doc));
    }
    Ok(if errs.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn combined_is_deterministic_across_workers() {
        let mk = |n: &str, d: &[u8]| -> Item {
            (n.into(), d.len() as u64, hashsum::digest(Alg::Xxh3, d))
        };
        let mut a = vec![mk("o2", b"two"), mk("o1", b"one"), mk("o3", b"")];
        let mut b = vec![mk("o3", b""), mk("o1", b"one"), mk("o2", b"two")];
        assert_eq!(
            hashsum::combine(&mut a).unwrap(),
            hashsum::combine(&mut b).unwrap()
        );
        assert_eq!(a, b); // sorted by name
    }

    #[test]
    fn rbd_object_order_is_bounded() {
        assert_eq!(rbd_object_size(12).unwrap(), 4096);
        assert_eq!(rbd_object_size(22).unwrap(), 4 << 20);
        assert_eq!(rbd_object_size(25).unwrap(), 32 << 20);
        for order in [0, 11, 26, 63, 64, u8::MAX] {
            assert!(rbd_object_size(order).is_err(), "order {order}");
        }
    }
}

#[cfg(test)]
mod wire_tests {
    use opwire::{ClientMsg, MOSDOp, OsdOp};

    /// The pgnls request survives the wire: snapid, cursor, count.
    #[test]
    fn pgnls_roundtrip() {
        let m = MOSDOp {
            ops: vec![OsdOp::pgnls(1000, &denc::types::Hobject::MIN())],
            snapid: opwire::NOSNAP,
            ..Default::default()
        };
        let (t, v, _c, segs) = ClientMsg::Op(m).encode(!0).unwrap();
        let ClientMsg::Op(d) = opwire::decode_client(t, v, &segs).unwrap() else {
            panic!()
        };
        assert_eq!(d.snapid, opwire::NOSNAP);
        assert_eq!(d.ops[0].pgls().count, 1000);
        assert_eq!(
            opwire::pgls_cursor(&d.ops[0].indata).unwrap(),
            denc::types::Hobject::MIN()
        );
    }
}
