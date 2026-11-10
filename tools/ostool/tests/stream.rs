// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Results are streamed: `--op list`, `get-bytes` and `export` must not hold the whole result in memory. The
//! observable is the peak of live heap bytes above one whole-result block (`BIG`): a listing string, the object
//! buffer, the encoder copy. One test, so the process-wide counter is not shared with a parallel test.
mod common;
use common::*;
use denc::types::{CollT, Eversion, SnapId};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use store::obj::OTxn;

/// Smallest block the counter tracks: the paths under test buffer a whole result in one block of at least this
/// size (a listing string, the whole object, the encoder copy), while a streamed result is one 8 MiB read chunk.
/// Smaller blocks are not tracked, so a block the runtime frees without the counter having seen it cannot skew
/// the figure.
const BIG: usize = 1 << 20;

struct Peak;

/// Live bytes of tracked blocks (never wraps: a counter imbalance can only lose bytes, not invent them).
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn add(n: usize) {
    if n >= BIG {
        let v = LIVE.fetch_add(n, Relaxed).saturating_add(n);
        PEAK.fetch_max(v, Relaxed);
    }
}

fn sub(n: usize) {
    if n >= BIG {
        let _ = LIVE.try_update(Relaxed, Relaxed, |v| Some(v.saturating_sub(n)));
    }
}

unsafe impl GlobalAlloc for Peak {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(l) };
        if !p.is_null() {
            add(l.size());
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        sub(l.size());
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, new: usize) -> *mut u8 {
        let q = unsafe { System.realloc(p, l, new) };
        if !q.is_null() {
            sub(l.size());
            add(new);
        }
        q
    }
}

#[global_allocator]
static ALLOC: Peak = Peak;

/// Peak tracked live heap bytes while `f` runs.
fn peak(f: impl FnOnce()) -> usize {
    let base = LIVE.load(Relaxed);
    PEAK.store(base, Relaxed);
    f();
    PEAK.load(Relaxed) - base
}

/// One object of `n` bytes, written in 1 MiB txns.
fn big_object(r: &Rig, s: denc::types::SpgT, name: &str, n: usize) {
    let cid = CollT::Pg(s);
    let h = hobj(s, name, SnapId::NOSNAP);
    let g = gh(s, &h);
    let oi = oi_bytes(&h, Eversion::new(3, 30), n as u64);
    let ss = denc::to_vec(&replwire::SnapSet::default()).unwrap();
    let mut t = OTxn::new();
    t.sys = true;
    t.touch(cid, &g);
    t.setattr(cid, &g, b"_", &oi);
    t.setattr(cid, &g, b"snapset", &ss);
    r.ad.with_store(|st| st.commit(&t)).unwrap();
    let data = pattern(1 << 20, 5);
    for off in (0..n).step_by(1 << 20) {
        let n = (n - off).min(1 << 20);
        let mut t = OTxn::new();
        t.sys = true;
        t.write(cid, &g, off as u64, &data[..n]);
        r.ad.with_store(|st| st.commit(&t)).unwrap();
    }
}

/// `n` small objects, committed in batches (a listing of a PG that is much bigger than one output buffer).
fn many_objects(r: &Rig, s: denc::types::SpgT, n: usize) {
    let cid = CollT::Pg(s);
    let ss = denc::to_vec(&replwire::SnapSet::default()).unwrap();
    for lo in (0..n).step_by(100) {
        let objs: Vec<(denc::types::Ghobject, Vec<u8>)> = (lo..(lo + 100).min(n))
            .map(|i| {
                let h = hobj(s, &format!("obj{i:06}"), SnapId::NOSNAP);
                (gh(s, &h), oi_bytes(&h, Eversion::new(3, 40), 1))
            })
            .collect();
        let mut t = OTxn::new();
        t.sys = true;
        for (g, oi) in &objs {
            t.touch(cid, g);
            t.write(cid, g, 0, b"x");
            t.setattr(cid, g, b"_", oi);
            t.setattr(cid, g, b"snapset", &ss);
        }
        r.ad.with_store(|st| st.commit(&t)).unwrap();
    }
}

#[test]
fn large_results_are_streamed() {
    let dir = std::env::temp_dir().join(format!("ostool-st-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut code = 1;

    // a listing: one line per object, written as the walk yields it (30k lines are several MB of text)
    let mut r = rig(6);
    let s = spg(1, 0);
    make_pg(&r, s, 0);
    many_objects(&r, s, 30_000);
    let p = peak(|| code = run_sink(&mut r, &["--op", "list", "--pgid", "1.0"]).code);
    assert_eq!(code, 0);
    assert!(p < 3 << 20, "listing peak {p} bytes");

    // get-bytes: each 8 MiB chunk goes to stdout as it is read
    let mut r = rig(6);
    let s = spg(1, 0);
    make_pg(&r, s, 0);
    big_object(&r, s, "big", 32 << 20);
    let p = peak(|| code = run_sink(&mut r, &["--pgid", "1.0", "big", "get-bytes"]).code);
    assert_eq!(code, 0);
    assert!(p < 16 << 20, "get-bytes peak {p} bytes");

    // export: the DATA payload goes from the read chunk straight into the file (no encoder copy)
    let f = dir.join("pg.export");
    let p = peak(|| {
        code = run(
            &mut r,
            &[
                "--op",
                "export",
                "--pgid",
                "1.0",
                "--file",
                f.to_str().unwrap(),
            ],
            b"",
        )
        .code
    });
    assert_eq!(code, 0);
    assert!(p < 13 << 20, "export peak {p} bytes");
    let _ = std::fs::remove_dir_all(&dir);
}
