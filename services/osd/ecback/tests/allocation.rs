// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Allocation ceilings for large EC writes/reads; counters are local to the measuring thread.
use bytes::Bytes;
use denc::types::*;
use ecback::Backend;
use replwire::txn::{Data, Transaction, TxnOp};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::collections::BTreeMap;

thread_local! {
    static COUNTS: Cell<Option<(usize, usize)>> = const { Cell::new(None) };
}
struct Counting;
fn count(bytes: usize) {
    let _ = COUNTS.try_with(|c| {
        if let Some((calls, size)) = c.get() {
            c.set(Some((calls + 1, size + bytes)));
        }
    });
}
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count(layout.size());
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        count(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        count(size);
        unsafe { System.realloc(ptr, layout, size) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: Counting = Counting;
fn measured<T>(f: impl FnOnce() -> T) -> (T, (usize, usize)) {
    COUNTS.with(|c| c.set(Some((0, 0))));
    let result = f();
    let counts = COUNTS.with(|c| c.replace(None).unwrap());
    (result, counts)
}
fn backend() -> Backend {
    Backend::from_parts(
        "isa",
        "reed_sol_van",
        (4, 2),
        (16384, 4096),
        (0..6).collect(),
        true,
    )
    .unwrap()
}
fn transaction(payload: &[u8]) -> Bytes {
    let mut t = Transaction::new();
    let cx = t.coll(&CollT::Pg(SpgT {
        pgid: PgT::new(1, 0),
        shard: ShardId(0),
    }));
    let ox = t.obj(&Ghobject::new(
        Hobject::new(b"probe", SnapId::NOSNAP, 0x1234, 1, b""),
        Ghobject::NO_GEN,
        ShardId(0),
    ));
    t.push(
        cx,
        TxnOp::Write {
            oid: ox,
            off: 0,
            data: Data::new(payload),
        },
    );
    t.encode_v9().unwrap().into()
}

#[test]
fn large_shared_write_avoids_per_stripe_allocations_and_rematerialization() {
    let be = backend();
    let payload = vec![7; 4 << 20];
    let txn = transaction(&payload);
    let (plan, planning) = measured(|| {
        be.plan_write_shared(PgT::new(1, 0), &txn, &BTreeMap::new(), &BTreeMap::new())
            .unwrap()
    });
    drop(txn); // the retained plan owns the input spans.
    let (generated, generation) = measured(|| plan.generate(&BTreeMap::new()).unwrap());
    let copied = be
        .plan_write(
            PgT::new(1, 0),
            &transaction(&payload),
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap()
        .generate(&BTreeMap::new())
        .unwrap();
    assert_eq!(generated.txns, copied.txns);
    assert_eq!(generated.txns.len(), 6);
    assert!(
        planning.0 + generation.0 < 256,
        "{planning:?} {generation:?}"
    );
    // Final shard streams consume 6 MiB. Allow 18 MiB total, not the previous >36 MiB.
    assert!(
        planning.1 + generation.1 < 18 << 20,
        "{planning:?} {generation:?}"
    );
}

#[test]
fn direct_assembly_borrows_complete_columns_and_pads_only_short_replies() {
    let be = backend();
    let payload = vec![7; 4 << 20];
    let got: BTreeMap<u32, Vec<u8>> = (0..4).map(|sh| (sh, vec![7; 1 << 20])).collect();
    let plan = be
        .plan_read(0, 256, &[0, 1, 2, 3], &[0, 1, 2, 3, 4, 5])
        .unwrap();
    let (result, allocations) = measured(|| be.assemble(&plan, &got, 0, 4 << 20).unwrap());
    assert_eq!(result, payload);
    assert!(allocations.1 < (4 << 20) + 4096, "{allocations:?}");
    // Existing zero-padding/truncation rules remain, even when a reply exceeds the span.
    let plan = be
        .plan_read(0, 1, &[0, 1, 2, 3], &[0, 1, 2, 3, 4, 5])
        .unwrap();
    let got = BTreeMap::from([(0, vec![1; 3]), (1, vec![2; 8192]), (3, vec![4; 4096])]);
    let result = be.assemble(&plan, &got, 0, 16384).unwrap();
    assert_eq!(&result[..3], &[1; 3]);
    assert!(result[3..4096].iter().all(|b| *b == 0));
    assert!(result[4096..8192].iter().all(|b| *b == 2));
    assert!(result[8192..12288].iter().all(|b| *b == 0));
    assert!(result[12288..].iter().all(|b| *b == 4));
}

#[test]
fn shared_generation_from_the_skeleton_copies_no_payload() {
    let be = backend();
    let payload = Bytes::from(vec![7u8; 4 << 20]);
    let copied = be
        .plan_write(
            PgT::new(1, 0),
            &transaction(&payload),
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap()
        .generate(&BTreeMap::new())
        .unwrap();
    // the client write as the primary holds it: local skeleton + the payload out of line
    let mut t = Transaction::new();
    let cx = t.coll(&CollT::Pg(SpgT {
        pgid: PgT::new(1, 0),
        shard: ShardId(0),
    }));
    let ox = t.obj(&Ghobject::new(
        Hobject::new(b"probe", SnapId::NOSNAP, 0x1234, 1, b""),
        Ghobject::NO_GEN,
        ShardId(0),
    ));
    t.push(
        cx,
        TxnOp::Write {
            oid: ox,
            off: 0,
            data: Data::new(&payload),
        },
    );
    let skel = Bytes::from(t.encode_v9_split(&|_| true).unwrap());
    let refs = [payload.clone()];
    let (shared, used) = measured(|| {
        be.plan_write_split(
            PgT::new(1, 0),
            &skel,
            &refs,
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap()
        .generate_shared(&BTreeMap::new())
        .unwrap()
    });
    assert_eq!(shared.len(), 6);
    for (s, b) in shared.iter().zip(&copied.txns) {
        assert_eq!(msgr2_flatten(&s.inline, &s.zc), *b);
        assert_eq!(s.zc.len(), 1, "the shard payload is spliced, not copied");
    }
    // only the 6 MiB of shard streams (encode output), no blob of 4 MiB input or 6 MiB per-shard copies
    assert!(used.1 < (6 << 20) + (512 << 10), "{used:?}");
}

fn msgr2_flatten(inline: &[u8], zc: &[(usize, Bytes)]) -> Vec<u8> {
    let (mut v, mut pos) = (Vec::new(), 0);
    for (at, r) in zc {
        v.extend_from_slice(&inline[pos..*at]);
        v.extend_from_slice(r);
        pos = *at;
    }
    v.extend_from_slice(&inline[pos..]);
    v
}

#[test]
fn mode_o_shared_generation_from_the_skeleton_copies_no_payload() {
    use ecback::OCtx;
    use std::sync::Arc;
    let be = Arc::new(backend());
    let payload = Bytes::from(vec![7u8; 4 << 20]);
    let members: Vec<u32> = (0..6).collect();
    let ctx = || OCtx {
        members: &members,
        first_write: true,
    };
    let copied = be
        .plan_write_o(
            PgT::new(1, 0),
            &transaction(&payload),
            &BTreeMap::new(),
            &BTreeMap::new(),
            ctx(),
        )
        .unwrap()
        .generate(&BTreeMap::new())
        .unwrap();
    let mut t = Transaction::new();
    let cx = t.coll(&CollT::Pg(SpgT {
        pgid: PgT::new(1, 0),
        shard: ShardId(0),
    }));
    let ox = t.obj(&Ghobject::new(
        Hobject::new(b"probe", SnapId::NOSNAP, 0x1234, 1, b""),
        Ghobject::NO_GEN,
        ShardId(0),
    ));
    t.push(
        cx,
        TxnOp::Write {
            oid: ox,
            off: 0,
            data: Data::new(&payload),
        },
    );
    let skel = t.encode_v9_split(&|_| true).unwrap();
    let refs = [payload.clone()];
    let (shared, used) = measured(|| {
        let d = Transaction::decode_split(&skel, &refs, 4096).unwrap();
        be.plan_write_o_txn(
            PgT::new(1, 0),
            &d,
            &refs,
            &BTreeMap::new(),
            &BTreeMap::new(),
            ctx(),
        )
        .unwrap()
        .generate_shared(&BTreeMap::new(), &BTreeMap::new(), None)
        .unwrap()
    });
    assert_eq!(shared.txns.len(), 6);
    for (s, b) in shared.txns.iter().zip(&copied.txns) {
        let (s, b) = (s.as_ref().unwrap(), b.as_ref().unwrap());
        assert_eq!(msgr2_flatten(&s.inline, &s.zc), *b);
        assert_eq!(s.zc.len(), 1, "the shard payload is spliced, not copied");
    }
    // only the 6 MiB of columns (data gather + parity), no input copy, no per-shard blob
    assert!(used.1 < (6 << 20) + (512 << 10), "{used:?}");
}

/// Old-stripe lookups of the legacy generator are one index per object: the allocation count of an overwrite does
/// not grow with the number of overwritten stripes (each lookup used to clone the object key).
fn overwrite_generation_allocations(be: &Backend, size: usize) -> usize {
    let h = Hobject::new(b"probe", SnapId::NOSNAP, 0x1234, 1, b"");
    let stripes = size / be.s as usize;
    let mut t = Transaction::new();
    let cx = t.coll(&CollT::Pg(SpgT {
        pgid: PgT::new(1, 0),
        shard: ShardId(0),
    }));
    let ox = t.obj(&Ghobject::new(h.clone(), Ghobject::NO_GEN, ShardId(0)));
    let payload = vec![7u8; be.c as usize];
    for x in 0..stripes {
        t.push(
            cx,
            TxnOp::Write {
                oid: ox,
                off: (x * be.s as usize) as u64,
                data: Data::new(&payload),
            },
        );
    }
    let txn = t.encode_v9().unwrap();
    let olds = BTreeMap::from([(
        h.clone(),
        ecback::OldObj {
            exists: true,
            size: size as u64,
            attrs: BTreeMap::from([(
                ec::HINFO_KEY.as_bytes().to_vec(),
                ec::HashInfo::new(be.n()).encode(),
            )]),
        },
    )]);
    let plan = be
        .plan_write(
            PgT::new(1, 0),
            &txn,
            &olds,
            &BTreeMap::from([(h.clone(), 1)]),
        )
        .unwrap();
    // one old stripe per overwritten stripe, as the plan asked them
    let old: BTreeMap<(Hobject, u64), Vec<u8>> = (0..stripes)
        .map(|x| ((h.clone(), x as u64), vec![1u8; be.s as usize]))
        .collect();
    assert_eq!(plan.reads().len(), stripes);
    measured(|| plan.generate(&old).unwrap()).1.0
}

#[test]
fn overwrite_generation_does_not_clone_a_key_per_stripe() {
    let be = backend();
    let one = overwrite_generation_allocations(&be, 1 << 20);
    let four = overwrite_generation_allocations(&be, 4 << 20);
    assert!(
        four <= one + 8,
        "1 MiB: {one} allocations, 4 MiB: {four} (grows with the stripe count)"
    );
}

/// A degraded mode O RMW read copies each wanted column once: the decode borrows the reply buffers of the plan
/// instead of copying every read shard a second time into `have`.
#[test]
fn degraded_rmw_read_copies_each_column_once() {
    let be = backend();
    let span = 1 << 20;
    let want: Vec<usize> = (0..4).collect();
    let avail: Vec<u32> = (1..6).collect(); // shard 0 down: one wanted column needs a decode
    let stripes = span / be.c as usize;
    let plan = be.plan_read(0, stripes as u64, &want, &avail).unwrap();
    assert!(!plan.shards.contains(&0), "{:?}", plan.shards);
    let got: BTreeMap<u32, Vec<u8>> = plan
        .shards
        .iter()
        .map(|sh| (*sh, vec![0u8; span]))
        .collect();
    let (cols, used) = measured(|| be.shard_columns(&plan, &got, span, &want).unwrap());
    let mut raws: Vec<usize> = cols.iter().map(|(r, _)| *r).collect();
    raws.sort_unstable();
    assert_eq!(raws, want);
    // 4 wanted columns + the decoded one
    assert!(used.1 < 6 * span, "{used:?} for 5 columns of {span} B");
}
