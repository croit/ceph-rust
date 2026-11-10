// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Differential tests of the streaming translator (adr 0160 D3) against the former decode-then-translate path, kept
//! here as the oracle only (never built into production): random transactions of every op code, v9 / v10 (split and
//! plain writes) / local skeleton forms, foreign collections and shards, out-of-range values, and byte-level mutations
//! of the encoded form. Both must return the same `TOp` list and hints, or the same error.

use super::*;
use denc::types::{Hobject, PgT, ShardId, SnapId};
use replwire::{Data, Transaction, TxnOp};

/// The former path: full `Transaction` decode, then translate (verbatim, except a NOP no longer reads the collection
/// table first: that indexed an empty table and panicked on a NOP-only txn without collections).
mod oracle {
    use super::super::{b, range_ok};
    use denc::types::{CollT, Ghobject, SpgT};
    use replwire::{Transaction, TxnOp};
    use store::obj::txn::Bytes as TxnBytes;
    use store::obj::{ObjError, TOp};

    /// Translate; `out` receives ops in order (collection creation for the temp collection first).
    pub fn translate<'a>(
        spg: SpgT,
        middle: &'a [u8],
        data: &'a [u8],
        out: &mut Vec<TOp<'a>>,
        hints: &mut u32,
    ) -> Result<(), ObjError> {
        let t = Transaction::decode(middle, data, replwire::DEFAULT_PAGE)
            .map_err(|e| ObjError::Invalid(format!("transaction decode: {e}")))?;
        translate_txn(spg, t, out, hints)
    }

    /// [`translate`] for the local skeleton form of a client write (`Transaction::encode_v9_split`): the out-of-line write
    /// payloads in `refs` are borrowed as they are, no copy until the store stages them.
    pub fn translate_split<'a>(
        spg: SpgT,
        skel: &'a [u8],
        refs: &'a [bytes::Bytes],
        out: &mut Vec<TOp<'a>>,
        hints: &mut u32,
    ) -> Result<(), ObjError> {
        let t = Transaction::decode_split(skel, refs, replwire::DEFAULT_PAGE)
            .map_err(|e| ObjError::Invalid(format!("transaction decode: {e}")))?;
        translate_txn(spg, t, out, hints)
    }

    fn translate_txn<'a>(
        spg: SpgT,
        t: Transaction<'a>,
        out: &mut Vec<TOp<'a>>,
        hints: &mut u32,
    ) -> Result<(), ObjError> {
        for c in &t.colls {
            match c {
                CollT::Pg(s) if *s == spg => {}
                CollT::PgTemp(s) if *s == spg => out.push(TOp::MkColl {
                    cid: *c,
                    bits: 0,
                    exist_ok: true,
                }),
                _ => {
                    return Err(ObjError::Invalid(format!(
                        "transaction names collection {c} outside pg {spg}"
                    )));
                }
            }
        }
        // a PG instance only ever touches objects of its own shard (replicated: NO_SHARD): data for a foreign shard is a
        // bug of the sender and must never land in our collection
        if let Some(g) = t.objs.iter().find(|g| g.shard != spg.shard) {
            return Err(ObjError::Invalid(format!(
                "transaction names object of shard {} in pg {spg}",
                g.shard.0
            )));
        }
        for op in &t.ops {
            if op.op == TxnOp::Nop {
                continue;
            }
            match &op.op {
                TxnOp::Write { off, data, .. } => range_ok(*off, data.len() as u64)?,
                TxnOp::Zero { off, len, .. } => range_ok(*off, *len)?,
                TxnOp::Truncate { size, .. } => range_ok(*size, 0)?,
                TxnOp::CloneRange2 {
                    src_off,
                    len,
                    dest_off,
                    ..
                } => {
                    range_ok(*src_off, *len)?;
                    range_ok(*dest_off, *len)?;
                }
                _ => {}
            }
            let cid = *t.get_coll(op.cid);
            let o = |x: replwire::Ox| -> Ghobject { t.get_obj(x).clone() };
            let top = match &op.op {
                TxnOp::Nop | TxnOp::CollHint { .. } => continue,
                // input of the pool's compression mode decision (adr 0059 am. 1)
                TxnOp::SetAllocHint { flags, .. } => {
                    *hints |= *flags;
                    continue;
                }
                TxnOp::Create { oid } | TxnOp::Touch { oid } | TxnOp::TouchTemp { oid, .. } => {
                    TOp::Touch { cid, oid: o(*oid) }
                }
                TxnOp::Write { oid, off, data } => TOp::Write {
                    cid,
                    oid: o(*oid),
                    off: *off,
                    data: if data.mid.is_empty() && data.tail.is_empty() {
                        TxnBytes::Borrowed(data.head)
                    } else {
                        TxnBytes::Owned(data.to_vec())
                    },
                },
                TxnOp::Zero { oid, off, len } => TOp::Zero {
                    cid,
                    oid: o(*oid),
                    off: *off,
                    len: *len,
                },
                TxnOp::Truncate { oid, size } => TOp::Truncate {
                    cid,
                    oid: o(*oid),
                    size: *size,
                },
                TxnOp::Remove { oid } => TOp::Remove { cid, oid: o(*oid) },
                TxnOp::SetAttr { oid, name, value } => TOp::SetAttrs {
                    cid,
                    oid: o(*oid),
                    attrs: vec![(b(name), b(value))],
                },
                TxnOp::SetAttrs { oid, attrs } => TOp::SetAttrs {
                    cid,
                    oid: o(*oid),
                    attrs: attrs.iter().map(|(k, v)| (b(k), b(v))).collect(),
                },
                TxnOp::RmAttr { oid, name } => TOp::RmAttr {
                    cid,
                    oid: o(*oid),
                    name: b(name),
                },
                TxnOp::RmAttrs { oid } => TOp::RmAttrs { cid, oid: o(*oid) },
                TxnOp::Clone { oid, dest_oid } => TOp::Clone {
                    cid,
                    src: o(*oid),
                    dst: o(*dest_oid),
                },
                TxnOp::CloneRange2 {
                    oid,
                    dest_oid,
                    src_off,
                    len,
                    dest_off,
                } => TOp::CloneRange {
                    cid,
                    src: o(*oid),
                    dst: o(*dest_oid),
                    src_off: *src_off,
                    len: *len,
                    dst_off: *dest_off,
                },
                TxnOp::MkColl { bits } => TOp::MkColl {
                    cid,
                    bits: *bits,
                    exist_ok: true,
                },
                TxnOp::RmColl => TOp::RmColl { cid },
                TxnOp::CollMoveRename {
                    oid,
                    dest_cid,
                    dest_oid,
                } => TOp::MoveRename {
                    cid,
                    oid: o(*oid),
                    dcid: *t.get_coll(*dest_cid),
                    doid: o(*dest_oid),
                },
                TxnOp::TryRename { oid, dest_oid } => TOp::MoveRename {
                    cid,
                    oid: o(*oid),
                    dcid: cid,
                    doid: o(*dest_oid),
                },
                TxnOp::OmapClear { oid } => TOp::OmapClear { cid, oid: o(*oid) },
                // a strictly ascending list (every map a peer encodes) is handed over as one run
                TxnOp::OmapSetKeys { oid, pairs }
                    if pairs
                        .iter()
                        .zip(pairs.iter().skip(1))
                        .all(|(a, b)| a.0 < b.0) =>
                {
                    let mut enc = Vec::new();
                    denc::SortedKv::encode_into(&mut enc, pairs.len(), pairs.iter());
                    TOp::OmapSetRun {
                        cid,
                        oid: o(*oid),
                        run: store::obj::KvRunData::from_encoding(enc.into()).unwrap(),
                    }
                }
                TxnOp::OmapSetKeys { oid, pairs } => TOp::OmapSetKeys {
                    cid,
                    oid: o(*oid),
                    pairs: pairs.iter().map(|(k, v)| (b(k), b(v))).collect(),
                },
                TxnOp::OmapRmKeys { oid, keys } => TOp::OmapRmKeys {
                    cid,
                    oid: o(*oid),
                    keys: keys.iter().map(|k| b(k)).collect(),
                },
                TxnOp::OmapRmKeyRange { oid, first, last } => TOp::OmapRmKeyRange {
                    cid,
                    oid: o(*oid),
                    first: b(first),
                    last: b(last),
                },
                TxnOp::OmapSetHeader { oid, header } => TOp::OmapSetHeader {
                    cid,
                    oid: o(*oid),
                    header: b(header),
                },
                TxnOp::CollSetBits { bits } => TOp::SetCollBits { cid, bits: *bits },
                TxnOp::SplitCollection2 { .. } => {
                    return Err(ObjError::Unsupported(
                        "SPLIT_COLLECTION2 (wire op; PG split runs locally)",
                    ));
                }
                TxnOp::MergeCollection { .. } => {
                    return Err(ObjError::Unsupported(
                        "MERGE_COLLECTION (wire op; PG merge runs locally)",
                    ));
                }
            };
            out.push(top);
        }
        Ok(())
    }
}

/// xorshift64*, deterministic per seed.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn one_in(&mut self, n: u64) -> bool {
        self.below(n) == 0
    }
}

fn spg_of(r: &mut Rng) -> SpgT {
    SpgT {
        pgid: PgT::new(3, 7),
        shard: if r.one_in(2) {
            ShardId::NO_SHARD
        } else {
            ShardId(r.below(3) as i8)
        },
    }
}

/// Random transaction: `Arena` owns the payloads the `Transaction` borrows.
struct Arena {
    blobs: Vec<Vec<u8>>,
}

fn gen_arena(r: &mut Rng) -> Arena {
    let mut blobs = Vec::new();
    for _ in 0..64 {
        let n = match r.below(6) {
            0 => 0,
            1 => 4096,
            2 => 8192 + r.below(3) as usize * 513,
            _ => r.below(300) as usize,
        };
        blobs.push((0..n).map(|_| r.next() as u8).collect());
    }
    Arena { blobs }
}

fn gen_txn<'a>(r: &mut Rng, spg: SpgT, a: &'a Arena) -> Transaction<'a> {
    let mut t = Transaction::new();
    let pg = t.coll(&CollT::Pg(spg));
    let temp = if r.one_in(3) {
        Some(t.coll(&CollT::PgTemp(spg)))
    } else {
        None
    };
    if r.one_in(25) {
        // a collection outside the PG
        t.coll(&if r.one_in(2) {
            CollT::Meta
        } else {
            CollT::Pg(SpgT {
                pgid: PgT::new(3, 8),
                shard: spg.shard,
            })
        });
    }
    // > 8 objects now and then: the heap use-count path
    let nobj = if r.one_in(6) {
        9 + r.below(6)
    } else {
        1 + r.below(4)
    };
    let mut ox = Vec::new();
    for i in 0..nobj {
        let mut h = Hobject::new(
            format!("obj{i}.{}", r.below(1000)).as_bytes(),
            SnapId(if r.one_in(4) {
                r.below(5)
            } else {
                u64::MAX - 1
            }),
            r.next() as u32,
            3,
            if r.one_in(4) { b"ns" } else { b"" },
        );
        if r.one_in(5) {
            h.key = b"locator".to_vec();
        }
        let shard = if r.one_in(40) {
            ShardId(5) // foreign shard
        } else {
            spg.shard
        };
        let generation = if r.one_in(5) {
            r.below(9)
        } else {
            Ghobject::NO_GEN
        };
        ox.push(t.obj(&Ghobject::new(h, generation, shard)));
    }
    let blob = |r: &mut Rng| a.blobs[r.below(a.blobs.len() as u64) as usize].as_slice();
    let off = |r: &mut Rng| match r.below(8) {
        0 => (128 << 20) - r.below(8192),
        1 => u64::MAX - r.below(3),
        _ => r.below(1 << 22),
    };
    let nops = r.below(12);
    for _ in 0..nops {
        let o = ox[r.below(ox.len() as u64) as usize];
        let d = ox[r.below(ox.len() as u64) as usize];
        let cid = match temp {
            Some(c) if r.one_in(3) => c,
            _ => pg,
        };
        let kv = |r: &mut Rng| -> Vec<(&'a [u8], &'a [u8])> {
            (0..r.below(4)).map(|_| (blob(r), blob(r))).collect()
        };
        let op = match r.below(30) {
            0 => TxnOp::Nop,
            1 => TxnOp::Create { oid: o },
            2 => TxnOp::Touch { oid: o },
            3 => TxnOp::TouchTemp {
                oid: o,
                dest_oid: d,
            },
            4..=7 => TxnOp::Write {
                oid: o,
                off: if r.one_in(2) {
                    r.below(16) * 4096
                } else {
                    off(r)
                },
                data: Data::new(blob(r)),
            },
            8 => TxnOp::Zero {
                oid: o,
                off: off(r),
                len: r.below(1 << 20),
            },
            9 => TxnOp::Truncate {
                oid: o,
                size: off(r),
            },
            10 => TxnOp::Remove { oid: o },
            11 => TxnOp::SetAttr {
                oid: o,
                name: blob(r),
                value: blob(r),
            },
            12 | 13 => TxnOp::SetAttrs {
                oid: o,
                attrs: kv(r),
            },
            14 => TxnOp::RmAttr {
                oid: o,
                name: blob(r),
            },
            15 => TxnOp::RmAttrs { oid: o },
            16 => TxnOp::Clone {
                oid: o,
                dest_oid: d,
            },
            17 => TxnOp::CloneRange2 {
                oid: o,
                dest_oid: d,
                src_off: off(r),
                len: r.below(1 << 16),
                dest_off: off(r),
            },
            18 => TxnOp::MkColl {
                bits: r.below(32) as u32,
            },
            19 => TxnOp::CollHint {
                ty: 1,
                data: blob(r),
            },
            20 => TxnOp::CollMoveRename {
                oid: o,
                dest_cid: if r.one_in(2) { pg } else { cid },
                dest_oid: d,
            },
            21 => TxnOp::TryRename {
                oid: o,
                dest_oid: d,
            },
            22 => TxnOp::OmapClear { oid: o },
            23 => TxnOp::OmapSetKeys {
                oid: o,
                pairs: kv(r).into(),
            },
            24 => TxnOp::OmapRmKeys {
                oid: o,
                keys: (0..r.below(4)).map(|_| blob(r)).collect(),
            },
            25 => TxnOp::OmapRmKeyRange {
                oid: o,
                first: blob(r),
                last: blob(r),
            },
            26 => TxnOp::OmapSetHeader {
                oid: o,
                header: blob(r),
            },
            27 => TxnOp::SetAllocHint {
                oid: o,
                expected_object_size: r.next(),
                expected_write_size: r.next(),
                flags: r.next() as u32,
            },
            28 => TxnOp::CollSetBits {
                bits: r.below(32) as u32,
            },
            _ if r.one_in(4) => TxnOp::SplitCollection2 {
                dest_cid: pg,
                bits: 3,
                rem: 1,
            },
            _ if r.one_in(3) => TxnOp::MergeCollection {
                dest_cid: pg,
                bits: 3,
            },
            _ => TxnOp::RmColl,
        };
        t.push(cid, op);
    }
    if r.one_in(2) {
        t.data_features = replwire::txn::SERVER_TENTACLE;
    }
    t
}

type Res<'a> = (Result<(), String>, Vec<TOp<'a>>, u32);

fn run<'a>(f: impl FnOnce(&mut Vec<TOp<'a>>, &mut u32) -> Result<(), ObjError>) -> Res<'a> {
    let (mut out, mut hints) = (Vec::new(), 0);
    let r = f(&mut out, &mut hints).map_err(|e| format!("{e:?}"));
    if r.is_err() {
        // the caller drops the whole txn: only the verdict counts
        out.clear();
        hints = 0;
    }
    (r, out, hints)
}

fn same(what: &str, seed: u64, old: Res<'_>, new: Res<'_>) {
    assert_eq!(old.0, new.0, "{what} seed {seed}: verdict");
    assert_eq!(old.1, new.1, "{what} seed {seed}: store ops");
    assert_eq!(old.2, new.2, "{what} seed {seed}: hints");
}

/// Same verdict, ops and hints for the wire forms (v9, v10) and their byte mutations.
fn check_wire(seed: u64, spg: SpgT, middle: &[u8], data: &[u8]) {
    let old = run(|o, h| oracle::translate(spg, middle, data, o, h));
    let new = run(|o, h| translate(spg, middle, data, o, h));
    same("wire", seed, old, new);
}

#[test]
fn configured_large_object_ranges_translate_in_every_wire_form() {
    for shard in [ShardId::NO_SHARD, ShardId(1)] {
        let spg = SpgT {
            pgid: PgT::new(1, 0),
            shard,
        };
        let mut t = Transaction::new();
        let c = t.coll(&CollT::Pg(spg));
        let h = Hobject::new(b"large", SnapId::NOSNAP, 0, 1, b"");
        let oid = t.obj(&Ghobject::new(h.clone(), Ghobject::NO_GEN, shard));
        let stash = t.obj(&Ghobject::new(h, 2, shard));
        let off = 150 << 20;
        t.push(
            c,
            TxnOp::Truncate {
                oid,
                size: off + 4096,
            },
        );
        t.push(
            c,
            TxnOp::Write {
                oid,
                off,
                data: Data::new(b"marker"),
            },
        );
        t.push(
            c,
            TxnOp::Zero {
                oid,
                off,
                len: 4096,
            },
        );
        t.push(
            c,
            TxnOp::CloneRange2 {
                oid,
                dest_oid: stash,
                src_off: off,
                len: 4096,
                dest_off: off,
            },
        );
        let v9 = t.encode_v9().unwrap();
        let (m, d) = t.encode_v10(4096).unwrap();
        for (middle, data) in [(&[][..], v9.as_slice()), (m.as_slice(), d.as_slice())] {
            let (r, ops, _) = run(|o, h| translate(spg, middle, data, o, h));
            assert!(r.is_ok(), "{shard:?}: {r:?}");
            assert_eq!(ops.len(), 4);
        }
        let skel = t.encode_v9_split(&|i| i == 1).unwrap();
        let refs = [bytes::Bytes::from_static(b"marker")];
        let (r, ops, _) = run(|o, h| translate_split(spg, &skel, &refs, o, h));
        assert!(r.is_ok(), "{shard:?} split: {r:?}");
        assert_eq!(ops.len(), 4);
    }
}

#[test]
fn object_range_overflow_is_rejected() {
    assert!(range_ok(u64::MAX, 1).is_err());
    assert!(range_ok(u64::MAX - 4095, 4096).is_err());
}

#[test]
fn stream_matches_oracle_on_random_transactions() {
    let (mut ok, mut refused) = (0, 0);
    for seed in 1..=4000u64 {
        let mut r = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
        let a = gen_arena(&mut r);
        let spg = spg_of(&mut r);
        // the txn may target another shard than the PG instance now and then
        let t = gen_txn(&mut r, spg, &a);
        let v9 = t.encode_v9().unwrap();
        check_wire(seed, spg, &[], &v9);
        let (m, d) = t.encode_v10(replwire::DEFAULT_PAGE).unwrap();
        check_wire(seed, spg, &m, &d);
        // local skeleton: random writes out of line
        let ool: Vec<bool> = (0..t.ops.len()).map(|_| r.one_in(2)).collect();
        let ool = |i: usize| ool[i] && matches!(t.ops[i].op, TxnOp::Write { .. });
        let skel = t.encode_v9_split(&ool).unwrap();
        let refs: Vec<bytes::Bytes> = (0..t.ops.len())
            .filter(|&i| ool(i))
            .map(|i| match &t.ops[i].op {
                TxnOp::Write { data, .. } => bytes::Bytes::from(data.to_vec()),
                _ => unreachable!(),
            })
            .collect();
        let old = run(|o, h| oracle::translate_split(spg, &skel, &refs, o, h));
        let new = run(|o, h| translate_split(spg, &skel, &refs, o, h));
        if old.0.is_ok() {
            ok += 1;
        } else {
            refused += 1;
        }
        same("split", seed, old, new);
        if !refs.is_empty() {
            // a missing / an extra out-of-line payload
            let short = &refs[..refs.len() - 1];
            same(
                "split short",
                seed,
                run(|o, h| oracle::translate_split(spg, &skel, short, o, h)),
                run(|o, h| translate_split(spg, &skel, short, o, h)),
            );
        }
        let mut extra = refs.clone();
        extra.push(bytes::Bytes::from_static(b"extra"));
        same(
            "split extra",
            seed,
            run(|o, h| oracle::translate_split(spg, &skel, &extra, o, h)),
            run(|o, h| translate_split(spg, &skel, &extra, o, h)),
        );
        // byte mutations / truncations of the wire forms: decode errors, bad indices, odd lengths
        for _ in 0..6 {
            let mut x = v9.clone();
            match r.below(3) {
                0 if !x.is_empty() => {
                    let i = r.below(x.len() as u64) as usize;
                    x[i] ^= 1 << r.below(8);
                }
                1 => x.truncate(r.below(x.len() as u64 + 1) as usize),
                _ if !x.is_empty() => {
                    let i = r.below(x.len() as u64) as usize;
                    x[i] = r.next() as u8;
                }
                _ => {}
            }
            check_wire(seed, spg, &[], &x);
            let mut y = m.clone();
            if !y.is_empty() {
                let i = r.below(y.len() as u64) as usize;
                y[i] ^= 1 << r.below(8);
            }
            check_wire(seed, spg, &y, &d);
        }
    }
    // the generator must exercise both outcomes broadly
    assert!(ok > 1000 && refused > 500, "ok {ok} refused {refused}");
}

#[test]
fn stream_moves_each_object_out_of_the_table_once() {
    // three ops on one object, two on another: the last use of each is a move, the others clones; same result as the
    // oracle and every op names the right object
    let spg = SpgT {
        pgid: PgT::new(1, 2),
        shard: ShardId::NO_SHARD,
    };
    let g = |n: &[u8]| {
        Ghobject::new(
            Hobject::new(n, SnapId(u64::MAX - 1), 7, 1, b""),
            Ghobject::NO_GEN,
            spg.shard,
        )
    };
    let mut t = Transaction::new();
    let c = t.coll(&CollT::Pg(spg));
    let (a, b2) = (t.obj(&g(b"a")), t.obj(&g(b"b")));
    t.push(
        c,
        TxnOp::Write {
            oid: a,
            off: 0,
            data: Data::new(b"xyz"),
        },
    );
    t.push(
        c,
        TxnOp::Clone {
            oid: a,
            dest_oid: b2,
        },
    );
    t.push(
        c,
        TxnOp::SetAttr {
            oid: b2,
            name: b"_",
            value: b"v",
        },
    );
    t.push(c, TxnOp::Remove { oid: a });
    let v9 = t.encode_v9().unwrap();
    let new = run(|o, h| translate(spg, &[], &v9, o, h));
    let old = run(|o, h| oracle::translate(spg, &[], &v9, o, h));
    same("moves", 0, old, new.clone());
    let names: Vec<Vec<u8>> = new
        .1
        .iter()
        .flat_map(|op| match op {
            TOp::Write { oid, .. } | TOp::SetAttrs { oid, .. } | TOp::Remove { oid, .. } => {
                vec![oid.hobj.oid.clone()]
            }
            TOp::Clone { src, dst, .. } => vec![src.hobj.oid.clone(), dst.hobj.oid.clone()],
            _ => vec![],
        })
        .collect();
    assert_eq!(names, [&b"a"[..], b"a", b"b", b"b", b"a"]);
}

#[test]
fn uncounted_operand_is_refused_not_emptied() {
    let mut objs = vec![Ghobject::MIN()];
    let mut uses = [1u32];
    assert!(take(&mut objs, &mut uses, replwire::Ox(0)).is_ok());
    assert!(take(&mut objs, &mut uses, replwire::Ox(0)).is_err());
    assert!(take(&mut objs, &mut uses, replwire::Ox(1)).is_err());
}

#[test]
fn single_piece_write_payloads_remain_borrowed() {
    let pieces = [&b"head"[..], &b"middle"[..], &b"tail"[..]];
    for mask in 0u8..8 {
        let parts =
            core::array::from_fn::<_, 3, _>(|i| if mask & (1 << i) != 0 { pieces[i] } else { &[] });
        let data = Data {
            head: parts[0],
            mid: parts[1],
            tail: parts[2],
        };
        let translated = write_bytes(data);
        assert_eq!(&translated[..], data.to_vec());
        if mask.count_ones() <= 1 {
            let store::obj::txn::Bytes::Borrowed(b) = translated else {
                panic!("single-piece payload copied: mask={mask}");
            };
            let expected = parts
                .into_iter()
                .find(|p| !p.is_empty())
                .unwrap_or(parts[0]);
            assert_eq!(b.as_ptr(), expected.as_ptr());
        }
    }
}

#[test]
fn aligned_v10_write_translation_copies_zero_payload_bytes() {
    let spg = SpgT {
        pgid: PgT::new(1, 2),
        shard: ShardId::NO_SHARD,
    };
    for size in [4096, 65536, 1048576] {
        let payload = vec![0x57; size];
        let mut txn = Transaction::new();
        txn.data_features = replwire::txn::SERVER_TENTACLE;
        let cid = txn.coll(&CollT::Pg(spg));
        let oid = txn.obj(&Ghobject::new(
            Hobject::new(b"data", SnapId(u64::MAX - 1), 7, 1, b""),
            Ghobject::NO_GEN,
            spg.shard,
        ));
        txn.push(
            cid,
            TxnOp::Write {
                oid,
                off: 4096,
                data: Data::new(&payload),
            },
        );
        let (middle, data) = txn.encode_v10(replwire::DEFAULT_PAGE).unwrap();
        let decoded = Transaction::decode(&middle, &data, replwire::DEFAULT_PAGE).unwrap();
        let TxnOp::Write { data: source, .. } = decoded.ops[0].op else {
            panic!("not a write")
        };
        assert!(source.head.is_empty() && source.tail.is_empty());
        assert_eq!(source.mid.len(), size);
        let (_, out, _) = run(|out, hints| translate(spg, &middle, &data, out, hints));
        let [
            TOp::Write {
                data: translated, ..
            },
        ] = out.as_slice()
        else {
            panic!("not one store write")
        };
        assert_eq!(&translated[..], payload);
        assert!(
            matches!(translated, store::obj::txn::Bytes::Borrowed(_)),
            "copied {size} bytes"
        );
        assert_eq!(translated.as_ptr(), source.mid.as_ptr());
    }
}

/// Oracle vs stream on a typical client 4 KiB write txn (data + object_info): `cargo test --release -p storeadapt --lib
/// translate_microbench -- --ignored --nocapture` (2026-10-15 Mac, system allocator: 199 -> 168 ns).
#[test]
#[ignore]
fn translate_microbench() {
    let spg = SpgT {
        pgid: PgT::new(1, 2),
        shard: ShardId::NO_SHARD,
    };
    let h = Hobject::new(
        b"rbd_data.1234567890abcdef.0000000000000001",
        SnapId(u64::MAX - 1),
        7,
        1,
        b"",
    );
    let mut t = Transaction::new();
    let c = t.coll(&CollT::Pg(spg));
    let o = t.obj(&Ghobject::new(h, Ghobject::NO_GEN, spg.shard));
    let data = vec![7u8; 4096];
    let oi = vec![1u8; 300];
    t.push(
        c,
        TxnOp::Write {
            oid: o,
            off: 8192,
            data: Data::new(&data),
        },
    );
    t.push(
        c,
        TxnOp::SetAttrs {
            oid: o,
            attrs: vec![(b"_", &oi[..])],
        },
    );
    let v9 = t.encode_v9().unwrap();
    for (name, f) in [("old", 0), ("new", 1), ("old", 0), ("new", 1)] {
        let n = 2_000_000;
        let t0 = std::time::Instant::now();
        for _ in 0..n {
            let (mut out, mut h) = (Vec::new(), 0);
            if f == 0 {
                oracle::translate(spg, &[], std::hint::black_box(&v9), &mut out, &mut h).unwrap();
            } else {
                translate(spg, &[], std::hint::black_box(&v9), &mut out, &mut h).unwrap();
            }
            std::hint::black_box(&out);
        }
        println!("{name} {:.1} ns", t0.elapsed().as_nanos() as f64 / n as f64);
    }
}
