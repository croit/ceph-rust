// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Repop encode cost of the primary per client op, ns/op: `plain` = the contiguous v9 blob (`encode_v9`: payload copied
//! into the blob), `chain` = what the primary does with shared payloads: local skeleton (`encode_v9_local`), then
//! `decode_split` + `encode_v9_rope` for the peers and the pieces cut around the shared runs. The payloads are
//! shared client buffers (`Bytes`); the primary uses `chain` for a case with a shared payload of at least `SPLIT_MIN`
//! bytes (omap set run, write) and `plain` otherwise (rm / header). Payload sets: hot (one, in cache) and cold (1024
//! distinct buffers, beyond the last-level cache). Cases: 256-key omap set (300 B values), 256-key omap rm, omap header, 128 KiB write.
//! `cargo run --release -p replwire --example bench_repop`.
use bytes::Bytes;
use denc::types::{CollT, Ghobject, Hobject, PgT, ShardId, SpgT};
use replwire::{DEFAULT_PAGE, Data, OmapKv, Transaction, TxnOp};
use std::hint::black_box;
use std::time::Instant;

fn pat(n: usize, seed: u8) -> Vec<u8> {
    (0..n)
        .map(|i| (i as u8).wrapping_mul(29).wrapping_add(seed))
        .collect()
}

fn ns(n: u32, mut f: impl FnMut()) -> f64 {
    for _ in 0..n / 10 {
        f();
    }
    let s = Instant::now();
    for _ in 0..n {
        f();
    }
    s.elapsed().as_secs_f64() * 1e9 / f64::from(n)
}

fn chain(t: &Transaction<'_>, owners: &[Bytes]) -> usize {
    let (skel, refs) = t.encode_v9_local(owners).unwrap();
    let t2 = Transaction::decode_split(&skel, &refs, DEFAULT_PAGE).unwrap();
    let (head, cuts) = t2.encode_v9_rope(&refs).unwrap();
    let head = Bytes::from(head);
    let mut n = 0;
    let mut pos = 0;
    for (at, r) in cuts {
        n += head.slice(pos..at).len() + r.len();
        pos = at;
    }
    n + head.slice(pos..).len()
}

fn main() {
    let spg = SpgT {
        pgid: PgT { pool: 1, seed: 2 },
        shard: ShardId::NO_SHARD,
    };
    let oi = pat(300, 3);
    let keys: Vec<Vec<u8>> = (0..256)
        .map(|i| format!("rgw.bucket.index.{i:08}.{:0>20}", i * 7).into_bytes())
        .collect();
    let val = pat(300, 9);
    let hdr = pat(2048, 7);
    // COPIES independent payload sets (> last-level cache) = cold payloads like a request fresh off the wire; 1 = hot
    for copies in [1usize, 1024] {
        let mk_run = |c: usize| {
            let mut run = Vec::new();
            denc::SortedKv::encode_into(
                &mut run,
                keys.len(),
                keys.iter().map(|k| (k.as_slice(), val.as_slice())),
            );
            let l = run.len();
            run[l - 1] ^= c as u8 & 1; // distinct allocation, same size
            Bytes::from(run)
        };
        let runs: Vec<Bytes> = (0..copies).map(|c| mk_run(c).slice(4..)).collect();
        let writes: Vec<Bytes> = (0..copies)
            .map(|c| Bytes::from(pat(128 << 10, c as u8)))
            .collect();
        println!("-- {} payload set(s)", copies);
        println!("{:<30} {:>12} {:>12}", "case", "plain ns/op", "chain ns/op");
        for name in [
            "omap set 256 keys (~90 KiB)",
            "omap rm 256 keys",
            "omap header 2 KiB",
            "write 128 KiB",
        ] {
            let txns: Vec<(Transaction<'_>, Vec<Bytes>)> = (0..copies)
                .map(|c| {
                    let mut t = Transaction::new();
                    let cx = t.coll(&CollT::Pg(spg));
                    let o = t.obj(&Ghobject::new(
                        Hobject {
                            oid: b"obj".to_vec(),
                            ..Hobject::MIN()
                        },
                        Ghobject::NO_GEN,
                        ShardId::NO_SHARD,
                    ));
                    let (op, owners) = match name {
                        n if n.starts_with("omap set") => (
                            TxnOp::OmapSetKeys {
                                oid: o,
                                pairs: OmapKv::Run(denc::SortedKv::trusted(256, &runs[c])),
                            },
                            vec![runs[c].clone()],
                        ),
                        n if n.starts_with("omap rm") => (
                            TxnOp::OmapRmKeys {
                                oid: o,
                                keys: keys.iter().map(|k| k.as_slice()).collect(),
                            },
                            vec![],
                        ),
                        n if n.starts_with("omap header") => (
                            TxnOp::OmapSetHeader {
                                oid: o,
                                header: &hdr,
                            },
                            vec![],
                        ),
                        _ => (
                            TxnOp::Write {
                                oid: o,
                                off: 0,
                                data: Data::new(&writes[c]),
                            },
                            vec![writes[c].clone()],
                        ),
                    };
                    t.push(cx, op);
                    t.push(
                        cx,
                        TxnOp::SetAttrs {
                            oid: o,
                            attrs: vec![(b"_".as_slice(), oi.as_slice())],
                        },
                    );
                    (t, owners)
                })
                .collect();
            let n = if copies == 1 { 20000 } else { 4096 };
            let mut i = 0;
            let plain = ns(n, || {
                black_box(txns[i % copies].0.encode_v9().unwrap());
                i += 1;
            });
            let ch = ns(n, || {
                let (t, ow) = &txns[i % copies];
                black_box(chain(t, ow));
                i += 1;
            });
            println!("{name:<30} {plain:>12.0} {ch:>12.0}");
        }
    }
}
