// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Deterministic input fuzz over every registered method of the RGW-family classes: random and
//! mutated-valid inputs against empty, populated and corrupted objects must never panic, and a
//! failing call must leave the committed object untouched (MemStore commits only on ret >= 0).
mod common;
use cls::mem::MemStore;
use cls::rgw::types::*;
use common::*;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

const CLASSES: &[&str] = &[
    "version",
    "refcount",
    "queue",
    "rgw_gc",
    "user",
    "rgw",
    "log",
    "timeindex",
    "fifo",
    "journal",
];

fn populated() -> MemStore {
    let mut s = MemStore::new();
    let o = "o";
    cls::mem::MemStore::call(&mut s, o, "rgw", "bucket_init_index", &[]);
    for i in 0..20 {
        let p = ObjPrepareOp {
            op: op::ADD,
            tag: "t".into(),
            key: ObjKey::new(&format!("k{i}"), ""),
            ..Default::default()
        };
        s.call(o, "rgw", "bucket_prepare_op", &e(&p));
        let c = ObjCompleteOp {
            op_tag: "t".into(),
            key: ObjKey::new(&format!("k{i}"), ""),
            meta: DirEntryMeta {
                size: i,
                accounted_size: i,
                ..Default::default()
            },
            ..Default::default()
        };
        s.call(o, "rgw", "bucket_complete_op", &e(&c));
    }
    s.objects
        .get_mut(o)
        .unwrap()
        .xattrs
        .insert("refcount".into(), vec![9, 9]);
    s
}

#[test]
fn random_inputs_never_panic() {
    let mut rng = Rng(0x1234_5678_9abc_def1);
    for class in CLASSES {
        for m in cls::methods(class) {
            // valid-looking envelope: (v,c,len) + random body, plus plain random bytes
            for round in 0..60 {
                let n = (rng.next() % 96) as usize;
                let input = if round % 2 == 0 {
                    let mut v = vec![(rng.next() % 10) as u8, 1];
                    v.extend((n as u32).to_le_bytes());
                    v.extend(rng.bytes(n));
                    v
                } else {
                    rng.bytes(n)
                };
                for mk in [0, 1, 2] {
                    let mut s = match mk {
                        0 => MemStore::new(),
                        1 => populated(),
                        _ => {
                            let mut s = populated();
                            // corrupt every stored value
                            let o = s.objects.get_mut("o").unwrap();
                            for v in o.omap.values_mut() {
                                v.truncate(v.len() / 2);
                            }
                            o.omap_header.truncate(5);
                            s
                        }
                    };
                    let before = s.objects.clone();
                    let r = s.call("o", class, m.name, &input);
                    if r.ret < 0 {
                        assert_eq!(
                            s.objects, before,
                            "{class}.{}: failed call changed state",
                            m.name
                        );
                    }
                }
            }
        }
    }
}
