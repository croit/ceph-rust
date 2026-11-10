// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Deterministic input fuzz over every method of the small classes (hello, sdk, numops, cmpomap,
//! sem_set, cas, 2pc_queue, otp, cephfs): random and mutated-valid inputs against empty, populated
//! and corrupted objects must never panic (debug build = overflow checks on), and a failing call
//! must leave the committed object untouched (MemStore commits only on ret >= 0).
mod common;
use cls::mem::MemStore;
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
    "hello",
    "sdk",
    "numops",
    "cmpomap",
    "sem_set",
    "cas",
    "2pc_queue",
    "otp",
    "cephfs",
];

fn envelope(rng: &mut Rng, n: usize) -> Vec<u8> {
    let mut v = vec![(rng.next() % 4) as u8, 1];
    v.extend((n as u32).to_le_bytes());
    v.extend(rng.bytes(n));
    v
}

/// Valid inputs per class, to be mutated.
fn seeds() -> Vec<(&'static str, &'static str, Vec<u8>)> {
    use cls::{cas, cephfs, cmpomap, otp, sem_set, tpc_queue};
    let s = |x: &str| x.as_bytes().to_vec();
    let str_enc = |x: &str| cat(&[&(x.len() as u32).to_le_bytes(), x.as_bytes()]);
    let cmp = cmpomap::CmpOp {
        mode: 2,
        comparison: 3,
        values: [
            (s("k1"), 5u64.to_le_bytes().to_vec()),
            (s("k2"), vec![1, 2]),
        ]
        .into(),
        default_value: Some(vec![0; 8]),
    };
    let h = denc::types::Hobject::new(b"obj", denc::types::SnapId::NOSNAP, 77, 3, b"");
    vec![
        ("numops", "add", cat(&[&str_enc("k1"), &str_enc("1.5")])),
        ("numops", "mul", cat(&[&str_enc("k2"), &str_enc("2")])),
        ("cmpomap", "cmp_vals", cmp.to_bytes(true)),
        ("cmpomap", "cmp_set_vals", cmp.to_bytes(true)),
        ("cmpomap", "cmp_rm_keys", cmp.to_bytes(false)),
        (
            "sem_set",
            "increment",
            e(&sem_set::Increment {
                keys: [s("a"), s("b")].into(),
            }),
        ),
        (
            "sem_set",
            "decrement",
            e(&sem_set::Decrement {
                keys: [s("a")].into(),
                grace: Default::default(),
            }),
        ),
        (
            "sem_set",
            "reset",
            e(&sem_set::Reset {
                keys: [(s("a"), 3)].into(),
            }),
        ),
        (
            "sem_set",
            "list",
            e(&sem_set::ListOp {
                count: 10,
                cursor: vec![],
            }),
        ),
        (
            "cas",
            "chunk_create_or_get_ref",
            e(&cas::CreateOrGetRefOp {
                source: h.clone(),
                flags: 1,
                data: s("data"),
            }),
        ),
        ("cas", "chunk_get_ref", e(&cas::RefOp { source: h.clone() })),
        ("cas", "chunk_put_ref", e(&cas::RefOp { source: h })),
        ("cas", "references_chunk", str_enc("fp")),
        (
            "2pc_queue",
            "2pc_queue_reserve",
            e(&tpc_queue::ReserveOp {
                size: 10,
                entries: 2,
            }),
        ),
        (
            "2pc_queue",
            "2pc_queue_commit",
            e(&tpc_queue::CommitOp {
                id: 1,
                bl_data_vec: vec![s("abc")],
            }),
        ),
        (
            "2pc_queue",
            "2pc_queue_abort",
            e(&tpc_queue::AbortOp { id: 1 }),
        ),
        (
            "2pc_queue",
            "2pc_queue_remove_entries",
            e(&tpc_queue::RemoveOp {
                end_marker: s("0/30000"),
                entries_to_remove: 0,
            }),
        ),
        (
            "2pc_queue",
            "2pc_queue_expire_reservations",
            e(&tpc_queue::ExpireOp {
                stale_time: denc::types::UTime::new(2_000_000_000, 0),
            }),
        ),
        (
            "otp",
            "otp_set",
            e(&otp::SetOp {
                entries: vec![otp::OtpInfo {
                    id: s("u"),
                    seed: s("3132333435"),
                    seed_type: 1,
                    ..Default::default()
                }],
            }),
        ),
        (
            "otp",
            "otp_check",
            e(&otp::CheckOp {
                id: s("u"),
                val: s("123456"),
                token: s("t"),
            }),
        ),
        (
            "otp",
            "otp_get",
            e(&otp::GetOp {
                get_all: false,
                ids: vec![s("u")],
            }),
        ),
        ("otp", "otp_remove", e(&otp::RemoveOp { ids: vec![s("u")] })),
        (
            "cephfs",
            "accumulate_inode_metadata",
            e(&cephfs::AccumulateArgs {
                obj_xattr_name: "c".into(),
                mtime_xattr_name: "m".into(),
                obj_size_xattr_name: "s".into(),
                obj_index: 4,
                obj_size: 9,
                mtime: -3,
            }),
        ),
    ]
}

/// An object with plausible state for every class.
fn populated() -> MemStore {
    use cls::{cas, otp, sem_set, tpc_queue};
    let mut s = MemStore::new();
    let o = "o";
    let q = cls::queue::InitOp {
        queue_size: 4000,
        max_urgent_data_size: 0,
        bl_urgent_data: vec![],
    };
    s.call(o, "2pc_queue", "2pc_queue_init", &e(&q));
    for _ in 0..3 {
        s.call(
            o,
            "2pc_queue",
            "2pc_queue_reserve",
            &e(&tpc_queue::ReserveOp {
                size: 10,
                entries: 1,
            }),
        );
    }
    s.call(
        o,
        "2pc_queue",
        "2pc_queue_commit",
        &e(&tpc_queue::CommitOp {
            id: 1,
            bl_data_vec: vec![b"abc".to_vec()],
        }),
    );
    s.call(
        o,
        "sem_set",
        "increment",
        &e(&sem_set::Increment {
            keys: [b"a".to_vec()].into(),
        }),
    );
    let info = otp::OtpInfo {
        id: b"u".to_vec(),
        seed: b"3132".to_vec(),
        seed_type: 1,
        ..Default::default()
    };
    s.call(
        o,
        "otp",
        "otp_set",
        &e(&otp::SetOp {
            entries: vec![info],
        }),
    );
    let h = denc::types::Hobject::new(b"obj", denc::types::SnapId::NOSNAP, 77, 3, b"");
    s.call(
        o,
        "cas",
        "chunk_create_or_get_ref",
        &e(&cas::CreateOrGetRefOp {
            source: h,
            flags: 0,
            data: b"data".to_vec(),
        }),
    );
    let ob = s.objects.get_mut(o).unwrap();
    ob.omap.insert(b"k1".to_vec(), 4u64.to_le_bytes().to_vec());
    ob.omap.insert(b"k2".to_vec(), b"x".to_vec());
    ob.xattrs.insert(
        "c".into(),
        vec![
            1, 1, 16, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0,
        ],
    );
    s
}

fn corrupt(s: &mut MemStore, rng: &mut Rng) {
    let o = s.objects.get_mut("o").unwrap();
    for v in o.omap.values_mut() {
        if rng.next().is_multiple_of(2) {
            v.truncate(v.len() / 2);
        } else if let Some(b) = v.first_mut() {
            *b ^= 0xff;
        }
    }
    for v in o.xattrs.values_mut() {
        if rng.next().is_multiple_of(2) {
            v.truncate(v.len() / 2);
        }
    }
    o.omap_header.truncate(3);
}

fn run(s: &mut MemStore, class: &str, m: &str, input: &[u8]) {
    let before = s.objects.clone();
    let r = s.call("o", class, m, input);
    if r.ret < 0 {
        assert_eq!(s.objects, before, "{class}.{m}: failed call changed state");
    }
}

#[test]
fn random_inputs_never_panic() {
    let mut rng = Rng(0x2468_ace1_3579_bdf1);
    for class in CLASSES {
        for m in cls::methods(class) {
            for round in 0..80 {
                let n = (rng.next() % 96) as usize;
                let input = if round % 2 == 0 {
                    envelope(&mut rng, n)
                } else {
                    rng.bytes(n)
                };
                for mk in 0..3 {
                    let mut s = match mk {
                        0 => MemStore::new(),
                        1 => populated(),
                        _ => {
                            let mut s = populated();
                            corrupt(&mut s, &mut rng);
                            s
                        }
                    };
                    run(&mut s, class, m.name, &input);
                }
            }
        }
    }
}

#[test]
fn mutated_valid_inputs_never_panic() {
    let mut rng = Rng(0x1357_9bdf_2468_ace1);
    for (class, m, valid) in seeds() {
        for round in 0..150 {
            let mut input = valid.clone();
            match round % 5 {
                0 => {
                    if !input.is_empty() {
                        let at = (rng.next() as usize) % input.len();
                        input[at] ^= 1 << (rng.next() % 8);
                    }
                }
                1 => input.truncate((rng.next() as usize) % (input.len() + 1)),
                2 => input.extend(rng.bytes(8)),
                3 => {
                    for _ in 0..3 {
                        if !input.is_empty() {
                            let at = (rng.next() as usize) % input.len();
                            input[at] = rng.next() as u8;
                        }
                    }
                }
                _ => {}
            }
            for mk in 0..3 {
                let mut s = match mk {
                    0 => MemStore::new(),
                    1 => populated(),
                    _ => {
                        let mut s = populated();
                        corrupt(&mut s, &mut rng);
                        s
                    }
                };
                run(&mut s, class, m, &input);
            }
        }
    }
}
