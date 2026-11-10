// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Generates the oprobe scripts of testdata/cls/classic/*.ops (typed input builders instead of
//! hand-written hex). Run: `cargo run -p cls --example gencases` (writes into testdata/cls/classic).
//! Every script runs on ONE object (fresh per script); messages are separated by `---`.

use cls::lock::*;
use cls::rbd::bitvec::ObjMap;
use cls::rbd::types::*;
use denc::types::{EntityName, UTime};
use denc::{Encode, Encoder};
use std::fmt::Write;

#[derive(Default)]
struct B(Encoder);
impl B {
    fn new() -> Self {
        B(Encoder::new())
    }
    fn u8(mut self, v: u8) -> Self {
        self.0.u8(v).unwrap();
        self
    }
    fn u32(mut self, v: u32) -> Self {
        self.0.u32(v).unwrap();
        self
    }
    fn u64(mut self, v: u64) -> Self {
        self.0.u64(v).unwrap();
        self
    }
    fn i64(mut self, v: i64) -> Self {
        self.0.i64(v).unwrap();
        self
    }
    fn s(mut self, v: &str) -> Self {
        self.0.bytes(v.as_bytes()).unwrap();
        self
    }
    fn bl(mut self, v: &[u8]) -> Self {
        self.0.bytes(v).unwrap();
        self
    }
    fn t<T: Encode>(mut self, v: &T) -> Self {
        v.encode(&mut self.0).unwrap();
        self
    }
    fn done(self) -> Vec<u8> {
        self.0.into_vec()
    }
}

fn hex(b: &[u8]) -> String {
    let mut s = String::from("hex:");
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}
/// `call rbd M hex:...`
fn rbd(m: &str, input: Vec<u8>) -> String {
    call("rbd", m, input)
}
fn call(c: &str, m: &str, input: Vec<u8>) -> String {
    if input.is_empty() {
        format!("call {c} {m}")
    } else {
        format!("call {c} {m} {}", hex(&input))
    }
}

const NOSNAP: u64 = u64::MAX - 1;
const PFX: &str = "rbd_data.abc";

fn create(size: u64, order: u8, features: u64) -> String {
    rbd(
        "create",
        B::new().u64(size).u8(order).u64(features).s(PFX).done(),
    )
}
fn snap_arg(id: u64) -> Vec<u8> {
    B::new().u64(id).done()
}
fn snap_add(name: &str, id: u64) -> String {
    rbd("snapshot_add", B::new().s(name).u64(id).done())
}
fn spec(pool: i64, image: &str, snap: u64) -> ParentImageSpec {
    ParentImageSpec {
        pool_id: pool,
        pool_namespace: Vec::new(),
        image_id: image.into(),
        snap_id: snap,
    }
}
fn child(pool: i64, image: &str) -> ChildImageSpec {
    ChildImageSpec {
        pool_id: pool,
        pool_namespace: Vec::new(),
        image_id: image.into(),
    }
}
fn trash_spec(name: &str, state: u8) -> TrashImageSpec {
    TrashImageSpec {
        source: 0,
        name: name.into(),
        deletion_time: UTime::new(1_000_000_000, 1),
        deferment_end_time: UTime::new(1_000_000_100, 2),
        state,
    }
}
const DUMP: &str = "omap-get-vals";

struct Case {
    name: &'static str,
    msgs: Vec<String>,
}
fn case(name: &'static str, msgs: Vec<String>) -> Case {
    Case { name, msgs }
}
fn one(stmts: &[&str]) -> String {
    stmts.join("; ")
}

fn cases() -> Vec<Case> {
    let mut v = Vec::new();
    let lk = |name: &str, ty: u8, cookie: &str, tag: &str, dur: u32, flags: u8| {
        call(
            "lock",
            "lock",
            B::new()
                .t(&LockOp {
                    name: name.into(),
                    ty,
                    cookie: cookie.into(),
                    tag: tag.into(),
                    description: "desc".into(),
                    duration: UTime::new(dur, 0),
                    flags,
                })
                .done(),
        )
    };
    let gi = |name: &str| {
        call(
            "lock",
            "get_info",
            B::new().t(&GetInfoOp { name: name.into() }).done(),
        )
    };
    let ul = |name: &str, cookie: &str| {
        call(
            "lock",
            "unlock",
            B::new()
                .t(&UnlockOp {
                    name: name.into(),
                    cookie: cookie.into(),
                })
                .done(),
        )
    };
    let al = |name: &str, ty: u8, cookie: &str, tag: &str| {
        call(
            "lock",
            "assert_locked",
            B::new()
                .t(&AssertOp {
                    name: name.into(),
                    ty,
                    cookie: cookie.into(),
                    tag: tag.into(),
                })
                .done(),
        )
    };

    // ---------------------------------------------------------------- lock
    v.push(case(
        "lock_basic",
        vec![
            lk("l", 1, "c", "t", 0, 0),
            gi("l"),
            lk("l", 1, "c", "t", 0, 0),
            lk("l", 1, "c2", "t", 0, 0),
            lk("l", 1, "c", "other", 0, 1),
            lk("l", 1, "c", "t", 0, 1),
            lk("l", 1, "c", "t", 0, 3),
            lk("l", 1, "c", "t", 0, 2),
            lk("l", 0, "c", "t", 0, 0),
            lk("", 1, "c", "t", 0, 0),
            call(
                "lock",
                "break_lock",
                B::new()
                    .t(&BreakOp {
                        name: "l".into(),
                        locker: EntityName::client(1),
                        cookie: "c".into(),
                    })
                    .done(),
            ),
            call("lock", "break_lock", vec![3]),
            call("lock", "list_locks", vec![]),
            al("l", 1, "c", "t"),
            al("l", 1, "zz", "t"),
            al("l", 2, "c", "t"),
            al("l", 1, "c", "tt"),
            al("l", 0, "c", "t"),
            ul("l", "zz"),
            ul("l", "c"),
            gi("l"),
            ul("l", "c"),
            call("lock", "get_info", vec![0]),
            call("lock", "lock", vec![1, 2, 3]),
            "getxattrs".into(),
        ],
    ));
    v.push(case(
        "lock_shared_expiry",
        vec![
            lk("s", 2, "a", "tag", 3600, 0),
            lk("s", 2, "b", "tag", 0, 0),
            lk("s", 2, "c", "badtag", 0, 0),
            lk("s", 1, "d", "tag", 0, 0),
            gi("s"),
            call(
                "lock",
                "set_cookie",
                B::new()
                    .t(&SetCookieOp {
                        name: "s".into(),
                        ty: 2,
                        cookie: "a".into(),
                        tag: "tag".into(),
                        new_cookie: "b".into(),
                    })
                    .done(),
            ),
            call(
                "lock",
                "set_cookie",
                B::new()
                    .t(&SetCookieOp {
                        name: "s".into(),
                        ty: 2,
                        cookie: "a".into(),
                        tag: "tag".into(),
                        new_cookie: "z".into(),
                    })
                    .done(),
            ),
            call(
                "lock",
                "set_cookie",
                B::new()
                    .t(&SetCookieOp {
                        name: "s".into(),
                        ty: 1,
                        cookie: "z".into(),
                        tag: "tag".into(),
                        new_cookie: "y".into(),
                    })
                    .done(),
            ),
            call(
                "lock",
                "set_cookie",
                B::new()
                    .t(&SetCookieOp {
                        name: "s".into(),
                        ty: 2,
                        cookie: "nope".into(),
                        tag: "tag".into(),
                        new_cookie: "y".into(),
                    })
                    .done(),
            ),
            gi("s"),
            lk("other", 1, "x", "", 0, 0),
            call("lock", "list_locks", vec![]),
            ul("s", "z"),
            ul("s", "b"),
            gi("s"),
            call("lock", "list_locks", vec![]),
            "getxattrs".into(),
        ],
    ));
    v.push(case(
        "lock_compound_rollback",
        vec![
            // lock + failing rbd method in one message: lock rolled back, object not created
            one(&[
                &lk("l", 1, "c", "", 30, 0),
                &rbd("get_size", snap_arg(NOSNAP)),
            ]),
            gi("l"),
            // lock then lock in the same message: second sees the committed (empty) state
            one(&[&lk("l", 1, "c", "", 0, 0), &lk("l", 1, "c", "", 0, 0)]),
            gi("l"),
            "getxattrs".into(),
        ],
    ));
    v.push(case(
        "lock_vis",
        vec![
            "writefull \"x\"".into(),
            one(&[&lk("l", 1, "c", "", 0, 0), &gi("l")]),
            gi("l"),
            one(&[&gi("l"), &lk("l", 1, "d", "", 0, 0)]),
        ],
    ));
    v.push(case(
        "lock_ephemeral",
        vec![
            lk("e", 3, "c", "", 0, 0),
            gi("e"),
            "stat".into(),
            ul("e", "c"),
            "stat".into(),
        ],
    ));

    // ---------------------------------------------------------------- rbd header
    let get1 = |m: &str| rbd(m, snap_arg(NOSNAP));
    v.push(case(
        "rbd_create_errors",
        vec![
            rbd(
                "create",
                B::new().u64(1 << 30).u8(22).u64(0x1000).s(PFX).done(),
            ),
            rbd(
                "create",
                B::new().u64(1 << 30).u8(22).u64(0x3d).s("").done(),
            ),
            rbd(
                "create",
                B::new().u64(1 << 30).u8(22).u64(0x100).s(PFX).done(),
            ),
            rbd(
                "create",
                B::new().u64(1 << 30).u8(22).u64(0x80).s(PFX).done(),
            ),
            rbd(
                "create",
                B::new().u64(1 << 30).u8(22).u64(0x3d).s(PFX).i64(5).done(),
            ),
            rbd(
                "create",
                B::new().u64(1 << 30).u8(22).u64(0x80).s(PFX).i64(-1).done(),
            ),
            rbd("create", vec![1, 2, 3]),
            "stat".into(),
            rbd(
                "create",
                B::new()
                    .u64(1 << 30)
                    .u8(22)
                    .u64(0x3d | 0x80)
                    .s(PFX)
                    .i64(7)
                    .done(),
            ),
            rbd(
                "create",
                B::new().u64(1 << 30).u8(22).u64(0x3d).s(PFX).done(),
            ),
            rbd("get_data_pool", vec![]),
            rbd("get_features", B::new().u64(0).done()),
            DUMP.into(),
        ],
    ));
    v.push(case(
        "rbd_header_getters",
        vec![
            create(1 << 30, 22, 0x3d),
            rbd("get_features", B::new().u64(0).done()),
            rbd("get_features", B::new().u64(0).u8(1).done()),
            rbd("get_features", vec![1]),
            get1("get_size"),
            rbd("get_size", snap_arg(9)),
            rbd("get_size", vec![0, 0]),
            rbd("get_object_prefix", vec![]),
            rbd("get_data_pool", vec![]),
            rbd("get_all_features", vec![]),
            rbd("get_create_timestamp", vec![]),
            rbd("get_access_timestamp", vec![]),
            rbd("get_modify_timestamp", vec![]),
            rbd("get_flags", snap_arg(NOSNAP)),
            rbd("get_flags", snap_arg(3)),
            rbd("get_snapcontext", vec![]),
            rbd("op_features_get", vec![]),
            rbd("snapshot_get_limit", vec![]),
            rbd("image_group_get", vec![]),
            rbd("parent_get", vec![]),
            rbd("parent_overlap_get", snap_arg(NOSNAP)),
            rbd("metadata_list", B::new().s("").u64(0).done()),
            rbd("get_stripe_unit_count", vec![]),
            rbd("get_stripe_unit_count", vec![]),
            DUMP.into(),
        ],
    ));
    v.push(case(
        "rbd_header_setters",
        vec![
            create(1 << 30, 22, 0x3d),
            rbd("set_size", B::new().u64(2 << 30).done()),
            get1("get_size"),
            rbd("set_size", B::new().u64(1 << 20).done()),
            get1("get_size"),
            rbd("set_size", vec![1]),
            rbd("set_flags", B::new().u64(3).u64(1).done()),
            rbd("get_flags", snap_arg(NOSNAP)),
            rbd("set_flags", B::new().u64(2).u64(3).done()),
            rbd("get_flags", snap_arg(NOSNAP)),
            rbd("set_flags", B::new().u64(1).u64(1).u64(77).done()),
            rbd("set_features", B::new().u64(0).u64(0x20).done()),
            rbd("get_features", B::new().u64(0).done()),
            rbd("set_features", B::new().u64(0x20).u64(0x20).done()),
            rbd("set_features", B::new().u64(0x40).u64(0x40).done()),
            rbd("set_features", B::new().u64(0).u64(0x300).done()),
            rbd("set_features", B::new().u64(0).u64(0x1).done()),
            rbd("set_features", B::new().u64(0x1000).u64(0x1000).done()),
            rbd("set_features", B::new().u64(0).u64(0x40).done()),
            rbd("get_features", B::new().u64(0).done()),
            rbd("op_features_set", B::new().u64(1).u64(1).done()),
            rbd("op_features_get", vec![]),
            rbd("get_features", B::new().u64(0).done()),
            rbd("op_features_set", B::new().u64(1).u64(1).done()),
            rbd("op_features_set", B::new().u64(0).u64(0x10).done()),
            rbd("op_features_set", B::new().u64(0).u64(1).done()),
            rbd("op_features_get", vec![]),
            rbd("get_features", B::new().u64(0).done()),
            rbd("set_access_timestamp", vec![]),
            rbd("set_modify_timestamp", vec![]),
            DUMP.into(),
        ],
    ));
    v.push(case(
        "rbd_stripe",
        vec![
            create(1 << 30, 22, 0x3d),
            rbd("get_stripe_unit_count", vec![]),
            rbd("set_stripe_unit_count", B::new().u64(65536).u64(4).done()),
            rbd("set_features", B::new().u64(2).u64(2).done()),
        ],
    ));
    v.push(case(
        "rbd_stripe2",
        vec![
            create(1 << 30, 22, 0x3f),
            rbd("get_stripe_unit_count", vec![]),
            rbd("set_stripe_unit_count", B::new().u64(0).u64(4).done()),
            rbd("set_stripe_unit_count", B::new().u64(3).u64(4).done()),
            rbd("set_stripe_unit_count", B::new().u64(1 << 23).u64(4).done()),
            rbd("set_stripe_unit_count", B::new().u64(65536).u64(4).done()),
            rbd("get_stripe_unit_count", vec![]),
            DUMP.into(),
        ],
    ));
    v.push(case(
        "rbd_metadata",
        vec![
            create(1 << 30, 22, 0x3d),
            rbd(
                "metadata_set",
                B::new()
                    .u32(3)
                    .s("a")
                    .bl(b"1")
                    .s("b")
                    .bl(b"22")
                    .s("conf_x")
                    .bl(b"yes")
                    .done(),
            ),
            rbd("metadata_list", B::new().s("").u64(0).done()),
            rbd("metadata_list", B::new().s("a").u64(1).done()),
            rbd("metadata_list", B::new().s("").u64(2).done()),
            rbd("metadata_list", B::new().s("zzz").u64(5).done()),
            rbd("metadata_get", B::new().s("b").done()),
            rbd("metadata_get", B::new().s("nope").done()),
            rbd("metadata_remove", B::new().s("b").done()),
            rbd("metadata_remove", B::new().s("b").done()),
            rbd("metadata_list", B::new().s("").u64(10).done()),
            rbd("metadata_get", vec![9]),
            DUMP.into(),
        ],
    ));
    // many metadata keys (pagination > 64)
    {
        let mut m = B::new().u32(70);
        for i in 0..70 {
            m = m.s(&format!("k{i:03}")).bl(format!("v{i}").as_bytes());
        }
        v.push(case(
            "rbd_metadata_many",
            vec![
                create(1 << 30, 22, 0x3d),
                rbd("metadata_set", m.done()),
                rbd("metadata_list", B::new().s("").u64(0).done()),
                rbd("metadata_list", B::new().s("").u64(100).done()),
                rbd("metadata_list", B::new().s("k050").u64(100).done()),
                rbd("metadata_list", B::new().s("").u64(65).done()),
            ],
        ));
    }
    // ---------------------------------------------------------------- snapshots
    v.push(case(
        "rbd_snap_basic",
        vec![
            create(1 << 30, 22, 0x3d),
            snap_add("s1", 4),
            snap_add("s2", 5),
            snap_add("s1", 6),
            snap_add("s3", 5),
            snap_add("s3", 3),
            snap_add("s4", u64::MAX - 1),
            rbd(
                "snapshot_add",
                B::new().s("u").u64(9).t(&SnapNs::Unknown(9)).done(),
            ),
            rbd("snapshot_add", vec![1, 2]),
            rbd("get_snapcontext", vec![]),
            rbd("snapshot_get", snap_arg(4)),
            rbd("snapshot_get", snap_arg(5)),
            rbd("snapshot_get", snap_arg(6)),
            rbd("snapshot_get", snap_arg(NOSNAP)),
            rbd("get_snapshot_name", snap_arg(4)),
            rbd("get_snapshot_timestamp", snap_arg(4)),
            rbd("get_size", snap_arg(4)),
            rbd("get_flags", snap_arg(4)),
            rbd("set_flags", B::new().u64(2).u64(2).u64(4).done()),
            rbd("get_flags", snap_arg(4)),
            rbd("snapshot_rename", B::new().u64(4).s("s5").done()),
            rbd("snapshot_rename", B::new().u64(4).s("s2").done()),
            rbd("snapshot_rename", B::new().u64(77).s("s6").done()),
            rbd("snapshot_rename", B::new().u64(4).s("s5").done()),
            rbd("set_protection_status", B::new().u64(4).u8(2).done()),
            rbd("set_protection_status", B::new().u64(4).u8(3).done()),
            rbd("set_protection_status", B::new().u64(NOSNAP).u8(1).done()),
            rbd("set_protection_status", B::new().u64(99).u8(1).done()),
            rbd("get_protection_status", snap_arg(4)),
            rbd("get_protection_status", snap_arg(99)),
            rbd("get_protection_status", snap_arg(NOSNAP)),
            rbd("snapshot_remove", snap_arg(4)),
            rbd("set_protection_status", B::new().u64(4).u8(0).done()),
            rbd("snapshot_remove", snap_arg(4)),
            rbd("snapshot_remove", snap_arg(4)),
            rbd("get_snapcontext", vec![]),
            DUMP.into(),
        ],
    ));
    v.push(case(
        "rbd_snap_limit_trash",
        vec![
            create(1 << 30, 22, 0x3d),
            snap_add("s1", 4),
            snap_add("s2", 5),
            rbd("snapshot_get_limit", vec![]),
            rbd("snapshot_set_limit", B::new().u64(1).done()),
            rbd("snapshot_set_limit", B::new().u64(2).done()),
            rbd("snapshot_get_limit", vec![]),
            snap_add("s3", 6),
            rbd("snapshot_set_limit", B::new().u64(0).done()),
            snap_add("s3", 6),
            rbd("snapshot_set_limit", B::new().u64(u64::MAX).done()),
            rbd("snapshot_get_limit", vec![]),
            snap_add("s3", 6),
            // trash
            rbd("snapshot_trash_add", snap_arg(5)),
            rbd("snapshot_trash_add", snap_arg(5)),
            rbd("snapshot_trash_add", snap_arg(77)),
            rbd("op_features_get", vec![]),
            rbd("get_features", B::new().u64(0).done()),
            rbd("snapshot_get", snap_arg(5)),
            rbd("get_snapcontext", vec![]),
            rbd("snapshot_rename", B::new().u64(5).s("zz").done()),
            rbd("set_protection_status", B::new().u64(6).u8(2).done()),
            rbd("snapshot_trash_add", snap_arg(6)),
            rbd("set_protection_status", B::new().u64(6).u8(0).done()),
            rbd("snapshot_remove", snap_arg(5)),
            rbd("op_features_get", vec![]),
            rbd("snapshot_remove", snap_arg(6)),
            rbd("op_features_get", vec![]),
            rbd(
                "snapshot_add",
                B::new()
                    .s("tr")
                    .u64(9)
                    .t(&SnapNs::Trash {
                        original_name: "orig".into(),
                        original_namespace_type: 0,
                    })
                    .done(),
            ),
            rbd("op_features_get", vec![]),
            rbd(
                "snapshot_add",
                B::new()
                    .s("tr")
                    .u64(10)
                    .t(&SnapNs::Trash {
                        original_name: "orig2".into(),
                        original_namespace_type: 0,
                    })
                    .done(),
            ),
            rbd(
                "snapshot_add",
                B::new()
                    .s("tr")
                    .u64(11)
                    .t(&SnapNs::Group {
                        pool: 1,
                        group_id: "g".into(),
                        group_snapshot_id: "gs".into(),
                    })
                    .done(),
            ),
            rbd("snapshot_get", snap_arg(11)),
            rbd("snapshot_rename", B::new().u64(11).s("x").done()),
            rbd("get_snapcontext", vec![]),
            DUMP.into(),
        ],
    ));
    // many snapshots (pagination > 64)
    {
        let mut msgs = vec![create(1 << 30, 22, 0x3d)];
        let adds: Vec<String> = (1..=70u64).map(|i| snap_add(&format!("s{i}"), i)).collect();
        for chunk in adds.chunks(1) {
            msgs.push(chunk.join("; "));
        }
        msgs.push(rbd("get_snapcontext", vec![]));
        msgs.push(rbd("snapshot_set_limit", B::new().u64(69).done()));
        msgs.push(rbd("snapshot_set_limit", B::new().u64(70).done()));
        msgs.push(snap_add("s71", 71));
        v.push(case("rbd_snap_many", msgs));
    }
    // ---------------------------------------------------------------- layering
    v.push(case(
        "rbd_clone_v2_parent",
        vec![
            create(1 << 30, 22, 0x3d),
            snap_add("snap", 4),
            rbd(
                "child_attach",
                B::new().u64(4).t(&child(1, "child1")).done(),
            ),
            rbd(
                "child_attach",
                B::new().u64(4).t(&child(1, "child1")).done(),
            ),
            rbd(
                "child_attach",
                B::new().u64(4).t(&child(2, "child0")).done(),
            ),
            rbd("child_attach", B::new().u64(77).t(&child(1, "c")).done()),
            rbd("children_list", snap_arg(4)),
            rbd("children_list", snap_arg(77)),
            rbd("op_features_get", vec![]),
            rbd("get_features", B::new().u64(0).done()),
            rbd("snapshot_get", snap_arg(4)),
            rbd("snapshot_remove", snap_arg(4)),
            rbd(
                "child_detach",
                B::new().u64(4).t(&child(1, "child1")).done(),
            ),
            rbd(
                "child_detach",
                B::new().u64(4).t(&child(1, "child1")).done(),
            ),
            rbd("op_features_get", vec![]),
            rbd("children_list", snap_arg(4)),
            rbd(
                "child_detach",
                B::new().u64(4).t(&child(2, "child0")).done(),
            ),
            rbd("op_features_get", vec![]),
            rbd("get_features", B::new().u64(0).done()),
            rbd("children_list", snap_arg(4)),
            rbd(
                "child_detach",
                B::new().u64(4).t(&child(2, "child0")).done(),
            ),
            rbd("snapshot_get", snap_arg(4)),
            DUMP.into(),
        ],
    ));
    v.push(case(
        "rbd_clone_v2_two_snaps",
        vec![
            create(1 << 30, 22, 0x3d),
            snap_add("a", 4),
            snap_add("b", 5),
            rbd("child_attach", B::new().u64(4).t(&child(1, "c1")).done()),
            rbd("child_attach", B::new().u64(5).t(&child(1, "c2")).done()),
            rbd("child_detach", B::new().u64(4).t(&child(1, "c1")).done()),
            rbd("op_features_get", vec![]),
            // trashed snapshots cannot take children
            rbd("snapshot_trash_add", snap_arg(4)),
            rbd("child_attach", B::new().u64(4).t(&child(1, "c3")).done()),
            rbd("child_detach", B::new().u64(5).t(&child(1, "c2")).done()),
            rbd("op_features_get", vec![]),
            DUMP.into(),
        ],
    ));
    let attach = |snap: u64, ov: u64| {
        rbd(
            "parent_attach",
            B::new().t(&spec(1, "parentid", snap)).u64(ov).done(),
        )
    };
    v.push(case(
        "rbd_clone_child",
        vec![
            create(1 << 30, 22, 0x3d),
            rbd("op_features_set", B::new().u64(2).u64(2).done()),
            rbd("get_features", B::new().u64(0).done()),
            attach(4, 0),
            rbd(
                "parent_attach",
                B::new().t(&spec(-1, "", NOSNAP)).u64(5).done(),
            ),
            attach(4, 1 << 40),
            rbd("parent_get", vec![]),
            rbd("parent_overlap_get", snap_arg(NOSNAP)),
            attach(4, 1 << 30),
            rbd(
                "parent_attach",
                B::new().t(&spec(1, "other", 4)).u64(1 << 30).done(),
            ),
            rbd(
                "parent_attach",
                B::new().t(&spec(1, "other", 4)).u64(1 << 29).u8(1).done(),
            ),
            rbd("parent_get", vec![]),
            rbd("parent_overlap_get", snap_arg(NOSNAP)),
            snap_add("s1", 7),
            rbd("parent_overlap_get", snap_arg(7)),
            rbd("set_size", B::new().u64(1 << 20).done()),
            rbd("parent_overlap_get", snap_arg(NOSNAP)),
            rbd("parent_overlap_get", snap_arg(7)),
            rbd("parent_overlap_get", snap_arg(88)),
            snap_add("s2", 8),
            rbd("parent_overlap_get", snap_arg(8)),
            DUMP.into(),
            rbd("parent_detach", vec![]),
            rbd("parent_get", vec![]),
            rbd("parent_overlap_get", snap_arg(NOSNAP)),
            rbd("parent_overlap_get", snap_arg(7)),
            rbd("op_features_get", vec![]),
            rbd("get_features", B::new().u64(0).done()),
            rbd("parent_detach", vec![]),
            DUMP.into(),
        ],
    ));
    v.push(case(
        "rbd_clone_child_nodeep",
        vec![
            create(1 << 30, 22, 0x1d),
            rbd("op_features_set", B::new().u64(2).u64(2).done()),
            attach(4, 1 << 30),
            snap_add("s1", 7),
            snap_add("s2", 8),
            rbd("parent_detach", vec![]),
            rbd("op_features_get", vec![]),
            rbd("parent_get", vec![]),
            rbd("parent_overlap_get", snap_arg(NOSNAP)),
            rbd("parent_overlap_get", snap_arg(7)),
            DUMP.into(),
            rbd("snapshot_remove", snap_arg(7)),
            DUMP.into(),
            rbd("snapshot_remove", snap_arg(8)),
            DUMP.into(),
            rbd("op_features_get", vec![]),
            rbd("get_features", B::new().u64(0).done()),
        ],
    ));
    v.push(case(
        "rbd_snap_remove_parent",
        vec![
            // snapshot_remove scan quirk: single snapshot referencing the parent, head detached
            create(1 << 30, 22, 0x1d),
            rbd("op_features_set", B::new().u64(2).u64(2).done()),
            attach(4, 1 << 30),
            snap_add("s1", 7),
            rbd("parent_detach", vec![]),
            rbd("snapshot_remove", snap_arg(7)),
            DUMP.into(),
            rbd("op_features_get", vec![]),
        ],
    ));
    v.push(case(
        "rbd_snap_remove_parent2",
        vec![
            // head still attached, one snapshot removed
            create(1 << 30, 22, 0x3d),
            rbd("op_features_set", B::new().u64(2).u64(2).done()),
            attach(4, 1 << 30),
            snap_add("s1", 7),
            rbd("snapshot_remove", snap_arg(7)),
            DUMP.into(),
            rbd("op_features_get", vec![]),
        ],
    ));
    v.push(case(
        "rbd_legacy_parent",
        vec![
            create(1 << 30, 22, 0x3d),
            rbd(
                "set_parent",
                B::new().i64(1).s("parentid").u64(4).u64(1 << 30).done(),
            ),
            rbd("get_parent", snap_arg(NOSNAP)),
            rbd("parent_get", vec![]),
            rbd("remove_parent", vec![]),
            rbd("get_parent", snap_arg(NOSNAP)),
            DUMP.into(),
        ],
    ));
    v.push(case(
        "rbd_children_v1",
        vec![
            rbd("get_children", B::new().u64(1).s("pid").u64(4).done()),
            "create".into(),
            rbd("get_children", B::new().u64(1).s("pid").u64(4).done()),
            rbd("add_child", B::new().u64(1).s("pid").u64(4).s("c1").done()),
            rbd("add_child", B::new().u64(1).s("pid").u64(4).s("c1").done()),
            rbd("add_child", B::new().u64(1).s("pid").u64(4).s("c0").done()),
            rbd("add_child", B::new().u64(1).s("pid").u64(5).s("d1").done()),
            rbd("get_children", B::new().u64(1).s("pid").u64(4).done()),
            rbd("get_children", B::new().u64(2).s("pid").u64(4).done()),
            rbd(
                "remove_child",
                B::new().u64(1).s("pid").u64(4).s("c1").done(),
            ),
            rbd(
                "remove_child",
                B::new().u64(1).s("pid").u64(4).s("c1").done(),
            ),
            rbd(
                "remove_child",
                B::new().u64(1).s("zzz").u64(4).s("c1").done(),
            ),
            rbd("get_children", B::new().u64(1).s("pid").u64(4).done()),
            rbd(
                "remove_child",
                B::new().u64(1).s("pid").u64(4).s("c0").done(),
            ),
            rbd("get_children", B::new().u64(1).s("pid").u64(4).done()),
            rbd("add_child", vec![1]),
            DUMP.into(),
        ],
    ));
    // ---------------------------------------------------------------- directory / id / trash / ns
    let dadd = |n: &str, id: &str| rbd("dir_add_image", B::new().s(n).s(id).done());
    let drem = |n: &str, id: &str| rbd("dir_remove_image", B::new().s(n).s(id).done());
    let dlist = |a: &str, m: u64| rbd("dir_list", B::new().s(a).u64(m).done());
    v.push(case(
        "rbd_dir",
        vec![
            dadd("img1", "abc123"),
            dadd("img1", "zzz"),
            dadd("img9", "abc123"),
            dadd("", "q1"),
            dadd("bad", "a-b"),
            dadd("bad", ""),
            dadd("img2", "def456"),
            dlist("", 10),
            dlist("img1", 1),
            dlist("", 0),
            dlist("zzz", 5),
            rbd("dir_get_id", B::new().s("img1").done()),
            rbd("dir_get_id", B::new().s("none").done()),
            rbd("dir_get_name", B::new().s("def456").done()),
            rbd("dir_get_name", B::new().s("none").done()),
            rbd(
                "dir_rename_image",
                B::new().s("img1").s("img3").s("abc123").done(),
            ),
            rbd(
                "dir_rename_image",
                B::new().s("img1").s("img4").s("abc123").done(),
            ),
            rbd(
                "dir_rename_image",
                B::new().s("img3").s("img2").s("abc123").done(),
            ),
            rbd(
                "dir_rename_image",
                B::new().s("img3").s("img5").s("wrongid").done(),
            ),
            rbd(
                "dir_rename_image",
                B::new().s("img3").s("").s("abc123").done(),
            ),
            dlist("", 10),
            drem("img3", "abc123"),
            drem("img3", "abc123"),
            drem("img2", "abc999"),
            drem("img2", "def456"),
            DUMP.into(),
            rbd("dir_state_assert", vec![0]),
            rbd("dir_state_set", vec![1]),
            rbd("dir_state_assert", vec![1]),
            rbd("dir_state_assert", vec![0]),
            dadd("late", "id1"),
            rbd("dir_state_set", vec![7]),
            rbd("dir_state_set", vec![0]),
            rbd("dir_state_assert", vec![0]),
            dadd("a", "id2"),
            rbd("dir_state_set", vec![1]),
            DUMP.into(),
        ],
    ));
    {
        let adds: Vec<String> = (0..70)
            .map(|i| dadd(&format!("n{i:03}"), &format!("id{i}")))
            .collect();
        v.push(case(
            "rbd_dir_many",
            vec![
                adds.join("; "),
                dlist("", 0),
                dlist("", 1000),
                dlist("", 65),
                dlist("n010", 3),
                dlist("n066", 100),
            ],
        ));
    }
    v.push(case(
        "rbd_id",
        vec![
            rbd("get_id", vec![]),
            one(&["create", &rbd("set_id", B::new().s("a b").done())]),
            one(&["create", &rbd("set_id", vec![1])]),
            rbd("set_id", B::new().s("abc").done()),
            one(&["create excl", &rbd("set_id", B::new().s("abc123").done())]),
            rbd("get_id", vec![]),
            "read 0 0".into(),
            one(&["create", &rbd("set_id", B::new().s("other").done())]),
            rbd("get_id", vec![]),
            "stat".into(),
        ],
    ));
    v.push(case(
        "rbd_id_empty",
        vec![
            "create".into(),
            rbd("get_id", vec![]),
            one(&["create", &rbd("get_id", vec![])]),
        ],
    ));
    v.push(case(
        "rbd_trash",
        vec![
            rbd("trash_list", B::new().s("").u64(10).done()),
            rbd(
                "trash_add",
                B::new().s("abc123").t(&trash_spec("img", 0)).done(),
            ),
            rbd(
                "trash_add",
                B::new().s("abc123").t(&trash_spec("img", 0)).done(),
            ),
            rbd(
                "trash_add",
                B::new().s("a-b").t(&trash_spec("img", 0)).done(),
            ),
            rbd("trash_add", B::new().s("").t(&trash_spec("img", 0)).done()),
            rbd(
                "trash_add",
                B::new().s("def456").t(&trash_spec("img2", 0)).done(),
            ),
            rbd(
                "trash_add",
                B::new().s("ghi789").t(&trash_spec("img3", 0)).done(),
            ),
            rbd("trash_add", vec![1, 2]),
            rbd("trash_get", B::new().s("abc123").done()),
            rbd("trash_get", B::new().s("zzz").done()),
            rbd("trash_list", B::new().s("").u64(10).done()),
            rbd("trash_list", B::new().s("").u64(2).done()),
            rbd("trash_list", B::new().s("abc123").u64(2).done()),
            rbd("trash_list", B::new().s("").u64(0).done()),
            rbd("trash_state_set", B::new().s("abc123").u8(2).u8(0).done()),
            rbd("trash_state_set", B::new().s("abc123").u8(2).u8(0).done()),
            rbd("trash_state_set", B::new().s("abc123").u8(3).u8(0).done()),
            rbd("trash_state_set", B::new().s("nope").u8(3).u8(0).done()),
            rbd("trash_get", B::new().s("abc123").done()),
            rbd("trash_remove", B::new().s("abc123").done()),
            rbd("trash_remove", B::new().s("abc123").done()),
            DUMP.into(),
        ],
    ));
    v.push(case(
        "rbd_namespace",
        vec![
            rbd("namespace_list", B::new().s("").u64(10).done()),
            rbd("namespace_add", B::new().s("ns1").done()),
            rbd("namespace_add", B::new().s("ns1").done()),
            rbd("namespace_add", B::new().s("ns0").done()),
            rbd("namespace_list", B::new().s("").u64(10).done()),
            rbd("namespace_list", B::new().s("ns0").u64(10).done()),
            rbd("namespace_list", B::new().s("").u64(1).done()),
            rbd("namespace_remove", B::new().s("ns1").done()),
            rbd("namespace_remove", B::new().s("ns1").done()),
            rbd("namespace_list", B::new().s("").u64(10).done()),
        ],
    ));
    v.push(case(
        "rbd_group",
        vec![
            create(1 << 30, 22, 0x3d),
            rbd("image_group_get", vec![]),
            rbd(
                "image_group_add",
                B::new()
                    .t(&GroupSpec {
                        pool_id: 1,
                        group_id: "g1".into(),
                    })
                    .done(),
            ),
            rbd(
                "image_group_add",
                B::new()
                    .t(&GroupSpec {
                        pool_id: 1,
                        group_id: "g1".into(),
                    })
                    .done(),
            ),
            rbd(
                "image_group_add",
                B::new()
                    .t(&GroupSpec {
                        pool_id: 1,
                        group_id: "g2".into(),
                    })
                    .done(),
            ),
            rbd("image_group_get", vec![]),
            rbd("op_features_get", vec![]),
            rbd(
                "image_group_remove",
                B::new()
                    .t(&GroupSpec {
                        pool_id: 1,
                        group_id: "g2".into(),
                    })
                    .done(),
            ),
            rbd(
                "image_group_remove",
                B::new()
                    .t(&GroupSpec {
                        pool_id: 1,
                        group_id: "g1".into(),
                    })
                    .done(),
            ),
            rbd(
                "image_group_remove",
                B::new()
                    .t(&GroupSpec {
                        pool_id: 1,
                        group_id: "g1".into(),
                    })
                    .done(),
            ),
            rbd("image_group_get", vec![]),
            rbd("op_features_get", vec![]),
            rbd("get_features", B::new().u64(0).done()),
        ],
    ));
    // ---------------------------------------------------------------- mirror probes
    v.push(case("rbd_mirror", vec![
        "create".into(),
        rbd("mirror_image_get", B::new().s("x").done()),
        rbd("mirror_mode_get", vec![]),
        rbd("mirror_uuid_get", vec![]),
        rbd("mirror_peer_list", vec![]),
        rbd("mirror_image_list", B::new().s("").u64(10).done()),
        rbd("mirror_image_remove", B::new().s("x").done()),
        rbd("mirror_image_get_image_id", B::new().s("g").done()),
        rbd("mirror_image_get", vec![9]),
        "omap-set image_x=hex:0201060000000100000067010000 global_g=hex:0100000078 image_y=hex:02010a000000010000006800000100 mirror_mode=hex:02000000".into(),
        rbd("mirror_image_get", B::new().s("x").done()),
        rbd("mirror_image_get", B::new().s("y").done()),
        rbd("mirror_mode_get", vec![]),
        rbd("mirror_image_list", B::new().s("").u64(10).done()),
        rbd("mirror_image_list", B::new().s("x").u64(10).done()),
        rbd("mirror_image_get_image_id", B::new().s("g").done()),
        rbd("mirror_image_remove", B::new().s("x").done()),
        rbd("mirror_image_remove", B::new().s("y").done()),
        DUMP.into(),
    ]));
    // ---------------------------------------------------------------- object map
    let om = |n: u64, fill: u8| ObjMap::new(n, fill);
    let upd = |s: u64, e: u64, ns: u8, cur: Option<u8>| {
        let mut b = B::new().u64(s).u64(e).u8(ns);
        b = match cur {
            None => b.u8(0),
            Some(c) => b.u8(1).u8(c),
        };
        rbd("object_map_update", b.done())
    };
    let res = |n: u64, d: u8| rbd("object_map_resize", B::new().u64(n).u8(d).done());
    let mut m3 = om(10, 0);
    m3.set(2, 1);
    let mut snapmap = om(8, 0);
    snapmap.set(1, 1);
    snapmap.set(2, 3);
    v.push(case(
        "rbd_objmap",
        vec![
            rbd("object_map_load", vec![]),
            one(&["create", &rbd("object_map_load", vec![])]),
            upd(0, 1, 1, None),
            res(8, 0),
            "read 0 0".into(),
            rbd("object_map_load", vec![]),
            upd(1, 3, 1, None),
            "read 0 0".into(),
            upd(1, 3, 1, None),
            upd(0, 8, 2, Some(1)),
            "read 0 0".into(),
            upd(0, 9, 1, None),
            upd(3, 3, 1, None),
            upd(5, 2, 1, None),
            upd(0, 8, 0, Some(2)),
            rbd("object_map_snap_add", vec![]),
            "read 0 0".into(),
            upd(0, 8, 1, None),
            upd(0, 8, 3, Some(1)),
            "read 0 0".into(),
            upd(0, 8, 1, Some(1)),
            upd(0, 8, 1, Some(3)),
            "read 0 0".into(),
            rbd("object_map_snap_add", vec![]),
            rbd("object_map_snap_remove", snapmap.encode()),
            "read 0 0".into(),
            rbd("object_map_snap_remove", vec![1, 2, 3]),
            res(20000, 0),
            "read 0 0".into(),
            upd(16380, 16390, 1, None),
            upd(0, 20000, 1, Some(0)),
            "read 0 0".into(),
            res(10, 0),
            res(20000, 0),
            res(16385, 0),
            upd(0, 20000, 0, Some(1)),
            res(10, 0),
            "read 0 0".into(),
            res(300_000_000, 0),
            res(30, 3),
            "read 0 0".into(),
            res(12, 3),
            res(5, 3),
            "read 0 0".into(),
            rbd("object_map_load", vec![]),
            rbd("object_map_save", m3.encode_nocrc()),
            "read 0 0".into(),
            rbd("object_map_save", m3.encode()),
            rbd("object_map_save", vec![1, 2, 3]),
            rbd("object_map_load", vec![]),
            res(0, 0),
            "read 0 0".into(),
            rbd("object_map_load", vec![]),
            upd(0, 1, 1, None),
        ],
    ));
    v.push(case(
        "rbd_objmap_corrupt",
        vec![
            "writefull hex:0e000000010108000000040000000000000000".into(),
            rbd("object_map_load", vec![]),
            rbd(
                "object_map_update",
                B::new().u64(0).u64(1).u8(1).u8(0).done(),
            ),
            rbd("object_map_snap_add", vec![]),
            res(8, 0),
            "read 0 0".into(),
            // flip a data byte (crc now wrong)
            "write 18 hex:ff".into(),
            rbd("object_map_load", vec![]),
            upd(0, 1, 1, None),
            res(8, 0),
            "writefull zeros:0".into(),
            rbd("object_map_load", vec![]),
            res(4, 1),
            "read 0 0".into(),
        ],
    ));
    // ---------------------------------------------------------------- data objects
    let sc = |ext: &[(u64, u64)], data: &[u8]| {
        let mut b = B::new().u32(ext.len() as u32);
        for (o, l) in ext {
            b = b.u64(*o).u64(*l);
        }
        rbd("sparse_copyup", b.bl(data).done())
    };
    v.push(case(
        "rbd_sparse_copyup",
        vec![
            sc(&[(0, 4), (8, 4)], b"AAAABBBB"),
            "read 0 0".into(),
            "stat".into(),
            sc(&[(0, 2)], b"ZZ"),
            "read 0 0".into(),
            "delete".into(),
            sc(&[(0, 4), (8, 4)], b"AAAA"),
            "stat".into(),
            sc(&[], b""),
            "stat".into(),
            sc(&[], b""),
            "delete".into(),
            rbd("sparse_copyup", vec![1, 2]),
            sc(&[(100, 3)], b"xyz"),
            "read 0 0".into(),
            one(&[
                &sc(&[(0, 2)], b"hh"),
                "alloc-hint 4194304 65536",
                "write 0 \"QQ\"",
            ]),
        ],
    ));
    v.push(case(
        "rbd_copyup_thick",
        vec![
            rbd("copyup", b"hello".to_vec()),
            "read 0 0".into(),
            rbd("copyup", b"again".to_vec()),
            "read 0 0".into(),
            "delete".into(),
            rbd("copyup", vec![]),
            "stat".into(),
        ],
    ));
    let asq = |s: u64, st: u8| rbd("assert_snapc_seq", B::new().u64(s).u8(st).done());
    v.push(case(
        "rbd_assert_snapc_seq",
        vec![
            asq(5, 0),
            asq(5, 1),
            "stat".into(),
            "create".into(),
            asq(5, 0),
            asq(5, 1),
            asq(0, 0),
            asq(0, 1),
            asq(5, 2),
            rbd("assert_snapc_seq", vec![1]),
            "@snapc=7:7\nwrite 0 \"x\"".into(),
            asq(8, 0),
            asq(7, 0),
            asq(7, 1),
            asq(6, 1),
            asq(8, 1),
        ],
    ));
    let spf = |sz: u64, re: u8| rbd("sparsify", B::new().u64(sz).u8(re).done());
    v.push(case(
        "rbd_sparsify",
        vec![
            spf(4, 0),
            "writefull hex:41414141000000004242424200000000".into(),
            spf(4, 0),
            "read 0 0".into(),
            "writefull hex:00000000414141410000000042424242".into(),
            spf(4, 0),
            "read 0 0".into(),
            "writefull hex:4141414142424242".into(),
            spf(4, 0),
            "read 0 0".into(),
            "writefull hex:41414141000000004343".into(),
            spf(4, 1),
            "read 0 0".into(),
            "writefull hex:00000000".into(),
            spf(4, 0),
            "stat".into(),
            "writefull hex:00000000".into(),
            spf(4, 1),
            "stat".into(),
            "create".into(),
            spf(4, 0),
            spf(4, 1),
            "writefull hex:00410000".into(),
            spf(2, 0),
            "read 0 0".into(),
            "writefull hex:0041000043".into(),
            spf(2, 0),
            "read 0 0".into(),
            rbd("sparsify", vec![1]),
        ],
    ));
    // ---------------------------------------------------------------- quirks on absent store object
    {
        let mut msgs = Vec::new();
        let probes: Vec<String> = vec![
            rbd("metadata_list", B::new().s("").u64(10).done()),
            rbd("dir_list", B::new().s("").u64(10).done()),
            rbd("trash_list", B::new().s("").u64(10).done()),
            rbd("namespace_list", B::new().s("").u64(10).done()),
            rbd("mirror_image_list", B::new().s("").u64(10).done()),
            rbd("mirror_peer_list", vec![]),
            rbd("snapshot_get_limit", vec![]),
            rbd("get_flags", snap_arg(NOSNAP)),
            rbd("get_data_pool", vec![]),
            rbd("get_create_timestamp", vec![]),
            rbd("op_features_get", vec![]),
            rbd("image_group_get", vec![]),
            rbd("parent_overlap_get", snap_arg(NOSNAP)),
            rbd("parent_get", vec![]),
            rbd("get_snapcontext", vec![]),
            rbd("children_list", snap_arg(4)),
            rbd("get_children", B::new().u64(1).s("p").u64(4).done()),
            rbd("dir_get_id", B::new().s("n").done()),
            rbd("metadata_get", B::new().s("n").done()),
            rbd("get_id", vec![]),
            rbd("object_map_load", vec![]),
            rbd("get_size", snap_arg(NOSNAP)),
            rbd("get_object_prefix", vec![]),
            rbd("get_all_features", vec![]),
            rbd("snapshot_get", snap_arg(4)),
            rbd("get_protection_status", snap_arg(4)),
            rbd("dir_state_assert", vec![0]),
            rbd("mirror_mode_get", vec![]),
            rbd("get_stripe_unit_count", vec![]),
            rbd("get_features", B::new().u64(0).done()),
        ];
        for p in probes {
            msgs.push(one(&["setxattr x y", &p]));
            msgs.push("delete".into());
        }
        v.push(case("rbd_quirks_absent", msgs));
    }
    {
        // same probes on an object that exists (empty)
        let mut msgs = vec!["create".into()];
        for p in [
            rbd("metadata_list", B::new().s("").u64(10).done()),
            rbd("dir_list", B::new().s("").u64(10).done()),
            rbd("trash_list", B::new().s("").u64(10).done()),
            rbd("namespace_list", B::new().s("").u64(10).done()),
            rbd("mirror_image_list", B::new().s("").u64(10).done()),
            rbd("snapshot_get_limit", vec![]),
            rbd("get_flags", snap_arg(NOSNAP)),
            rbd("get_data_pool", vec![]),
            rbd("get_create_timestamp", vec![]),
            rbd("op_features_get", vec![]),
            rbd("image_group_get", vec![]),
            rbd("parent_overlap_get", snap_arg(NOSNAP)),
            rbd("parent_get", vec![]),
            rbd("get_snapcontext", vec![]),
            rbd("children_list", snap_arg(4)),
            rbd("get_size", snap_arg(NOSNAP)),
            rbd("set_size", B::new().u64(1).done()),
            rbd("set_features", B::new().u64(4).u64(4).done()),
            rbd("op_features_set", B::new().u64(1).u64(1).done()),
            rbd("set_protection_status", B::new().u64(4).u8(1).done()),
            rbd("get_protection_status", snap_arg(4)),
            rbd("snapshot_add", B::new().s("s").u64(1).done()),
            rbd("set_access_timestamp", vec![]),
            rbd("get_stripe_unit_count", vec![]),
            rbd("set_stripe_unit_count", B::new().u64(1).u64(1).done()),
            rbd("snapshot_set_limit", B::new().u64(3).done()),
            rbd("snapshot_set_limit", B::new().u64(u64::MAX).done()),
            rbd("dir_state_set", vec![1]),
            rbd("dir_state_assert", vec![1]),
            rbd("parent_detach", vec![]),
            rbd("set_flags", B::new().u64(1).u64(1).done()),
            rbd(
                "image_group_remove",
                B::new()
                    .t(&GroupSpec {
                        pool_id: 1,
                        group_id: "g".into(),
                    })
                    .done(),
            ),
        ] {
            msgs.push(p);
        }
        msgs.push(DUMP.into());
        v.push(case("rbd_quirks_empty", msgs));
    }
    // ---------------------------------------------------------------- visibility inside one message
    v.push(case(
        "rbd_vis",
        vec![
            create(1 << 30, 22, 0x3d),
            // dir-style remove+add in one message relies on the start view
            one(&[
                "@flags=returnvec",
                "omap-set size=hex:0001000000000000",
                &rbd("get_size", snap_arg(NOSNAP)),
            ]),
            one(&[&snap_add("s1", 4), &rbd("get_snapcontext", vec![])]),
            one(&[&snap_add("s2", 5), &snap_add("s3", 6)]),
            one(&[
                &rbd("snapshot_remove", snap_arg(5)),
                &rbd("snapshot_remove", snap_arg(5)),
            ]),
            one(&[
                &rbd("snapshot_remove", snap_arg(5)),
                &rbd("get_snapcontext", vec![]),
            ]),
            rbd("get_snapcontext", vec![]),
            DUMP.into(),
        ],
    ));
    v.push(case(
        "rbd_vis_dir",
        vec![
            rbd("dir_add_image", B::new().s("a").s("id1").done()),
            // rename a->b and add b in one message: second op sees committed state
            one(&[
                &rbd("dir_rename_image", B::new().s("a").s("b").s("id1").done()),
                &rbd("dir_get_id", B::new().s("b").done()),
            ]),
            one(&[
                &rbd("dir_remove_image", B::new().s("b").s("id1").done()),
                &rbd("dir_add_image", B::new().s("b").s("id1").done()),
            ]),
            DUMP.into(),
            one(&[
                &rbd("dir_remove_image", B::new().s("b").s("id1").done()),
                &rbd("dir_remove_image", B::new().s("b").s("id1").done()),
            ]),
            DUMP.into(),
        ],
    ));
    v
}

fn main() {
    let dir = std::path::Path::new("testdata/cls/classic");
    std::fs::create_dir_all(dir).unwrap();
    let all = cases();
    for c in &all {
        let mut s = "# generated by crates/cls/examples/gencases.rs\n".to_string();
        for (i, m) in c.msgs.iter().enumerate() {
            if i > 0 {
                s.push_str("---\n");
            }
            s.push_str(m);
            s.push('\n');
        }
        std::fs::write(dir.join(format!("{}.ops", c.name)), s).unwrap();
    }
    println!("{} cases", all.len());
    let _ = EntityName::client(0);
}
