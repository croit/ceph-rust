// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! cls_rbd mirroring (spec C.3): pool object `rbd_mirroring` scenarios on MemStore, snapshot
//! namespace bookkeeping on a header object, hand-derived byte vectors and an input fuzz.
mod common;
use cls::ctx::Watcher;
use cls::errno::*;
use cls::mem::MemStore;
use cls::rbd::mirror_types::*;
use cls::rbd::types::*;
use common::*;
use denc::types::{EntityAddr, EntityInst, EntityName, UTime};
use std::collections::{BTreeMap, BTreeSet};

const POOL: &str = "rbd_mirroring";

fn s(v: &str) -> Vec<u8> {
    e(v)
}
fn call_ok(st: &mut MemStore, m: &str, inp: &[u8]) -> Vec<u8> {
    ok(st, POOL, "rbd", m, inp)
}
fn call_err(st: &mut MemStore, m: &str, inp: &[u8], errno: i32) {
    err(st, POOL, "rbd", m, inp, errno)
}
fn u32b(v: u32) -> Vec<u8> {
    v.to_le_bytes().to_vec()
}
fn omap_keys(st: &MemStore, o: &str) -> Vec<String> {
    st.obj(o)
        .map(|o| {
            o.omap
                .keys()
                .map(|k| String::from_utf8_lossy(k).into_owned())
                .collect()
        })
        .unwrap_or_default()
}

fn enabled_pool(st: &mut MemStore) {
    call_ok(st, "mirror_uuid_set", &s("pool-uuid-1"));
    call_ok(st, "mirror_mode_set", &u32b(MODE_IMAGE));
}
fn peer(uuid: &str, site: &str, dir: u8, client: &str, muuid: &str) -> MirrorPeer {
    MirrorPeer {
        uuid: uuid.into(),
        direction: dir,
        site_name: site.into(),
        client_name: client.into(),
        mirror_uuid: muuid.into(),
        last_seen: UTime::default(),
    }
}
fn img(g: &str, state: u8, mode: u8) -> MirrorImage {
    MirrorImage {
        global_image_id: g.into(),
        state,
        mode,
    }
}
fn set_image(st: &mut MemStore, id: &str, m: &MirrorImage) {
    call_ok(st, "mirror_image_set", &cat(&[&s(id), &e(m)]));
}
/// Endpoint of the default test client (what `origin` reports, sanitized).
fn origin_inst(st: &MemStore) -> EntityInst {
    sanitize(EntityInst {
        name: st.env.origin.name,
        addr: st.env.origin.addr,
    })
}
fn watch(st: &mut MemStore, who: EntityInst) {
    let o = st.objects.entry(POOL.into()).or_default();
    o.watchers.push(Watcher {
        name: who.name,
        cookie: 1,
        // watchers report the real (msgr2) address type
        timeout_seconds: 30,
        addr: EntityAddr {
            ty: EntityAddr::TYPE_MSGR2,
            ..who.addr
        },
    });
}

#[test]
fn uuid_mode_namespace() {
    let mut st = MemStore::new();
    call_err(&mut st, "mirror_uuid_get", &[], ENOENT);
    call_err(&mut st, "mirror_mode_get", &[], ENOENT);
    call_err(&mut st, "mirror_remote_namespace_get", &[], ENOENT);
    // enabling needs a uuid
    call_err(&mut st, "mirror_mode_set", &u32b(MODE_IMAGE), EINVAL);
    call_err(&mut st, "mirror_uuid_set", &s(""), EINVAL);
    call_err(&mut st, "mirror_uuid_set", &[1, 2], EINVAL);
    call_ok(&mut st, "mirror_uuid_set", &s("pool-uuid-1"));
    // stored raw (no length prefix), returned encoded
    assert_eq!(
        st.obj(POOL).unwrap().omap[b"mirror_uuid".as_slice()],
        b"pool-uuid-1"
    );
    assert_eq!(
        d::<String>(&call_ok(&mut st, "mirror_uuid_get", &[])),
        "pool-uuid-1"
    );
    call_err(&mut st, "mirror_mode_set", &u32b(7), EINVAL);
    call_err(&mut st, "mirror_mode_set", &[1], EINVAL);
    call_ok(&mut st, "mirror_remote_namespace_set", &s("ns1"));
    assert_eq!(
        d::<String>(&call_ok(&mut st, "mirror_remote_namespace_get", &[])),
        "ns1"
    );
    call_ok(&mut st, "mirror_mode_set", &u32b(MODE_POOL));
    assert_eq!(call_ok(&mut st, "mirror_mode_get", &[]), u32b(MODE_POOL));
    // frozen while enabled
    call_err(&mut st, "mirror_uuid_set", &s("other"), EINVAL);
    call_err(&mut st, "mirror_remote_namespace_set", &s("ns2"), EINVAL);
    call_ok(&mut st, "mirror_mode_set", &u32b(MODE_INIT_ONLY));
    call_ok(&mut st, "mirror_remote_namespace_set", &s("ns2")); // init-only allows it
    // disable: removes mode, uuid and remote namespace (peers must be gone first)
    call_ok(
        &mut st,
        "mirror_peer_add",
        &e(&peer("p1", "siteB", DIR_RX_TX, "client.rbd-mirror", "")),
    );
    call_err(&mut st, "mirror_mode_set", &u32b(MODE_DISABLED), EBUSY);
    call_ok(&mut st, "mirror_peer_remove", &s("p1"));
    call_ok(&mut st, "mirror_peer_remove", &s("p1")); // idempotent
    call_ok(&mut st, "mirror_mode_set", &u32b(MODE_DISABLED));
    assert!(omap_keys(&st, POOL).is_empty());
    call_ok(&mut st, "mirror_mode_set", &u32b(MODE_DISABLED)); // idempotent
}

#[test]
fn peers() {
    let mut st = MemStore::new();
    // peer_list: success with an empty vector on an absent object
    assert_eq!(call_ok(&mut st, "mirror_peer_list", &[]), u32b(0));
    // needs mirroring enabled
    let p1 = peer("uuid-1", "siteB", DIR_RX_TX, "client.admin", "m-b");
    call_err(&mut st, "mirror_peer_add", &e(&p1), EINVAL);
    enabled_pool(&mut st);
    call_err(&mut st, "mirror_peer_add", &[0], EINVAL);
    call_err(
        &mut st,
        "mirror_peer_add",
        &e(&peer("u", "site", DIR_RX, "", "")),
        EINVAL,
    ); // no client
    call_err(
        &mut st,
        "mirror_peer_add",
        &e(&peer("", "site", DIR_RX, "c", "")),
        EINVAL,
    );
    call_err(
        &mut st,
        "mirror_peer_add",
        &e(&peer("u", "", DIR_RX, "c", "")),
        EINVAL,
    );
    call_err(
        &mut st,
        "mirror_peer_add",
        &e(&peer("u", "site", 3, "c", "")),
        EINVAL,
    );
    call_err(
        &mut st,
        "mirror_peer_add",
        &e(&peer("u", "site", DIR_TX, "", "")),
        EINVAL,
    ); // no TX adds
    call_err(
        &mut st,
        "mirror_peer_add",
        &e(&peer("pool-uuid-1", "site", DIR_RX, "c", "")),
        EINVAL,
    );
    call_ok(&mut st, "mirror_peer_add", &e(&p1));
    call_err(&mut st, "mirror_peer_add", &e(&p1), ESTALE);
    call_err(
        &mut st,
        "mirror_peer_add",
        &e(&peer("uuid-2", "siteB", DIR_RX, "c", "")),
        EEXIST,
    );
    call_err(
        &mut st,
        "mirror_peer_add",
        &e(&peer("uuid-2", "siteC", DIR_RX, "c", "m-b")),
        EEXIST,
    );
    let p2 = peer("uuid-2", "siteC", DIR_RX, "client.x", "");
    call_ok(&mut st, "mirror_peer_add", &e(&p2));
    let l: Vec<MirrorPeer> = d(&call_ok(&mut st, "mirror_peer_list", &[]));
    assert_eq!(l, vec![p1.clone(), p2.clone()]);
    // setters
    call_err(
        &mut st,
        "mirror_peer_set_client",
        &cat(&[&s("nope"), &s("c")]),
        ENOENT,
    );
    call_ok(
        &mut st,
        "mirror_peer_set_client",
        &cat(&[&s("uuid-1"), &s("client.new")]),
    );
    call_err(
        &mut st,
        "mirror_peer_set_cluster",
        &cat(&[&s("uuid-1"), &s("siteC")]),
        EEXIST,
    );
    call_err(
        &mut st,
        "mirror_peer_set_cluster",
        &cat(&[&s("zzz"), &s("siteQ")]),
        ENOENT,
    );
    call_ok(
        &mut st,
        "mirror_peer_set_cluster",
        &cat(&[&s("uuid-1"), &s("siteB2")]),
    );
    call_ok(
        &mut st,
        "mirror_peer_set_cluster",
        &cat(&[&s("uuid-1"), &s("siteB2")]),
    ); // own name ok
    call_err(
        &mut st,
        "mirror_peer_set_direction",
        &cat(&[&s("zzz"), &[1]]),
        ENOENT,
    );
    call_ok(
        &mut st,
        "mirror_peer_set_direction",
        &cat(&[&s("uuid-1"), &[DIR_RX]]),
    );
    let l: Vec<MirrorPeer> = d(&call_ok(&mut st, "mirror_peer_list", &[]));
    assert_eq!(txt(&l[0].client_name), "client.new");
    assert_eq!(txt(&l[0].site_name), "siteB2");
    assert_eq!(l[0].direction, DIR_RX);
    call_ok(&mut st, "mirror_peer_remove", &s("uuid-1"));
    assert_eq!(
        omap_keys(&st, POOL)
            .iter()
            .filter(|k| k.starts_with("mirror_peer_"))
            .count(),
        1
    );
}

#[test]
fn peer_encoding_vector() {
    // v2/c1 envelope: uuid, site, client, i64 -1 (legacy pool id), dir u8, mirror_uuid, utime
    let p = MirrorPeer {
        uuid: "u".into(),
        direction: DIR_RX,
        site_name: "s".into(),
        client_name: "c".into(),
        mirror_uuid: "m".into(),
        last_seen: UTime::new(7, 9),
    };
    let mut want = vec![2, 1];
    let body: Vec<u8> = [
        vec![1, 0, 0, 0, b'u'],
        vec![1, 0, 0, 0, b's'],
        vec![1, 0, 0, 0, b'c'],
        vec![0xff; 8],
        vec![DIR_RX],
        vec![1, 0, 0, 0, b'm'],
        vec![7, 0, 0, 0, 9, 0, 0, 0],
    ]
    .concat();
    want.extend((body.len() as u32).to_le_bytes());
    want.extend(body);
    assert_eq!(e(&p), want);
    assert_eq!(d::<MirrorPeer>(&want), p);
    // a v1 peer (no direction / mirror uuid / last_seen) decodes with RX_TX default
    let mut v1 = vec![1, 1];
    let b1: Vec<u8> = [
        vec![1, 0, 0, 0, b'u'],
        vec![1, 0, 0, 0, b's'],
        vec![0, 0, 0, 0],
        vec![0xff; 8],
    ]
    .concat();
    v1.extend((b1.len() as u32).to_le_bytes());
    v1.extend(b1);
    let q: MirrorPeer = d(&v1);
    assert_eq!((q.direction, txt(&q.mirror_uuid)), (DIR_RX_TX, ""));
}

#[test]
fn site_status_vectors() {
    // local site: v1/c1, no uuid
    let local = SiteStatus {
        mirror_uuid: Vec::new(),
        state: 4,
        description: "ok".into(),
        last_update: UTime::new(1, 2),
        up: true,
    };
    let want = [
        vec![1, 1, 16, 0, 0, 0, 4, 2, 0, 0, 0, b'o', b'k'],
        vec![1, 0, 0, 0, 2, 0, 0, 0, 1],
    ]
    .concat();
    assert_eq!(e(&local), want);
    // remote: v2/c2 with uuid first
    let remote = SiteStatus {
        mirror_uuid: "r".into(),
        state: 1,
        ..Default::default()
    };
    let b = e(&remote);
    assert_eq!(&b[..2], &[2, 2]);
    assert_eq!(&b[6..11], &[1, 0, 0, 0, b'r']);
    assert_eq!(d::<SiteStatus>(&b), remote);
    // image status: local first (v1 layout) + valid flag + count + remote (v2 layout)
    let st = ImageStatus {
        sites: vec![remote.clone(), local.clone()],
    };
    let b = e(&st);
    assert_eq!(&b[..2], &[2, 1]);
    let back: ImageStatus = d(&b);
    assert_eq!(back.sites, vec![local, remote]); // local always first
    // no local: default local body, valid=false
    let only_remote = ImageStatus {
        sites: vec![SiteStatus {
            mirror_uuid: "r".into(),
            ..Default::default()
        }],
    };
    let b = e(&only_remote);
    // header(6) + local meta v1 (1+4+8+1=14) + valid(1) + n(4)
    assert_eq!(b[6 + 14], 0);
    assert_eq!(&b[6 + 15..6 + 19], &[1, 0, 0, 0]);
    assert_eq!(d::<ImageStatus>(&b), only_remote);
}

#[test]
fn ping() {
    let mut st = MemStore::new();
    let ping = |st: &mut MemStore, site: &str, mu: &str, dir: u8| {
        call(
            st,
            POOL,
            "rbd",
            "mirror_peer_ping",
            &cat(&[&s(site), &s(mu), &[dir]]),
        )
        .ret
    };
    assert_eq!(ping(&mut st, "siteX", "mx", DIR_TX), EINVAL); // not enabled
    enabled_pool(&mut st);
    assert_eq!(ping(&mut st, "siteX", "mx", DIR_RX), EINVAL); // only TX on the wire
    assert_eq!(ping(&mut st, "", "mx", DIR_TX), EINVAL);
    assert_eq!(ping(&mut st, "siteX", "", DIR_TX), EINVAL);
    // unknown site: auto-registers a TX-only peer with a generated v4 uuid
    assert_eq!(ping(&mut st, "siteX", "mx", DIR_TX), 0);
    let l: Vec<MirrorPeer> = d(&call_ok(&mut st, "mirror_peer_list", &[]));
    assert_eq!(l.len(), 1);
    let p = &l[0];
    assert_eq!(
        (p.direction, txt(&p.site_name), txt(&p.mirror_uuid)),
        (DIR_TX, "siteX", "mx")
    );
    assert_eq!(p.last_seen, st.env.now);
    let u = p.uuid.as_slice();
    assert_eq!(u.len(), 36);
    assert_eq!((u[8], u[13], u[18], u[23]), (b'-', b'-', b'-', b'-'));
    assert_eq!(u[14], b'4');
    // ping again: same peer, time updated
    st.env.now = UTime::new(1_800_000_100, 0);
    assert_eq!(ping(&mut st, "siteX", "mx", DIR_TX), 0);
    let l2: Vec<MirrorPeer> = d(&call_ok(&mut st, "mirror_peer_list", &[]));
    assert_eq!(l2.len(), 1);
    assert_eq!(l2[0].last_seen, UTime::new(1_800_000_100, 0));
    // RX peer registered by an admin without a mirror uuid: ping learns it, RX -> RX_TX
    call_ok(
        &mut st,
        "mirror_peer_add",
        &e(&peer("rx1", "siteR", DIR_RX, "client.m", "")),
    );
    assert_eq!(ping(&mut st, "siteR", "mr", DIR_TX), 0);
    let l: Vec<MirrorPeer> = d(&call_ok(&mut st, "mirror_peer_list", &[]));
    let r = l.iter().find(|p| p.uuid == b"rx1").unwrap();
    assert_eq!((r.direction, txt(&r.mirror_uuid)), (DIR_RX_TX, "mr"));
    // remote renamed its site: matched by mirror uuid, site name follows
    assert_eq!(ping(&mut st, "siteR-new", "mr", DIR_TX), 0);
    let l: Vec<MirrorPeer> = d(&call_ok(&mut st, "mirror_peer_list", &[]));
    assert_eq!(
        txt(&l.iter().find(|p| p.uuid == b"rx1").unwrap().site_name),
        "siteR-new"
    );
    assert_eq!(l.len(), 2);
}

#[test]
fn images() {
    let mut st = MemStore::new();
    call_err(&mut st, "mirror_image_get", &s("i1"), ENOENT);
    call_err(&mut st, "mirror_image_get_image_id", &s("g1"), ENOENT);
    // creating straight into DISABLING answers ENOENT (lost a race with disable)
    call_err(
        &mut st,
        "mirror_image_set",
        &cat(&[&s("i1"), &e(&img("g1", IMG_DISABLING, 0))]),
        ENOENT,
    );
    call_err(&mut st, "mirror_image_set", &[1], EINVAL);
    set_image(&mut st, "i1", &img("g1", IMG_ENABLED, 1));
    set_image(&mut st, "i2", &img("g2", IMG_CREATING, 0));
    set_image(&mut st, "i1", &img("g1", IMG_ENABLED, 1)); // idempotent
    // same global id for another image / other global id for an existing image
    call_err(
        &mut st,
        "mirror_image_set",
        &cat(&[&s("i3"), &e(&img("g1", IMG_ENABLED, 0))]),
        EEXIST,
    );
    call_err(
        &mut st,
        "mirror_image_set",
        &cat(&[&s("i1"), &e(&img("gX", IMG_ENABLED, 0))]),
        EINVAL,
    );
    assert_eq!(
        d::<MirrorImage>(&call_ok(&mut st, "mirror_image_get", &s("i1"))),
        img("g1", IMG_ENABLED, 1)
    );
    assert_eq!(
        d::<String>(&call_ok(&mut st, "mirror_image_get_image_id", &s("g2"))),
        "i2"
    );
    // list pagination
    let l: BTreeMap<String, String> = d(&call_ok(
        &mut st,
        "mirror_image_list",
        &cat(&[&s(""), &u64b(10)]),
    ));
    assert_eq!(
        l,
        BTreeMap::from([("i1".into(), "g1".into()), ("i2".into(), "g2".into())])
    );
    let l: BTreeMap<String, String> = d(&call_ok(
        &mut st,
        "mirror_image_list",
        &cat(&[&s(""), &u64b(1)]),
    ));
    assert_eq!(l.len(), 1);
    let l: BTreeMap<String, String> = d(&call_ok(
        &mut st,
        "mirror_image_list",
        &cat(&[&s("i1"), &u64b(10)]),
    ));
    assert_eq!(l.keys().collect::<Vec<_>>(), ["i2"]);
    let l: BTreeMap<String, String> = d(&call_ok(
        &mut st,
        "mirror_image_list",
        &cat(&[&s(""), &u64b(0)]),
    ));
    assert!(l.is_empty());
    // remove only in DISABLING
    call_err(&mut st, "mirror_image_remove", &s("zz"), ENOENT);
    call_err(&mut st, "mirror_image_remove", &s("i1"), EBUSY);
    set_image(&mut st, "i1", &img("g1", IMG_DISABLING, 1));
    call_ok(&mut st, "mirror_image_remove", &s("i1"));
    assert_eq!(omap_keys(&st, POOL), ["global_g2", "image_i2"]);
}

#[test]
fn status_lifecycle() {
    let mut st = MemStore::new();
    let who = origin_inst(&st);
    set_image(&mut st, "i1", &img("g1", IMG_ENABLED, 1));
    set_image(&mut st, "i2", &img("g2", IMG_ENABLED, 1));
    set_image(&mut st, "i2", &img("g2", IMG_DISABLING, 1));
    let site = |uuid: &str, state: u8, desc: &str| SiteStatus {
        mirror_uuid: uuid.into(),
        state,
        description: desc.into(),
        last_update: UTime::new(1, 1),
        up: true, // ignored on set
    };
    call_err(&mut st, "mirror_image_status_get", &s("g1"), ENOENT);
    // set: silently ignored for unknown / disabling images
    call_ok(
        &mut st,
        "mirror_image_status_set",
        &cat(&[&s("gUnknown"), &e(&site("", 4, "x"))]),
    );
    call_ok(
        &mut st,
        "mirror_image_status_set",
        &cat(&[&s("g2"), &e(&site("", 4, "x"))]),
    );
    assert_eq!(
        omap_keys(&st, POOL)
            .iter()
            .filter(|k| k.contains("status"))
            .count(),
        0
    );
    call_err(&mut st, "mirror_image_status_set", &s("g1"), EINVAL);
    st.env.now = UTime::new(1_800_000_001, 7);
    call_ok(
        &mut st,
        "mirror_image_status_set",
        &cat(&[&s("g1"), &e(&site("", 4, "replaying"))]),
    );
    call_ok(
        &mut st,
        "mirror_image_status_set",
        &cat(&[&s("g1"), &e(&site("peer-a", 2, "syncing"))]),
    );
    assert_eq!(
        omap_keys(&st, POOL)
            .into_iter()
            .filter(|k| k.contains("status"))
            .collect::<Vec<_>>(),
        ["remote_status_global_g1_peer-a", "status_global_g1"]
    );
    // stored value: origin envelope + site-status envelope (v1, uuid cleared, up=false, now)
    let raw = &st.obj(POOL).unwrap().omap[b"status_global_g1".as_slice()];
    let od: OnDiskStatus = d(raw);
    assert_eq!(od.origin, who);
    assert_eq!(od.origin.addr.ty, EntityAddr::TYPE_ANY);
    assert_eq!(
        (od.status.up, od.status.last_update),
        (false, UTime::new(1_800_000_001, 7))
    );
    assert_eq!(txt(&od.status.mirror_uuid), "");
    assert_eq!(raw[..2], [1, 1]);

    // no watcher: everything down
    let g: ImageStatus = d(&call_ok(&mut st, "mirror_image_status_get", &s("g1")));
    assert_eq!(g.sites.len(), 2);
    assert!(g.sites.iter().all(|x| !x.up));
    assert_eq!(txt(&g.sites[0].mirror_uuid), "");
    assert_eq!(txt(&g.sites[1].mirror_uuid), "peer-a");
    assert_eq!(txt(&g.sites[1].description), "syncing");
    call_err(&mut st, "mirror_image_instance_get", &s("g1"), ESTALE);
    call_err(&mut st, "mirror_image_instance_get", &s("gNone"), ENOENT);
    // watcher registered (with a different address TYPE: must still match)
    watch(&mut st, who);
    let g: ImageStatus = d(&call_ok(&mut st, "mirror_image_status_get", &s("g1")));
    assert!(g.sites.iter().all(|x| x.up));
    let inst: EntityInst = d(&call_ok(&mut st, "mirror_image_instance_get", &s("g1")));
    assert_eq!(inst.name, EntityName::client(4123));
    // list: statuses only for images that have one
    let out = call_ok(
        &mut st,
        "mirror_image_status_list",
        &cat(&[&s(""), &u64b(10)]),
    );
    let mut dec = denc::Decoder::new(&out);
    let imgs: BTreeMap<String, MirrorImage> = denc::Decode::decode(&mut dec).unwrap();
    let sts: BTreeMap<String, ImageStatus> = denc::Decode::decode(&mut dec).unwrap();
    assert_eq!(imgs.keys().collect::<Vec<_>>(), ["i1", "i2"]);
    assert_eq!(sts.keys().collect::<Vec<_>>(), ["i1"]);
    let il: BTreeMap<String, EntityInst> = d(&call_ok(
        &mut st,
        "mirror_image_instance_list",
        &cat(&[&s(""), &u64b(10)]),
    ));
    assert_eq!(il.keys().collect::<Vec<_>>(), ["i1"]);
    let il: BTreeMap<String, EntityInst> = d(&call_ok(
        &mut st,
        "mirror_image_instance_list",
        &cat(&[&s(""), &u64b(0)]),
    ));
    assert!(il.is_empty());

    // remove_down keeps live origins, drops stale ones
    call_ok(&mut st, "mirror_image_status_remove_down", &[]);
    assert_eq!(
        omap_keys(&st, POOL)
            .iter()
            .filter(|k| k.contains("status"))
            .count(),
        2
    );
    st.objects.get_mut(POOL).unwrap().watchers.clear();
    call_ok(&mut st, "mirror_image_status_remove_down", &[]);
    assert_eq!(
        omap_keys(&st, POOL)
            .iter()
            .filter(|k| k.contains("status"))
            .count(),
        0
    );
    // status_remove drops local + all remotes; image_remove also clears them
    call_ok(
        &mut st,
        "mirror_image_status_set",
        &cat(&[&s("g1"), &e(&site("", 4, "a"))]),
    );
    call_ok(
        &mut st,
        "mirror_image_status_set",
        &cat(&[&s("g1"), &e(&site("p", 4, "a"))]),
    );
    call_ok(&mut st, "mirror_image_status_remove", &s("g1"));
    assert_eq!(
        omap_keys(&st, POOL)
            .iter()
            .filter(|k| k.contains("status"))
            .count(),
        0
    );
    call_ok(&mut st, "mirror_image_status_remove", &s("g1")); // idempotent
    call_ok(
        &mut st,
        "mirror_image_status_set",
        &cat(&[&s("g1"), &e(&site("p", 4, "a"))]),
    );
    set_image(&mut st, "i1", &img("g1", IMG_DISABLING, 1));
    call_ok(&mut st, "mirror_image_remove", &s("i1"));
    assert_eq!(omap_keys(&st, POOL), ["global_g2", "image_i2"]);
}

fn states(out: &[u8]) -> BTreeMap<u8, i32> {
    d(out)
}

#[test]
fn status_summary() {
    let mut st = MemStore::new();
    let who = origin_inst(&st);
    for (i, g) in ["g1", "g2", "g3"].iter().enumerate() {
        set_image(&mut st, &format!("i{i}"), &img(g, IMG_ENABLED, 1));
    }
    let site = |uuid: &str, state: u8| SiteStatus {
        mirror_uuid: uuid.into(),
        state,
        ..Default::default()
    };
    let set = |st: &mut MemStore, g: &str, uuid: &str, state: u8| {
        call_ok(
            st,
            "mirror_image_status_set",
            &cat(&[&s(g), &e(&site(uuid, state))]),
        );
    };
    set(&mut st, "g1", "", 4); // replaying
    set(&mut st, "g2", "", 1); // error
    // g3 has no status
    // not watching: all UNKNOWN (RX default, no peers input)
    assert_eq!(
        states(&call_ok(&mut st, "mirror_image_status_get_summary", &[])),
        BTreeMap::from([(0, 3)])
    );
    watch(&mut st, who);
    assert_eq!(
        states(&call_ok(&mut st, "mirror_image_status_get_summary", &[])),
        BTreeMap::from([(0, 1), (1, 1), (4, 1)])
    );
    // TX peer "m-b": remote status counts, unmatched TX peer forces UNKNOWN
    let tx = vec![peer("t1", "siteB", DIR_TX, "", "m-b")];
    let inp = e(&tx);
    assert_eq!(
        states(&call_ok(&mut st, "mirror_image_status_get_summary", &inp)),
        BTreeMap::from([(0, 3)])
    );
    set(&mut st, "g1", "m-b", 4);
    set(&mut st, "g2", "m-b", 2);
    set(&mut st, "g3", "m-b", 1);
    assert_eq!(
        states(&call_ok(&mut st, "mirror_image_status_get_summary", &inp)),
        BTreeMap::from([(1, 1), (2, 1), (4, 1)])
    );
    // RX_TX: local + remote combined (error wins, otherwise the minimum)
    let both = e(&vec![peer("t1", "siteB", DIR_RX_TX, "c", "m-b")]);
    assert_eq!(
        states(&call_ok(&mut st, "mirror_image_status_get_summary", &both)),
        BTreeMap::from([(1, 2), (4, 1)])
    );
    call_err(&mut st, "mirror_image_status_get_summary", &[5, 5], EINVAL);
}

#[test]
fn instances_and_map() {
    let mut st = MemStore::new();
    assert_eq!(call_ok(&mut st, "mirror_instances_list", &[]), u32b(0));
    call_ok(&mut st, "mirror_instances_add", &s("4711"));
    call_ok(&mut st, "mirror_instances_add", &s("100"));
    call_ok(&mut st, "mirror_instances_add", &s("100"));
    assert_eq!(
        d::<Vec<String>>(&call_ok(&mut st, "mirror_instances_list", &[])),
        ["100", "4711"]
    );
    assert!(st.obj(POOL).unwrap().omap[b"instance_100".as_slice()].is_empty());
    call_ok(&mut st, "mirror_instances_remove", &s("100"));
    call_ok(&mut st, "mirror_instances_remove", &s("100"));
    assert_eq!(
        d::<Vec<String>>(&call_ok(&mut st, "mirror_instances_list", &[])),
        ["4711"]
    );

    let m1 = ImageMap {
        instance_id: "4711".into(),
        mapped_time: UTime::new(5, 6),
        data: vec![1, 2, 3],
    };
    call_ok(
        &mut st,
        "mirror_image_map_update",
        &cat(&[&s("g1"), &e(&m1)]),
    );
    call_ok(
        &mut st,
        "mirror_image_map_update",
        &cat(&[&s("g2"), &e(&ImageMap::default())]),
    );
    // envelope v1/c1: id, utime, bufferlist
    assert_eq!(
        st.obj(POOL).unwrap().omap[b"image_map_g1".as_slice()],
        [
            vec![1, 1, 23, 0, 0, 0],
            vec![4, 0, 0, 0],
            b"4711".to_vec(),
            vec![5, 0, 0, 0, 6, 0, 0, 0],
            vec![3, 0, 0, 0, 1, 2, 3]
        ]
        .concat()
    );
    let l: BTreeMap<String, ImageMap> = d(&call_ok(
        &mut st,
        "mirror_image_map_list",
        &cat(&[&s(""), &u64b(10)]),
    ));
    assert_eq!(l.len(), 2);
    assert_eq!(l["g1"], m1);
    let l: BTreeMap<String, ImageMap> = d(&call_ok(
        &mut st,
        "mirror_image_map_list",
        &cat(&[&s("g1"), &u64b(10)]),
    ));
    assert_eq!(l.keys().collect::<Vec<_>>(), ["g2"]);
    call_ok(&mut st, "mirror_image_map_remove", &s("g1"));
    call_ok(&mut st, "mirror_image_map_remove", &s("g1"));
    // corrupt payload -> EINVAL (not EIO)
    st.objects
        .get_mut(POOL)
        .unwrap()
        .omap
        .insert(b"image_map_g9".to_vec(), vec![1]);
    call_err(
        &mut st,
        "mirror_image_map_list",
        &cat(&[&s(""), &u64b(10)]),
        EINVAL,
    );
}

#[test]
fn snapshot_bookkeeping() {
    let mut st = MemStore::new();
    let hdr = "rbd_header.abc";
    ok(
        &mut st,
        hdr,
        "rbd",
        "create",
        &cat(&[&u64b(1 << 22), &[22], &u64b(1), &s("rbd_data.abc")]),
    );
    let mir = |state: u8, peers: &[&str]| SnapNs::Mirror {
        state,
        complete: false,
        peer_uuids: peers
            .iter()
            .map(|p| p.as_bytes().to_vec())
            .collect::<BTreeSet<_>>(),
        primary_mirror_uuid: "pm".into(),
        primary_snap_id: 9,
        last_copied_object_number: 0,
        snap_seqs: BTreeMap::from([(3, 4)]),
    };
    ok(
        &mut st,
        hdr,
        "rbd",
        "snapshot_add",
        &cat(&[&s("m-prim"), &u64b(1), &e(&mir(0, &["p1", "p2"]))]),
    );
    ok(
        &mut st,
        hdr,
        "rbd",
        "snapshot_add",
        &cat(&[&s("m-non"), &u64b(2), &e(&mir(2, &[]))]),
    );
    ok(
        &mut st,
        hdr,
        "rbd",
        "snapshot_add",
        &cat(&[&s("user"), &u64b(3)]),
    );
    // snapshot_get returns the namespace unchanged
    let info: SnapshotInfo = d(&ok(&mut st, hdr, "rbd", "snapshot_get", &u64b(1)));
    assert_eq!(info.ns, mir(0, &["p1", "p2"]));
    // same name, different namespace content is a different snapshot only when ns differs
    err(
        &mut st,
        hdr,
        "rbd",
        "snapshot_add",
        &cat(&[&s("m-prim"), &u64b(4), &e(&mir(0, &["p1", "p2"]))]),
        EEXIST,
    );
    ok(
        &mut st,
        hdr,
        "rbd",
        "snapshot_add",
        &cat(&[&s("m-prim"), &u64b(5), &e(&mir(0, &["p1"]))]),
    );

    let unlink = |st: &mut MemStore, id: u64, p: &str| {
        call(
            st,
            hdr,
            "rbd",
            "mirror_image_snapshot_unlink_peer",
            &cat(&[&u64b(id), &s(p)]),
        )
        .ret
    };
    assert_eq!(unlink(&mut st, 1, "p1"), 0);
    assert_eq!(unlink(&mut st, 1, "p1"), ENOENT); // already unlinked
    assert_eq!(unlink(&mut st, 3, "p1"), EINVAL); // user snapshot
    assert_eq!(unlink(&mut st, 99, "p1"), ENOENT);
    let info: SnapshotInfo = d(&ok(&mut st, hdr, "rbd", "snapshot_get", &u64b(1)));
    assert_eq!(info.ns, mir(0, &["p2"]));

    let prog = |st: &mut MemStore, id: u64, done: bool, n: u64| {
        call(
            st,
            hdr,
            "rbd",
            "mirror_image_snapshot_set_copy_progress",
            &cat(&[&u64b(id), &[done as u8], &u64b(n)]),
        )
        .ret
    };
    assert_eq!(prog(&mut st, 2, false, 17), 0); // non-primary: position tracked
    let SnapNs::Mirror {
        complete,
        last_copied_object_number,
        ..
    } = d::<SnapshotInfo>(&ok(&mut st, hdr, "rbd", "snapshot_get", &u64b(2))).ns
    else {
        panic!()
    };
    assert_eq!((complete, last_copied_object_number), (false, 17));
    assert_eq!(prog(&mut st, 2, true, 40), 0);
    assert_eq!(prog(&mut st, 1, true, 40), 0); // primary: only `complete` changes
    let SnapNs::Mirror {
        complete,
        last_copied_object_number,
        ..
    } = d::<SnapshotInfo>(&ok(&mut st, hdr, "rbd", "snapshot_get", &u64b(1))).ns
    else {
        panic!()
    };
    assert_eq!((complete, last_copied_object_number), (true, 0));
    assert_eq!(prog(&mut st, 3, true, 1), EINVAL);
    assert_eq!(prog(&mut st, 77, true, 1), ENOENT);
    assert_eq!(
        call(
            &mut st,
            hdr,
            "rbd",
            "mirror_image_snapshot_set_copy_progress",
            &u64b(1)
        )
        .ret,
        EINVAL
    );
}

/// Random / truncated inputs against empty, populated and corrupted pool + header objects: never
/// panic, failing calls leave the committed state untouched.
#[test]
fn fuzz_mirror_inputs() {
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }
    let populated = || {
        let mut st = MemStore::new();
        enabled_pool(&mut st);
        let who = origin_inst(&st);
        call_ok(
            &mut st,
            "mirror_peer_add",
            &e(&peer("p1", "siteB", DIR_RX_TX, "c", "m-b")),
        );
        set_image(&mut st, "i1", &img("g1", IMG_ENABLED, 1));
        let site = SiteStatus {
            state: 4,
            ..Default::default()
        };
        call_ok(
            &mut st,
            "mirror_image_status_set",
            &cat(&[&s("g1"), &e(&site)]),
        );
        call_ok(&mut st, "mirror_instances_add", &s("7"));
        call_ok(
            &mut st,
            "mirror_image_map_update",
            &cat(&[&s("g1"), &e(&ImageMap::default())]),
        );
        watch(&mut st, who);
        st
    };
    let valid: Vec<Vec<u8>> = vec![
        cat(&[&s("g1"), &e(&SiteStatus::default())]),
        cat(&[&s("i1"), &e(&img("g1", 1, 0))]),
        cat(&[&s(""), &u64b(5)]),
        e(&peer("p9", "s9", DIR_RX, "c", "m9")),
        cat(&[&s("s9"), &s("m9"), &[1]]),
        cat(&[&u64b(1), &[1], &u64b(3)]),
        e(&vec![peer("p1", "siteB", DIR_TX, "", "m-b")]),
    ];
    let names: Vec<&str> = cls::methods("rbd")
        .iter()
        .map(|m| m.name)
        .filter(|n| n.starts_with("mirror_"))
        .collect();
    assert!(
        names.len() >= 34,
        "{} mirror methods registered",
        names.len()
    );
    let mut rng = Rng(0xfeed_f00d_1234_5678);
    for name in names {
        for round in 0..80 {
            let input: Vec<u8> = if round % 3 == 0 {
                (0..rng.next() % 64).map(|_| rng.next() as u8).collect()
            } else {
                let v = &valid[(rng.next() % valid.len() as u64) as usize];
                let cut = (rng.next() % (v.len() as u64 + 1)) as usize;
                let mut v = v[..cut].to_vec();
                if round % 3 == 2 && !v.is_empty() {
                    let i = (rng.next() % v.len() as u64) as usize;
                    v[i] ^= 1 << (rng.next() % 8);
                }
                v
            };
            for mk in 0..3 {
                let mut st = match mk {
                    0 => MemStore::new(),
                    1 => populated(),
                    _ => {
                        let mut st = populated();
                        for v in st.objects.get_mut(POOL).unwrap().omap.values_mut() {
                            v.truncate(v.len() / 2);
                        }
                        st
                    }
                };
                let before = st.objects.clone();
                let r = call(&mut st, POOL, "rbd", name, &input);
                if r.ret < 0 {
                    assert_eq!(st.objects, before, "{name}: failed call changed state");
                }
            }
        }
    }
}

/// Removes on an absent `rbd_mirroring` object succeed (classic ignores ENOENT from the key removal there):
/// mirror_mode_set(DISABLED) on a never-enabled pool, peer_remove, image_map_remove, image_status_remove.
#[test]
fn removes_on_absent_object_succeed() {
    let mut st = MemStore::new();
    call_ok(&mut st, "mirror_mode_set", &u32b(MODE_DISABLED));
    call_ok(&mut st, "mirror_peer_remove", &s("no-such-peer"));
    call_ok(&mut st, "mirror_image_map_remove", &s("gid"));
    call_ok(&mut st, "mirror_image_status_remove", &s("gid"));
    assert!(st.obj(POOL).is_none(), "nothing created");
}
