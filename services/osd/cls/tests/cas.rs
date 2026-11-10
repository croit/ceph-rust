// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! cas scenarios (spec/cls_cas.md) on MemStore.
mod common;
use cls::cas::*;
use cls::errno::*;
use cls::mem::MemStore;
use common::*;
use denc::types::{Hobject, SnapId};

const O: &str = "chunk";

fn ho(name: &str, hash: u32, pool: i64) -> Hobject {
    Hobject::new(name.as_bytes(), SnapId::NOSNAP, hash, pool, b"")
}
fn create(s: &mut MemStore, src: &Hobject, flags: u64, data: &[u8]) -> cls::Reply {
    let op = CreateOrGetRefOp {
        source: src.clone(),
        flags,
        data: data.to_vec(),
    };
    call(s, O, "cas", "chunk_create_or_get_ref", &e(&op))
}
fn get(s: &mut MemStore, src: &Hobject) -> cls::Reply {
    call(
        s,
        O,
        "cas",
        "chunk_get_ref",
        &e(&RefOp {
            source: src.clone(),
        }),
    )
}
fn put(s: &mut MemStore, src: &Hobject) -> cls::Reply {
    call(
        s,
        O,
        "cas",
        "chunk_put_ref",
        &e(&RefOp {
            source: src.clone(),
        }),
    )
}
fn refs(s: &MemStore) -> ChunkRefs {
    d(&s.obj(O).unwrap().xattrs[ATTR.as_bytes()])
}

#[test]
fn registry() {
    use cls::registry::*;
    assert_eq!(methods("cas").len(), 4);
    for m in ["chunk_create_or_get_ref", "chunk_get_ref", "chunk_put_ref"] {
        assert_eq!(lookup("cas", m).unwrap().flags, RW);
    }
    assert_eq!(lookup("cas", "references_chunk").unwrap().flags, RD);
}

#[test]
fn exact_xattr_bytes() {
    let mut s = MemStore::new();
    assert_eq!(create(&mut s, &ho("foo", 7, 3), 0, b"DATA").ret, 0);
    assert_eq!(s.obj(O).unwrap().data, b"DATA");
    let hobj = cat(&[
        &[4, 3, 36, 0, 0, 0],
        &[0, 0, 0, 0],
        &[3, 0, 0, 0, b'f', b'o', b'o'],
        &u64b(u64::MAX - 1),
        &7u32.to_le_bytes(),
        &[0],
        &[0, 0, 0, 0],
        &u64b(3),
    ]);
    let want = cat(&[
        &[1, 1, 53, 0, 0, 0, 1, 1, 1, 46, 0, 0, 0, 1, 0, 0, 0],
        &hobj,
    ]);
    assert_eq!(s.obj(O).unwrap().xattrs[ATTR.as_bytes()], want);
}

#[test]
fn lifecycle() {
    let mut s = MemStore::new();
    let (a, b) = (ho("a", 1, 3), ho("b", 2, 3));
    assert_eq!(create(&mut s, &a, 0, b"X").ret, 0);
    // existing chunk: data ignored without VERIFY, ref added
    assert_eq!(create(&mut s, &b, 0, b"IGNORED").ret, 0);
    assert_eq!(s.obj(O).unwrap().data, b"X");
    assert_eq!(get(&mut s, &a).ret, 0);
    assert_eq!(refs(&s).count(), 3);
    // VERIFY
    assert_eq!(create(&mut s, &b, FLAG_VERIFY, b"Y").ret, ENOMSG);
    assert_eq!(create(&mut s, &b, FLAG_VERIFY, b"X").ret, 0);
    assert_eq!(refs(&s).count(), 4);
    // puts
    assert_eq!(put(&mut s, &ho("zz", 9, 3)).ret, ENOLINK);
    for _ in 0..2 {
        assert_eq!(put(&mut s, &a).ret, 0);
    }
    assert_eq!(put(&mut s, &a).ret, ENOLINK, "a only held twice");
    assert_eq!(put(&mut s, &b).ret, 0);
    assert!(s.obj(O).is_some());
    assert_eq!(put(&mut s, &b).ret, 0);
    assert!(s.obj(O).is_none(), "last ref removes the chunk");
    assert_eq!(put(&mut s, &b).ret, ENOENT);
    assert_eq!(get(&mut s, &b).ret, ENOENT);
}

#[test]
fn multiset_is_hobject_ordered() {
    let mut s = MemStore::new();
    // bitwise (bit-reversed hash) ordering: hash 1 -> 0x80000000 sorts after hash 2 -> 0x40000000
    let (x, y) = (ho("x", 1, 3), ho("y", 2, 3));
    create(&mut s, &x, 0, b"D");
    get(&mut s, &y);
    match refs(&s) {
        ChunkRefs::ByObject(v) => assert_eq!(v, vec![y, x]),
        o => panic!("{o:?}"),
    }
}

#[test]
fn decode_other_resolutions() {
    // BY_HASH, 8 bits: total 2, one key (pool 1, hash 0xAB) count 2
    let by_hash = [1, 1, 13, 0, 0, 0, 2, 1, 1, 6, 0, 0, 0, 2, 8, 1, 2, 0xAB, 2];
    let mut s = MemStore::new();
    create(&mut s, &ho("seed", 1, 1), 0, b"D");
    s.objects
        .get_mut(O)
        .unwrap()
        .xattrs
        .insert(ATTR.into(), by_hash.to_vec());
    assert_eq!(
        refs(&s),
        ChunkRefs::ByHash {
            total: 2,
            hash_bits: 8,
            map: [((1, 0xAB), 2)].into()
        }
    );
    // reference from pool 1 with a hash that masks to 0xAB: decrement, then removal at zero
    assert_eq!(put(&mut s, &ho("o", 0x1234_00AB, 1)).ret, 0);
    assert_eq!(refs(&s).count(), 1);
    assert_eq!(
        put(&mut s, &ho("o", 0x00FF_00AB, 2)).ret,
        ENOLINK,
        "other pool"
    );
    assert_eq!(get(&mut s, &ho("p", 0x55, 1)).ret, 0, "new key");
    assert_eq!(refs(&s).count(), 2);
    assert_eq!(put(&mut s, &ho("o", 0xAB, 1)).ret, 0);
    assert_eq!(put(&mut s, &ho("q", 0x55, 1)).ret, 0);
    assert!(s.obj(O).is_none());

    // BY_POOL: total 3, pools 1 -> 2, -5 -> 1 (signed varints 2 and 11)
    let by_pool = [1, 1, 13, 0, 0, 0, 4, 1, 1, 6, 0, 0, 0, 3, 2, 2, 2, 11, 1];
    let mut s = MemStore::new();
    create(&mut s, &ho("seed", 1, 1), 0, b"D");
    s.objects
        .get_mut(O)
        .unwrap()
        .xattrs
        .insert(ATTR.into(), by_pool.to_vec());
    assert_eq!(
        refs(&s),
        ChunkRefs::ByPool {
            total: 3,
            map: [(1, 2), (-5, 1)].into()
        }
    );
    assert_eq!(put(&mut s, &ho("a", 0, -5)).ret, 0);
    assert_eq!(put(&mut s, &ho("a", 0, -5)).ret, ENOLINK);
    assert_eq!(get(&mut s, &ho("a", 0, 9)).ret, 0);
    // re-encode round trip is stable
    let raw = s.obj(O).unwrap().xattrs[ATTR.as_bytes()].clone();
    assert_eq!(e(&d::<ChunkRefs>(&raw)), raw);

    // COUNT: total 2; zero resets to an empty by_object set (-> object removal)
    let count = [
        1, 1, 15, 0, 0, 0, 5, 1, 1, 8, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0,
    ];
    let mut s = MemStore::new();
    create(&mut s, &ho("seed", 1, 1), 0, b"D");
    s.objects
        .get_mut(O)
        .unwrap()
        .xattrs
        .insert(ATTR.into(), count[..].to_vec());
    assert_eq!(refs(&s), ChunkRefs::Count(2));
    assert_eq!(put(&mut s, &ho("x", 0, 0)).ret, 0);
    assert_eq!(refs(&s), ChunkRefs::Count(1));
    assert_eq!(put(&mut s, &ho("x", 0, 0)).ret, 0);
    assert!(s.obj(O).is_none());
}

#[test]
fn hash_bits_roundtrip() {
    for bits in [0u32, 1, 8, 17, 32] {
        let m = if bits == 0 {
            0
        } else {
            u32::MAX >> (32 - bits)
        };
        let r = ChunkRefs::ByHash {
            total: 5,
            hash_bits: bits,
            map: [((2, 0xDEAD_BEEF & m), 5)].into(),
        };
        assert_eq!(d::<ChunkRefs>(&e(&r)), r, "bits {bits}");
    }
}

#[test]
fn malformed_stored_and_inputs() {
    let mut s = MemStore::new();
    create(&mut s, &ho("seed", 1, 1), 0, b"D");
    for bad in [
        vec![1, 1, 1, 0, 0, 0, 3],                      // BY_PARTIAL / unknown type
        vec![1, 1, 1, 0, 0, 0, 9],                      // unknown type
        vec![1, 1, 8, 0, 0, 0, 2, 1, 1, 2, 0, 0, 0, 0], // truncated
        vec![1, 1, 7, 0, 0, 0, 2, 1, 1, 1, 0, 0, 0, 33], // hash_bits 33
        vec![],
    ] {
        s.objects
            .get_mut(O)
            .unwrap()
            .xattrs
            .insert(ATTR.into(), bad);
        let before = s.objects.clone();
        assert_eq!(get(&mut s, &ho("a", 1, 1)).ret, EIO);
        assert_eq!(put(&mut s, &ho("a", 1, 1)).ret, EIO);
        assert_eq!(create(&mut s, &ho("a", 1, 1), 0, b"").ret, EIO);
        assert_eq!(s.objects, before);
    }
    for m in [
        "chunk_create_or_get_ref",
        "chunk_get_ref",
        "chunk_put_ref",
        "references_chunk",
    ] {
        err(&mut s, O, "cas", m, &[1, 2, 3], EINVAL);
    }
}

#[test]
fn references_chunk_is_enolink() {
    let mut s = MemStore::new();
    create(&mut s, &ho("seed", 1, 1), 0, b"D");
    let fp = cat(&[&3u32.to_le_bytes(), b"abc"]);
    err(&mut s, O, "cas", "references_chunk", &fp, ENOLINK);
}

#[test]
fn existing_object_without_attr_counts_as_chunk() {
    let mut s = MemStore::new();
    s.objects.insert(
        O.into(),
        cls::mem::Obj {
            data: b"Z".to_vec(),
            ..Default::default()
        },
    );
    assert_eq!(create(&mut s, &ho("a", 1, 1), FLAG_VERIFY, b"Z").ret, 0);
    assert_eq!(refs(&s).count(), 1);
    assert_eq!(s.obj(O).unwrap().data, b"Z");
}
