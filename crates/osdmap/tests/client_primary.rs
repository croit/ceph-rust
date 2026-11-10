// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Own vectors from rados-client/ec-primary-routing.md (both pinned versions).
use denc::types::{PgT, ShardId};
use osdmap::{
    OsdMap, PgMapping, PgPool, PgWatch,
    consts::osd_state,
    pool::{TYPE_ERASURE, flags},
};

fn map() -> OsdMap {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/osdmap/full/0091.bin");
    let mut m = OsdMap::decode_from(&std::fs::read(fixture).unwrap()).unwrap();
    m.pools.clear();
    m.pg_temp.clear();
    m.primary_temp.clear();
    m.set_max_osd(50);
    m.osd_state.fill(osd_state::EXISTS | osd_state::UP);
    m.pools.insert(
        701,
        PgPool {
            ptype: TYPE_ERASURE,
            size: 6,
            pg_num: 8,
            pgp_num: 4,
            ..Default::default()
        },
    );
    m.epoch = 1;
    m
}
fn mapping(acting: &[i32], primary: i32) -> PgMapping {
    PgMapping {
        acting: acting.to_vec(),
        acting_primary: primary,
        ..PgMapping::empty()
    }
}
#[test]
fn pinned_common_primary_shard_vectors() {
    let mut m = map();
    let pg = PgT::new(701, 5);
    for (acting, primary, shard) in [
        (vec![14, 27, 31], 27, 1),
        (vec![osdmap::consts::ITEM_NONE, 27, 31], 27, 1),
    ] {
        assert_eq!(
            m.primary_destination(pg, &mapping(&acting, primary))
                .unwrap()
                .shard,
            ShardId(shard)
        );
    }
    let acting = [osdmap::consts::ITEM_NONE, 37, 21, 24, 37, 42];
    let p = m.pools.get_mut(&701).unwrap();
    p.flags |= flags::EC_OPTIMIZATIONS;
    for s in [1, 2, 3] {
        p.nonprimary_shards.insert(s);
    }
    assert_eq!(
        m.primary_destination(pg, &mapping(&acting, 37))
            .unwrap()
            .shard,
        ShardId(1)
    );
    m.pg_temp
        .insert(pg, vec![osdmap::consts::ITEM_NONE, 37, 42, 37, 21, 24]);
    assert_eq!(
        m.primary_destination(pg, &mapping(&acting, 37))
            .unwrap()
            .shard,
        ShardId(4)
    );
    m.pools.get_mut(&701).unwrap().ptype = osdmap::pool::TYPE_REPLICATED;
    assert_eq!(
        m.primary_destination(pg, &mapping(&acting, 37))
            .unwrap()
            .shard,
        ShardId::NO_SHARD
    );
}
#[test]
fn absent_primary_invalid_pg_removed_pool_and_down_osd_are_passive() {
    let mut m = map();
    let pg = PgT::new(701, 5);
    for a in [mapping(&[], -1), mapping(&[14, 27], 31)] {
        assert_eq!(m.primary_destination(pg, &a), None);
    }
    let a = mapping(&[14, 27], 27);
    assert_eq!(m.primary_destination(PgT::new(701, 8), &a), None);
    m.osd_state[27] = osd_state::EXISTS;
    assert_eq!(m.primary_destination(pg, &a), None);
    m.pools.clear();
    assert_eq!(m.primary_destination(pg, &a), None);
}
#[test]
fn interval_detects_same_osd_and_canonical_vector_with_changed_primary_shard() {
    let mut a = map();
    let pg = PgT::new(701, 5);
    // All entries identical so eligibility metadata changes the selected shard,
    // while both canonical acting and primary OSD stay unchanged.
    a.pg_temp.insert(pg, vec![37; 6]);
    let p = a.pools.get_mut(&701).unwrap();
    p.flags |= flags::EC_OPTIMIZATIONS;
    let mut b = a.clone();
    b.epoch += 1;
    b.pools.get_mut(&701).unwrap().nonprimary_shards.insert(0);
    assert_eq!(a.pg_to_up_acting(pg), b.pg_to_up_acting(pg));
    assert_eq!(
        a.primary_destination(pg, &a.pg_to_up_acting(pg))
            .unwrap()
            .shard,
        ShardId(0)
    );
    assert_eq!(
        b.primary_destination(pg, &b.pg_to_up_acting(pg))
            .unwrap()
            .shard,
        ShardId(1)
    );
    let mut w = PgWatch::default();
    w.observe(None, &a);
    w.track(pg, a.epoch);
    w.observe(Some(&a), &b);
    assert_eq!(w.interval_since(pg), Some(2));
}

#[test]
fn distinct_pool_ids_and_pg_num_not_pgp_num_resolve_actual_pg() {
    use osdmap::mapping::testing::FixedMapper;
    let mut m = map();
    let pool = m.pool(701).unwrap();
    let raw = m
        .object_to_raw_pg(701, b"data", b"key", b"namespace", 13)
        .unwrap();
    let pg = pool.raw_pg_to_pg(raw);
    assert_eq!(pg, PgT::new(701, 5));
    // Unhashed placement adds the pool id after the pgp_num reduction.
    assert_eq!(pool.raw_pg_to_pps(pg), 702);
    let mut other = pool.clone();
    other.pg_num = 16;
    m.pools.insert(1701, other);
    m.pg_temp.insert(pg, vec![14, 27, 31]);
    m.primary_temp.insert(pg, 27);
    m.pg_temp.insert(PgT::new(701, 1), vec![31, 14, 27]);
    m.pg_temp.insert(PgT::new(1701, 5), vec![31, 14, 27]);
    let mapper = FixedMapper(vec![14, 27, 31]);
    let a = m
        .primary_destination(pg, &m.pg_to_up_acting_with(&mapper, pg))
        .unwrap();
    let other_pg = PgT::new(1701, 5);
    let b = m
        .primary_destination(other_pg, &m.pg_to_up_acting_with(&mapper, other_pg))
        .unwrap();
    assert_eq!((a.osd, a.shard), (27, ShardId(1)));
    assert_eq!((b.osd, b.shard), (31, ShardId(0)));
}

#[test]
fn malformed_optimized_temp_cannot_prove_a_canonical_shard() {
    let mut m = map();
    let pg = PgT::new(701, 5);
    m.pools.get_mut(&701).unwrap().flags |= flags::EC_OPTIMIZATIONS;
    m.pg_temp.insert(pg, vec![14, 27, 31]);
    assert_eq!(m.primary_destination(pg, &mapping(&[14, 27, 31], 27)), None);
    m.pg_temp.insert(pg, vec![14, 27, 31, 37, 42, 21]);
    m.pools.get_mut(&701).unwrap().nonprimary_shards.insert(99);
    assert_eq!(
        m.primary_destination(pg, &mapping(&[14, 27, 31, 37, 42, 21], 27)),
        None
    );
}

/// Optimized EC with a permuted chunk mapping (`nonprimary_shards` not `{1..N}`): the primary shard is
/// the canonical slot of the first primary-capable occurrence, i.e. the PG shard that OSD really hosts.
/// The reference client converts the primary-first index with an arithmetic undo that is only the
/// inverse of the vector reorder for contiguous sets; for the sets below it names a shard the primary
/// does not host (the OSD drops the op as misdirected). We route to the hosted shard (adr 0256).
#[test]
fn permuted_chunk_mapping_routes_to_the_hosted_canonical_shard() {
    const NONE: i32 = osdmap::consts::ITEM_NONE;
    for (np, stored, primary, shard) in [
        // canonical [NONE,11,12,13,14,15]; stored (primary-capable first) [NONE,11,14,15,12,13].
        ([2usize, 3], [NONE, 11, 14, 15, 12, 13], 11, 1),
        // canonical [10..=15]; stored [11,13,14,15,10,12]: shard 1 is primary-capable, 0 is not.
        ([0, 2], [11, 13, 14, 15, 10, 12], 11, 1),
        // canonical [10,NONE,12,13,14,15]: primary is slot 3.
        ([0, 2], [NONE, 13, 14, 15, 10, 12], 13, 3),
    ] {
        let mut m = map();
        let pg = PgT::new(701, 5);
        let p = m.pools.get_mut(&701).unwrap();
        p.flags |= flags::EC_OPTIMIZATIONS;
        for s in np {
            p.nonprimary_shards.insert(s);
        }
        m.pg_temp.insert(pg, stored.to_vec());
        let a = m.pg_to_up_acting(pg);
        assert_eq!(a.acting_primary, primary, "np {np:?}");
        let slot = a.acting.iter().position(|&o| o == primary).unwrap();
        let d = m.primary_destination(pg, &a).unwrap();
        assert_eq!(d.osd, primary);
        assert_eq!(d.shard, ShardId(shard), "np {np:?}");
        assert_eq!(d.shard, ShardId(slot as i8), "np {np:?}");
    }
}
