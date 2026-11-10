// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! PG mapping pipeline: synthetic cases with fake mappers + real CRUSH vs reference.

use denc::types::PgT;
use osdmap::consts::{ITEM_NONE as NONE, WEIGHT_IN, osd_state};
use osdmap::mapping::testing::FixedMapper;
use osdmap::pool::{PgPool, TYPE_ERASURE, flags};
use osdmap::*;
use std::path::{Path, PathBuf};

fn td() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/osdmap")
}

#[test]
fn real_crush_matches_pgs_brief() {
    let dir = td();
    let txt = std::fs::read_to_string(dir.join("expected/pgs_brief.json")).unwrap();
    let j: serde_json::Value = serde_json::from_str(&txt).unwrap();
    let m = OsdMap::decode_from(&std::fs::read(dir.join("full/0091.bin")).unwrap()).unwrap();
    let ints = |v: &serde_json::Value| -> Vec<i32> {
        v.as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_i64().unwrap() as i32)
            .collect()
    };
    let mut n = 0;
    for pg in j["pg_stats"].as_array().unwrap() {
        let id = PgT::parse(pg["pgid"].as_str().unwrap()).unwrap();
        let r = m.pg_to_up_acting(id);
        let ctx = format!("pg {id}: got {r:?}");
        assert_eq!(r.up, ints(&pg["up"]), "{ctx}");
        assert_eq!(r.acting, ints(&pg["acting"]), "{ctx}");
        assert_eq!(
            r.up_primary as i64,
            pg["up_primary"].as_i64().unwrap(),
            "{ctx}"
        );
        assert_eq!(
            r.acting_primary as i64,
            pg["acting_primary"].as_i64().unwrap(),
            "{ctx}"
        );
        n += 1;
    }
    assert!(n > 10);
}

#[test]
fn real_crush_matches_objmap_up_acting() {
    let dir = td();
    let m = OsdMap::decode_from(&std::fs::read(dir.join("full/0091.bin")).unwrap()).unwrap();
    let txt = std::fs::read_to_string(dir.join("expected/objmap.json")).unwrap();
    for line in txt.lines().filter(|l| l.starts_with('{')) {
        let j: serde_json::Value = serde_json::from_str(line).unwrap();
        let pg = PgT::parse(j["pgid"].as_str().unwrap()).unwrap();
        let r = m.pg_to_up_acting(pg);
        let want: Vec<i32> = j["up"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_i64().unwrap() as i32)
            .collect();
        assert_eq!(r.up, want, "{pg}");
        assert_eq!(
            r.acting_primary as i64,
            j["acting_primary"].as_i64().unwrap(),
            "{pg}"
        );
    }
}

// ---- synthetic -----------------------------------------------------------

fn base_map(n: i32, pool: PgPool) -> OsdMap {
    let mut m = OsdMap::default();
    m.set_max_osd(n);
    for o in 0..n as usize {
        m.osd_state[o] = osd_state::EXISTS | osd_state::UP;
        m.osd_weight[o] = WEIGHT_IN;
    }
    m.pools.insert(1, pool);
    m
}

fn rep_pool(size: u8) -> PgPool {
    PgPool {
        size,
        pg_num: 8,
        pgp_num: 8,
        flags: flags::HASHPSPOOL,
        ..PgPool::default()
    }
}
fn ec_pool(size: u8) -> PgPool {
    PgPool {
        ptype: TYPE_ERASURE,
        ..rep_pool(size)
    }
}

const PG: PgT = PgT::new(1, 3);

#[test]
fn replicated_basic_and_down_osds() {
    let mut m = base_map(5, rep_pool(3));
    let mp = FixedMapper(vec![4, 2, 0]);
    let r = m.pg_to_up_acting_with(&mp, PG);
    assert_eq!((r.up.clone(), r.up_primary), (vec![4, 2, 0], 4));
    assert_eq!((r.acting, r.acting_primary), (vec![4, 2, 0], 4));
    m.osd_state[4] &= !osd_state::UP; // down: shifts out
    let r = m.pg_to_up_acting_with(&mp, PG);
    assert_eq!((r.up, r.up_primary), (vec![2, 0], 2));
    // non-existent osd dropped from raw
    m.osd_state[2] = 0;
    assert_eq!(m.pg_to_raw_osds(&mp, PG), vec![4, 0]);
    // out of range / missing pool / pg >= pg_num
    assert_eq!(
        m.pg_to_up_acting_with(&mp, PgT::new(9, 0)),
        PgMapping::empty()
    );
    assert_eq!(
        m.pg_to_up_acting_with(&mp, PgT::new(1, 8)),
        PgMapping::empty()
    );
}

#[test]
fn ec_keeps_positions() {
    let mut m = base_map(5, ec_pool(3));
    let mp = FixedMapper(vec![4, NONE, 0]);
    let r = m.pg_to_up_acting_with(&mp, PG);
    assert_eq!(r.up, vec![4, NONE, 0]);
    m.osd_state[4] &= !osd_state::UP;
    let r = m.pg_to_up_acting_with(&mp, PG);
    assert_eq!((r.up, r.up_primary), (vec![NONE, NONE, 0], 0));
    assert_eq!(r.acting_primary, 0);
}

#[test]
fn upmap_items_chain_skip_and_bad_target() {
    let mut m = base_map(6, rep_pool(3));
    let mp = FixedMapper(vec![0, 1, 2]);
    m.pg_upmap_items.insert(PG, vec![(1, 4), (4, 5)]);
    assert_eq!(m.pg_to_up_acting_with(&mp, PG).up, vec![0, 5, 2]);
    // `to` already present -> skipped; swap pattern does not work
    m.pg_upmap_items.insert(PG, vec![(0, 2), (0, 1)]);
    assert_eq!(m.pg_to_up_acting_with(&mp, PG).up, vec![0, 1, 2]);
    // bad target (out) -> not applied
    m.osd_weight[3] = 0;
    m.pg_upmap_items.insert(PG, vec![(0, 3)]);
    assert_eq!(m.pg_to_up_acting_with(&mp, PG).up, vec![0, 1, 2]);
    // target beyond max_osd is not "bad"; the replaced osd then does not exist -> dropped
    m.pg_upmap_items.insert(PG, vec![(0, 77)]);
    assert_eq!(m.pg_to_up_acting_with(&mp, PG).up, vec![1, 2]);
}

#[test]
fn pg_upmap_full_replace_and_bad_target_aborts_everything() {
    let mut m = base_map(6, rep_pool(3));
    let mp = FixedMapper(vec![0, 1, 2]);
    m.pg_upmap.insert(PG, vec![5, 4, 3]);
    m.pg_upmap_items.insert(PG, vec![(5, 0)]);
    assert_eq!(m.pg_to_up_acting_with(&mp, PG).up, vec![0, 4, 3]);
    m.osd_weight[3] = 0;
    // pg_upmap has an out osd: ignored AND items/primaries not applied
    m.pg_upmap_primaries.insert(PG, 2);
    let r = m.pg_to_up_acting_with(&mp, PG);
    assert_eq!(r.up, vec![0, 1, 2]);
}

#[test]
fn upmap_primary_swap() {
    let mut m = base_map(6, rep_pool(3));
    let mp = FixedMapper(vec![0, 1, 2]);
    m.pg_upmap_primaries.insert(PG, 2);
    let r = m.pg_to_up_acting_with(&mp, PG);
    assert_eq!((r.up, r.up_primary), (vec![2, 1, 0], 2));
    m.pg_upmap_primaries.insert(PG, 5); // not in set
    assert_eq!(m.pg_to_up_acting_with(&mp, PG).up, vec![0, 1, 2]);
}

#[test]
fn primary_affinity() {
    let mut m = base_map(4, rep_pool(3));
    let mp = FixedMapper(vec![0, 1, 2]);
    m.osd_primary_affinity = vec![WEIGHT_IN; 4];
    assert_eq!(m.pg_to_up_acting_with(&mp, PG).up_primary, 0);
    // zero affinity on 0: primary becomes 1 and is rotated to front
    m.osd_primary_affinity[0] = 0;
    let r = m.pg_to_up_acting_with(&mp, PG);
    assert_eq!((r.up.clone(), r.up_primary), (vec![1, 0, 2], 1));
    assert_eq!(r.acting_primary, 1);
    // everyone zero: fallback = first
    for a in m.osd_primary_affinity.iter_mut() {
        *a = 0;
    }
    let r = m.pg_to_up_acting_with(&mp, PG);
    assert_eq!((r.up, r.up_primary), (vec![0, 1, 2], 0));
    // EC: order untouched, only primary changes
    let mut m = base_map(4, ec_pool(3));
    m.osd_primary_affinity = vec![WEIGHT_IN, WEIGHT_IN, WEIGHT_IN, WEIGHT_IN];
    m.osd_primary_affinity[0] = 0;
    let r = m.pg_to_up_acting_with(&mp, PG);
    assert_eq!((r.up, r.up_primary), (vec![0, 1, 2], 1));
}

#[test]
fn pg_temp_and_primary_temp() {
    let mut m = base_map(5, rep_pool(3));
    let mp = FixedMapper(vec![0, 1, 2]);
    m.pg_temp.insert(PG, vec![3, 4, 1]);
    let r = m.pg_to_up_acting_with(&mp, PG);
    assert_eq!((r.up, r.up_primary), (vec![0, 1, 2], 0));
    assert_eq!((r.acting.clone(), r.acting_primary), (vec![3, 4, 1], 3));
    // down osd in temp is dropped for replicated
    m.osd_state[3] &= !osd_state::UP;
    assert_eq!(m.pg_to_up_acting_with(&mp, PG).acting, vec![4, 1]);
    assert_eq!(m.pg_to_up_acting_with(&mp, PG).acting_primary, 4);
    m.primary_temp.insert(PG, 1);
    assert_eq!(m.pg_to_up_acting_with(&mp, PG).acting_primary, 1);
    // primary_temp alone overrides acting_primary only
    m.pg_temp.clear();
    let r = m.pg_to_up_acting_with(&mp, PG);
    assert_eq!(
        (r.acting, r.acting_primary, r.up_primary),
        (vec![0, 1, 2], 1, 0)
    );
    // all temp osds dead -> falls back to up
    m.primary_temp.clear();
    m.pg_temp.insert(PG, vec![3]);
    let r = m.pg_to_up_acting_with(&mp, PG);
    assert_eq!((r.acting, r.acting_primary), (vec![0, 1, 2], 0));
}

#[test]
fn pg_temp_ec_keeps_none_slots() {
    let mut m = base_map(5, ec_pool(3));
    let mp = FixedMapper(vec![0, 1, 2]);
    m.osd_state[3] &= !osd_state::UP;
    m.pg_temp.insert(PG, vec![3, 4, 1]);
    let r = m.pg_to_up_acting_with(&mp, PG);
    assert_eq!(r.acting, vec![NONE, 4, 1]);
    assert_eq!(r.acting_primary, 4);
}

#[test]
fn ec_optimizations_pg_temp_order_is_undone() {
    let mut p = ec_pool(4);
    p.flags |= flags::EC_OPTIMIZATIONS;
    p.nonprimary_shards.insert(1);
    p.nonprimary_shards.insert(3);
    let mut m = base_map(8, p);
    let mp = FixedMapper(vec![0, 1, 2, 3]);
    // stored: capable shards (0,2) first, non-primary shards (1,3) last
    m.pg_temp.insert(PG, vec![4, 6, 5, 7]);
    let r = m.pg_to_up_acting_with(&mp, PG);
    assert_eq!(r.acting, vec![4, 5, 6, 7]);
    assert_eq!(r.acting_primary, 4);
}

#[test]
fn pps_and_str_hashes() {
    use osdmap::hash::*;
    let p = rep_pool(3);
    // HASHPSPOOL: crush_hash32_2(stable_mod(ps), pool)
    let pg = PgT::new(1, 0xdead_beef);
    assert_eq!(
        p.raw_pg_to_pps(pg),
        crush_hash32_2(stable_mod(0xdead_beef, 8, 7), 1)
    );
    let mut q = p.clone();
    q.flags = 0;
    assert_eq!(q.raw_pg_to_pps(pg), stable_mod(0xdead_beef, 8, 7) + 1);
    assert_eq!(str_hash(9, b"x"), 0xFFFF_FFFF);
    assert_eq!(hash_key(2, b"ns", b"k"), str_hash_rjenkins(b"ns\x1fk"));
}

#[test]
fn blocklist_ranges() {
    use denc::types::{EntityAddr, UTime};
    let mut m = base_map(1, rep_pool(1));
    let a = EntityAddr::v4(EntityAddr::TYPE_ANY, 77, [10, 1, 2, 3], 4000);
    assert!(!m.is_blocklisted(&a));
    // exact
    m.blocklist.insert(a, UTime::default());
    assert!(m.is_blocklisted(&a));
    m.blocklist.clear();
    // ip only
    m.blocklist.insert(
        EntityAddr::v4(EntityAddr::TYPE_ANY, 0, [10, 1, 2, 3], 0),
        UTime::default(),
    );
    assert!(m.is_blocklisted(&a));
    m.blocklist.clear();
    // range 10.1.0.0/16
    m.insert_range_blocklist(
        EntityAddr::v4(EntityAddr::TYPE_CIDR, 16, [10, 1, 0, 0], 0),
        UTime::default(),
    );
    assert!(m.is_blocklisted(&a));
    assert!(!m.is_blocklisted(&EntityAddr::v4(EntityAddr::TYPE_ANY, 1, [10, 2, 2, 3], 1)));
}

// ---- default mapper: whole chain, class flags, throughput ------------------

#[test]
fn chain_crc_all_epochs_and_default_mapper_per_epoch() {
    let dir = td();
    let mut incs: Vec<_> = std::fs::read_dir(dir.join("inc"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "bin"))
        .collect();
    incs.sort();
    let mut m = OsdMap::default();
    let mut crush_incs = 0;
    for p in &incs {
        let inc = Incremental::decode_from(&std::fs::read(p).unwrap()).unwrap();
        crush_incs += !inc.crush.is_empty() as usize;
        assert!(inc.has_crc, "{p:?}");
        // checked apply verifies full_crc (no CRUSH re-encode stub)
        m = m
            .apply_incremental_checked(&inc)
            .unwrap_or_else(|e| panic!("{p:?}: {e}"));
        let want = OsdMap::decode_from(
            &std::fs::read(dir.join(format!("full/{:04}.bin", inc.epoch))).unwrap(),
        )
        .unwrap();
        assert_eq!(m.crush_blob(), want.crush_blob(), "epoch {}", inc.epoch);
        // decoded crush from the incremental maps like the one decoded from the full map
        for (&id, pool) in &m.pools {
            for ps in 0..pool.pg_num.min(16) {
                let pg = PgT::new(id as u64, ps);
                assert_eq!(
                    m.pg_to_up_acting(pg),
                    want.pg_to_up_acting(pg),
                    "epoch {} {pg}",
                    inc.epoch
                );
            }
        }
    }
    assert_eq!(incs.len(), 91);
    assert!(crush_incs > 0);
    assert_eq!(m.epoch, 91);
}

#[test]
fn device_class_flags_dropped_for_missing_classes() {
    let dir = td();
    let mut m = OsdMap::decode_from(&std::fs::read(dir.join("full/0091.bin")).unwrap()).unwrap();
    let cm = m.crush_state().unwrap().map.clone();
    let cid = *cm.class_name.keys().next().expect("a device class");
    m.device_class_flags.insert(cid, 1);
    m.device_class_flags.insert(9999, 1);
    let inc = Incremental {
        epoch: m.epoch + 1,
        fsid: m.fsid,
        crush: cm.encode(),
        encode_features: u64::MAX,
        ..Default::default()
    };
    m.apply_incremental(&inc).unwrap();
    assert!(m.device_class_flags.contains_key(&cid));
    assert!(!m.device_class_flags.contains_key(&9999));
}

#[test]
#[ignore = "benchmark: cargo test --release -p osdmap -- --ignored --nocapture"]
fn bench_pg_mappings_per_sec() {
    let m = OsdMap::decode_from(&std::fs::read(td().join("full/0091.bin")).unwrap()).unwrap();
    let mut pgs = Vec::new();
    'o: for round in 0.. {
        for (&id, pool) in &m.pools {
            for ps in 0..pool.pg_num {
                pgs.push(PgT::new(id as u64, ps));
                if pgs.len() >= 10_000 {
                    break 'o;
                }
            }
        }
        if round > 10_000 {
            break;
        }
    }
    // pad by repeating (pg_num may be small on the lab map)
    let n = pgs.len();
    let base = pgs.clone();
    while pgs.len() < 10_000 {
        pgs.push(base[pgs.len() % n]);
    }
    let _ = m.pg_to_up_acting(pgs[0]);
    let t = std::time::Instant::now();
    let mut acc = 0i64;
    let iters = 50;
    for _ in 0..iters {
        for &pg in &pgs {
            acc += m.pg_to_up_acting(pg).up_primary as i64;
        }
    }
    let dt = t.elapsed().as_secs_f64();
    println!(
        "pg_to_up_acting: {:.0} PG mappings/s ({} distinct pgs, acc {acc})",
        (iters * pgs.len()) as f64 / dt,
        n
    );
}

#[test]
fn blocklist_conn_type_and_nonce() {
    use denc::types::{EntityAddr, UTime};
    let mut m = base_map(1, rep_pool(1));
    // `osd blocklist add ip:0/nonce` stores type ANY, port 0; connections carry type MSGR2 (or LEGACY)
    m.blocklist.insert(
        EntityAddr::v4(EntityAddr::TYPE_ANY, 555, [10, 1, 2, 3], 0),
        UTime::default(),
    );
    for ty in [
        EntityAddr::TYPE_MSGR2,
        EntityAddr::TYPE_LEGACY,
        EntityAddr::TYPE_ANY,
    ] {
        assert!(m.is_blocklisted(&EntityAddr::v4(ty, 555, [10, 1, 2, 3], 0)));
    }
    // another incarnation (nonce) of the same host is not fenced
    assert!(!m.is_blocklisted(&EntityAddr::v4(
        EntityAddr::TYPE_MSGR2,
        556,
        [10, 1, 2, 3],
        0
    )));
    // ipv6 range
    m.blocklist.clear();
    let mut r = EntityAddr::v4(EntityAddr::TYPE_CIDR, 0, [0; 4], 0);
    r.family = 10;
    r.data[6..22].copy_from_slice(&[0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    r.nonce = 8;
    m.insert_range_blocklist(r, UTime::default());
    let mut c = r;
    c.ty = EntityAddr::TYPE_MSGR2;
    c.nonce = 1;
    c.data[21] = 7;
    assert!(m.is_blocklisted(&c));
    c.data[6] = 0xfe;
    assert!(!m.is_blocklisted(&c));
}

/// `is_noup`: global flag, own state bit, a `set-group` flag on a CRUSH bucket of the OSD's location or on its device
/// class (spec osd-lifecycle.md 3.2).
#[test]
fn noup_from_every_source() {
    use osdmap::consts::{map_flags, osd_state};
    let dir = td();
    let mut m = OsdMap::decode_from(&std::fs::read(dir.join("full/0091.bin")).unwrap()).unwrap();
    let cm = m.crush_state().unwrap().map.clone();
    let osds: Vec<i32> = (0..m.max_osd).filter(|o| m.exists(*o)).collect();
    let o = osds[0];
    let loc = cm.location_ids(o);
    assert!(!loc.is_empty(), "osd.{o} sits in the hierarchy");
    // an OSD outside the first OSD's nearest bucket (if the fixture has one)
    let other = osds
        .iter()
        .copied()
        .find(|x| !cm.location_ids(*x).contains(&loc[0]));
    assert!(!m.is_noup(o));
    m.flags |= map_flags::NOUP;
    assert!(m.is_noup(o));
    m.flags &= !map_flags::NOUP;
    m.osd_state[o as usize] |= osd_state::NOUP;
    assert!(m.is_noup(o));
    m.osd_state[o as usize] &= !osd_state::NOUP;
    // set-group on the nearest bucket, then on the top of the location
    for b in [loc[0], *loc.last().unwrap()] {
        m.crush_node_flags.insert(b, osd_state::NOUP);
        assert!(m.is_noup(o), "bucket {b}");
        m.crush_node_flags.insert(b, osd_state::NOOUT);
        assert!(!m.is_noup(o), "other flag on bucket {b}");
        m.crush_node_flags.clear();
    }
    m.crush_node_flags.insert(loc[0], osd_state::NOUP);
    if let Some(x) = other {
        assert!(!m.is_noup(x), "osd.{x} is not below bucket {}", loc[0]);
    }
    m.crush_node_flags.clear();
    // device class
    let cls = *cm.class_map.get(&o).expect("osd has a device class");
    m.device_class_flags.insert(cls, osd_state::NOUP);
    assert!(m.is_noup(o));
    let unclassed = osds
        .iter()
        .copied()
        .find(|x| cm.class_map.get(x) != Some(&cls));
    if let Some(x) = unclassed {
        assert!(!m.is_noup(x));
    }
}

/// The decoded CRUSH map always belongs to the blob in the map (spec 1.2 field 16): replacing the blob makes the next
/// mapping use it, so no stale placement can survive a CRUSH update.
#[test]
fn crush_replacement_changes_placement() {
    let dir = td();
    let m = OsdMap::decode_from(&std::fs::read(dir.join("full/0091.bin")).unwrap()).unwrap();
    let pg = m
        .pools
        .iter()
        .filter(|(_, p)| p.is_replicated() && p.pg_num > 0)
        .map(|(id, _)| PgT::new(*id as u64, 0))
        .find(|pg| !m.pg_to_up_acting(*pg).acting.is_empty())
        .expect("a replicated pg with a mapping");
    let before = m.pg_to_up_acting(pg);
    assert!(!before.acting.is_empty());
    // a CRUSH map without the pool's rule places nothing
    let empty = crush::CrushMap::new().encode();
    let mut m2 = m.clone();
    m2.set_crush(empty.clone());
    assert_eq!(m2.crush_blob(), empty.as_slice());
    assert!(
        m2.pg_to_up_acting(pg).acting.is_empty(),
        "the mapping follows the new blob"
    );
    // and back
    m2.set_crush(m.crush_blob().to_vec());
    assert_eq!(m2.pg_to_up_acting(pg), before);
}
