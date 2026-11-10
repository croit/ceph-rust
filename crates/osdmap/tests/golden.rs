// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Golden tests against reference-cluster data (testdata/osdmap, testdata/mon).

use denc::{Decode, Encode};
use osdmap::*;
use std::path::{Path, PathBuf};

#[test]
fn crush_version_wraps_without_aborting_map_install() {
    let mut map = OsdMap::default();
    map.epoch = 1;
    map.crush_version = u32::MAX;
    map.require_osd_release = consts::release::LUMINOUS;
    let inc = Incremental {
        epoch: 2,
        crush: crush::CrushMap::new().encode(),
        has_crc: false,
        ..Incremental::default()
    };
    let next = map.apply_incremental_checked(&inc).unwrap();
    assert_eq!(next.epoch, 2);
    assert_eq!(next.crush_version, 0);
    assert_eq!(map.crush_version, u32::MAX);
}

fn td() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata")
}

fn bins(dir: &Path) -> Vec<PathBuf> {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return vec![];
    };
    let mut v: Vec<PathBuf> = rd
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "bin"))
        .collect();
    v.sort();
    v
}

fn first_diff(a: &[u8], b: &[u8]) -> Option<usize> {
    (0..a.len().min(b.len()))
        .find(|&i| a[i] != b[i])
        .or((a.len() != b.len()).then_some(a.len().min(b.len())))
}

fn epoch_of(p: &Path) -> u32 {
    p.file_stem().unwrap().to_str().unwrap().parse().unwrap()
}

fn roundtrip<T: for<'a> Decode<'a> + Encode>(dir: &Path, what: &str) -> usize {
    let mut n = 0;
    for p in bins(dir) {
        let b = std::fs::read(&p).unwrap();
        let v: T = denc::from_slice(&b).unwrap_or_else(|e| panic!("{what} {p:?}: {e}"));
        let out = v.encode_to_vec().unwrap();
        assert_eq!(first_diff(&b, &out), None, "{what} {p:?} re-encode differs");
        n += 1;
    }
    n
}

#[test]
fn full_maps_reencode_byte_exact() {
    let files = bins(&td().join("osdmap/full"));
    assert!(!files.is_empty(), "no golden full maps");
    for p in files {
        let b = std::fs::read(&p).unwrap();
        let m = OsdMap::decode_from(&b).unwrap_or_else(|e| panic!("{p:?}: {e}"));
        assert_eq!(m.epoch, epoch_of(&p), "{p:?}");
        let out = m.encode_full().unwrap();
        assert_eq!(
            first_diff(&b, &out),
            None,
            "{p:?} re-encode differs (len {} vs {})",
            b.len(),
            out.len()
        );
        // second generation is stable
        let m2 = OsdMap::decode_from(&out).unwrap();
        assert_eq!(m, m2);
    }
}

#[test]
fn full_map_crc_validation() {
    let b = std::fs::read(td().join("osdmap/full/0001.bin")).unwrap();
    assert!(OsdMap::decode_from(&b).is_ok());
    let mut bad = b.clone();
    let n = bad.len();
    bad[n - 1] ^= 1;
    assert!(matches!(
        OsdMap::decode_from(&bad),
        Err(Error::BadCrc { .. })
    ));
    // payload corruption
    let mut bad = b.clone();
    bad[40] ^= 0x10;
    assert!(OsdMap::decode_from(&bad).is_err());
    assert!(OsdMap::decode_opts(&b[..b.len() - 1], true).is_err());
}

#[test]
fn incrementals_reencode() {
    let mut n = 0;
    for p in bins(&td().join("osdmap/inc")) {
        let b = std::fs::read(&p).unwrap();
        let inc = Incremental::decode_from(&b).unwrap_or_else(|e| panic!("{p:?}: {e}"));
        assert_eq!(inc.epoch, epoch_of(&p));
        let out = inc.encode_inc().unwrap();
        assert_eq!(first_diff(&b, &out), None, "{p:?} inc re-encode differs");
        n += 1;
    }
    assert!(n > 0);
}

#[test]
fn incremental_chain_matches_full_maps() {
    let dir = td().join("osdmap");
    let mut have: Option<OsdMap> = None;
    let mut checked = 0;
    for p in bins(&dir.join("inc")) {
        let e = epoch_of(&p);
        let inc = Incremental::decode_from(&std::fs::read(&p).unwrap()).unwrap();
        let full_p = dir.join(format!("full/{e:04}.bin"));
        let cur = match have.take() {
            None => {
                // start from a full map at e-1 (or an empty map for epoch 1)
                let prev = dir.join(format!("full/{:04}.bin", e - 1));
                if e == 1 {
                    OsdMap::default()
                } else if prev.exists() {
                    OsdMap::decode_from(&std::fs::read(prev).unwrap()).unwrap()
                } else {
                    continue;
                }
            }
            Some(m) => m,
        };
        let next = cur
            .apply_incremental_checked(&inc)
            .unwrap_or_else(|er| panic!("apply inc {e}: {er}"));
        if full_p.exists() {
            let want = std::fs::read(&full_p).unwrap();
            let got = next.encode_full().unwrap();
            assert_eq!(
                first_diff(&want, &got),
                None,
                "epoch {e}: applied map differs from full map"
            );
            assert_eq!(next, OsdMap::decode_from(&want).unwrap(), "epoch {e}");
            checked += 1;
        }
        have = Some(next);
    }
    assert!(checked > 10, "only {checked} epochs verified");
}

#[test]
fn incremental_gap_and_fsid() {
    let dir = td().join("osdmap");
    let m = OsdMap::decode_from(&std::fs::read(dir.join("full/0005.bin")).unwrap()).unwrap();
    let inc7 = Incremental::decode_from(&std::fs::read(dir.join("inc/0007.bin")).unwrap()).unwrap();
    assert!(matches!(
        m.clone().apply_incremental(&inc7),
        Err(Error::Gap { .. })
    ));
    let mut inc6 =
        Incremental::decode_from(&std::fs::read(dir.join("inc/0006.bin")).unwrap()).unwrap();
    inc6.fsid.0[0] ^= 1;
    assert_eq!(m.clone().apply_incremental(&inc6), Err(Error::FsidMismatch));
    // corrupted full_crc -> post-apply check fails
    let mut inc6 =
        Incremental::decode_from(&std::fs::read(dir.join("inc/0006.bin")).unwrap()).unwrap();
    inc6.full_crc ^= 1;
    assert!(matches!(
        m.apply_incremental_checked(&inc6),
        Err(Error::FullCrcMismatch { .. })
    ));
}

#[test]
fn embedded_fullmap_must_match_incremental_identity() {
    let mut base = OsdMap::default();
    base.epoch = 4;
    let mut full = base.clone();
    full.epoch = 5;
    let mut inc = Incremental {
        epoch: 5,
        fsid: base.fsid,
        fullmap: full.encode_full().unwrap(),
        ..Incremental::default()
    };
    assert_eq!(base.apply_incremental_checked(&inc).unwrap().epoch, 5);
    full.fsid.0[0] ^= 1;
    inc.fullmap = full.encode_full().unwrap();
    assert_eq!(
        base.apply_incremental_checked(&inc),
        Err(Error::FsidMismatch)
    );
    full.fsid = base.fsid;
    for epoch in [4, 6] {
        full.epoch = epoch;
        inc.fullmap = full.encode_full().unwrap();
        assert!(matches!(
            base.apply_incremental_checked(&inc),
            Err(Error::Invalid(_))
        ));
    }
    assert_eq!(base.epoch, 4);
}

#[test]
fn incremental_epoch_wrap_does_not_panic() {
    let mut base = OsdMap::default();
    base.epoch = u32::MAX;
    let inc = Incremental {
        epoch: 0,
        fsid: base.fsid,
        ..Incremental::default()
    };
    base.apply_incremental(&inc).unwrap();
    assert_eq!(base.epoch, 0);
}

#[test]
fn incremental_crc_validation() {
    let b = std::fs::read(td().join("osdmap/inc/0006.bin")).unwrap();
    let mut bad = b.clone();
    let n = bad.len();
    bad[n - 6] ^= 1; // inside inc_crc
    assert!(matches!(
        Incremental::decode_from(&bad),
        Err(Error::BadCrc { .. })
    ));
    let mut bad = b.clone();
    bad[n - 1] ^= 1; // full_crc is covered by inc_crc
    assert!(matches!(
        Incremental::decode_from(&bad),
        Err(Error::BadCrc { .. })
    ));
}

#[test]
fn dencoder_instances() {
    let o = td().join("osdmap/dencoder");
    let mut tot = 0;
    tot += roundtrip::<PgPool>(&o.join("pg_pool_t"), "pg_pool_t");
    tot += roundtrip::<pool::PoolSnapInfo>(&o.join("pool_snap_info_t"), "pool_snap_info_t");
    tot += roundtrip::<OsdInfo>(&o.join("osd_info_t"), "osd_info_t");
    tot += roundtrip::<OsdXInfo>(&o.join("osd_xinfo_t"), "osd_xinfo_t");
    tot += roundtrip::<MonInfo>(&td().join("mon/dencoder/mon_info_t"), "mon_info_t");
    tot += roundtrip::<MonMap>(&td().join("mon/dencoder/MonMap"), "MonMap");
    assert!(tot > 0);
}

#[test]
fn dencoder_osdmap_and_inc() {
    // dencoder test instances may carry odd/old versions: they must at least decode
    // and re-decode stably; byte equality is checked where the instance is current.
    for p in bins(&td().join("osdmap/dencoder/OSDMap")) {
        let b = std::fs::read(&p).unwrap();
        let m = OsdMap::decode_from(&b).unwrap_or_else(|e| panic!("{p:?}: {e}"));
        let out = m.encode_full().unwrap();
        assert_eq!(OsdMap::decode_from(&out).unwrap(), m);
    }
    for p in bins(&td().join("osdmap/dencoder/OSDMap_Incremental")) {
        let b = std::fs::read(&p).unwrap();
        let i = Incremental::decode_from(&b).unwrap_or_else(|e| panic!("{p:?}: {e}"));
        let out = i.encode_inc().unwrap();
        assert_eq!(Incremental::decode_from(&out).unwrap(), i);
    }
}

#[test]
fn monmap_golden() {
    let b = std::fs::read(td().join("mon/monmap.bin")).unwrap();
    let m = MonMap::decode_from(&b).unwrap();
    assert_eq!(m.encode_to().unwrap(), b);
    assert_eq!(m.ranks.len(), m.mon_info.len());
}

#[test]
fn objects_to_pg_match_reference() {
    let dir = td().join("osdmap");
    let Ok(txt) = std::fs::read_to_string(dir.join("expected/objmap.json")) else {
        return;
    };
    let mut n = 0;
    let mut cache: std::collections::HashMap<u32, OsdMap> = Default::default();
    for line in txt.lines().filter(|l| l.trim_start().starts_with('{')) {
        let j: serde_json::Value = serde_json::from_str(line).unwrap();
        let epoch = j["epoch"].as_u64().unwrap() as u32;
        let m = cache.entry(epoch).or_insert_with(|| {
            OsdMap::decode_from(&std::fs::read(dir.join(format!("full/{epoch:04}.bin"))).unwrap())
                .unwrap()
        });
        let pool = j["pool_id"].as_i64().unwrap();
        let name = j["objname"].as_str().unwrap();
        // `ceph osd map` splits the object argument at the LAST '/' into namespace + oid
        let (ns, oid) = name.rsplit_once('/').unwrap_or(("", name));
        let raw = m
            .object_to_raw_pg(pool, oid.as_bytes(), b"", ns.as_bytes(), -1)
            .unwrap();
        let pg = m
            .object_to_pg(pool, oid.as_bytes(), b"", ns.as_bytes(), -1)
            .unwrap();
        assert_eq!(raw.to_string(), j["raw_pgid"].as_str().unwrap(), "{name}");
        assert_eq!(pg.to_string(), j["pgid"].as_str().unwrap(), "{name}");
        n += 1;
    }
    assert!(n > 0);
}
