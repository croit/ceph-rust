// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Scrub messages: spec vector, round trips, ceph-dencoder golden (testdata/replwire/scrub).
mod common;
use common::*;
use denc::Encode;
use denc::types::*;
use messages::Message;
use replwire::scrubmsgs::*;
use replwire::*;
use std::collections::BTreeMap;

#[test]
fn hinfo_checks_envelope_compat_and_bounds() {
    use replwire::ecscrub::{encode_hinfo, parse_hinfo};
    let valid = encode_hinfo(4096, &[11, 22, 33]);
    let expected = parse_hinfo(&valid).unwrap();
    let mut incompatible = valid.clone();
    incompatible[0] = 2;
    incompatible[1] = 2;
    assert!(parse_hinfo(&incompatible).is_none());

    let mut newer = valid.clone();
    newer[0] = 2;
    newer.extend_from_slice(&[7, 8]);
    let len = (newer.len() - 6) as u32;
    newer[2..6].copy_from_slice(&len.to_le_bytes());
    assert_eq!(parse_hinfo(&newer), Some(expected.clone()));

    // classic decodes the envelope from an iterator and ignores what follows it
    let mut trailing = valid.clone();
    trailing.push(0);
    assert_eq!(parse_hinfo(&trailing), Some(expected.clone()));
    for n in 0..valid.len() {
        assert!(parse_hinfo(&valid[..n]).is_none(), "prefix {n}");
    }
    let mut bad_count = valid;
    bad_count[14..18].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(parse_hinfo(&bad_count).is_none());
}

fn emit() -> bool {
    std::env::var_os("EMIT_SAMPLES").is_some()
}

fn scrub_data(rel: &str) -> std::path::PathBuf {
    testdata(&format!("scrub/{rel}"))
}

fn check_ours(name: &str, bytes: &[u8]) {
    let p = scrub_data(&format!("ours/{name}.bin"));
    if emit() {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, bytes).unwrap();
        return;
    }
    assert_eq!(
        std::fs::read(&p).unwrap(),
        bytes,
        "{name}: stale sample (EMIT_SAMPLES=1)"
    );
    // dencoder re-encode (raw types)
    if let Ok(re) = std::fs::read(scrub_data(&format!("oracle/{name}.bin"))) {
        assert_eq!(re, bytes, "{name}: dencoder re-encode differs");
    }
}

fn pgid() -> SpgT {
    SpgT {
        pgid: PgT::new(2, 0x1f),
        shard: ShardId::NO_SHARD,
    }
}

#[test]
fn reserve_spec_vector() {
    let m = MOSDScrubReserve {
        pgid: pgid(),
        map_epoch: 100,
        ty: MOSDScrubReserve::REQUEST,
        from: PgShard {
            osd: 3,
            shard: ShardId::NO_SHARD,
        },
        nonce: 1,
        wait_for_resources: true,
    };
    let want: Vec<u8> = [
        &[
            1u8, 1, 0x12, 0, 0, 0, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0x1f, 0, 0, 0, 0xff, 0xff, 0xff,
            0xff, 0xff,
        ][..],
        &[0x64, 0, 0, 0, 0, 0, 0, 0],
        &[1, 1, 5, 0, 0, 0, 3, 0, 0, 0, 0xff],
        &[1, 0, 0, 0, 1],
    ]
    .concat();
    let s = m.encode(denc::features::ALL).unwrap();
    assert_eq!(s.front, want);
    assert_eq!(s.front.len(), 48);
    for v in [1u16, 2, 3] {
        let b = MOSDScrubReserve::decode(
            v,
            &s.front[..if v == 1 {
                43
            } else if v == 2 {
                47
            } else {
                48
            }],
            &[],
            &[],
        )
        .unwrap();
        let mut w = m.clone();
        if v < 3 {
            w.wait_for_resources = false;
        }
        if v < 2 {
            w.nonce = 0;
        }
        assert_eq!(b, w);
    }
}

fn hb(oid: &str, snap: u64, hash: u32) -> Hobject {
    Hobject::new(oid.as_bytes(), SnapId(snap), hash, 2, b"")
}

fn sample_obj() -> ScrubObject {
    ScrubObject {
        size: 4096,
        attrs: BTreeMap::from([
            (b"_".to_vec(), vec![1, 2, 3]),
            (b"_user".to_vec(), vec![9]),
            (b"snapset".to_vec(), vec![4, 5]),
        ]),
        digest: 0x1234_5678,
        digest_present: true,
        omap_digest: 0xdead_beef,
        omap_digest_present: true,
        large_omap_object_found: true,
        large_omap_object_key_count: 300_000,
        large_omap_object_value_size: 5,
        object_omap_bytes: 77,
        object_omap_keys: 3,
        ..Default::default()
    }
}

fn sample_map() -> ScrubMap {
    let mut m = ScrubMap {
        valid_through: Eversion::new(5, 17),
        ..Default::default()
    };
    m.objects.insert(hb("a", SnapId::NOSNAP.0, 1), sample_obj());
    m.objects.insert(
        hb("b", 3, 2),
        ScrubObject {
            read_error: true,
            ..Default::default()
        },
    );
    m.objects.insert(
        hb("c", SnapId::NOSNAP.0, 3),
        ScrubObject {
            stat_error: true,
            ..Default::default()
        },
    );
    m
}

#[test]
fn sizes_and_roundtrip() {
    let e = ScrubMap::default().encode_to_vec().unwrap();
    assert_eq!(e.len(), 42);
    let o = ScrubObject {
        attrs: BTreeMap::new(),
        ..Default::default()
    }
    .encode_to_vec()
    .unwrap();
    assert_eq!(o.len(), 75);
    let m = sample_map();
    let b = m.encode_to_vec().unwrap();
    assert_eq!(denc::from_slice::<ScrubMap>(&b).unwrap(), m);
    check_ours("ScrubMap.a", &b);
    let ob = sample_obj().encode_to_vec().unwrap();
    assert_eq!(denc::from_slice::<ScrubObject>(&ob).unwrap(), sample_obj());
    check_ours("ScrubMap__object.a", &ob);
    // read_error sets the compat flag too (field 10)
    let re = ScrubObject {
        read_error: true,
        ..Default::default()
    }
    .encode_to_vec()
    .unwrap();
    assert_eq!(re[6 + 8 + 1 + 4 + 4 + 1 + 4 + 4 + 4 + 1], 1);
}

#[test]
fn local_omap_key_bytes_do_not_change_scrub_wire_bytes() {
    let wire_object = sample_obj();
    let object_bytes = wire_object.encode_to_vec().unwrap();
    let mut local_object = wire_object.clone();
    local_object.object_omap_key_bytes = Some(123);
    assert_eq!(local_object.encode_to_vec().unwrap(), object_bytes);
    let decoded: ScrubObject = denc::from_slice(&object_bytes).unwrap();
    assert_eq!(decoded.object_omap_key_bytes, None);
    assert_eq!(decoded, wire_object);

    let wire_map = sample_map();
    let map_bytes = wire_map.encode_to_vec().unwrap();
    let mut local_map = wire_map.clone();
    for object in local_map.objects.values_mut() {
        object.object_omap_key_bytes = Some(0);
    }
    assert_eq!(local_map.encode_to_vec().unwrap(), map_bytes);
    assert_eq!(denc::from_slice::<ScrubMap>(&map_bytes).unwrap(), wire_map);
    check_ours("ScrubMap.a", &map_bytes);
    check_ours("ScrubMap__object.a", &object_bytes);
}

#[test]
fn golden_dencoder_types() {
    let mut n = 0;
    for e in std::fs::read_dir(scrub_data("")).unwrap() {
        let p = e.unwrap().path();
        let name = p.file_name().unwrap().to_str().unwrap().to_string();
        if !name.ends_with(".bin") {
            continue;
        }
        let b = std::fs::read(&p).unwrap();
        if name.starts_with("ScrubMap__object.") {
            let o: ScrubObject = denc::from_slice(&b).unwrap();
            assert_eq!(o.encode_to_vec().unwrap(), b, "{name}");
        } else if name.starts_with("ScrubMap.") {
            let o: ScrubMap = denc::from_slice(&b).unwrap();
            assert_eq!(o.encode_to_vec().unwrap(), b, "{name}");
        } else if name.starts_with("MOSD") {
            let ty = u16::from_le_bytes([b[16], b[17]]);
            let ver = u16::from_le_bytes([b[20], b[21]]);
            let mut p = 53 + 13;
            let mut seg = || {
                let n = u32::from_le_bytes(b[p..p + 4].try_into().unwrap()) as usize;
                p += 4 + n;
                b[p - n..p].to_vec()
            };
            let segs = messages::Segments {
                front_zc: Vec::new(),
                front_hints: Default::default(),
                front: seg(),
                middle: seg(),
                data: seg().into(),
            };
            let m = decode_repl(ty, ver, &segs).unwrap().expect("known");
            let (_, v, _, re) = m.encode(denc::features::ALL).unwrap();
            assert_eq!(v, ver, "{name}");
            assert_eq!(re, segs, "{name}");
        } else {
            continue;
        }
        n += 1;
    }
    assert_eq!(n, 7);
}

#[test]
fn rep_scrub_roundtrip_and_old_versions() {
    let m = MOSDRepScrub {
        pgid: pgid(),
        scrub_from: Eversion::default(),
        scrub_to: Eversion::new(3, 9),
        map_epoch: 50,
        chunky: true,
        start: hb("a", 0, 1),
        end: Hobject::MAX(),
        deep: true,
        seed: 0xFFFF_FFFF,
        min_epoch: 48,
        allow_preemption: true,
        priority: 5,
        high_priority: true,
    };
    let s = m.encode(denc::features::ALL).unwrap();
    assert_eq!(MOSDRepScrub::decode(9, &s.front, &[], &[]).unwrap(), m);
    // header-only bytes: pgid 17, from 12, to 12, epoch 4, chunky 1 ...
    assert_eq!(
        &s.front[..17],
        &PgT::new(2, 0x1f).encode_to_vec().unwrap()[..]
    );
    assert_eq!(
        s.front.len(),
        62 + m.start.encode_to_vec().unwrap().len() + m.end.encode_to_vec().unwrap().len()
    );
    // v6 body: drop the trailing min_epoch/allow_preemption/priority/high_priority fields
    let n = s.front.len();
    let o = MOSDRepScrub::decode(8, &s.front[..n - 5], &[], &[]).unwrap();
    assert_eq!((o.min_epoch, o.allow_preemption, o.priority), (48, true, 0));
    let o = MOSDRepScrub::decode(7, &s.front[..n - 6], &[], &[]).unwrap();
    assert_eq!((o.min_epoch, o.allow_preemption), (48, false));
    let o = MOSDRepScrub::decode(6, &s.front[..n - 10], &[], &[]).unwrap();
    assert_eq!((o.min_epoch, o.map_epoch), (50, 50));
    assert!(MOSDRepScrub::decode(5, &s.front, &[], &[]).is_err());
    check_ours("MOSDRepScrub.a", &dencoder_wrapper(93, 9, 6, &s));
}

#[test]
fn rep_scrub_map_and_scrub2() {
    let m = MOSDRepScrubMap {
        pgid: pgid(),
        map_epoch: 48,
        from: PgShard {
            osd: 1,
            shard: ShardId::NO_SHARD,
        },
        preempted: false,
        map: sample_map(),
    };
    let s = m.encode(denc::features::ALL).unwrap();
    assert!(s.middle.is_empty());
    assert_eq!(s.data, sample_map().encode_to_vec().unwrap());
    assert_eq!(
        MOSDRepScrubMap::decode(2, &s.front, &[], &s.data).unwrap(),
        m
    );
    let v1 = MOSDRepScrubMap::decode(1, &s.front[..s.front.len() - 1], &[], &s.data).unwrap();
    assert_eq!(v1, m);
    let x = MOSDScrub2 {
        fsid: [7; 16],
        epoch: 9,
        scrub_pgs: vec![pgid()],
        repair: false,
        deep: true,
    };
    let s = x.encode(denc::features::ALL).unwrap();
    assert_eq!(s.front.len(), 16 + 4 + 4 + 24 + 2);
    assert_eq!(MOSDScrub2::decode(1, &s.front, &[], &[]).unwrap(), x);
    check_ours("MOSDScrub2.a", &dencoder_wrapper(121, 1, 1, &s));
    // through ReplMsg
    let r: ReplMsg = x.clone().into();
    let (ty, v, _, segs) = r.encode(denc::features::ALL).unwrap();
    assert_eq!(decode_repl(ty, v, &segs).unwrap().unwrap(), r);
}

#[test]
fn digests() {
    // data "123456789" -> 0x1CF96D7C (spec 3.3); empty -> seed
    assert_eq!(data_digest_update(DIGEST_SEED, b"123456789"), 0x1CF96D7C);
    assert_eq!(data_digest_update(DIGEST_SEED, b""), 0xFFFF_FFFF);
    // chaining == concatenation
    let c = data_digest_update(data_digest_update(DIGEST_SEED, b"1234"), b"56789");
    assert_eq!(c, 0x1CF96D7C);
    // omap
    assert_eq!(OmapDigest::default().finish(), 0xFFFF_FFFF);
    let mut o = OmapDigest::default();
    o.entry(b"k", b"v");
    let mut want = DIGEST_SEED;
    for p in [&[1u8, 0, 0, 0, b'k'][..], &[1, 0, 0, 0, b'v'][..]] {
        want = crc::crc32c(want, p);
    }
    assert_eq!((o.finish(), o.keys, o.key_bytes, o.bytes), (want, 1, 1, 1));
    // header is raw (no length prefix); empty header skipped
    let mut h = OmapDigest::default();
    h.header(b"");
    assert_eq!(h.finish(), 0xFFFF_FFFF);
    h.header(b"hdr");
    assert_eq!(h.finish(), crc::crc32c(DIGEST_SEED, b"hdr"));
    assert_eq!((h.keys, h.key_bytes, h.bytes), (0, 0, 0));
}

#[test]
fn omap_counts_binary_keys_and_empty_values_without_header_or_encoding_bytes() {
    let entries: [(&[u8], &[u8]); 3] = [(b"", b""), (b"\0\xffk", b""), (b"lengthy", b"\xff\0")];
    let mut one = OmapDigest::default();
    let mut page = OmapDigest::default();
    one.header(b"header is not logical usage");
    page.header(b"header is not logical usage");
    let mut encoded = Vec::new();
    for (key, value) in entries {
        one.entry(key, value);
        encoded.extend((key.len() as u32).to_le_bytes());
        encoded.extend(key);
        encoded.extend((value.len() as u32).to_le_bytes());
        encoded.extend(value);
    }
    assert_eq!(
        page.entries_enc(&encoded, 3),
        Some(Some(b"lengthy".as_slice()))
    );
    for digest in [&one, &page] {
        assert_eq!((digest.keys, digest.key_bytes, digest.bytes), (3, 10, 2));
        assert_eq!(digest.key_bytes + digest.bytes, 12);
        assert_eq!(digest.finish(), one.finish());
    }
}

#[test]
fn completed_local_omap_scan_records_zero_and_read_error_clears_it() {
    let mut object = ScrubObject::default();
    assert_eq!(object.object_omap_key_bytes, None);
    object.set_omap(&OmapDigest::default());
    assert_eq!(object.object_omap_key_bytes, Some(0));
    object.set_read_error();
    assert_eq!(object.object_omap_key_bytes, None);
    assert!(!object.omap_digest_present);
}

#[test]
fn omap_stats_preserve_ec_digest_convention() {
    let mut digest = OmapDigest::default();
    digest.entry(b"\0\xff", b"value");
    let mut object = ScrubObject {
        digest: 0x1234_5678,
        digest_present: true,
        omap_digest: DIGEST_SEED,
        omap_digest_present: true,
        ..Default::default()
    };
    object.set_omap_stats(&digest);
    assert_eq!((object.digest, object.digest_present), (0x1234_5678, true));
    assert_eq!(
        (object.omap_digest, object.omap_digest_present),
        (DIGEST_SEED, true)
    );
    assert_eq!((object.object_omap_keys, object.object_omap_bytes), (1, 5));
    assert_eq!(object.object_omap_key_bytes, Some(2));
}

#[test]
fn large_omap_thresholds_use_values_without_key_bytes() {
    let mut digest = OmapDigest::default();
    digest.entry(b"long-user-key", b"v");
    let mut object = ScrubObject::default();
    object.set_omap(&digest);
    assert_eq!(object.object_omap_key_bytes, Some(13));
    assert_eq!(object.object_omap_bytes, 1);
    assert!(!object.large_omap_object_found);
    object.apply_large_omap(1, 1);
    assert!(
        !object.large_omap_object_found,
        "threshold is strictly greater and values-only"
    );
    object.apply_large_omap(1, 0);
    assert!(object.large_omap_object_found);
    assert_eq!(object.large_omap_object_value_size, 1);
}

/// A page in the listing encoding (`le32 klen, key, le32 vlen, value`) digests exactly like the same entries one by one
/// (scrub hashes store listing pages in one pass); a malformed page adds nothing.
#[test]
fn omap_digest_of_an_encoded_page_equals_per_entry() {
    let kv: Vec<(Vec<u8>, Vec<u8>)> = (0..300u32)
        .map(|i| {
            (
                format!("key/{i:05}").into_bytes(),
                vec![i as u8; (i % 37) as usize],
            )
        })
        .collect();
    let mut one = OmapDigest::default();
    one.header(b"hdr");
    let mut page = OmapDigest::default();
    page.header(b"hdr");
    let mut buf = Vec::new();
    for (k, v) in &kv {
        one.entry(k, v);
        buf.extend((k.len() as u32).to_le_bytes());
        buf.extend(k);
        buf.extend((v.len() as u32).to_le_bytes());
        buf.extend(v);
    }
    // two pages: split after entry 100
    let cut = kv[..100]
        .iter()
        .map(|(k, v)| 8 + k.len() + v.len())
        .sum::<usize>();
    assert_eq!(
        page.entries_enc(&buf[..cut], 100),
        Some(Some(&kv[99].0[..]))
    );
    assert_eq!(
        page.entries_enc(&buf[cut..], 200),
        Some(Some(&kv[299].0[..]))
    );
    assert_eq!(
        (page.finish(), page.keys, page.key_bytes, page.bytes),
        (one.finish(), one.keys, one.key_bytes, one.bytes)
    );
    assert_eq!(page.entries_enc(&[], 0), Some(None));
    let before = (page.finish(), page.keys, page.key_bytes, page.bytes);
    assert_eq!(page.entries_enc(&buf[..cut - 1], 100), None);
    assert_eq!(page.entries_enc(&buf[..cut], 99), None);
    assert_eq!(
        (page.finish(), page.keys, page.key_bytes, page.bytes),
        before
    );
}

/// MOSDForceRecovery (151): v2 carries spg_t (shard kept), a v1 peer sends bare pg_t (decoded as NO_SHARD); options u8.
#[test]
fn force_recovery_v2_and_v1_vectors() {
    let fsid = [9u8; 16];
    let ec = SpgT {
        pgid: PgT::new(3, 0x2a),
        shard: ShardId(2),
    };
    let x = MOSDForceRecovery {
        fsid,
        forced_pgs: vec![pgid(), ec],
        options: MOSDForceRecovery::OFR_BACKFILL | MOSDForceRecovery::OFR_CANCEL,
    };
    let s = x.encode(denc::features::ALL).unwrap();
    // fsid + count + 2 x (6 envelope + 17 pg_t + 1 shard) + options
    assert_eq!(s.front.len(), 16 + 4 + 2 * 24 + 1);
    assert_eq!(&s.front[16..20], &[2, 0, 0, 0]);
    assert_eq!(*s.front.last().unwrap(), 6);
    assert_eq!(MOSDForceRecovery::decode(2, &s.front, &[], &[]).unwrap(), x);
    let r: ReplMsg = x.clone().into();
    let (ty, v, c, segs) = r.encode(denc::features::ALL).unwrap();
    assert_eq!((ty, v, c), (151, 2, 2));
    assert_eq!(decode_repl(ty, v, &segs).unwrap().unwrap(), r);
    // v1: u32 count + pg_t (u8 ver 1, u64 pool, u32 seed, i32 preferred -1), options
    let mut v1 = fsid.to_vec();
    v1.extend_from_slice(&1u32.to_le_bytes());
    v1.push(1);
    v1.extend_from_slice(&3u64.to_le_bytes());
    v1.extend_from_slice(&0x2au32.to_le_bytes());
    v1.extend_from_slice(&(-1i32).to_le_bytes());
    v1.push(MOSDForceRecovery::OFR_RECOVERY);
    assert_eq!(
        MOSDForceRecovery::decode(1, &v1, &[], &[]).unwrap(),
        MOSDForceRecovery {
            fsid,
            forced_pgs: vec![SpgT {
                pgid: PgT::new(3, 0x2a),
                shard: ShardId::NO_SHARD
            }],
            options: 1,
        }
    );
    assert!(MOSDForceRecovery::decode(2, &v1, &[], &[]).is_err());
}
