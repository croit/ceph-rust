// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Golden vectors from the reference ceph-dencoder (testdata/opwire/gen.sh): decode, re-encode,
//! require byte equality.
mod common;
use common::*;
use denc::{Decode, Encode, from_slice};
use opwire::*;

fn goldens(dir: &str) -> Vec<(String, Vec<u8>)> {
    let mut v = Vec::new();
    for e in std::fs::read_dir(testdata(dir)).unwrap() {
        let p = e.unwrap().path();
        if p.extension().is_some_and(|x| x == "bin") {
            v.push((
                format!("{dir}/{}", p.file_name().unwrap().to_string_lossy()),
                std::fs::read(&p).unwrap(),
            ));
        }
    }
    assert!(!v.is_empty(), "no goldens in {dir}");
    v.sort();
    v
}

fn roundtrip<T: Encode + for<'a> Decode<'a> + PartialEq + std::fmt::Debug>(dir: &str) -> Vec<T> {
    goldens(dir)
        .into_iter()
        .map(|(n, b)| {
            let v: T = from_slice(&b).unwrap_or_else(|e| panic!("{n}: {e}"));
            assert_eq!(v.encode_to_vec().unwrap(), b, "{n}");
            v
        })
        .collect()
}

#[test]
fn request_redirect() {
    let v: Vec<RequestRedirect> = roundtrip("request_redirect_t");
    assert_eq!(v.len(), 4);
}

#[test]
fn list_snaps() {
    let v: Vec<ObjListSnapResponse> = roundtrip("obj_list_snap_response_t");
    assert!(v.iter().any(|r| !r.clones.is_empty()));
    let c: Vec<CloneInfo> = roundtrip("clone_info");
    assert_eq!(c.len(), 3);
}

#[test]
fn list_watchers() {
    let w: Vec<WatchItem> = roundtrip("watch_item_t");
    assert_eq!((w[0].cookie, w[0].timeout_s), (10, 30));
    let r: Vec<ObjListWatchResponse> = roundtrip("obj_list_watch_response_t");
    assert!(!r[1].entries.is_empty());
}

#[test]
fn pgls() {
    let n: Vec<PgNlsResponse> = roundtrip("pg_nls_response_t");
    assert_eq!(n[1].entries[1].oid, b"two");
    assert_eq!(n[1].entries[1].locator, b"twokey");
    let l: Vec<PgLsResponse> = roundtrip("pg_ls_response_t");
    assert_eq!(l.len(), 2);
}

#[test]
fn copy_get_types() {
    let c: Vec<CopyCursor> = roundtrip("object_copy_cursor_t");
    assert!(c.iter().any(|x| x.is_initial()) && c.iter().any(|x| x.is_complete()));
    let d: Vec<CopyData> = roundtrip("object_copy_data_t");
    assert_eq!(d.len(), 3);
    assert_eq!(d[2].size, 1234);
    assert_eq!(d[2].snaps, vec![123]);
    assert_eq!(d[2].data.len(), 20);
}

#[test]
fn copy_cursor_initial_requires_every_flag_unset() {
    assert!(CopyCursor::default().is_initial());
    for cursor in [
        CopyCursor {
            attr_complete: true,
            ..Default::default()
        },
        CopyCursor {
            data_offset: 1,
            ..Default::default()
        },
        CopyCursor {
            data_complete: true,
            ..Default::default()
        },
        CopyCursor {
            omap_offset: b"k".to_vec(),
            ..Default::default()
        },
        CopyCursor {
            omap_complete: true,
            ..Default::default()
        },
    ] {
        assert!(!cursor.is_initial(), "{cursor:?}");
    }
}
