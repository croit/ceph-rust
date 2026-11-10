// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Golden vectors from ceph-dencoder (testdata/replwire, regen: gen.sh): decode, re-encode byte-exact.
use denc::{Decode, Encode};
use replwire::*;
use std::path::PathBuf;

fn dir(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../testdata/replwire")
        .join(name)
}

fn bins(name: &str) -> Vec<(String, Vec<u8>)> {
    let mut v: Vec<_> = std::fs::read_dir(dir(name))
        .unwrap_or_else(|e| panic!("{name}: {e}"))
        .filter_map(|e| {
            let p = e.unwrap().path();
            (p.extension()? == "bin").then(|| {
                (
                    p.file_name().unwrap().to_string_lossy().into_owned(),
                    std::fs::read(&p).unwrap(),
                )
            })
        })
        .collect();
    v.sort();
    assert!(!v.is_empty(), "{name}: no vectors");
    v
}

fn roundtrip<T: Encode + for<'a> Decode<'a> + std::fmt::Debug + PartialEq>(name: &str) -> Vec<T> {
    bins(name)
        .into_iter()
        .map(|(f, b)| {
            let t: T = denc::from_slice(&b).unwrap_or_else(|e| panic!("{name}/{f}: decode {e}"));
            let re = t.encode_to_vec().unwrap();
            assert_eq!(re, b, "{name}/{f}: re-encode differs");
            let t2: T = denc::from_slice(&re).unwrap();
            assert_eq!(t, t2);
            t
        })
        .collect()
}

#[test]
fn object_info() {
    let v: Vec<ObjectInfo> = roundtrip("object_info_t");
    assert_eq!(v[0].data_digest, u32::MAX);
}

#[test]
fn snapset() {
    let v: Vec<SnapSet> = roundtrip("SnapSet");
    assert_eq!(v[1].seq, 123);
}

#[test]
fn snapcontext() {
    let _: Vec<SnapContext> = roundtrip("SnapContext");
}

#[test]
fn small_types() {
    let _: Vec<WatchInfo> = roundtrip("watch_info_t");
    let _: Vec<ObjectManifest> = roundtrip("object_manifest_t");
    let _: Vec<ChunkInfo> = roundtrip("chunk_info_t");
}

#[test]
fn recovery() {
    let _: Vec<ObjectRecoveryInfo> = roundtrip("ObjectRecoveryInfo");
    let _: Vec<ObjectRecoveryProgress> = roundtrip("ObjectRecoveryProgress");
    let _: Vec<PullOp> = roundtrip("PullOp");
    let _: Vec<PushOp> = roundtrip("PushOp");
    let _: Vec<PushReplyOp> = roundtrip("PushReplyOp");
}

#[test]
fn transactions() {
    for name in ["ObjectStore__Transaction", "ceph__os__Transaction"] {
        for (f, b) in bins(name) {
            let t = Transaction::decode(&[], &b, DEFAULT_PAGE)
                .unwrap_or_else(|e| panic!("{name}/{f}: {e}"));
            assert_eq!(t.struct_v, 9);
            assert_eq!(t.trailing, 0, "{name}/{f}");
            assert_eq!(t.encode_v9().unwrap(), b, "{name}/{f}");
        }
    }
}
