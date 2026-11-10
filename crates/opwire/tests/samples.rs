// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Round-trip every sample and compare with `testdata/opwire/ours/<name>.msg`; rewrite them when
//! `EMIT_SAMPLES=1` (input for testdata/opwire/oracle.sh). Checks the real ceph-dencoder's decode
//! summaries (oracle/*.json).
mod common;
use common::*;
use opwire::*;

#[test]
fn all_samples_roundtrip_and_match_stored() {
    for (name, ver, m) in samples() {
        let (ty, v, compat, segs) = encode_sample(ver, &m);
        assert_eq!(v, ver);
        let back = decode_client(ty, v, &segs).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(back, m, "{name}");
        let wrapped = dencoder_wrapper(ty, v, compat, &segs);
        let path = testdata(&format!("ours/{name}.msg"));
        if std::env::var_os("EMIT_SAMPLES").is_some() {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, &wrapped).unwrap();
        } else {
            let stored = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            assert_eq!(
                stored, wrapped,
                "{name} differs from stored sample (regen: EMIT_SAMPLES=1)"
            );
        }
    }
}

/// The reference decoder accepted each sample (oracle.sh) and its summary shows our values.
#[test]
fn oracle_summaries() {
    let want = |n: &str, needles: &[&str]| {
        let j = std::fs::read_to_string(testdata(&format!("oracle/{n}.json"))).unwrap();
        for s in needles {
            assert!(j.contains(s), "{n}: {s:?} not in {j}");
        }
    };
    want(
        "MOSDOp.v9",
        &[
            "client.4242.5:77 1.d 1.6d31a10d (undecoded) ack+ondisk+write+known_if_redirected+supports_pool_eio e248",
        ],
    );
    want("MOSDOp.v8", &["client.4242.5:77 1.d 1.6d31a10d"]);
    want("MOSDOp.v7", &["client.4242.5:77 1.6d31a10d"]);
    want("MOSDOp.read", &["ack+ondisk+read"]);
    want(
        "MOSDOpReply.a",
        &["[read 0~4096 out=4096b,stat out=16b,sparse-read 0~65536] v250'17 uv12 ondisk = -2"],
    );
    want("MOSDOpReply.redirect", &["v250'18 uv13"]);
    want(
        "MWatchNotify.notify",
        &["watch-notify(notify (1) cookie 187647441017664 notify 996432412815"],
    );
    want(
        "MWatchNotify.complete",
        &["notify_complete (2) cookie 1 notify 5 ret -110"],
    );
}
