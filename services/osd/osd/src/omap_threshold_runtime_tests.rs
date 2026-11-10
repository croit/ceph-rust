// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
//! Runtime range policy changes are acknowledged only after every core's mounted shards apply them.
use super::*;
use crate::asok::CmdResult;
use crate::config::Level;
use crate::tell::ReplyTo;
use serde_json::{Value, json};
use std::sync::mpsc::{Receiver, TryRecvError};

const KEY: &str = "flashstore_omap_delete_range_threshold";

fn begin(mc: &mut Mc, command: Value) -> Receiver<CmdResult> {
    let (tx, rx) = std::sync::mpsc::channel();
    let control = &mut mc.osds[0];
    control.cmds.seq += 1;
    let token = control.cmds.seq;
    control.cmds.pending.insert(token, tx);
    control.set_now(mc.t);
    control.exec_command(&command.to_string(), ReplyTo::Asok(token));
    rx
}

fn ask(mc: &mut Mc, command: Value) -> (i32, Value) {
    let rx = begin(mc, command);
    mc.settle();
    let (r, rs, out) = rx.try_recv().expect("configuration command answered");
    (
        r,
        serde_json::from_slice(&out.into_bytes()).unwrap_or(Value::String(rs)),
    )
}

fn thresholds(mc: &Mc) -> Vec<Vec<u64>> {
    mc.osds
        .iter()
        .map(|o| {
            o.pg.store.with_store(|s| {
                s.shards
                    .iter()
                    .map(|s| s.sh.omap_delete_range_threshold())
                    .collect()
            })
        })
        .collect()
}

fn assert_threshold(mc: &Mc, threshold: u64) {
    let values = thresholds(mc);
    assert_eq!(values.iter().map(Vec::len).sum::<usize>(), S as usize);
    assert!(
        values.iter().flatten().all(|v| *v == threshold),
        "{values:?}"
    );
    for o in &mc.osds {
        assert_eq!(o.conf.u64(KEY, u64::MAX), threshold);
    }
}

#[test]
fn omap_range_threshold_runtime_set_waits_for_every_core_without_replacing_stores() {
    let mut mc = Mc::with_olsm(3, 512);
    mc.up();
    let original_stores: Vec<_> = mc
        .osds
        .iter()
        .map(|o| Rc::as_ptr(&o.pg.store.shared()))
        .collect();
    assert_threshold(&mc, 0);
    for threshold in [1_048_576, 32, 0] {
        mc.delay = Some(|dst, m| dst == 2 && matches!(m, XMsg::Query { .. }));
        let rx = begin(
            &mut mc,
            json!({"prefix": "config set", "var": KEY, "val": threshold.to_string()}),
        );
        assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
        mc.settle();
        assert!(!mc.delayed.is_empty(), "last worker update is held");
        assert!(
            matches!(rx.try_recv(), Err(TryRecvError::Empty)),
            "must wait for last core"
        );
        let partial = thresholds(&mc);
        assert!(partial[..2].iter().flatten().all(|v| *v == threshold));
        assert!(partial[2].iter().all(|v| *v != threshold));
        mc.release_delayed();
        assert_eq!(rx.try_recv().expect("all cores acknowledged").0, 0);
        assert_threshold(&mc, threshold);
        let stores: Vec<_> = mc
            .osds
            .iter()
            .map(|o| Rc::as_ptr(&o.pg.store.shared()))
            .collect();
        assert_eq!(stores, original_stores, "no remount or store replacement");
    }
    let other = Mc::with_olsm(1, 512);
    assert_threshold(&other, 0);
    assert_threshold(&mc, 0);
}

#[test]
fn omap_range_threshold_runtime_invalid_values_preserve_state_and_unset_restores_layers() {
    let mut mc = Mc::with_olsm(2, 512);
    mc.up();
    for o in &mut mc.osds {
        o.conf.set(Level::File, KEY, "1048576").unwrap();
        o.conf_changed();
    }
    assert_threshold(&mc, 1_048_576);
    assert_eq!(
        ask(
            &mut mc,
            json!({"prefix":"config set", "var":KEY, "val":"32"})
        )
        .0,
        0
    );
    for bad in ["", "-1", "not-a-number", "4.0", "18446744073709551616"] {
        let rx = begin(
            &mut mc,
            json!({"prefix":"config set", "var":KEY, "val":bad}),
        );
        assert_eq!(
            rx.try_recv()
                .expect("invalid input answered without scattering")
                .0,
            -22
        );
        assert_threshold(&mc, 32);
    }
    assert_eq!(ask(&mut mc, json!({"prefix":"config set", "var":"flashstore-omap-delete-range-threshold", "val":" 64 "})).0, 0);
    let (r, got) = ask(&mut mc, json!({"prefix":"config get", "var":KEY}));
    assert_eq!(r, 0);
    assert_eq!(got[KEY], "64");
    assert_threshold(&mc, 64);
    assert_eq!(
        ask(&mut mc, json!({"prefix":"config unset", "var":KEY})).0,
        0
    );
    assert_threshold(&mc, 1_048_576);
    for o in &mut mc.osds {
        o.conf.unset(Level::File, KEY);
        o.conf_changed();
    }
    assert_eq!(
        ask(
            &mut mc,
            json!({"prefix":"config set", "var":KEY, "val":u64::MAX.to_string()})
        )
        .0,
        0
    );
    assert_threshold(&mc, u64::MAX);
    assert_eq!(
        ask(&mut mc, json!({"prefix":"config unset", "var":KEY})).0,
        0
    );
    assert_threshold(&mc, 0);
}

#[test]
fn omap_range_threshold_runtime_injectargs_and_monitor_configuration_reach_worker_stores() {
    let mut mc = Mc::with_olsm(2, 512);
    mc.up();
    assert_eq!(ask(&mut mc, json!({"prefix":"injectargs", "injected_args":["--flashstore_omap_delete_range_threshold=32"]})).0, 0);
    assert_threshold(&mc, 32);
    assert_eq!(
        ask(&mut mc, json!({"prefix":"config unset", "var":KEY})).0,
        0
    );
    let update = BTreeMap::from([(KEY.to_owned(), "64".to_owned())]);
    assert!(mc.osds[0].conf.apply_mon(&update).is_empty());
    mc.osds[0].conf_changed();
    mc.osds[0].publish_conf();
    mc.settle();
    assert_threshold(&mc, 64);
    assert_eq!(
        ask(
            &mut mc,
            json!({"prefix":"config set", "var":KEY, "val":"32"})
        )
        .0,
        0
    );
    assert_threshold(&mc, 32);
    let other = Mc::with_olsm(1, 512);
    assert_threshold(&other, 0);
    assert_threshold(&mc, 32);
}
