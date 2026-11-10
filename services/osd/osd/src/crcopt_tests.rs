// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! `ms_crc_data` (spec msgr2.md 4.3): the layered option reaches every messenger of a core (new connections only) and
//! the loss of frame integrity is loud. Child of `xcore_tests` (multi-core harness).
use super::*;

fn crc_cfg(o: &Osd<B>) -> Vec<bool> {
    o.msgr.iter().map(|m| m.cfg.crc_data).collect()
}

fn noted(mc: &Mc, core: usize, what: &str) -> usize {
    mc.osds[core]
        .logs
        .iter()
        .filter(|l| l.contains(what))
        .count()
}

#[test]
fn ms_crc_data_follows_the_config_and_is_loud_when_off() {
    let mut mc = Mc::new(2);
    mc.up();
    for o in &mc.osds {
        assert_eq!(crc_cfg(o), [true; 6], "default: every messenger verifies");
    }
    for o in &mut mc.osds {
        o.conf
            .set(crate::config::Level::Override, "ms_crc_data", "false")
            .unwrap();
        o.refresh_obs_conf();
        o.refresh_obs_conf(); // once per value, not per tick
    }
    for i in 0..mc.osds.len() {
        assert_eq!(crc_cfg(&mc.osds[i]), [false; 6], "core {i}");
    }
    // one line from the control core, not one per core
    assert_eq!(
        noted(&mc, 0, "WARNING ms_crc_data is false"),
        1,
        "{:?}",
        mc.osds[0].logs
    );
    // links keep the option they were created with (old: verify/verify), new ones write and skip crcs on both ends, so
    // traffic keeps working; the 0-crc frames are covered by the msgr2 interop matrix
    let cl = mc.client(0);
    let keys: BTreeMap<Vec<u8>, Vec<u8>> = [(b"k1".to_vec(), b"v1".to_vec())].into();
    let w = mc.op(1, "crc", vec![OsdOp::omap_set_vals(&keys)]);
    assert_eq!(mc.call(0, cl, 1, w)[0].1.result, 0);
    for o in &mut mc.osds {
        o.conf
            .set(crate::config::Level::Override, "ms_crc_data", "true")
            .unwrap();
        o.refresh_obs_conf();
    }
    for o in &mc.osds {
        assert_eq!(crc_cfg(o), [true; 6], "back to verified");
    }
}
