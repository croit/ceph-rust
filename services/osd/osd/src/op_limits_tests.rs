// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Classic per-request limits (`osd_max_omap_entries_per_request`, ...) follow the OSD config at runtime (review F7).
use super::*;

/// An operator `osd_max_omap_entries_per_request` caps omap listings of engines that already exist and of the cls
/// `cls_get_config` view, like a classic OSD.
#[test]
fn omap_entries_per_request_follows_the_config() {
    let mut mc = Mc::new(2);
    mc.up();
    let keys: BTreeMap<Vec<u8>, Vec<u8>> =
        (0..5u8).map(|i| (vec![b'k', b'0' + i], vec![i])).collect();
    let cl = mc.client(0);
    let w = mc.op(1, "limits", vec![OsdOp::omap_set_vals(&keys)]);
    assert_eq!(mc.call(0, cl, 1, w)[0].1.result, 0);
    let list = |mc: &mut Mc, tid: u64| {
        let r = mc.op(1, "limits", vec![OsdOp::omap_get_vals(b"", 100, b"")]);
        let rep = mc.call(0, cl, tid, r);
        let out: opwire::OmapValsOut = denc::from_slice(&rep[0].1.ops[0].outdata).unwrap();
        (out.vals.len(), out.truncated)
    };
    assert_eq!(list(&mut mc, 2), (5, false));
    for o in &mut mc.osds {
        o.conf
            .set(
                crate::config::Level::Override,
                "osd_max_omap_entries_per_request",
                "2",
            )
            .unwrap();
        o.refresh_obs_conf();
    }
    assert_eq!(list(&mut mc, 3), (2, true));
}
