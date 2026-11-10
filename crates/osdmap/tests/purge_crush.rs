// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Regression: an inc that removes a device from crush (osd purge) must reproduce the mon's
//! full-map crc (max_devices recomputed on decode, see testdata/osdmap/README.md).
use osdmap::{Incremental, OsdMap};
use std::path::Path;

#[test]
fn purge_inc_reproduces_full_crc() {
    let d = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/osdmap/purge");
    let m113 = OsdMap::decode_from(&std::fs::read(d.join("full_0113.bin")).unwrap()).unwrap();
    let raw114 = std::fs::read(d.join("full_0114.bin")).unwrap();
    let inc = Incremental::decode_from(&std::fs::read(d.join("inc_0114.bin")).unwrap()).unwrap();
    let m114 = m113
        .apply_incremental_checked(&inc)
        .expect("crc must match");
    assert_eq!(m114.encode_full().unwrap(), raw114);
}
