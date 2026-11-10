// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! `mgr_connect_retry_interval` is a schema `float` without min/max (up to ~1e308, `u64::MAX` seconds after the cast):
//! a value the retry deadline cannot hold falls back to the 1 s default instead of aborting a reconnect.
use super::*;

/// Both retry deadlines (a fresh attempt inside the window and a lost link) stay finite on an unusable mon value.
#[test]
fn an_unusable_mgr_connect_retry_interval_falls_back_to_the_default() {
    let mut mc = Mc::new(1);
    let now = mc.t;
    let o = &mut mc.osds[0];
    o.conf
        .set(
            crate::config::Level::Mon,
            "mgr_connect_retry_interval",
            "1e30",
        )
        .unwrap();
    o.set_now(now);
    o.mgr.available = true;
    o.mgr_connect(); // no address in the (empty) MgrMap: no link, the attempt is recorded
    assert!(o.mgr.link.is_none());
    o.mgr_connect(); // inside the retry window: the next attempt is scheduled
    assert_eq!(o.mgr.retry_at, Some(now + Duration::from_secs(1)));
    o.mgr.link = Some(7);
    o.mgr_link_lost(7);
    assert_eq!(o.mgr.retry_at, Some(now + Duration::from_secs(1)));
}
