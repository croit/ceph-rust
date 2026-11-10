// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! `Store::perf_counters` exports a fixed list of names and gauge flags (operator scripts read them from `perf dump`):
//! the list is pinned in `perf-counter-names.txt` (`name gauge|counter`, in dump order). `UPDATE_PERF_NAMES=1` rewrites it.
//! Elastic-pool names (`lend_*`, `reclaim_*`) depend on the `elastic` feature and are not part of the file.
use store::dev::{SimClock, SimConfig, SimDisk};
use store::layout::{MkfsParams, mkfs};
use store::obj::{Store, StoreCfg};

#[test]
fn perf_counter_names_are_stable() {
    let disk = SimDisk::new(SimConfig::new(4 << 30));
    let mut dev = disk.queue();
    let mut clk = SimClock::default();
    let p = MkfsParams {
        shards: 1,
        ..Default::default()
    };
    mkfs(&mut dev, &mut clk, &p).unwrap();
    let d2 = disk.clone();
    let (st, _) =
        Store::mount(move || d2.queue(), SimClock::default(), StoreCfg::default()).unwrap();
    let got: Vec<String> = st
        .perf_counters()
        .into_iter()
        .filter(|(n, _, _)| !n.starts_with("lend_") && !n.starts_with("reclaim_"))
        .map(|(n, g, _)| format!("{n} {}", if g { "gauge" } else { "counter" }))
        .collect();
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/perf-counter-names.txt");
    if std::env::var_os("UPDATE_PERF_NAMES").is_some() {
        std::fs::write(path, got.join("\n") + "\n").unwrap();
        return;
    }
    let want = std::fs::read_to_string(path).unwrap();
    let want: Vec<&str> = want.lines().collect();
    assert_eq!(
        got, want,
        "perf_counters names changed (UPDATE_PERF_NAMES=1 rewrites the file)"
    );
}
