// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Leaf-delta relocation must not invalidate an unchanged remote OMAP compaction.
mod common;
use common::*;
use std::sync::Arc;
use store::dev::{CrashPolicy, SimDisk};
use store::layout::FEAT_DELTA_RELOG;
use store::obj::keys::omap_key;
use store::runs::{RunBuilder, RunPool};
use store::shard::ShardCfg;
use store::state::Op;

fn leaf_key(i: usize) -> Vec<u8> {
    format!("leaf/{i:05}/padding-for-multiple-leaves").into_bytes()
}

#[test]
fn held_helper_output_survives_owner_delta_relog_and_cold_replay() {
    let pool = Arc::new(RunPool::default());
    let cfg = ShardCfg {
        cache_pages: 400,
        dirty_soft_pages: 40,
        dirty_hard_pages: 600,
        ckpt_interval_ns: u64::MAX, // explicit checkpoints; do not trigger idle run-tree merges
        delta_cap_bytes: 4096,      // four segment pages: reach cleaning with a bounded fixture
        meta_slack_cells: 0,
        run_fan: 2,
        run_helpers: true,
        run_pool: Some(pool.clone()),
        ..Default::default()
    };
    let env = make_env_full(128, 8192, 1, cfg, 3, 4096, true, 64);
    assert_ne!(env.sb.features & FEAT_DELTA_RELOG, 0);
    let mut r = Rig::new(&env, 47);
    for start in (0..4000).step_by(200) {
        r.apply(
            (start..start + 200)
                .map(|i| Op::Put(leaf_key(i), vec![0; 48]))
                .collect(),
        );
    }
    r.remount_clean(); // real base pages, then small updates can become deltas

    r.shard.compaction_helpers(true, 1);
    for batch in 0..2u32 {
        let mut b = RunBuilder::default();
        for i in 0..64u32 {
            b.push(
                &omap_key(91, &(batch * 64 + i).to_be_bytes()),
                &[],
                &[0],
                b"run-value",
            );
        }
        r.apply(vec![Op::RunPut(b.finish(91).unwrap())]);
        r.sync();
    }
    let mut job = r
        .shard
        .take_compaction(false)
        .expect("owner exported the two-run compaction");
    let job = std::thread::spawn(move || {
        while !job.step(16) {}
        job
    })
    .join()
    .unwrap();
    let reserved = pool.helper_bytes();
    assert!(reserved > 0);
    let relogs_before = r.shard.tree_stats().relog_chains;
    let run_relogs_before = r.shard.stats.run_relogs;
    let run_merges_before = r.shard.stats.run_merges;
    for round in 0..64usize {
        r.put(&leaf_key(round * 503 % 4000), &[(round + 1) as u8; 48]);
        r.checkpoint();
        assert_eq!(
            pool.helper_bytes(),
            reserved,
            "checkpoint cannot retire the remote permit"
        );
        if r.shard.tree_stats().relog_chains > relogs_before {
            break;
        }
    }
    assert!(
        r.shard.tree_stats().relog_chains > relogs_before,
        "fixture must execute delta relog"
    );
    assert_eq!(
        r.shard.stats.run_relogs, run_relogs_before,
        "not an OMAP run relog"
    );
    assert_eq!(
        r.shard.stats.run_merges, run_merges_before,
        "inputs must not merge into the tree"
    );
    assert_eq!(r.shard.state().runs.n_runs(), 2);
    assert!(r.shard.return_compaction(job, true));
    assert_eq!(pool.helper_bytes(), 0);
    assert_eq!(r.shard.stats.run_helper_done, 1);
    assert_eq!(r.shard.stats.run_helper_lost, 0);
    assert_eq!(r.shard.state().runs.n_runs(), 1);
    r.verify();

    r.checkpoint();
    let image = r.disk.crash_image(CrashPolicy::DROP_ALL);
    r.fsck(&image);
    r.disk = SimDisk::from_image(&image, r.env.sim.clone());
    let (shard, _) = mount(&r.env, &r.disk, &mut r.clk).unwrap();
    r.shard = shard;
    r.submitted = 0;
    r.acked = 0;
    r.verify(); // exact OMAP and tree content, rebuilt from checkpoint/WAL with a cold cache
}
