// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! In-place store format upgrades (adr 0611): the step registry, the mount gate and the offline driver behind
//! `croit-flashstore-tool upgrade`.
//!
//! A step adds one incompatible feature bit. An offline step runs with the OSD stopped: the superblock first carries
//! `FEAT_UPGRADING` and the step id (`Superblock::upgrading`), so no build mounts the half-converted store for service
//! (this one refuses with [`StoreError::UpgradeNeeded`], older ones do not know the bit); the step's bit is set and the
//! mark cleared in one superblock write once the step finished. Every step is resumable: rerunning the driver after a
//! crash continues the marked step. A store without a bit an offline step adds to [`FEATURES_REQUIRED`] is refused by
//! the mount gate the same way.
//!
//! Steps: S7 `omap_lsm` (tree omap -> omap LSM engine, adr 0610; opt-in until the engine is the default format).

use crate::BLK;
use crate::dev::{BlockDev, Clock};
use crate::error::StoreError;
use crate::layout::{
    FEAT_OMAP_LSM, FEAT_UPGRADING, FEATURES_REQUIRED, Superblock, feature_names, heal_super,
    read_super,
};
use crate::obj::{ObjError, Store, StoreCfg};

/// Kind of a step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    /// Done at mount (no data rewrite).
    Quick,
    /// Needs `croit-flashstore-tool upgrade` with the OSD stopped.
    Offline,
}

/// One upgrade step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Step {
    /// Stable id (adr 0611 S<n>), stored in `Superblock::upgrading` while the step runs.
    pub id: u32,
    pub name: &'static str,
    pub class: Class,
    /// Feature bit the step adds.
    pub adds: u64,
}

/// S7: tree omap -> omap LSM engine (adr 0610).
pub const S7_OMAP_LSM: Step = Step {
    id: 7,
    name: "omap_lsm",
    class: Class::Offline,
    adds: FEAT_OMAP_LSM,
};

/// Every step this build can run, in order.
pub const STEPS: &[Step] = &[S7_OMAP_LSM];

pub fn step(id: u32) -> Option<&'static Step> {
    STEPS.iter().find(|s| s.id == id)
}

/// The step the store is marked with (`FEAT_UPGRADING`); `Err` for an id this build does not know.
fn marked(sb: &Superblock) -> Result<Option<&'static Step>, StoreError> {
    if sb.features & FEAT_UPGRADING == 0 {
        return Ok(None);
    }
    step(sb.upgrading).map(Some).ok_or_else(|| {
        StoreError::Newer(format!(
            "store is in upgrade step {} which this build does not know: finish it with the build that started it",
            sb.upgrading
        ))
    })
}

/// The omap LSM engine runs on this store: it has the format bit, or S7 is converting it.
pub fn engine_on(sb: &Superblock) -> bool {
    sb.features & FEAT_OMAP_LSM != 0
        || (sb.features & FEAT_UPGRADING != 0 && sb.upgrading == S7_OMAP_LSM.id)
}

/// Steps to reach the bits `want` (the marked step first), skipping those whose bit the store has.
pub fn plan(sb: &Superblock, want: u64) -> Result<Vec<&'static Step>, StoreError> {
    let m = marked(sb)?;
    let mut v: Vec<&'static Step> = m.into_iter().collect();
    v.extend(STEPS.iter().filter(|s| {
        want & s.adds != 0 && sb.features & s.adds == 0 && m.is_none_or(|x| x.id != s.id)
    }));
    Ok(v)
}

/// Mount gate for service: refuses a store marked upgrading or one an offline step must bring to
/// [`FEATURES_REQUIRED`] (`UpgradeNeeded`, the OSD exits 78 with the command).
pub fn mount_check(sb: &Superblock) -> Result<(), StoreError> {
    if let Some(s) = marked(sb)? {
        return Err(StoreError::UpgradeNeeded(format!(
            "offline step S{} {} was interrupted: run it to the end",
            s.id, s.name
        )));
    }
    let need: Vec<&str> = plan(sb, FEATURES_REQUIRED)?
        .iter()
        .filter(|s| s.class == Class::Offline)
        .map(|s| s.name)
        .collect();
    if !need.is_empty() {
        return Err(StoreError::UpgradeNeeded(format!(
            "offline step(s) {need:?} needed"
        )));
    }
    Ok(())
}

/// Driver options.
#[derive(Clone, Copy, Debug, Default)]
pub struct Opts {
    /// Add the omap LSM engine (S7); opt-in while the engine is not in [`FEATURES_REQUIRED`].
    pub omap_lsm: bool,
    /// Plan only, from the superblock: no mount, no write.
    pub dry_run: bool,
}

/// Progress of the driver (`croit-flashstore-tool upgrade --format jsonl` prints one line each).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// Steps to run; `resume` = the first one was interrupted and continues.
    Plan {
        steps: Vec<&'static str>,
        resume: bool,
    },
    /// S7 space check of one shard (before the mark): tree omap entries, their run bytes, data bytes available.
    Survey {
        shard: u32,
        entries: u64,
        bytes: u64,
        avail_bytes: u64,
    },
    /// The store is marked: the step started (no service mount until it finished).
    Mark {
        step: &'static str,
    },
    /// Shard conversion progress (S7): entries / bytes done of the totals left when the shard started.
    Progress {
        step: &'static str,
        shard: u32,
        entries: u64,
        entries_total: u64,
        bytes: u64,
        bytes_total: u64,
    },
    ShardDone {
        step: &'static str,
        shard: u32,
    },
    /// The step's bit is set, the mark cleared.
    Done {
        step: &'static str,
    },
}

/// Outcome of [`run`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// Steps run (or planned, dry run).
    pub steps: Vec<&'static str>,
    /// The first step resumed an interrupted run.
    pub resumed: bool,
    pub dry_run: bool,
    /// Feature bits after the run.
    pub features: Vec<String>,
}

/// Driver failure.
#[derive(Debug)]
pub enum UpgradeError {
    Obj(ObjError),
    /// A device queue could not be opened.
    Open(String),
    /// A shard has too little free data space for the step; nothing was changed.
    Space {
        shard: u32,
        need_bytes: u64,
        avail_bytes: u64,
    },
}

impl std::fmt::Display for UpgradeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UpgradeError::Obj(e) => write!(f, "{e}"),
            UpgradeError::Open(e) => write!(f, "open device queue: {e}"),
            UpgradeError::Space {
                shard,
                need_bytes,
                avail_bytes,
            } => write!(
                f,
                "shard {shard}: the omap conversion needs {need_bytes} free data bytes, {avail_bytes} available (short by {}): free space first; nothing was changed",
                need_bytes - avail_bytes
            ),
        }
    }
}

impl std::error::Error for UpgradeError {}

impl From<ObjError> for UpgradeError {
    fn from(e: ObjError) -> Self {
        UpgradeError::Obj(e)
    }
}

impl From<StoreError> for UpgradeError {
    fn from(e: StoreError) -> Self {
        UpgradeError::Obj(e.into())
    }
}

/// Data bytes S7 needs in a shard for `bytes` of run entries: the runs plus an eighth for run indexes, filters and
/// chunk rounding.
fn s7_need(bytes: u64) -> u64 {
    let b = crate::obj::upgrade_blocks(bytes);
    (b + b / 8) * BLK as u64
}

/// Run the steps that bring the store to the bits of this build ([`FEATURES_REQUIRED`], plus the opt-ins of `opts`),
/// resuming an interrupted one. The OSD must be stopped; `open` gives one queue handle per call. Idempotent: an
/// up-to-date store gets no write.
pub fn run<D: BlockDev, C: Clock>(
    mut open: impl FnMut() -> Result<D, String>,
    mut clk: C,
    cfg: StoreCfg,
    opts: Opts,
    ev: &mut dyn FnMut(&Event),
) -> Result<Report, UpgradeError> {
    let want = FEATURES_REQUIRED | if opts.omap_lsm { FEAT_OMAP_LSM } else { 0 };
    let (sb, _) = read_super(&mut open().map_err(UpgradeError::Open)?, &mut clk)?;
    let steps = plan(&sb, want)?;
    // A partial registry must not report an unservable store as up to date, or
    // make an optional conversion irreversible while mandatory migrations are
    // unavailable. Check the planned result before any mount or write, also
    // for dry runs. The mount gate still uses the plan independently.
    let mut projected = sb.clone();
    for s in &steps {
        projected.features |= s.adds;
    }
    crate::layout::check_required(&projected)?;
    let resumed = sb.features & FEAT_UPGRADING != 0;
    ev(&Event::Plan {
        steps: steps.iter().map(|s| s.name).collect(),
        resume: resumed,
    });
    let mut rep = Report {
        steps: steps.iter().map(|s| s.name).collect(),
        resumed,
        dry_run: opts.dry_run,
        features: Vec::new(),
    };
    if !opts.dry_run {
        for s in &steps {
            clk = match s.id {
                7 => s7(&mut open, clk, &cfg, ev)?,
                _ => unreachable!("registry step without a driver"),
            };
        }
    }
    let (sb, _) = read_super(&mut open().map_err(UpgradeError::Open)?, &mut clk)?;
    rep.features = feature_names(sb.features);
    Ok(rep)
}

/// Write the superblock with `f` applied (both copies, copy 0 first: the commit point).
fn set_super<D: BlockDev, C: Clock>(
    open: &mut impl FnMut() -> Result<D, String>,
    clk: &mut C,
    f: impl FnOnce(&mut Superblock),
) -> Result<(), UpgradeError> {
    let mut d = open().map_err(UpgradeError::Open)?;
    let (mut sb, _) = read_super(&mut d, clk)?;
    f(&mut sb);
    Ok(heal_super(&mut d, clk, &sb)?)
}

/// Mount every shard for the upgrade: the queue handles are opened first (superblock + one per shard + the elastic
/// pool's), so an open failure is an error, not a panic inside the mount.
fn mount<D: BlockDev, C: Clock>(
    open: &mut impl FnMut() -> Result<D, String>,
    mut clk: C,
    cfg: &StoreCfg,
) -> Result<Store<D, C>, UpgradeError> {
    let mut d0 = open().map_err(UpgradeError::Open)?;
    let (sb, _) = read_super(&mut d0, &mut clk)?;
    let mut qs = vec![d0];
    for _ in 0..=sb.shards {
        qs.push(open().map_err(UpgradeError::Open)?);
    }
    qs.reverse();
    let get = move || {
        qs.pop()
            .expect("queue handles prepared: superblock, shards, pool")
    };
    Ok(Store::mount_upgrade(get, clk, cfg.clone())?.0)
}

/// S7 (adr 0611): replay + checkpoint under the tree format and the space check, the mark, the per-shard conversion
/// (resumable, [`crate::obj::ShardStore`] `upgrade_omap_convert`), then the bit.
fn s7<D: BlockDev, C: Clock>(
    open: &mut impl FnMut() -> Result<D, String>,
    mut clk: C,
    cfg: &StoreCfg,
    ev: &mut dyn FnMut(&Event),
) -> Result<C, UpgradeError> {
    let st = S7_OMAP_LSM.name;
    let (sb, _) = read_super(&mut open().map_err(UpgradeError::Open)?, &mut clk)?;
    if sb.features & FEAT_UPGRADING == 0 {
        let mut store = mount(open, clk, cfg)?;
        let mut short = None;
        for s in &mut store.shards {
            let (entries, bytes) = s.upgrade_omap_survey(&mut store.clk)?;
            let avail = crate::obj::upgrade_avail_blocks(s) * BLK as u64;
            ev(&Event::Survey {
                shard: s.idx,
                entries,
                bytes,
                avail_bytes: avail,
            });
            let need = s7_need(bytes);
            if need > avail && short.is_none() {
                short = Some(UpgradeError::Space {
                    shard: s.idx,
                    need_bytes: need,
                    avail_bytes: avail,
                });
            }
        }
        store.checkpoint()?;
        clk = store.into_clock();
        if let Some(e) = short {
            return Err(e);
        }
        set_super(open, &mut clk, |sb| {
            sb.features |= FEAT_UPGRADING;
            sb.upgrading = S7_OMAP_LSM.id;
        })?;
        ev(&Event::Mark { step: st });
    }
    let mut store = mount(open, clk, cfg)?;
    for s in &mut store.shards {
        let shard = s.idx;
        let (entries_total, bytes_total) = s.upgrade_omap_survey(&mut store.clk)?;
        let (mut entries, mut bytes) = (0, 0);
        s.upgrade_omap_convert(&mut store.clk, |n, b| {
            entries += n;
            bytes += b;
            ev(&Event::Progress {
                step: st,
                shard,
                entries,
                entries_total,
                bytes,
                bytes_total,
            });
        })?;
        ev(&Event::ShardDone { step: st, shard });
    }
    store.checkpoint()?;
    clk = store.into_clock();
    set_super(open, &mut clk, |sb| {
        sb.features = (sb.features | FEAT_OMAP_LSM) & !FEAT_UPGRADING;
        sb.upgrading = 0;
    })?;
    ev(&Event::Done { step: st });
    Ok(clk)
}
