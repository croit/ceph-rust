// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! oprobe: dev-only RADOS client for differential testing of OSD op semantics (classic OSD vs
//! croit-flashstore-osd). Kernel TCP (adr 0015 amendment); never linked into the daemon.
//!
//! * [`script`]: text op script -> compound MOSDOp ops
//! * [`client`]: [`Probe`] = mon session + osdmap + msgr2/cephx OSD connections + exec
//! * [`render`]: deterministic reply rendering
//! * [`harness`]: canned scripts, transcripts, A/B diff, golden check

pub mod client;
pub mod fill;
pub mod harness;
pub mod hash;
pub mod hotobj;
pub mod omapbench;
pub mod omapgate;
pub mod omapload;
pub mod omapworkload;
pub mod realbench;
pub mod render;
pub mod rmstall;
pub mod script;

/// Crate version plus the commit compiled in by `build.rs` (printed by `oprobe --version`).
pub const VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " (commit ",
    env!("OPROBE_GIT"),
    ")"
);

pub use client::{OpOutcome, Opts, Placement, Probe, Target};
