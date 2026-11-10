// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Object classes `lock` and `rbd` as a static registry over the [`ClsCtx`] objclass surface.
//!
//! Spec: doc/spec/cls.md (execution model), cls_lock.md, cls_rbd.md. Clean-room from those specs.
//!
//! Integration (crates/opexec): implement [`ClsCtx`] for the per-message object context, classify
//! every `call` op with [`lookup`], run it with [`call`] (static dispatch, generic over the ctx).
//! Method flags drive the cap check; the RD/WR counter enforcement is the executor's job.
//! `mem::MemCtx` (feature `mem`) is the reference implementation incl. the message-start view.

pub mod cas;
pub mod cephfs;
pub mod cmpomap;
pub mod config;
pub mod ctx;
pub mod errno;
pub mod fifo;
pub mod hello;
pub mod journal;
pub mod lock;
pub mod log;
#[cfg(any(test, feature = "mem"))]
pub mod mem;
pub mod numops;
pub mod otp;
pub mod queue;
pub mod rbd;
pub mod refcount;
pub mod registry;
pub mod rgw;
pub mod rgw_gc;
pub mod sdk;
pub mod sem_set;
pub mod timeindex;
pub mod tpc_queue;
pub mod unsupported;
pub mod user;
pub mod version;
pub mod wire;

pub use config::ClsConfig;
pub use ctx::{ARMOR, ClsCtx, OmapMap, Origin, Stat, Watcher, rand_armor, rand_uuid_text, release};
pub use errno::Errno;
pub use registry::{
    CLASSES, Method, PROMOTE, RD, RW, Reply, WR, call, call_by_name, lookup, methods,
};
