// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! opexec: sans-IO primary op execution engine of croit-flashstore-osd (spec: client-ops.md, cls.md, replication.md).
//!
//! * [`Engine`] = one per primary PG. Inputs: client ops ([`ClientReq`]), write completions, PG state changes,
//!   connection closes, timers. Outputs: [`Out`] (replies, watch/notify messages) drained with
//!   [`Engine::take_out`]. The PG itself is reached through the [`Env`] trait (log versions, dup lookup,
//!   `submit_write`, the store's read side = [`ObjView`]).
//! * [`exec::Exec`] = the op executor: one compound message against a working view of the object plus the
//!   committed store content ("two views", client-ops.md s7). cls primitives and plain ops share it.
//! * Per-object ordering: writes pipeline (the next write builds on the previous one's cached state), reads wait for
//!   in-flight writes of their object, other objects are independent (client-ops.md s5.5).
//!
//! Static dispatch only (adr 0024): everything is generic over `E: Env`.

pub mod backoff;
pub mod caps;
pub mod clsx;
pub mod engine;
pub mod exec;
mod fast;
mod objcache;
pub use objcache::{OBJ_HEAD_BYTES, obj_cache_cap};
pub mod pgop;
pub mod snap;
pub mod trim;
pub mod types;
pub mod view;
pub mod watch;

pub use engine::{ClientReq, Dropped, Engine, Env, Out, head_of};
pub use types::*;
pub use view::ObjView;
