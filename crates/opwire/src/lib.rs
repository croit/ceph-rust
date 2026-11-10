// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! opwire: client op wire: OSDOp, MOSDOp/MOSDOpReply, MOSDBackoff, MWatchNotify (spec: client-ops.md).
//! Sans-IO, byte-exact; MOSDOp v7/v8/v9 decode (+encode), MOSDOpReply v8, typed per-op views.

pub mod classify;
pub mod consts;
pub mod copy;
mod msgs;
pub mod osdop;
pub mod payload;

pub use classify::*;
pub use consts::{NOSNAP, SNAPDIR, errno, flag, op, opflag};
pub use copy::*;
pub use msgs::*;
pub use osdop::*;
pub use payload::*;
