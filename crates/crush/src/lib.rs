// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! CRUSH: map model, codec, rjenkins/straw2 and `do_rule` (sans-IO, allocation-free mapping).
//! Implemented from doc/spec/crush.md.

pub mod codec;
pub mod hash;
pub mod map;
pub mod mapper;
mod tables;

pub use codec::DecodeError;
pub use map::*;
pub use mapper::Workspace;
