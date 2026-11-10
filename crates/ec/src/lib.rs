// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! ec: erasure-coded pool facts for the shard role (adr 0039/0040, spec ec.md / ec-gap.md).
//!
//! Sans-IO: profile parsing, the per-pool support gate (allow-list, default deny), shard geometry, the `hinfo_key` xattr
//! codec, the `ObjectModDesc` rollback record codec and (primary role, adr 0048) the GF(2^8) codec in [`gf`].

#![deny(clippy::print_stderr, clippy::print_stdout)]
#![cfg_attr(test, allow(clippy::print_stderr, clippy::print_stdout))]
pub mod bitmat;
pub mod clay;
pub mod code;
pub mod enable;
pub mod gate;
pub mod geom;
pub mod gf;
pub mod hinfo;
pub mod lrc;
pub mod moddesc;
pub mod placed;
pub mod profile;
pub mod shec;

pub use code::Code;
pub use enable::EcEnable;
pub use gate::{EcFacts, EcMode, PoolEcInput, Verdict, evaluate};
pub use hinfo::{HINFO_KEY, HashInfo};
pub use profile::{EcProfile, Plugin, ProfileError};
pub mod wide;
