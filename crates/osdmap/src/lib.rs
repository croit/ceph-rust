// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! osdmap: OSDMap / Incremental / pg_pool_t / MonMap codecs and the PG mapping
//! pipeline (spec: doc/spec/osdmap.md). Sans-IO. CRUSH: verbatim blob + lazily decoded map (crush crate);
//! placement goes through [`CrushMapper`].

mod compat;
pub mod consts;
mod crushmap;
pub mod error;
pub mod hash;
pub mod inc;
pub mod interval;
pub mod map;
pub mod mapping;
pub mod monmap;
pub mod pg_watch;
pub mod pool;
mod pool_name;
pub use pool_name::PoolName;

pub use crushmap::CrushState;
pub use error::{Error, Result};
pub use inc::Incremental;
pub use interval::IntervalSet;
pub use map::{OsdInfo, OsdMap, OsdXInfo};
pub use mapping::{CrushMapper, PgMapping, PrimaryDestination};
pub use monmap::{MonInfo, MonMap};
pub use pg_watch::{PgHashMap, PgWatch};
pub use pool::PgPool;
