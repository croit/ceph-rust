// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Experimental native RADOS client; release compatibility is not yet qualified.
//! `experimental` enables the owned object engine; `bootstrap` adds transport-neutral
//! CephX monitor bootstrap and OSD authorizers. Production object runtime remains incomplete.
//! Driver must authenticate frames and supply validated pool/primary-shard placement.
#![deny(clippy::print_stderr, clippy::print_stdout)]
#![cfg_attr(test, allow(clippy::print_stderr, clippy::print_stdout))]

pub use diag::diag;

mod ec_split;
mod read_policy;
pub mod time;
pub use ec_split::{EcChildProgress, EcReadLayout, EcSplitCompletion, EcSplitRead, EcSplitResult};
mod read_routing;
pub use read_policy::ReplicaReadPolicy;
pub use read_routing::{ReadOperations, ReadRouting, is_primary_only_split_read};
mod admission;
mod map_admission;
pub use admission::{ByteAdmission, ByteAdmissionError};
pub use map_admission::*;
mod backoff;
mod bootstrap;
mod cluster_view;
pub use cluster_view::*;
mod dedup;
pub use bootstrap::*;
pub use dedup::*;
mod osd_auth;
pub use osd_auth::*;
mod class_access;
mod compound;
pub use class_access::pinned_class_access;
mod read;
mod recovery;
mod watch;
pub use backoff::*;
pub use compound::*;
pub use read::*;
#[cfg(feature = "registered-memory")]
mod read_into;
#[cfg(feature = "registered-memory")]
pub use read_into::{
    ReadDeliveryPath, ReadIntoPolicy, ReadIntoRequest, ReadIntoResult, RejectedReadInto,
};
pub use recovery::*;
pub use watch::*;
pub type FrozenPayload = bytes::Bytes;
mod watch_lifecycle;
pub use watch_lifecycle::*;
mod linger;
pub use linger::*;
mod snapshot;
pub use snapshot::*;
mod named_snapshots;
pub use named_snapshots::*;
mod listing;
pub use listing::*;
mod list_scan;
pub use list_scan::*;
mod list_filter;
pub use list_filter::*;
mod locks;
pub use locks::*;
mod map_barrier;
pub use map_barrier::*;
mod metadata;
pub use metadata::*;
mod blocklist;
pub use blocklist::*;
mod command_compatible;
mod monitor_commands;
pub use command_compatible::CommandCompatibleProfile;
pub use monitor_commands::*;
