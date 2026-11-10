// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! pgwire: peering + PG log structs and MOSDPG* messages (spec: peering.md, pglog.md).
//!
//! Byte-exact encode/decode of `pg_history_t`, `pg_info_t`, `pg_stat_t`, `PastIntervals`,
//! `pg_log_entry_t`, `pg_log_t`, `pg_missing_t`, notify/query/lease structs and the peering
//! messages; plus pure interval-building helpers (`is_new_interval`, `check_new_interval`,
//! prior set) over an [`intervals::OsdMapView`] trait and the PG state bits/strings.

pub mod history;
pub mod info;
pub mod intervals;
pub mod log;
pub mod missing;
pub mod msgs;
pub mod peer;
pub mod pgmath;
pub mod stat;
pub mod state;

pub use history::PgHistory;
pub use info::{PgHitSetHistory, PgHitSetInfo, PgInfo};
pub use intervals::{
    BoundsCheck, BoundsVerdict, CompactInterval, EcPoolInfo, IntervalInput, MapFlags, Mapping,
    MergeMeta, NONE_OSD, OsdMapView, PastIntervals, PgInterval, PoolParams, PriorSet, can_peer,
    check_new_interval, is_new_interval, is_new_interval_maps, to_shards,
};
pub use log::{
    LogDup, LogEntry, LogOp, LogOpReturnItem, ObjectCleanRegions, ObjectModDesc, PgLog, ShardIdSet,
};
pub use missing::{MissingItem, PgMissing};
pub use msgs::*;
pub use peer::{PgLease, PgLeaseAck, PgNotify, PgQuery, QueryType, pg_features};
pub use pgmath::{is_split, pg_num_mask, stable_mod};
pub use stat::{IoCount, ObjectStatCollection, ObjectStatSum, PgStat};

pub use denc::{Error, Result};
/// `interval_set<T>` wire form (`map<start, length>`).
pub use messages::IntervalSet;
