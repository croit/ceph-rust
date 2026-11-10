// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! peering: sans-IO PG peering state machine for croit-flashstore-osd (spec: peering.md, pglog.md,
//! replication.md; adr 0006/0008/0015).
//!
//! One [`Pg`] per PG, owned by exactly one core (no locks). Inputs: map epochs, peer messages
//! ([`Inbound`]), store commits, timers (`now` = monotonic ns since process start). Outputs:
//! [`Action`]s. [`PgSet`] is the per-core container an OSD drives.
//!
//! # Driver contract
//! * Startup: feed the retained maps oldest first with [`PgSet::add_map`], then
//!   [`PgSet::load_pgs`]. Afterwards every new epoch goes through [`PgSet::handle_map`].
//! * Messages: decode the msgr2 frame with [`Body::decode`] (type id, header version, segments),
//!   call [`PgSet::handle_msg`] with the sender OSD and header `tid`. Peering messages for an
//!   epoch the OSD has not got yet are parked inside and `Action::RequestMap` is emitted.
//! * `Action::Send`: encode with [`Body::encode`], set header tid/priority, send over the cluster
//!   messenger (already filtered: target up and `up_from(to) <= epoch`).
//! * `Action::Persist { spg, token, txn }`: apply the [`StoreTxn`] atomically and durably
//!   ([`PgStoreOps::submit`]), then call [`PgSet::on_commit`]. Transactions of one PG must commit
//!   in submission order; reads ([`PgStoreOps`]) must see every committed transaction.
//! * `NeedUpThru` -> MOSDAlive, `PgTemp` -> MOSDPGTemp, `PgCreated` -> MOSDPGCreated, `PgStats` ->
//!   MPGStats (primaries only), `WriteDone` -> finish the client op, `ReadableChanged` -> requeue
//!   ops waiting for the lease. Re-issue pending mon requests on a new session with
//!   [`PgSet::resend_mon_requests`].
//! * Timers: call [`PgSet::tick`] at [`PgSet::next_deadline`] (lease renewal, WAIT expiry, stats).
//! * Mon `MOSDPGCreate2` -> [`PgSet::handle_create`]. Client writes on a primary:
//!   [`PgSet::submit_write`] (the op layer builds the object-store transaction; the PG assigns
//!   versions, appends the log, fans out `MOSDRepOp`, completes in version order).
//!
//! Roles: replica/stray (M2) and primary (M3), log-based recovery with pull/push, backfill (primary
//! side batch by batch, `backfill.rs`), leases. pg_num split and merge (adr 0029, `split.rs`); not implemented:
//! the EC primary role runs only with `ec_enable_primary` (adr 0049, else PGs refuse, see [`Pg::refusal`]), scrub write preemption, heartbeat clock deltas
//! for replica reads. Snap trimming: PG side in `snaptrim.rs` (queue, gate, slot, purged snaps), mapper in `snaps.rs`, the
//! steps run in the primary's op engine (`opexec::trim`, adr 0037).

mod backfill;
mod damage;
pub mod ecdirect;
pub mod ecomap;
pub mod ecopt;
mod ecpg;
mod ecprim;
mod ecrec;
pub mod ecroll;
mod held;
pub mod map;
pub mod pg;
mod pgmap;
pub mod pgset;
pub mod place;
pub use pgmap::Touched;
pub mod latch;
mod lost;
pub mod plog;
mod primary;
mod recops;
mod recovery;
#[cfg(test)]
mod recovery_delete_tests;
#[cfg(test)]
mod recovery_durability_tests;
pub mod recstats;
pub mod scrub;
pub mod scrubcmp;
pub mod scrubls;
pub mod scrubp;
mod slots;
pub mod snaps;
mod snaptrim;
mod split;
pub mod store;
mod strays;
mod stretch;
pub mod types;
pub mod wake;

pub use ecprim::Attrs;
pub use latch::{DurStat, LatchKind, LatchPerf};
pub use lost::{LostDone, LostMode, LostReply, LostResult, UnfoundList, UnfoundObj};
pub use map::{MapHandle, PgMapView, RbFlags, RealMap, synth};
pub use pg::{ASt, PSt, Pg, PgCounters, REPOP_HELD_COMPLAINT_NS, RepRes, St, WriteErr, gating_of};
pub use pgset::{
    PEER_BACKOFF_MAX, PEER_BACKOFF_MIN, PeerStats, PgSet, ResumeCreates, Spgs, body_spg, body_spgs,
};
pub use plog::{IndexedLog, MissingSet};
pub use primary::{WriteEntry, WriteReq};
pub use recops::{OpsMsg, OpsReply, OpsReq};
pub use scrub::ScrubPart;
pub use scrubp::{ScrubFlags, ScrubGate, ScrubReq};
pub use slots::{Reservations, ResvDump};
pub use snaptrim::{PurgedScrub, TrimPoll};
pub use split::MergeStatus;
pub use store::{
    EncLogEntry, MemObj, MemStore, ObjListing, PersistedPg, PgStoreOps, PoolMsg, Queued, Space,
    SplitChild, StoreOp, StoreReadError, StoreTxn,
};
pub use types::*;
