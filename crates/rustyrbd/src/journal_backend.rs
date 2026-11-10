// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Storage interface of the sans-IO journal engine.
//!
//! The journal core (writer, player, recovery; spec
//! `doc/spec/rustyrbd/ffi-journal-io.md`, "Implementation design (croit)")
//! talks to storage only through [`JournalBackend`]. All calls are
//! synchronous and durable on `Ok`; every failure is a negative Linux errno
//! and cls errors pass through unchanged. The RADOS backend lives in
//! rbd-ffi; the in-memory testkit implementation is `crate::journal_mem`
//! (compiled out of non-test builds without feature `journal-testkit`).

use crate::{JournalGeometry, JournalObjectPosition};

// Pinned Linux errno values of the journal protocol, negative as the
// backend returns them; independent of host libc.
/// `EPERM`: the current tag is not owned by the local image (not
/// promoted); a local writer cannot open.
pub const EPERM: i32 = -1;
/// `ENOENT`: journal header, client, tag or data object absent.
pub const ENOENT: i32 = -2;
/// `EIO`: storage failure, undecodable state during a scan, or a fault-plan
/// crash in the testkit.
pub const EIO: i32 = -5;
/// `EBUSY`: replay idempotency code of snapshot protect.
pub const EBUSY: i32 = -16;
/// `EEXIST`: journal header, client or tag already present.
pub const EEXIST: i32 = -17;
/// `EINVAL`: malformed input, too many commit positions, set-order violation.
pub const EINVAL: i32 = -22;
/// `ERANGE`: replay idempotency code of the snapshot limit.
pub const ERANGE: i32 = -34;
/// `EOVERFLOW`: the journal data object reached its soft maximum.
pub const EOVERFLOW: i32 = -75;
/// `EILSEQ`: compare-and-write mismatch.
pub const EILSEQ: i32 = -84;
/// `ESTALE`: non-monotonic set move or out-of-order tag TID.
pub const ESTALE: i32 = -116;
/// `ENOMSG`: a record's entry TID is not `last + 1` within the current tag
/// (mid-stream TID gap; stock `JournalPlayer::try_pop_front`).
pub const ENOMSG: i32 = -42;
/// `EOPNOTSUPP`: a replay target cannot re-execute this operation event;
/// recovery fails instead of skipping it.
pub const EOPNOTSUPP: i32 = -95;
/// `EBLOCKLISTED` (Ceph's alias of `ESHUTDOWN`): this client is fenced by
/// the cluster blocklist; the journal writer fails.
pub const EBLOCKLISTED: i32 = -108;
/// `EBADMSG`: malformed geometry, commit positions, record, padding or
/// stream state during replay.
pub const EBADMSG: i32 = -74;

/// The cls `journal` header methods plus the journal data objects.
///
/// Implementations are sans-IO friendly: no transport types cross this
/// boundary, every call is synchronous, `Ok` means durable, and every
/// failure is a negative errno (see the constants in this module).
pub trait JournalBackend {
    /// `get_order`, `get_splay_width`, `get_pool_id`, `get_minimum_set` and
    /// `get_active_set` in one call. `-ENOENT` when the header is absent.
    fn get_geometry(&self) -> Result<JournalGeometry, i32>;

    /// `get_client`: the raw `Client` record of `id`.
    fn get_client(&self, id: &[u8]) -> Result<Vec<u8>, i32>;

    /// `client_list`: raw `set<Client>` with IDs after `start_after`, at most
    /// `max` entries (`max <= 256`); an absent header yields the empty set.
    fn client_list(&self, start_after: &[u8], max: u64) -> Result<Vec<u8>, i32>;

    /// `client_register`: register `id` with the raw ClientData `data`; the
    /// new client inherits the minimum commit position of the existing ones.
    fn client_register(&self, id: &[u8], data: &[u8]) -> Result<(), i32>;

    /// `client_commit`: store the commit positions (newest first) of `id`;
    /// more than `splay_width` positions is `-EINVAL`.
    fn client_commit(&self, id: &[u8], positions: &[JournalObjectPosition]) -> Result<(), i32>;

    /// `tag_list`: raw `set<Tag>` with TIDs after `start_after`, at most
    /// `max` entries, hidden by the commit position of `client_id` and
    /// filtered by the optional `tag_class`.
    fn tag_list(
        &self,
        start_after: u64,
        max: u64,
        client_id: &[u8],
        tag_class: Option<u64>,
    ) -> Result<Vec<u8>, i32>;

    /// `get_tag`: the raw `Tag` record of `tid`.
    fn get_tag(&self, tid: u64) -> Result<Vec<u8>, i32>;

    /// `tag_create`: create tag `tid` of class `tag_class` with the raw
    /// TagData `data`; out-of-order TIDs are `-ESTALE`.
    fn tag_create(&self, tid: u64, tag_class: u64, data: &[u8]) -> Result<(), i32>;

    /// `get_next_tag_tid`: the next allocatable tag TID.
    fn get_next_tag_tid(&self) -> Result<u64, i32>;

    /// `set_active_set`: move the inclusive append set forward; moving
    /// backwards is `-ESTALE`.
    fn set_active_set(&self, set: u64) -> Result<(), i32>;

    /// `set_minimum_set`: move the trim floor forward; moving backwards is
    /// `-ESTALE`, a set above the active set is `-EINVAL`.
    fn set_minimum_set(&self, set: u64) -> Result<(), i32>;

    /// `append`: cls append to one data object with the `soft_max` limit;
    /// `-EOVERFLOW` means the object is full and nothing was written.
    fn append(&self, object_number: u64, soft_max: u64, bytes: &[u8]) -> Result<(), i32>;

    /// Read up to `buf` bytes from the object at `offset`; returns the bytes
    /// read, a short read (including zero) means the object end. `-ENOENT`
    /// when the object is absent.
    fn read_object(&self, object_number: u64, offset: u64, buf: &mut [u8]) -> Result<usize, i32>;

    /// Remove one data object; `-ENOENT` is tolerated by callers.
    fn remove_object(&self, object_number: u64) -> Result<(), i32>;

    /// `create`: initialize the journal header; `-EEXIST` when present.
    fn create(&self, order: u8, splay_width: u8, pool_id: i64) -> Result<(), i32>;

    /// `remove_header`: delete the journal header object; `-ENOENT` when
    /// absent.
    fn remove_header(&self) -> Result<(), i32>;
}
