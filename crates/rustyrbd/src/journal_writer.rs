// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Local librbd journal writer (journaling step S4).
//!
//! Implements the writer rules of `doc/spec/rustyrbd/ffi-journal-io.md`
//! ("DATA ordering", "Rollover", "Commit, trim, close") and
//! `doc/adr/0700-rbd-journaling.md` over the [`JournalBackend`] trait:
//!
//! - [`JournalWriter::append`] assigns consecutive entry TIDs of the current
//!   tag, appends the records one class append per splay object (splays in
//!   ascending TID-of-first-record order) and hands back a [`Ticket`] only
//!   after every append returned durably. A record that would pass the
//!   object's soft maximum, or a class `-EOVERFLOW`, rolls the shared active
//!   set forward (`set_active_set`, `-ESTALE` = moved by someone else) and
//!   retries that splay batch in the new set.
//! - [`JournalWriter::complete`] records the data result. Commit positions
//!   advance only over completed tickets in TID order; a data error (other
//!   than a compare-and-write's `-EILSEQ`) sets `commit_blocked` and stops
//!   all further advancement until the next recovery.
//! - Positions are persisted (`client_commit`) at most every
//!   `commit_age` by the injected [`JournalClock`] after a completion, or on
//!   an explicit [`JournalWriter::persist`] barrier; unchanged positions are
//!   not sent. A persist that wrote trims when the active set is above the
//!   minimum set.
//! - [`JournalWriter::close`] persists (unless blocked) and appends nothing.
//!
//! Any append, rollover or commit error moves the writer to
//! [`WriterState::Failed`]; trim errors are logged and leave it ready, except
//! `-EBLOCKLISTED`. The writer starts no thread and no timer; it is driven
//! serially by its owner.

use rustyrados::diag;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::journal_append::JournalAppendCursor;
use crate::journal_backend::{
    EBADMSG, EBLOCKLISTED, EILSEQ, EINVAL, EIO, ENOENT, EOVERFLOW, ESTALE, JournalBackend,
};
use crate::journal_client::{
    JOURNAL_CLIENT_STATE_DISCONNECTED, JournalObjectPosition, decode_journal_client_fields_set,
};
use crate::journal_event::{JournalEvent, encode_journal_event_entry, encode_journal_record};
use crate::journal_meta::JournalGeometry;

/// Fixed bytes of one journal data-object record around its event entry
/// (25-byte header plus 8-byte remainder, spec J2).
pub const JOURNAL_ENTRY_FIXED_SIZE: u64 = 33;
/// Fixed bytes of a Write event entry: event and timestamp frames (28) plus
/// offset and length (spec J2).
pub const AIO_WRITE_EVENT_FIXED_SIZE: u64 = 44;
/// Fixed bytes of a compare-and-write event entry (28 + 32, spec J2).
pub const AIO_COMPARE_AND_WRITE_EVENT_FIXED_SIZE: u64 = 60;
/// Page size of the trim's `client_list` scan.
pub const CLIENT_LIST_PAGE: u64 = 256;

/// The local image client's ID.
const LOCAL_CLIENT_ID: &[u8] = b"";

/// Identity of the next writer generation. A ticket is valid only for the
/// writer generation that issued it, so a stale ticket can never complete
/// an in-flight entry of a later writer that reused its TID range.
static NEXT_WRITER_GENERATION: AtomicU64 = AtomicU64::new(1);

/// Time source of the writer, injected so tests never read a wall clock.
pub trait JournalClock {
    /// Monotonic time since an arbitrary fixed origin; drives the commit
    /// cadence.
    fn monotonic(&self) -> Duration;
    /// Wall-clock event timestamp `(seconds, nanoseconds)` recorded in each
    /// EventEntry's metadata frame.
    fn timestamp(&self) -> (u32, u32);
}

/// Writer configuration from the effective image config.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalWriterConfig {
    /// `rbd_journal_commit_age`: minimum interval between cadence persists.
    pub commit_age: Duration,
    /// `rbd_journal_max_payload_bytes`.
    pub max_payload_bytes: u64,
    /// Image ID for diagnostics.
    pub image_id: String,
}

/// Writer state; a closed writer is consumed by [`JournalWriter::close`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriterState {
    /// Appends, completions, persists and trims are admitted.
    Ready,
    /// A journal call failed with this errno; nothing is admitted and the
    /// next owner acquisition recovers.
    Failed(i32),
}

/// Durable append of one request's entries; consumed by
/// [`JournalWriter::complete`] of the writer that issued it.
#[derive(Debug, PartialEq, Eq)]
#[must_use = "a ticket must be completed with the data result"]
pub struct Ticket {
    /// The issuing writer generation.
    generation: u64,
    first_tid: u64,
    count: u64,
    compare_and_write: bool,
}

impl Ticket {
    /// The first entry TID of the request.
    pub fn first_tid(&self) -> u64 {
        self.first_tid
    }

    /// The last entry TID of the request.
    pub fn last_tid(&self) -> u64 {
        self.first_tid + (self.count - 1)
    }
}

/// One appended request awaiting its data result.
#[derive(Debug)]
struct InFlight {
    first_tid: u64,
    /// Where each entry landed, in TID order.
    positions: Vec<JournalObjectPosition>,
    done: bool,
}

/// The journal writer of one owner generation.
#[derive(Debug)]
pub struct JournalWriter<C> {
    config: JournalWriterConfig,
    clock: C,
    /// This writer's identity; see [`NEXT_WRITER_GENERATION`].
    generation: u64,
    tag_tid: u64,
    max_append_size: u64,
    minimum_set: u64,
    cursor: JournalAppendCursor,
    /// Per splay the last completed entry (in-memory commit position).
    positions: Vec<Option<JournalObjectPosition>>,
    /// The list last stored by `client_commit`.
    persisted: Vec<JournalObjectPosition>,
    last_persist: Duration,
    in_flight: VecDeque<InFlight>,
    commit_blocked: bool,
    state: WriterState,
}

impl<C: JournalClock> JournalWriter<C> {
    /// Build the writer from the current header geometry, the current tag
    /// and the player's seal `(positions newest first, next_tid)`.
    ///
    /// The caller has already persisted the sealed positions (spec state
    /// `Sealing`); they are the writer's persisted baseline. Malformed
    /// geometry or positions is `-EBADMSG`; a position of a newer tag, a
    /// current-tag position at or past `next_tid`, or a maximum append size
    /// that cannot hold one Write data byte is `-EINVAL`.
    pub fn new(
        geometry: &JournalGeometry,
        tag_tid: u64,
        sealed: (Vec<JournalObjectPosition>, u64),
        config: JournalWriterConfig,
        clock: C,
    ) -> Result<Self, i32> {
        let (sealed_positions, next_tid) = sealed;
        geometry.validate().map_err(|_| EBADMSG)?;
        geometry
            .validate_positions(&sealed_positions)
            .map_err(|_| EBADMSG)?;
        if sealed_positions
            .iter()
            .any(|p| p.tag_tid > tag_tid || (p.tag_tid == tag_tid && p.entry_tid >= next_tid))
        {
            return Err(EINVAL);
        }
        let object_size = 1u64 << geometry.order;
        let max_append_size =
            (object_size - JOURNAL_ENTRY_FIXED_SIZE).min(config.max_payload_bytes);
        if max_append_size <= AIO_WRITE_EVENT_FIXED_SIZE {
            return Err(EINVAL);
        }
        let cursor = JournalAppendCursor::new(
            geometry.splay_width,
            geometry.order,
            geometry.active_set,
            next_tid,
        )
        .map_err(|_| EBADMSG)?;
        let width = u64::from(geometry.splay_width);
        let mut positions = vec![None; usize::from(geometry.splay_width)];
        for position in &sealed_positions {
            positions[(position.object_number % width) as usize] = Some(*position);
        }
        let mut writer = Self {
            last_persist: clock.monotonic(),
            config,
            clock,
            generation: NEXT_WRITER_GENERATION.fetch_add(1, Ordering::Relaxed),
            tag_tid,
            max_append_size,
            minimum_set: geometry.minimum_set,
            cursor,
            positions,
            persisted: Vec::new(),
            in_flight: VecDeque::new(),
            commit_blocked: false,
            state: WriterState::Ready,
        };
        writer.persisted = writer.positions();
        Ok(writer)
    }

    /// `min(1 << order - 33, rbd_journal_max_payload_bytes)` (spec J2): the
    /// largest encoded event entry one record may hold.
    pub fn max_append_size(&self) -> u64 {
        self.max_append_size
    }

    /// Data bytes per Write event chunk (spec DATA ordering step 2).
    pub fn write_chunk_len(&self) -> u64 {
        self.max_append_size - AIO_WRITE_EVENT_FIXED_SIZE
    }

    /// Compare (and replacement) bytes per compare-and-write event chunk
    /// (spec DATA ordering step 2): half the remaining entry, so one chunk
    /// with both buffers fits one record.
    pub fn compare_and_write_chunk_len(&self) -> u64 {
        self.max_append_size
            .saturating_sub(AIO_COMPARE_AND_WRITE_EVENT_FIXED_SIZE)
            / 2
    }

    /// The writer state.
    pub fn state(&self) -> WriterState {
        self.state
    }

    /// A data error stopped commit advancement until the next recovery.
    pub fn commit_blocked(&self) -> bool {
        self.commit_blocked
    }

    /// The tag of every appended entry.
    pub fn tag_tid(&self) -> u64 {
        self.tag_tid
    }

    /// The next entry TID to assign.
    pub fn next_tid(&self) -> u64 {
        self.cursor.next_tid()
    }

    /// The current, inclusive append set.
    pub fn active_set(&self) -> u64 {
        self.cursor.active_set()
    }

    /// The trim floor this writer last established or observed.
    pub fn minimum_set(&self) -> u64 {
        self.minimum_set
    }

    /// In-memory commit positions, newest (tag, TID) first, at most one
    /// per splay.
    pub fn positions(&self) -> Vec<JournalObjectPosition> {
        let mut list: Vec<JournalObjectPosition> =
            self.positions.iter().flatten().copied().collect();
        list.sort_by_key(|p| std::cmp::Reverse((p.tag_tid, p.entry_tid)));
        list
    }

    /// The positions last stored by `client_commit` (or the sealed
    /// baseline).
    pub fn persisted_positions(&self) -> &[JournalObjectPosition] {
        &self.persisted
    }

    /// Append the events of one request and return its ticket once every
    /// record is durable.
    ///
    /// A compare-and-write event is split into consecutive sub-range events
    /// of at most [`Self::compare_and_write_chunk_len`] compare (and
    /// replacement) bytes, one record per sub-range; a small one stays one
    /// event. An empty request, an event whose encoded entry exceeds
    /// [`Self::max_append_size`], an inconsistent compare-and-write (compare,
    /// replacement and length differ), or TID exhaustion is `-EINVAL` with no
    /// state change. A backend error (other than a handled `-EOVERFLOW`)
    /// fails the writer; records already appended stay unacknowledged and
    /// are resolved by recovery.
    pub fn append(
        &mut self,
        backend: &impl JournalBackend,
        events: &[JournalEvent<'_>],
    ) -> Result<Ticket, i32> {
        self.ready()?;
        if events.is_empty() {
            return Err(EINVAL);
        }
        let (seconds, nanoseconds) = self.clock.timestamp();
        let first_tid = self.cursor.next_tid();
        let mut records = Vec::with_capacity(events.len());
        let mut entry = Vec::new();
        let mut count = 0u64;
        for event in events {
            if let JournalEvent::CompareAndWrite {
                offset,
                length,
                compare,
                replacement,
            } = *event
            {
                let total = compare.len();
                if replacement.len() != total || length != total as u64 {
                    return Err(EINVAL);
                }
                let chunk =
                    usize::try_from(self.compare_and_write_chunk_len()).unwrap_or(usize::MAX);
                if total != 0 && chunk == 0 {
                    return Err(EINVAL);
                }
                let mut start = 0usize;
                loop {
                    let end = total.min(start.saturating_add(chunk.max(1)));
                    let part = JournalEvent::CompareAndWrite {
                        offset: offset
                            .checked_add(u64::try_from(start).map_err(|_| EINVAL)?)
                            .ok_or(EINVAL)?,
                        length: (end - start) as u64,
                        compare: &compare[start..end],
                        replacement: &replacement[start..end],
                    };
                    encode_journal_event_entry(&part, seconds, nanoseconds, &mut entry)
                        .map_err(|_| EINVAL)?;
                    if entry.len() as u64 > self.max_append_size {
                        return Err(EINVAL);
                    }
                    let tid = first_tid.checked_add(count).ok_or(EINVAL)?;
                    let mut record = Vec::new();
                    encode_journal_record(tid, self.tag_tid, &entry, &mut record)
                        .map_err(|_| EINVAL)?;
                    records.push(record);
                    count += 1;
                    start = end;
                    if start >= total {
                        break;
                    }
                }
                continue;
            }
            encode_journal_event_entry(event, seconds, nanoseconds, &mut entry)
                .map_err(|_| EINVAL)?;
            if entry.len() as u64 > self.max_append_size {
                return Err(EINVAL);
            }
            let tid = first_tid.checked_add(count).ok_or(EINVAL)?;
            let mut record = Vec::new();
            encode_journal_record(tid, self.tag_tid, &entry, &mut record).map_err(|_| EINVAL)?;
            records.push(record);
            count += 1;
        }
        self.cursor.allocate(count).map_err(|_| EINVAL)?;
        let positions = match self.append_records(backend, first_tid, &records) {
            Ok(positions) => positions,
            Err((stage, errno)) => return Err(self.fail(stage, errno)),
        };
        self.in_flight.push_back(InFlight {
            first_tid,
            positions,
            done: false,
        });
        Ok(Ticket {
            generation: self.generation,
            first_tid,
            count,
            compare_and_write: events
                .iter()
                .any(|event| matches!(event, JournalEvent::CompareAndWrite { .. })),
        })
    }

    /// Record the data result of a ticket's request, advance the in-memory
    /// commit positions over the completed TID prefix, then persist when
    /// `commit_age` elapsed and the positions changed.
    ///
    /// `0`, or `-EILSEQ` for a compare-and-write request, completes the
    /// entries; any other result leaves them uncommitted and blocks commit
    /// advancement. An `Err` is the journal's failure (writer `Failed`, or
    /// `-EINVAL` for a stale or foreign ticket: another writer generation,
    /// or an entry count that does not identify the in-flight entry); it
    /// never changes the data result the caller returns.
    pub fn complete(
        &mut self,
        backend: &impl JournalBackend,
        ticket: Ticket,
        result: i32,
    ) -> Result<(), i32> {
        let index = self
            .in_flight
            .binary_search_by_key(&ticket.first_tid, |entry| entry.first_tid)
            .map_err(|_| EINVAL)?;
        if ticket.generation != self.generation
            || ticket.count != self.in_flight[index].positions.len() as u64
        {
            return Err(EINVAL);
        }
        if result == 0 || (result == EILSEQ && ticket.compare_and_write) {
            self.in_flight[index].done = true;
        } else {
            self.commit_blocked = true;
        }
        self.advance();
        self.ready()?;
        let elapsed = self.clock.monotonic().saturating_sub(self.last_persist);
        if elapsed >= self.config.commit_age {
            self.persist(backend)?;
        }
        Ok(())
    }

    /// Persist the in-memory positions now (barrier); skipped when they
    /// equal the persisted ones. A persist that wrote trims when the active
    /// set is above the minimum set. A commit error fails the writer.
    pub fn persist(&mut self, backend: &impl JournalBackend) -> Result<(), i32> {
        self.ready()?;
        if self.commit(backend)? && self.cursor.active_set() > self.minimum_set {
            self.trim(backend)?;
        }
        Ok(())
    }

    /// Remove the object sets no client needs any more.
    ///
    /// Pages `client_list` reading only the cls client fields (ClientData is
    /// never decoded); DISCONNECTED clients are ignored and a client with
    /// empty positions disables the trim. The target set starts at the
    /// active set and drops to the minimum object set of every remaining
    /// position (with every client DISCONNECTED it stays the active set);
    /// every data object of `[minimum_set, target)` is removed (`-ENOENT`
    /// ok), then `set_minimum_set(target)` (`-ESTALE` ok). Errors are logged
    /// and leave the writer ready, except `-EBLOCKLISTED`, which fails it.
    pub fn trim(&mut self, backend: &impl JournalBackend) -> Result<(), i32> {
        self.ready()?;
        match self.trim_sets(backend) {
            Ok(()) => Ok(()),
            Err((stage, errno)) if errno == EBLOCKLISTED => Err(self.fail(stage, errno)),
            Err((stage, errno)) => {
                diag!(
                    "WARNING journal trim failed image={} errno={errno} stage={stage}",
                    self.config.image_id
                );
                Ok(())
            }
        }
    }

    /// Close the writer: persist the completed prefix (unless commit is
    /// blocked); no event is appended. Entries of tickets not yet completed
    /// stay uncommitted and replay on the next open, so the owner drains its
    /// requests first. A failed writer does no I/O and returns its errno; a
    /// commit error is logged and returned.
    pub fn close(mut self, backend: &impl JournalBackend) -> Result<(), i32> {
        self.ready()?;
        if self.commit_blocked {
            diag!(
                "WARNING journal close with blocked commit image={}: uncommitted entries replay on the next open",
                self.config.image_id
            );
            return Ok(());
        }
        self.commit(backend).map(|_| ())
    }

    fn ready(&self) -> Result<(), i32> {
        match self.state {
            WriterState::Ready => Ok(()),
            WriterState::Failed(errno) => Err(errno),
        }
    }

    fn fail(&mut self, stage: &str, errno: i32) -> i32 {
        diag!(
            "ERROR journal writer failed image={} errno={errno} stage={stage}",
            self.config.image_id
        );
        self.state = WriterState::Failed(errno);
        errno
    }

    /// Store the in-memory positions; `Ok(true)` when `client_commit` ran.
    fn commit(&mut self, backend: &impl JournalBackend) -> Result<bool, i32> {
        let list = self.positions();
        if list == self.persisted {
            return Ok(false);
        }
        match backend.client_commit(LOCAL_CLIENT_ID, &list) {
            Ok(()) => {
                self.persisted = list;
                self.last_persist = self.clock.monotonic();
                Ok(true)
            }
            Err(errno) => Err(self.fail("commit", errno)),
        }
    }

    /// Advance the in-memory positions over the completed TID prefix.
    fn advance(&mut self) {
        if self.commit_blocked {
            return;
        }
        while self.in_flight.front().is_some_and(|entry| entry.done) {
            let Some(entry) = self.in_flight.pop_front() else {
                break;
            };
            for position in entry.positions {
                let splay = self.cursor.splay(position.entry_tid);
                debug_assert!(self.positions[splay].is_none_or(
                    |old| (old.tag_tid, old.entry_tid) < (position.tag_tid, position.entry_tid)
                ));
                self.positions[splay] = Some(position);
            }
        }
    }

    /// Append encoded records `first_tid..` one class append per splay
    /// object; returns where each record landed.
    fn append_records(
        &mut self,
        backend: &impl JournalBackend,
        first_tid: u64,
        records: &[Vec<u8>],
    ) -> Result<Vec<JournalObjectPosition>, (&'static str, i32)> {
        let width = self.positions.len();
        let mut positions = Vec::with_capacity(records.len());
        positions.extend(
            (0..records.len() as u64).map(|offset| JournalObjectPosition {
                object_number: 0,
                tag_tid: self.tag_tid,
                entry_tid: first_tid + offset,
            }),
        );
        let mut batch = Vec::new();
        // Lanes in ascending TID-of-first-record order; lane `l` holds the
        // records `l, l + width, ...`, all in one splay.
        for lane in 0..records.len().min(width) {
            let splay = self.cursor.splay(first_tid + lane as u64);
            let mut index = lane;
            while index < records.len() {
                let take = self
                    .cursor
                    .batch_len(splay, records[index..].iter().step_by(width).map(Vec::len));
                if take == 0 {
                    self.rollover(backend)
                        .map_err(|errno| ("rollover", errno))?;
                    continue;
                }
                batch.clear();
                for record in records[index..].iter().step_by(width).take(take) {
                    batch.extend_from_slice(record);
                }
                let object = self.cursor.object_number(splay);
                match backend.append(object, self.cursor.soft_max(), &batch) {
                    Ok(()) => {
                        self.cursor.appended(splay, batch.len() as u64);
                        for position in positions[index..].iter_mut().step_by(width).take(take) {
                            position.object_number = object;
                        }
                        index += take * width;
                    }
                    Err(EOVERFLOW) => {
                        self.rollover(backend)
                            .map_err(|errno| ("rollover", errno))?;
                    }
                    Err(errno) => return Err(("append", errno)),
                }
            }
        }
        Ok(positions)
    }

    /// Publish the next active set; `-ESTALE` means another writer moved it
    /// and the refetched set must be at least the requested one.
    fn rollover(&mut self, backend: &impl JournalBackend) -> Result<(), i32> {
        let next = self.cursor.active_set().checked_add(1).ok_or(EIO)?;
        let set = match backend.set_active_set(next) {
            Ok(()) => next,
            Err(ESTALE) => {
                let current = backend.get_geometry()?.active_set;
                if current < next {
                    return Err(EIO);
                }
                current
            }
            Err(errno) => return Err(errno),
        };
        self.cursor.rollover_to(set).map_err(|_| EIO)
    }

    fn trim_sets(&mut self, backend: &impl JournalBackend) -> Result<(), (&'static str, i32)> {
        let active_set = self.cursor.active_set();
        if active_set <= self.minimum_set {
            return Ok(());
        }
        let Some(target) = self.needed_set(backend)? else {
            return Ok(());
        };
        if target <= self.minimum_set {
            return Ok(());
        }
        let width = self.positions.len() as u64;
        for set in self.minimum_set..target {
            for splay in 0..width {
                // Below the active set: representable.
                match backend.remove_object(set * width + splay) {
                    Ok(()) | Err(ENOENT) => {}
                    Err(errno) => return Err(("remove_object", errno)),
                }
            }
        }
        match backend.set_minimum_set(target) {
            Ok(()) | Err(ESTALE) => {}
            Err(errno) => return Err(("set_minimum_set", errno)),
        }
        self.minimum_set = target;
        Ok(())
    }

    /// The lowest object set any connected client still needs, starting at
    /// the active set; `None` when a connected client has empty positions.
    /// Only the cls client fields are read (stock trimmer): ClientData is
    /// never decoded, so an unknown client variant cannot block the trim.
    fn needed_set(
        &self,
        backend: &impl JournalBackend,
    ) -> Result<Option<u64>, (&'static str, i32)> {
        let width = self.positions.len() as u64;
        let mut needed = self.cursor.active_set();
        let mut start_after = Vec::new();
        loop {
            let raw = backend
                .client_list(&start_after, CLIENT_LIST_PAGE)
                .map_err(|errno| ("client_list", errno))?;
            let clients =
                decode_journal_client_fields_set(&raw).map_err(|_| ("client_list", EBADMSG))?;
            for client in &clients {
                if client.state == JOURNAL_CLIENT_STATE_DISCONNECTED {
                    continue;
                }
                if client.commit_positions.is_empty() {
                    return Ok(None);
                }
                for position in &client.commit_positions {
                    needed = needed.min(position.object_number / width);
                }
            }
            match clients.last() {
                Some(last) if clients.len() as u64 >= CLIENT_LIST_PAGE => {
                    start_after = last.id.to_vec();
                }
                _ => return Ok(Some(needed)),
            }
        }
    }
}

#[cfg(test)]
mod tests;
