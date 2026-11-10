// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Streaming per-splay journal player (journaling step S3).
//!
//! Implements the player and seal rules of
//! `doc/spec/rustyrbd/ffi-journal-io.md` ("Owner-open replay lifecycle",
//! "Player and seal", resolved questions J1/J9/J11) over the
//! [`JournalBackend`] trait. Memory is bounded to one in-flight object per
//! splay stream: each stream reads its object in chunks through
//! [`JournalObjectStream`] and retains only the pending chunk between reads.
//!
//! Replay order is the stock round robin: after every consumed record the
//! player advances one splay, wrapping at the width. Within the current tag
//! the expected next entry TID is `last + 1`; a record with another TID in a
//! live splay is a mid-stream gap and fails with `-ENOMSG` (J11). A gap whose
//! missing TIDs lie entirely in streams already ended at the active set is a
//! tail gap: the replay prefix ends and the remaining records are orphans
//! that the seal covers (the serial writer only leaves gaps at the tail).
//! Without a persisted position the active tag is unset and becomes the tag
//! of the first record found (round robin from splay 0, set 0 onward), with
//! that record's TID as the expected one. Older-tag records are stale and
//! skipped; a newer tag becomes active only at entry TID 0, a higher-tag record with `tid != 0` is retained and the
//! player re-seeks the new tag's TID-0 record from splay 0 (J1).

use crate::JournalObjectPosition;
use crate::journal_backend::{EBADMSG, ENOENT, ENOMSG, JournalBackend};
use crate::journal_event::{JournalObjectRecord, JournalObjectStream};
use crate::journal_meta::JournalGeometry;

/// One verified journal record emitted for replay; the stock record framing
/// is the one of [`JournalObjectRecord`].
pub type ReplayRecord = JournalObjectRecord;

/// Chunk size of one object read; a stream retains at most one chunk plus
/// one incomplete record, so the player's memory bound is one chunk (plus
/// parsed records, plus a record larger than a chunk while it is read) per
/// splay.
pub const OBJECT_READ_CHUNK: usize = 64 * 1024;

/// Pending-byte limit of one object stream: the object size bound plus one
/// read chunk, so an incomplete record is retained until the bound check
/// rejects it. Only an actual large record makes a stream retain this much.
fn stream_pending_bytes(order: u8) -> usize {
    usize::try_from(object_size_bound(order))
        .unwrap_or(usize::MAX)
        .saturating_add(OBJECT_READ_CHUNK)
}

/// The object size bound (`2 << order`). The writer pre-empts by its own
/// unpadded byte count while the class refuses an append only once the padded
/// size reaches `1 << order`, so a record may start below the soft maximum
/// and end past it: an object stays below `2 << order` plus the pad. Every
/// record fits the soft maximum (a compare-and-write is split), so a record
/// still partial after a full `2 << order` window is corruption. Bytes past
/// the soft maximum are ordinary records or zero pad.
fn object_size_bound(order: u8) -> u64 {
    2u64 << order
}

/// Per-splay stream cursor: one in-flight object, chunked reads.
#[derive(Debug)]
struct SplayStream {
    /// The object currently being read.
    object: u64,
    /// The incremental record parser of the current object.
    stream: JournalObjectStream,
    /// Records parsed but not yet consumed.
    records: Vec<ReplayRecord>,
    /// The stream reached its tail (the refetched active set).
    done: bool,
    /// Bytes read from the current object.
    object_bytes: u64,
    /// The size bound of the current object.
    bound: u64,
    /// The last record seen per tag (tags are non-decreasing per stream).
    per_tag_last: Vec<(u64, u64, u64)>,
}

/// The streaming journal player.
#[derive(Debug)]
pub struct JournalPlayer {
    width: usize,
    order: u8,
    active_set: u64,
    /// The current tag; a higher tag activates only at entry TID 0.
    /// Meaningful only while `tag_set`.
    active_tag: u64,
    /// The current tag is known: from the newest persisted position, or
    /// from the first record found when there is none.
    tag_set: bool,
    /// The next expected entry TID within the current tag.
    expected_tid: u64,
    /// The splay the round robin points at.
    rotation: usize,
    /// The replay prefix has ended; `next` yields no more records.
    ended: bool,
    /// The start-splay resolution of the newest persisted position is
    /// pending for the first `next` call.
    start_pending: bool,
    streams: Vec<SplayStream>,
    /// The persisted position per splay, for the seal fallback.
    persisted: Vec<Option<JournalObjectPosition>>,
    /// The exact persisted record to skip through per splay.
    skip_until: Vec<Option<(u64, u64)>>,
}

impl JournalPlayer {
    /// Build the player from the header geometry, the persisted commit
    /// positions (newest first) and the tag TIDs of the client's tag class
    /// (ascending). Malformed geometry, positions or an empty tag list is
    /// `-EBADMSG`; so is a newest position whose tag is not listed. Without
    /// a position the current tag is unset until the first record.
    pub fn new(
        geometry: &JournalGeometry,
        positions: &[JournalObjectPosition],
        tags: &[u64],
    ) -> Result<Self, i32> {
        geometry.validate().map_err(|_| EBADMSG)?;
        geometry
            .validate_positions(positions)
            .map_err(|_| EBADMSG)?;
        if tags.is_empty() {
            return Err(EBADMSG);
        }
        let width = usize::from(geometry.splay_width);
        let newest = positions.first().copied();
        let active_tag = match newest {
            Some(position) => {
                if !tags.contains(&position.tag_tid) {
                    return Err(EBADMSG);
                }
                position.tag_tid
            }
            None => 0,
        };
        let expected_tid = match newest {
            Some(position) => position.entry_tid.checked_add(1).ok_or(EBADMSG)?,
            None => 0,
        };
        let mut persisted = vec![None; width];
        for &position in positions {
            let splay = (position.object_number % width as u64) as usize;
            persisted[splay] = Some(position);
        }
        let mut skip_until = vec![None; width];
        for &position in positions {
            let splay = (position.object_number % width as u64) as usize;
            skip_until[splay] = Some((position.tag_tid, position.entry_tid));
        }
        let mut streams = Vec::with_capacity(width);
        for (splay, persisted) in persisted.iter().enumerate() {
            let object = persisted
                .map(|position| position.object_number)
                .unwrap_or(splay as u64);
            streams.push(SplayStream {
                object,
                stream: JournalObjectStream::new(object, 0, stream_pending_bytes(geometry.order))
                    .map_err(|_| EBADMSG)?,
                records: Vec::new(),
                done: false,
                object_bytes: 0,
                bound: object_size_bound(geometry.order),
                per_tag_last: Vec::new(),
            });
        }
        Ok(Self {
            width,
            order: geometry.order,
            active_set: geometry.active_set,
            active_tag,
            tag_set: newest.is_some(),
            expected_tid,
            rotation: 0,
            ended: false,
            start_pending: newest.is_some(),
            streams,
            persisted,
            skip_until,
        })
    }

    /// The next replay record in journal order; `Ok(None)` ends the replay
    /// prefix (end of stream or a tail gap, streams drained for the seal).
    /// `-ENOMSG` on a mid-stream TID gap, `-EBADMSG` on malformed records,
    /// padding, stream state or commit positions; backend errors pass
    /// through unchanged.
    pub fn next(&mut self, backend: &mut impl JournalBackend) -> Result<Option<ReplayRecord>, i32> {
        if self.ended {
            return Ok(None);
        }
        if self.start_pending {
            self.resolve_start(backend)?;
        }
        loop {
            let splay = self.rotation;
            self.fill(splay, backend)?;
            if self.exhausted(splay) {
                self.advance_rotation();
                if self.all_exhausted() {
                    self.ended = true;
                    return Ok(None);
                }
                continue;
            }
            self.apply_skip(splay, backend)?;
            if self.exhausted(splay) {
                self.advance_rotation();
                if self.all_exhausted() {
                    self.ended = true;
                    return Ok(None);
                }
                continue;
            }
            let record = self.streams[splay].records[0].clone();
            let tag = record.tag_tid;
            let tid = record.entry_tid;
            if tid % self.width as u64 != splay as u64 {
                // A record in the wrong splay stream.
                return Err(EBADMSG);
            }
            if !self.tag_set {
                // No persisted position: the first record found sets the
                // current tag and the expected TID.
                self.active_tag = tag;
                self.expected_tid = tid;
                self.tag_set = true;
            }
            if tag < self.active_tag {
                // Stale: an older tag's record is skipped.
                self.consume(splay)?;
                self.advance_rotation();
                continue;
            }
            if tag > self.active_tag {
                if tid == 0 {
                    // A higher tag activates at entry TID 0.
                    self.active_tag = tag;
                    self.expected_tid = 1;
                    self.consume(splay)?;
                    self.advance_rotation();
                    return Ok(Some(record));
                }
                // Retained: prune old-tag records, re-seek the new tag's
                // TID-0 record from splay 0, then replay the retained
                // records in sequence (J1).
                if !self.seek_new_tag(tag, backend)? {
                    self.drain(backend)?;
                    self.ended = true;
                    return Ok(None);
                }
                continue;
            }
            if tid == self.expected_tid {
                self.consume(splay)?;
                self.expected_tid = self.expected_tid.saturating_add(1);
                self.advance_rotation();
                return Ok(Some(record));
            }
            if self.is_tail_gap(tid) {
                self.drain(backend)?;
                self.ended = true;
                return Ok(None);
            }
            return Err(ENOMSG);
        }
    }

    /// The tag the player currently replays: the newest persisted
    /// position's tag, else the first record's tag, advanced by every
    /// higher tag activated at its entry TID 0. `None` without a persisted
    /// position until a record is found. The seal's positions and next TID
    /// refer to this tag.
    pub fn active_tag(&self) -> Option<u64> {
        self.tag_set.then_some(self.active_tag)
    }

    /// The seal: the commit positions to persist and the next append TID.
    ///
    /// Call after the replay prefix has ended (`next` returned `None`). For
    /// every splay the position is the last record physically present in
    /// that splay's streams with the current tag, else the splay's existing
    /// persisted position; the list is sorted by (tag, TID) descending. The
    /// next append TID is one plus the highest current-tag TID present or
    /// persisted, else 0.
    pub fn seal(self) -> (Vec<JournalObjectPosition>, u64) {
        let mut positions = Vec::new();
        let mut highest: Option<u64> = None;
        for (splay, stream) in self.streams.iter().enumerate() {
            let current = stream
                .per_tag_last
                .iter()
                .find(|(tag, _, _)| *tag == self.active_tag)
                .map(|(_, object, tid)| {
                    highest = Some(highest.map_or(*tid, |h| h.max(*tid)));
                    JournalObjectPosition {
                        object_number: *object,
                        tag_tid: self.active_tag,
                        entry_tid: *tid,
                    }
                });
            let position = current.or(self.persisted[splay]);
            if let Some(position) = position {
                if position.tag_tid == self.active_tag {
                    highest =
                        Some(highest.map_or(position.entry_tid, |h| h.max(position.entry_tid)));
                }
                positions.push(position);
            }
        }
        positions.sort_by_key(|position| std::cmp::Reverse((position.tag_tid, position.entry_tid)));
        let next_tid = highest.map_or(0, |tid| tid.saturating_add(1));
        (positions, next_tid)
    }

    /// Resolve the start splay from the newest persisted position: advance
    /// to the next splay when the persisted stream's next record still has
    /// the committed tag or the stream is empty and complete; otherwise
    /// start at the persisted splay to resolve the tag transition there.
    fn resolve_start(&mut self, backend: &mut impl JournalBackend) -> Result<(), i32> {
        self.start_pending = false;
        let newest = self
            .persisted
            .iter()
            .flatten()
            .max_by_key(|p| (p.tag_tid, p.entry_tid))
            .expect("start_pending only with a persisted position");
        let splay = (newest.object_number % self.width as u64) as usize;
        self.rotation = (splay + 1) % self.width;
        self.apply_skip(splay, backend)?;
        if !self.exhausted(splay) {
            let record = &self.streams[splay].records[0];
            if record.tag_tid != self.active_tag {
                self.rotation = splay;
            }
        }
        Ok(())
    }

    /// Skip records through the exact persisted position of one stream,
    /// reading as needed; the stream is done or its front record is past
    /// the position on return. A record past the persisted one before it is
    /// seen is malformed.
    fn apply_skip(&mut self, splay: usize, backend: &mut impl JournalBackend) -> Result<(), i32> {
        loop {
            if self.exhausted(splay) {
                return Ok(());
            }
            if self.streams[splay].records.is_empty() {
                self.read_chunk(splay, backend)?;
                continue;
            }
            let Some((position_tag, position_tid)) = self.skip_until[splay] else {
                return Ok(());
            };
            let (tag, tid) = {
                let record = &self.streams[splay].records[0];
                (record.tag_tid, record.entry_tid)
            };
            if tag == position_tag && tid == position_tid {
                self.consume(splay)?;
                self.skip_until[splay] = None;
                continue;
            }
            if tag < position_tag || (tag == position_tag && tid < position_tid) {
                self.consume(splay)?;
                continue;
            }
            // Past the persisted position before it is seen.
            return Err(EBADMSG);
        }
    }

    /// Seek the `tag`'s TID-0 record from splay 0 after a retained
    /// higher-tag record; prunes older-tag records. The TID-0 record is left
    /// pending so the round robin replays it. Returns whether the seek
    /// promoted the tag.
    fn seek_new_tag(&mut self, tag: u64, backend: &mut impl JournalBackend) -> Result<bool, i32> {
        for splay in 0..self.width {
            loop {
                self.fill(splay, backend)?;
                if self.exhausted(splay) {
                    break;
                }
                self.apply_skip(splay, backend)?;
                if self.exhausted(splay) {
                    break;
                }
                let (rec_tag, rec_tid) = {
                    let record = &self.streams[splay].records[0];
                    (record.tag_tid, record.entry_tid)
                };
                if rec_tag < tag {
                    self.consume(splay)?;
                    continue;
                }
                if rec_tag == tag && rec_tid == 0 {
                    self.active_tag = tag;
                    self.expected_tid = 0;
                    self.rotation = splay;
                    return Ok(true);
                }
                // Retained for later: a higher-tag record with a nonzero
                // TID, or a yet-newer tag's record.
                break;
            }
        }
        Ok(false)
    }

    /// Drain every stream to its tail, consuming the remaining records
    /// (orphans) without TID checks, so the seal sees every physically
    /// present record.
    fn drain(&mut self, backend: &mut impl JournalBackend) -> Result<(), i32> {
        for splay in 0..self.width {
            while !self.exhausted(splay) {
                self.fill(splay, backend)?;
                if self.exhausted(splay) {
                    break;
                }
                self.apply_skip(splay, backend)?;
                while !self.streams[splay].records.is_empty() {
                    self.consume(splay)?;
                }
            }
        }
        Ok(())
    }

    /// Consume the front record of one stream, recording it for the seal.
    /// A record whose entry TID does not belong to this splay is
    /// `-EBADMSG`.
    fn consume(&mut self, splay: usize) -> Result<(), i32> {
        let record = self.streams[splay].records.remove(0);
        if record.entry_tid % self.width as u64 != splay as u64 {
            return Err(EBADMSG);
        }
        let stream = &mut self.streams[splay];
        match stream.per_tag_last.last_mut() {
            Some((last_tag, last_object, last_tid)) if *last_tag == record.tag_tid => {
                *last_object = record.object_number;
                *last_tid = record.entry_tid;
            }
            _ => stream
                .per_tag_last
                .push((record.tag_tid, record.object_number, record.entry_tid)),
        };
        Ok(())
    }

    /// Test helper: the bytes retained across all splay streams (pending
    /// chunk plus parsed records), the streaming memory bound measurement.
    #[cfg(any(test, feature = "journal-testkit"))]
    pub fn retained_bytes(&self) -> usize {
        self.streams
            .iter()
            .map(|stream| {
                stream.stream.pending_bytes()
                    + stream
                        .records
                        .iter()
                        .map(|record| record.data.len())
                        .sum::<usize>()
            })
            .sum()
    }

    fn advance_rotation(&mut self) {
        self.rotation = (self.rotation + 1) % self.width;
    }

    /// A stream is exhausted when it reached its tail and no record is
    /// pending; the tail object's records must be consumed first.
    fn exhausted(&self, splay: usize) -> bool {
        self.streams[splay].done && self.streams[splay].records.is_empty()
    }

    fn all_exhausted(&self) -> bool {
        (0..self.width).all(|splay| self.exhausted(splay))
    }

    /// A TID gap is a tail gap when every stream that a missing TID would
    /// occupy has ended; then the prefix stops and the seal covers the
    /// orphans. A gap with a live stream is mid-stream: `-ENOMSG`.
    fn is_tail_gap(&self, tid: u64) -> bool {
        if tid <= self.expected_tid {
            return false;
        }
        let span = (tid - self.expected_tid) as usize;
        for offset in 0..span.min(self.width) {
            let splay = (self.expected_tid + offset as u64) % self.width as u64;
            if !self.exhausted(splay as usize) {
                return false;
            }
        }
        true
    }

    /// Fill one stream until it has a pending record or is done: read
    /// chunks of the current object through the backend, enforce the object
    /// size bound, and advance through sets to the (refetched) active set.
    fn fill(&mut self, splay: usize, backend: &mut impl JournalBackend) -> Result<(), i32> {
        loop {
            if self.streams[splay].done {
                return Ok(());
            }
            if !self.streams[splay].records.is_empty() {
                return Ok(());
            }
            self.read_chunk(splay, backend)?;
        }
    }

    /// Read one chunk of the current object; on EOF finish the object and
    /// advance the stream. An absent object is empty.
    fn read_chunk(&mut self, splay: usize, backend: &mut impl JournalBackend) -> Result<(), i32> {
        let stream = &mut self.streams[splay];
        let object = stream.object;
        let offset = stream.stream.read_offset();
        let mut buf = vec![0u8; OBJECT_READ_CHUNK];
        let read = match backend.read_object(object, offset, &mut buf) {
            Err(ENOENT) => {
                self.finish_object(splay, backend)?;
                return Ok(());
            }
            other => other?,
        };
        let eof = read < OBJECT_READ_CHUNK;
        let bytes = &buf[..read];
        let object_bytes = stream
            .object_bytes
            .checked_add(read as u64)
            .ok_or(EBADMSG)?;
        if object_bytes > stream.bound {
            return Err(EBADMSG);
        }
        stream.object_bytes = object_bytes;
        let records = stream.stream.push(bytes, eof).map_err(|_| EBADMSG)?;
        stream.records.extend(records);
        if eof {
            self.finish_object(splay, backend)?;
        }
        Ok(())
    }

    /// The current object reached its end: advance to the next set object,
    /// or end the stream at the (once refetched) active set.
    fn finish_object(
        &mut self,
        splay: usize,
        backend: &mut impl JournalBackend,
    ) -> Result<(), i32> {
        let set = self.streams[splay].object / self.width as u64;
        if set == self.active_set {
            // A changing active set requires refetching the current set
            // before deciding it is the tail.
            let geometry = backend.get_geometry()?;
            if geometry.active_set > self.active_set {
                self.active_set = geometry.active_set;
                return self
                    .start_object(splay, self.active_set * self.width as u64 + splay as u64);
            }
            self.streams[splay].done = true;
            return Ok(());
        }
        self.start_object(splay, self.streams[splay].object + self.width as u64)
    }

    fn start_object(&mut self, splay: usize, object: u64) -> Result<(), i32> {
        let stream = &mut self.streams[splay];
        stream.object = object;
        stream.object_bytes = 0;
        stream.bound = object_size_bound(self.order);
        stream.stream = JournalObjectStream::new(object, 0, stream_pending_bytes(self.order))
            .map_err(|_| EBADMSG)?;
        Ok(())
    }
}
