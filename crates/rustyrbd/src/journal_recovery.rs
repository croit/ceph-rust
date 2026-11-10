// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Owner-open journal recovery and journaled mutation ordering (journaling
//! step S5).
//!
//! Implements `doc/spec/rustyrbd/ffi-journal-io.md` ("Owner-open replay
//! lifecycle", "State machine", "DATA ordering", "Op events", "Crash points
//! and recovery result", SPEC-CHECK 1/2) and `doc/adr/0700-rbd-journaling.md`:
//!
//! - [`recover`] opens the journal as its owner: validated geometry, the
//!   local image client `""` (ClientData image variant) and its positions,
//!   the tags of the client's tag class (current tag = highest TID; its
//!   owner must be local, else `-EPERM`), then streams the uncommitted
//!   suffix through [`JournalPlayer`] into a [`ReplayTarget`]. Operation
//!   starts are held until their finish; a finish with result 0 re-executes
//!   the operation idempotently, a failed or orphan finish is skipped, and a
//!   start without finish is re-executed at the end of replay (SPEC-CHECK 2).
//!   Then `target.flush()`, seal, persist the sealed positions (skipped when
//!   unchanged) and hand back a ready [`JournalWriter`] continuing the TID
//!   sequence. No tag is allocated: the data path never creates tags (ADR
//!   0700). Any failure fails recovery loudly with its [`RecoveryStage`];
//!   entries are never skipped to open anyway.
//! - [`journaled_mutation`] appends a request's events durably before its
//!   data dispatch and completes them with the data result afterwards;
//!   a compare-and-write is split into bounded sub-range events (one image
//!   request) and is a barrier on both sides. A data error leaves the
//!   request's entries uncommitted and stops
//!   commit advancement at the completed prefix; the writer stays ready and
//!   later requests (CAW and operations included) are admitted; the next
//!   open replays the whole uncommitted suffix in order (stock-equivalent).
//! - [`journaled_op`] wraps an image operation in its start/finish events
//!   with a barrier before the start and a persist after the finish.

use rustyrados::diag;
use std::fmt;

use crate::journal_backend::{
    EBADMSG, EBUSY, EEXIST, EILSEQ, EINVAL, ENOENT, EPERM, ERANGE, JournalBackend,
};
use crate::journal_client::{
    decode_journal_image_client, decode_journal_tag, decode_journal_tag_set, decode_tag_data,
};
use crate::journal_event::{JournalEvent, JournalEventKind, decode_journal_event_entry};
use crate::journal_player::JournalPlayer;
use crate::journal_writer::{
    CLIENT_LIST_PAGE, JournalClock, JournalWriter, JournalWriterConfig, Ticket, WriterState,
};

/// The local image client's ID.
const LOCAL_CLIENT_ID: &[u8] = b"";

/// The image a recovery replays into (`MemImage` in tests, the flat image
/// writer in rbd-ffi). Replay calls never append journal events.
///
/// [`recover`] clips every DATA call to [`ReplayTarget::image_size`]
/// before calling it (an event fully beyond the size is a no-op), so the
/// extents a target receives are in range.
pub trait ReplayTarget {
    /// The current image size in bytes.
    fn image_size(&self) -> u64;
    /// Write `data` at `offset`.
    fn write(&mut self, offset: u64, data: &[u8]) -> Result<(), i32>;
    /// Discard `length` bytes at `offset` with the recorded discard
    /// granularity (0 for write_zeroes).
    fn discard(
        &mut self,
        offset: u64,
        length: u64,
        skip_partial: bool,
        granularity: u32,
    ) -> Result<(), i32>;
    /// Fill `length` bytes at `offset` with the repeating `pattern`.
    fn write_same(&mut self, offset: u64, length: u64, pattern: &[u8]) -> Result<(), i32>;
    /// Replace `length` bytes at `offset` with `data` when they equal
    /// `compare`; a mismatch is `-EILSEQ`.
    fn compare_and_write(
        &mut self,
        offset: u64,
        length: u64,
        compare: &[u8],
        data: &[u8],
    ) -> Result<(), i32>;
    /// Make every replayed mutation durable.
    fn flush(&mut self) -> Result<(), i32>;
    /// Re-execute one operation start event (types 4..17 except the
    /// promote/demote marker). [`recover`] treats the per-operation
    /// idempotency errno of the spec ("Op events") as success; an operation
    /// the target cannot replay returns `-EOPNOTSUPP` and fails recovery.
    fn apply_op(&mut self, event: &JournalEvent<'_>) -> Result<(), i32>;
}

/// The recovery step that failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryStage {
    /// Header geometry read or validation.
    Geometry,
    /// Local image client lookup, metadata or commit positions.
    Client,
    /// Tag listing of the client's tag class or the current tag's owner.
    Tags,
    /// Player stream: record read, framing, TID order.
    Replay,
    /// EventEntry decode or operation start/finish pairing.
    Decode,
    /// A replayed DATA event or operation on the target.
    Apply,
    /// The target flush after replay.
    Flush,
    /// Seal: tag consistency or persisting the sealed positions.
    Seal,
    /// Building the writer from the sealed state.
    Writer,
}

impl RecoveryStage {
    /// Stable lower-case name used in the diagnostic line.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Geometry => "geometry",
            Self::Client => "client",
            Self::Tags => "tags",
            Self::Replay => "replay",
            Self::Decode => "decode",
            Self::Apply => "apply",
            Self::Flush => "flush",
            Self::Seal => "seal",
            Self::Writer => "writer",
        }
    }
}

impl fmt::Display for RecoveryStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A failed recovery: the stage and the negative errno (backend and target
/// errors unchanged; malformed state `-EBADMSG`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryError {
    pub stage: RecoveryStage,
    pub errno: i32,
}

impl fmt::Display for RecoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "journal recovery failed errno={} stage={}",
            self.errno, self.stage
        )
    }
}

impl std::error::Error for RecoveryError {}

fn at(stage: RecoveryStage) -> impl Fn(i32) -> RecoveryError {
    move |errno| RecoveryError { stage, errno }
}

/// An operation start held until its finish record.
struct PendingOp {
    tag_tid: u64,
    operation_id: u64,
    /// The start record's EventEntry bytes, decoded again on execution.
    entry: Vec<u8>,
}

/// Open the journal as its owner, replay the uncommitted suffix into
/// `target`, seal and return the ready writer.
///
/// Every failure prints `ERROR journal recovery failed image=<id>
/// errno=<e> stage=<s>` to stderr and is returned unchanged; callers do not
/// log it again. A failed recovery leaves the journal as it was apart from
/// replayed (idempotent) target mutations; the next acquisition starts
/// over.
pub fn recover<B, T, C>(
    backend: &mut B,
    target: &mut T,
    cfg: JournalWriterConfig,
    clock: C,
) -> Result<JournalWriter<C>, RecoveryError>
where
    B: JournalBackend,
    T: ReplayTarget,
    C: JournalClock,
{
    let image_id = cfg.image_id.clone();
    open_and_replay(backend, target, cfg, clock).inspect_err(|error| {
        diag!(
            "ERROR journal recovery failed image={image_id} errno={} stage={}",
            error.errno,
            error.stage
        );
    })
}

fn open_and_replay<B, T, C>(
    backend: &mut B,
    target: &mut T,
    cfg: JournalWriterConfig,
    clock: C,
) -> Result<JournalWriter<C>, RecoveryError>
where
    B: JournalBackend,
    T: ReplayTarget,
    C: JournalClock,
{
    let geometry = backend
        .get_geometry()
        .map_err(at(RecoveryStage::Geometry))?;
    geometry
        .validate()
        .map_err(|_| at(RecoveryStage::Geometry)(EBADMSG))?;

    let raw_client = backend
        .get_client(LOCAL_CLIENT_ID)
        .map_err(at(RecoveryStage::Client))?;
    let client =
        decode_journal_image_client(&raw_client).map_err(|_| at(RecoveryStage::Client)(EBADMSG))?;
    let committed = client.commit_positions.clone();
    geometry
        .validate_positions(&committed)
        .map_err(|_| at(RecoveryStage::Client)(EBADMSG))?;

    let tags = class_tags(backend, client.tag_class).map_err(at(RecoveryStage::Tags))?;
    let current_tag = *tags.last().ok_or(at(RecoveryStage::Tags)(ENOENT))?;
    check_local_owner(backend, current_tag, client.tag_class).map_err(at(RecoveryStage::Tags))?;

    let mut player =
        JournalPlayer::new(&geometry, &committed, &tags).map_err(at(RecoveryStage::Replay))?;
    let mut pending: Vec<PendingOp> = Vec::new();
    while let Some(record) = player.next(backend).map_err(at(RecoveryStage::Replay))? {
        let entry = decode_journal_event_entry(&record.data)
            .map_err(|_| at(RecoveryStage::Decode)(EBADMSG))?;
        let Some(event) = entry.event else {
            // Unknown event type: a successful no-op.
            continue;
        };
        if let JournalEvent::OpFinish {
            operation_id,
            result,
            ..
        } = event
        {
            let index = pending
                .iter()
                .position(|op| op.tag_tid == record.tag_tid && op.operation_id == operation_id);
            // A finish without a pending start is already committed; a
            // failed operation is not re-executed.
            if let Some(index) = index {
                let op = pending.remove(index);
                if result == 0 {
                    reexecute(target, &op.entry)?;
                }
            }
        } else if let Some(operation_id) = operation_id(&event) {
            if pending
                .iter()
                .any(|op| op.tag_tid == record.tag_tid && op.operation_id == operation_id)
            {
                return Err(at(RecoveryStage::Decode)(EBADMSG));
            }
            pending.push(PendingOp {
                tag_tid: record.tag_tid,
                operation_id,
                entry: record.data.clone(),
            });
        } else {
            apply_data(target, &event).map_err(at(RecoveryStage::Apply))?;
        }
    }
    // A start without finish is re-executed idempotently (SPEC-CHECK 2).
    for op in &pending {
        reexecute(target, &op.entry)?;
    }
    target.flush().map_err(at(RecoveryStage::Flush))?;

    let player_tag = player.active_tag();
    let (sealed, sealed_next_tid) = player.seal();
    let next_tid = match player_tag {
        Some(tag) if tag == current_tag => sealed_next_tid,
        // No position and no record, or the current tag has no record yet:
        // it starts at entry TID 0.
        None => 0,
        Some(tag) if tag < current_tag => 0,
        Some(_) => return Err(at(RecoveryStage::Seal)(EBADMSG)),
    };
    if sealed != committed {
        backend
            .client_commit(LOCAL_CLIENT_ID, &sealed)
            .map_err(at(RecoveryStage::Seal))?;
    }
    let geometry = backend.get_geometry().map_err(at(RecoveryStage::Writer))?;
    JournalWriter::new(&geometry, current_tag, (sealed, next_tid), cfg, clock)
        .map_err(at(RecoveryStage::Writer))
}

/// Every tag TID of `tag_class` visible to the local client, ascending.
fn class_tags(backend: &impl JournalBackend, tag_class: u64) -> Result<Vec<u64>, i32> {
    let mut tids = Vec::new();
    let mut start_after = 0;
    loop {
        let raw = backend.tag_list(
            start_after,
            CLIENT_LIST_PAGE,
            LOCAL_CLIENT_ID,
            Some(tag_class),
        )?;
        let page = decode_journal_tag_set(&raw).map_err(|_| EBADMSG)?;
        for tag in &page {
            if tag.tag_class != tag_class || tids.last().is_some_and(|&last| tag.tid <= last) {
                return Err(EBADMSG);
            }
            tids.push(tag.tid);
        }
        match page.last() {
            Some(last) if page.len() as u64 >= CLIENT_LIST_PAGE => start_after = last.tid,
            _ => return Ok(tids),
        }
    }
}

/// The current tag must be owned by the local image (empty owner UUID);
/// otherwise the image is not primary and a local writer cannot open
/// (`-EPERM`, J5).
fn check_local_owner(backend: &impl JournalBackend, tid: u64, tag_class: u64) -> Result<(), i32> {
    let raw = backend.get_tag(tid)?;
    let tag = decode_journal_tag(&raw).map_err(|_| EBADMSG)?;
    if tag.tid != tid || tag.tag_class != tag_class {
        return Err(EBADMSG);
    }
    let data = decode_tag_data(tag.data).map_err(|_| EBADMSG)?;
    if !data.owner.is_empty() {
        return Err(EPERM);
    }
    Ok(())
}

/// The operation ID of an operation start event; `None` for DATA events,
/// the finish and the promote/demote marker.
fn operation_id(event: &JournalEvent<'_>) -> Option<u64> {
    event.operation_id()
}

/// The errno a re-executed operation treats as success (spec "Op events",
/// J7); `None` for absolute operations.
fn idempotent_errno(event: &JournalEvent<'_>) -> Option<i32> {
    match event {
        JournalEvent::Snapshot { kind, .. } => match kind {
            JournalEventKind::Create => Some(EEXIST),
            JournalEventKind::Remove => Some(ENOENT),
            JournalEventKind::Protect => Some(EBUSY),
            JournalEventKind::Unprotect => Some(EINVAL),
            JournalEventKind::Rollback => None,
        },
        JournalEvent::SnapshotRename { .. } | JournalEvent::ImageRename { .. } => Some(EEXIST),
        JournalEvent::Flatten { .. } => Some(EINVAL),
        JournalEvent::SnapshotLimit { .. } => Some(ERANGE),
        JournalEvent::MetadataRemove { .. } => Some(ENOENT),
        _ => None,
    }
}

/// Re-execute one held operation start.
fn reexecute(target: &mut impl ReplayTarget, entry: &[u8]) -> Result<(), RecoveryError> {
    let decoded =
        decode_journal_event_entry(entry).map_err(|_| at(RecoveryStage::Decode)(EBADMSG))?;
    let event = decoded.event.ok_or(at(RecoveryStage::Decode)(EBADMSG))?;
    match target.apply_op(&event) {
        Ok(()) => Ok(()),
        Err(errno) if Some(errno) == idempotent_errno(&event) => Ok(()),
        Err(errno) => Err(at(RecoveryStage::Apply)(errno)),
    }
}

/// The in-range length of an extent; `None` when it starts at or beyond
/// the image size.
fn clip(size: u64, offset: u64, length: u64) -> Option<u64> {
    (offset < size).then(|| length.min(size - offset))
}

fn prefix(bytes: &[u8], length: u64) -> &[u8] {
    &bytes[..bytes
        .len()
        .min(usize::try_from(length).unwrap_or(usize::MAX))]
}

/// Apply one DATA event, clipped to the image size. A compare-and-write
/// mismatch is a normal replay outcome.
fn apply_data(target: &mut impl ReplayTarget, event: &JournalEvent<'_>) -> Result<(), i32> {
    let size = target.image_size();
    match *event {
        JournalEvent::Write { offset, data, .. } => match clip(size, offset, data.len() as u64) {
            Some(length) => target.write(offset, prefix(data, length)),
            None => Ok(()),
        },
        JournalEvent::Discard {
            offset,
            length,
            skip_partial,
            discard_granularity,
        } => match clip(size, offset, length) {
            Some(length) => target.discard(offset, length, skip_partial, discard_granularity),
            None => Ok(()),
        },
        JournalEvent::WriteSame {
            offset,
            length,
            pattern,
        } => match clip(size, offset, length) {
            Some(length) => target.write_same(offset, length, pattern),
            None => Ok(()),
        },
        JournalEvent::CompareAndWrite {
            offset,
            length,
            compare,
            replacement,
        } => match clip(size, offset, length) {
            Some(length) => match target.compare_and_write(
                offset,
                length,
                prefix(compare, length),
                prefix(replacement, length),
            ) {
                Ok(()) | Err(EILSEQ) => Ok(()),
                Err(errno) => Err(errno),
            },
            None => Ok(()),
        },
        JournalEvent::Flush => target.flush(),
        // Operation events are routed by the caller; reaching here is a
        // pairing bug in the caller, reported as malformed.
        _ => Err(EBADMSG),
    }
}

/// Split one image write into Write events of at most
/// [`JournalWriter::write_chunk_len`] data bytes each (spec DATA ordering
/// step 2); offsets advance with the data.
pub fn write_events<'a, C: JournalClock>(
    writer: &JournalWriter<C>,
    offset: u64,
    data: &'a [u8],
) -> Vec<JournalEvent<'a>> {
    let chunk = usize::try_from(writer.write_chunk_len()).unwrap_or(usize::MAX);
    data.chunks(chunk)
        .scan(offset, |next, piece| {
            let event = JournalEvent::Write {
                offset: *next,
                length: piece.len() as u64,
                data: piece,
            };
            *next += piece.len() as u64;
            Some(event)
        })
        .collect()
}

/// Append one journaled request and return its ticket plus whether the
/// request is a barrier (contains a compare-and-write).
///
/// A barrier first persists the positions of every prior entry (spec "DATA
/// ordering" step 3). The events are appended durably; the caller dispatches
/// the data afterwards and passes the ticket to [`journaled_complete`].
/// `Err` means nothing was dispatched.
pub fn journaled_append<B, C>(
    writer: &mut JournalWriter<C>,
    backend: &B,
    events: &[JournalEvent<'_>],
) -> Result<(Ticket, bool), i32>
where
    B: JournalBackend,
    C: JournalClock,
{
    let barrier = events
        .iter()
        .any(|event| matches!(event, JournalEvent::CompareAndWrite { .. }));
    if barrier {
        writer.persist(backend)?;
    }
    let ticket = writer.append(backend, events)?;
    Ok((ticket, barrier))
}

/// Complete one journaled request after its data dispatch.
///
/// `result` is the unchanged data result (0 or a negative errno); a
/// compare-and-write `-EILSEQ` counts as success. A barrier persists the
/// request's own position before returning (spec "DATA ordering" step 8).
/// A journal failure moves the writer to `Failed` (logged by the writer);
/// the caller keeps returning the data result.
pub fn journaled_complete<B, C>(
    writer: &mut JournalWriter<C>,
    backend: &B,
    ticket: Ticket,
    barrier: bool,
    result: i32,
) -> Result<(), i32>
where
    B: JournalBackend,
    C: JournalClock,
{
    writer.complete(backend, ticket, result)?;
    if barrier {
        writer.persist(backend)?;
    }
    Ok(())
}

/// Run one journaled DATA request (spec "DATA ordering").
///
/// A request containing a compare-and-write first persists the positions
/// of every prior entry (barrier). The events are appended durably; only
/// then `dispatch` runs the data write and returns its result (0 or a
/// negative errno). The result completes the entries (`0`, or `-EILSEQ` for
/// a compare-and-write) or blocks commit advancement (any other error);
/// a compare-and-write then persists its own position before returning.
///
/// `Err` is a journal error before dispatch: nothing was dispatched.
/// `Ok(result)` is the unchanged data result. A journal failure after the
/// dispatch (completion persist) moves the writer to `Failed` and is logged
/// by the writer; the next admission returns it.
pub fn journaled_mutation<B, C>(
    writer: &mut JournalWriter<C>,
    backend: &B,
    events: &[JournalEvent<'_>],
    dispatch: impl FnOnce() -> i32,
) -> Result<i32, i32>
where
    B: JournalBackend,
    C: JournalClock,
{
    let (ticket, barrier) = journaled_append(writer, backend, events)?;
    let result = dispatch();
    if let Err(errno) = journaled_complete(writer, backend, ticket, barrier, result) {
        debug_assert_eq!(writer.state(), WriterState::Failed(errno));
    }
    Ok(result)
}

/// Run one journaled image operation (spec "Op events").
///
/// Persists every prior entry (barrier), appends the start event built by
/// `start` from the operation ID (the start's entry TID, J6), runs
/// `mutation` on that event, appends `OpFinish(id, id, result)`, completes
/// both entries and persists. `start` must return an operation start event
/// carrying the given ID, else `-EINVAL`.
///
/// `Err` is a journal error: before the start append nothing ran; after the
/// mutation ran (finish append failed) the operation is re-executed
/// idempotently by the next recovery. `Ok(result)` is the operation result;
/// a failed final persist moves the writer to `Failed` (logged by the
/// writer) without changing it.
pub fn journaled_op<'a, B, C>(
    writer: &mut JournalWriter<C>,
    backend: &B,
    start: impl FnOnce(u64) -> JournalEvent<'a>,
    mutation: impl FnOnce(&JournalEvent<'a>) -> i32,
) -> Result<i32, i32>
where
    B: JournalBackend,
    C: JournalClock,
{
    writer.persist(backend)?;
    let id = writer.next_tid();
    let event = start(id);
    if operation_id(&event) != Some(id) {
        return Err(EINVAL);
    }
    let start_ticket = writer.append(backend, std::slice::from_ref(&event))?;
    let result = mutation(&event);
    let finish_ticket = writer.append(
        backend,
        &[JournalEvent::OpFinish {
            operation_id: id,
            repeated_operation_id: id,
            result,
        }],
    )?;
    // Completing the finish first lets the start and finish commit together.
    let after = writer
        .complete(backend, finish_ticket, 0)
        .and_then(|()| writer.complete(backend, start_ticket, 0))
        .and_then(|()| writer.persist(backend));
    if let Err(errno) = after {
        debug_assert_eq!(writer.state(), WriterState::Failed(errno));
    }
    Ok(result)
}

#[cfg(test)]
mod tests;
