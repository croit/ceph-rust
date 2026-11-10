// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Client-side librbd `EventEntry` frames used by journal append and replay.
//!
//! This is only the entry codec. The journal class append envelope, durable
//! append/commit ordering, and replay execution belong to their own layers.

use denc::{Decoder, Error};

use crate::SnapshotNamespace;

/// Event frame version emitted by the pinned writer.
pub const JOURNAL_EVENT_VERSION: u8 = 5;

/// Encode the outer journal data-object record around an EventEntry payload.
///
/// The record has its own CRC and is distinct from both the nested EventEntry
/// frames and the journal class append request. `out` is reused by the caller.
pub fn encode_journal_record(
    entry_tid: u64,
    tag_tid: u64,
    event: &[u8],
    out: &mut Vec<u8>,
) -> denc::Result<()> {
    let length = u32::try_from(event.len()).map_err(|_| Error::TooLong)?;
    let capacity = event.len().checked_add(33).ok_or(Error::TooLong)?;
    out.clear();
    out.try_reserve(capacity).map_err(|_| Error::NoSpace)?;
    out.extend_from_slice(&0x3141592653589793u64.to_le_bytes());
    out.push(1);
    put_u64(out, entry_tid);
    put_u64(out, tag_tid);
    put_u32(out, length);
    out.extend_from_slice(event);
    // The journal record uses Ceph's raw CRC32C with seed zero, without
    // the initial/final complements of the standard CRC32C convention.
    let crc = crc::crc32c(0, out);
    put_u32(out, crc);
    Ok(())
}

/// A verified journal data-object record; `data` borrows the input buffer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalRecord<'a> {
    pub entry_tid: u64,
    pub tag_tid: u64,
    pub data: &'a [u8],
    /// Number of bytes consumed, excluding subsequent records or padding.
    pub consumed: usize,
}

/// Decode and verify one journal record before passing its payload to replay.
///
/// This verifies the record preamble, version and raw CRC32C. It does not
/// parse the enclosed event, scan through padding, or apply replay operations.
pub fn decode_journal_record(input: &[u8]) -> denc::Result<JournalRecord<'_>> {
    let mut decoder = Decoder::new(input);
    if decoder.u64()? != 0x3141592653589793 {
        return Err(Error::BadValue("journal record preamble"));
    }
    if decoder.u8()? != 1 {
        return Err(Error::BadValue("journal record version"));
    }
    let entry_tid = decoder.u64()?;
    let tag_tid = decoder.u64()?;
    let data = decoder.bytes()?;
    let crc_end = decoder.position();
    let stored_crc = decoder.u32()?;
    if stored_crc != crc::crc32c(0, &input[..crc_end]) {
        return Err(Error::BadValue("journal record crc"));
    }
    Ok(JournalRecord {
        entry_tid,
        tag_tid,
        data,
        consumed: decoder.position(),
    })
}

/// One verified record found in a journal data object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalObjectEntry<'a> {
    pub object_number: u64,
    pub object_offset: u64,
    pub record: JournalRecord<'a>,
}

/// Complete records from one fetched object range and whether its tail is partial.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalObjectScan<'a> {
    pub entries: Vec<JournalObjectEntry<'a>>,
    /// Bytes consumed through complete records and complete padding.
    pub consumed: usize,
    /// The final record or its alignment padding may continue in a later fetch.
    pub needs_more: bool,
}

/// One owned journal record emitted after its complete frame and CRC verify.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalObjectRecord {
    pub object_number: u64,
    pub object_offset: u64,
    pub entry_tid: u64,
    pub tag_tid: u64,
    pub data: Vec<u8>,
}

/// Incremental parser for one journal data object.
///
/// It retains only the incomplete tail between reads and emits verified
/// records as owned payloads. Each input chunk must fit `max_pending_bytes`,
/// which is supplied from the journal's negotiated object bound.
#[derive(Debug)]
pub struct JournalObjectStream {
    object_number: u64,
    pending_offset: u64,
    read_offset: u64,
    max_pending_bytes: usize,
    pending: Vec<u8>,
    finished: bool,
}

impl JournalObjectStream {
    pub fn new(
        object_number: u64,
        initial_offset: u64,
        max_pending_bytes: usize,
    ) -> denc::Result<Self> {
        if max_pending_bytes == 0 {
            return Err(Error::BadValue("journal stream limit"));
        }
        Ok(Self {
            object_number,
            pending_offset: initial_offset,
            read_offset: initial_offset,
            max_pending_bytes,
            pending: Vec::new(),
            finished: false,
        })
    }

    /// Next absolute offset to request from RADOS.
    pub fn read_offset(&self) -> u64 {
        self.read_offset
    }

    /// Bytes retained between reads (the incomplete tail); bounded by
    /// `max_pending_bytes`.
    pub fn pending_bytes(&self) -> usize {
        self.pending.len()
    }

    /// Append one read result. Set `eof` only when the provider returned a
    /// short read (including zero); a partial record at EOF is corruption.
    pub fn push(&mut self, bytes: &[u8], eof: bool) -> denc::Result<Vec<JournalObjectRecord>> {
        if self.finished || (bytes.is_empty() && !eof) {
            return Err(Error::BadValue("journal stream read state"));
        }
        if bytes.len() > self.max_pending_bytes {
            return Err(Error::TooLong);
        }
        self.read_offset = self
            .read_offset
            .checked_add(u64::try_from(bytes.len()).map_err(|_| Error::TooLong)?)
            .ok_or(Error::TooLong)?;
        self.pending
            .try_reserve(bytes.len())
            .map_err(|_| Error::NoSpace)?;
        self.pending.extend_from_slice(bytes);

        let scan = scan_journal_object(self.object_number, self.pending_offset, &self.pending)?;
        let consumed = scan.consumed;
        let needs_more = scan.needs_more;
        let mut records = Vec::new();
        records
            .try_reserve_exact(scan.entries.len())
            .map_err(|_| Error::NoSpace)?;
        for entry in &scan.entries {
            let mut data = Vec::new();
            data.try_reserve_exact(entry.record.data.len())
                .map_err(|_| Error::NoSpace)?;
            data.extend_from_slice(entry.record.data);
            records.push(JournalObjectRecord {
                object_number: entry.object_number,
                object_offset: entry.object_offset,
                entry_tid: entry.record.entry_tid,
                tag_tid: entry.record.tag_tid,
                data,
            });
        }

        if eof && needs_more {
            return Err(Error::BadValue("journal incomplete tail"));
        }
        if consumed > self.pending.len() {
            return Err(Error::BadValue("journal scan length"));
        }
        drop(scan);
        self.pending.drain(..consumed);
        self.pending_offset = self
            .pending_offset
            .checked_add(u64::try_from(consumed).map_err(|_| Error::TooLong)?)
            .ok_or(Error::TooLong)?;
        if self.pending.len() > self.max_pending_bytes {
            return Err(Error::TooLong);
        }
        self.finished = eof;
        Ok(records)
    }
}

/// Scan complete records from one journal object range.
///
/// The object offset is absolute within the object and determines zero-padding
/// alignment. Padding may span multiple aligned allocation units. A partial
/// record or unaligned zero-padding tail is retained for a later fetch.
/// Corrupt complete records and malformed padding are errors.
pub fn scan_journal_object(
    object_number: u64,
    object_offset: u64,
    input: &[u8],
) -> denc::Result<JournalObjectScan<'_>> {
    let mut entries = Vec::new();
    let mut cursor = 0usize;
    let mut needs_more = false;

    while cursor < input.len() {
        let remaining = &input[cursor..];
        let zero_prefix = remaining.iter().take_while(|byte| **byte == 0).count();
        if zero_prefix != 0 {
            let absolute_offset = object_offset
                .checked_add(u64::try_from(cursor).map_err(|_| Error::TooLong)?)
                .ok_or(Error::TooLong)?;
            let minimum_padding =
                usize::try_from((8 - absolute_offset % 8) % 8).map_err(|_| Error::TooLong)?;
            let padding_end = absolute_offset
                .checked_add(u64::try_from(zero_prefix).map_err(|_| Error::TooLong)?)
                .ok_or(Error::TooLong)?;
            if zero_prefix < minimum_padding || padding_end % 8 != 0 {
                if zero_prefix == remaining.len() {
                    needs_more = true;
                    break;
                }
                return Err(Error::BadValue("journal record padding"));
            }
            if zero_prefix == remaining.len() {
                cursor += zero_prefix;
                break;
            }
            cursor += zero_prefix;
            continue;
        }

        match decode_journal_record(remaining) {
            Ok(record) => {
                let record_offset = object_offset
                    .checked_add(u64::try_from(cursor).map_err(|_| Error::TooLong)?)
                    .ok_or(Error::TooLong)?;
                cursor += record.consumed;
                entries.try_reserve(1).map_err(|_| Error::NoSpace)?;
                entries.push(JournalObjectEntry {
                    object_number,
                    object_offset: record_offset,
                    record,
                });
            }
            Err(Error::Eof { .. } | Error::BadLength { .. }) => {
                let magic = 0x3141592653589793u64.to_le_bytes();
                if remaining.len() < magic.len() && !magic.starts_with(remaining) {
                    return Err(Error::BadValue("journal record preamble"));
                }
                needs_more = true;
                break;
            }
            Err(error) => return Err(error),
        }
    }

    Ok(JournalObjectScan {
        entries,
        consumed: cursor,
        needs_more,
    })
}

/// Snapshot operation represented by an administrative event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JournalEventKind {
    Create,
    Remove,
    Protect,
    Unprotect,
    Rollback,
}

/// One decoded event payload. Variable byte fields borrow the journal record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JournalEvent<'a> {
    Discard {
        offset: u64,
        length: u64,
        skip_partial: bool,
        discard_granularity: u32,
    },
    Write {
        offset: u64,
        length: u64,
        data: &'a [u8],
    },
    Flush,
    WriteSame {
        offset: u64,
        length: u64,
        pattern: &'a [u8],
    },
    CompareAndWrite {
        offset: u64,
        length: u64,
        compare: &'a [u8],
        replacement: &'a [u8],
    },
    OpFinish {
        /// Replay identifies the associated operation by this first encoded ID.
        operation_id: u64,
        /// The duplicated second wire ID is retained; pinned replay does not use
        /// or compare it independently.
        repeated_operation_id: u64,
        result: i32,
    },
    Snapshot {
        kind: JournalEventKind,
        operation_id: u64,
        name: &'a [u8],
        namespace: SnapshotNamespace,
    },
    SnapshotRename {
        operation_id: u64,
        destination_name: &'a [u8],
        snapshot_id: u64,
        source_name: &'a [u8],
    },
    ImageRename {
        operation_id: u64,
        new_name: &'a [u8],
    },
    Resize {
        operation_id: u64,
        size: u64,
    },
    Flatten {
        operation_id: u64,
    },
    MirrorPromoteDemote,
    SnapshotLimit {
        operation_id: u64,
        limit: u64,
    },
    FeatureUpdate {
        operation_id: u64,
        features: u64,
        enabled: bool,
    },
    MetadataSet {
        operation_id: u64,
        key: &'a [u8],
        value: &'a [u8],
    },
    MetadataRemove {
        operation_id: u64,
        key: &'a [u8],
    },
}

impl JournalEvent<'_> {
    /// The operation ID of an operation start event; `None` for DATA events,
    /// the finish record and the promote/demote marker.
    pub fn operation_id(&self) -> Option<u64> {
        match *self {
            Self::Snapshot { operation_id, .. }
            | Self::SnapshotRename { operation_id, .. }
            | Self::ImageRename { operation_id, .. }
            | Self::Resize { operation_id, .. }
            | Self::Flatten { operation_id }
            | Self::SnapshotLimit { operation_id, .. }
            | Self::FeatureUpdate { operation_id, .. }
            | Self::MetadataSet { operation_id, .. }
            | Self::MetadataRemove { operation_id, .. } => Some(operation_id),
            Self::Discard { .. }
            | Self::Write { .. }
            | Self::Flush
            | Self::WriteSame { .. }
            | Self::CompareAndWrite { .. }
            | Self::OpFinish { .. }
            | Self::MirrorPromoteDemote => None,
        }
    }
}

/// Decoded event and the number of bytes consumed from the enclosing record.
/// Unknown event types are successful no-ops (`event == None`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalEventEntry<'a> {
    pub version: u8,
    pub event: Option<JournalEvent<'a>>,
    pub timestamp_seconds: u32,
    pub timestamp_nanoseconds: u32,
    pub consumed: usize,
}

/// Encode a v5 event and separate timestamp frame, retaining the output allocation.
pub fn encode_journal_event_entry(
    event: &JournalEvent<'_>,
    timestamp_seconds: u32,
    timestamp_nanoseconds: u32,
    out: &mut Vec<u8>,
) -> denc::Result<()> {
    out.clear();
    let frame_start = open_frame(out, JOURNAL_EVENT_VERSION, 1)?;
    encode_event_payload(event, out)?;
    close_frame(out, frame_start)?;

    let timestamp_start = open_frame(out, 1, 1)?;
    put_u32(out, timestamp_seconds);
    put_u32(out, timestamp_nanoseconds);
    close_frame(out, timestamp_start)
}

/// Decode one event entry, leaving any enclosing-record bytes unconsumed.
///
/// Event and metadata bodies are independently bounded. Unknown event types
/// skip the rest of their event body and still consume the v4+ timestamp frame.
pub fn decode_journal_event_entry(input: &[u8]) -> denc::Result<JournalEventEntry<'_>> {
    let mut decoder = Decoder::new(input);
    let mut frame_version = 0;
    let mut decoded_event = None;
    decoder.versioned(5, |body, version| {
        frame_version = version;
        let kind = body.u32()?;
        decoded_event = decode_event_payload(kind, version, body)?;
        Ok(())
    })?;

    let (timestamp_seconds, timestamp_nanoseconds) = if frame_version >= 4 {
        decoder.versioned(1, |body, _| Ok((body.u32()?, body.u32()?)))?
    } else {
        (0, 0)
    };

    Ok(JournalEventEntry {
        version: frame_version,
        event: decoded_event,
        timestamp_seconds,
        timestamp_nanoseconds,
        consumed: decoder.position(),
    })
}

fn decode_event_payload<'a>(
    kind: u32,
    version: u8,
    body: &mut Decoder<'a>,
) -> denc::Result<Option<JournalEvent<'a>>> {
    let event = match kind {
        0 => {
            let offset = body.u64()?;
            let length = body.u64()?;
            let skip_partial = if version >= 4 { body.bool()? } else { false };
            let discard_granularity = if version >= 5 {
                body.u32()?
            } else if version == 4 && skip_partial {
                u32::MAX
            } else {
                0
            };
            JournalEvent::Discard {
                offset,
                length,
                skip_partial,
                discard_granularity,
            }
        }
        1 => JournalEvent::Write {
            offset: body.u64()?,
            length: body.u64()?,
            data: body.bytes()?,
        },
        2 => JournalEvent::Flush,
        18 => JournalEvent::WriteSame {
            offset: body.u64()?,
            length: body.u64()?,
            pattern: body.bytes()?,
        },
        19 => JournalEvent::CompareAndWrite {
            offset: body.u64()?,
            length: body.u64()?,
            compare: body.bytes()?,
            replacement: body.bytes()?,
        },
        3 => JournalEvent::OpFinish {
            operation_id: body.u64()?,
            repeated_operation_id: body.u64()?,
            result: body.i32()?,
        },
        4 | 5 | 7 | 8 | 9 => {
            let operation_id = body.u64()?;
            let name = body.bytes()?;
            let has_namespace = match kind {
                4 => version >= 3,
                _ => version >= 4,
            };
            let namespace = if has_namespace {
                crate::snapshot_query::decode_namespace(body)?
            } else {
                SnapshotNamespace::User
            };
            JournalEvent::Snapshot {
                kind: match kind {
                    4 => JournalEventKind::Create,
                    5 => JournalEventKind::Remove,
                    7 => JournalEventKind::Protect,
                    8 => JournalEventKind::Unprotect,
                    _ => JournalEventKind::Rollback,
                },
                operation_id,
                name,
                namespace,
            }
        }
        6 => JournalEvent::SnapshotRename {
            operation_id: body.u64()?,
            destination_name: body.bytes()?,
            snapshot_id: body.u64()?,
            source_name: if version >= 2 { body.bytes()? } else { &[] },
        },
        10 => JournalEvent::ImageRename {
            operation_id: body.u64()?,
            new_name: body.bytes()?,
        },
        11 => JournalEvent::Resize {
            operation_id: body.u64()?,
            size: body.u64()?,
        },
        12 => JournalEvent::Flatten {
            operation_id: body.u64()?,
        },
        13 => JournalEvent::MirrorPromoteDemote,
        14 => JournalEvent::SnapshotLimit {
            operation_id: body.u64()?,
            limit: body.u64()?,
        },
        15 => JournalEvent::FeatureUpdate {
            operation_id: body.u64()?,
            features: body.u64()?,
            enabled: body.bool()?,
        },
        16 => JournalEvent::MetadataSet {
            operation_id: body.u64()?,
            key: body.bytes()?,
            value: body.bytes()?,
        },
        17 => JournalEvent::MetadataRemove {
            operation_id: body.u64()?,
            key: body.bytes()?,
        },
        _ => return Ok(None),
    };
    Ok(Some(event))
}

fn encode_event_payload(event: &JournalEvent<'_>, out: &mut Vec<u8>) -> denc::Result<()> {
    match event {
        JournalEvent::Discard {
            offset,
            length,
            skip_partial,
            discard_granularity,
        } => {
            put_u32(out, 0);
            put_u64(out, *offset);
            put_u64(out, *length);
            out.push(u8::from(*skip_partial));
            put_u32(out, *discard_granularity);
        }
        JournalEvent::Write {
            offset,
            length,
            data,
        } => {
            put_u32(out, 1);
            put_u64(out, *offset);
            put_u64(out, *length);
            put_bytes(out, data)?;
        }
        JournalEvent::Flush => put_u32(out, 2),
        JournalEvent::WriteSame {
            offset,
            length,
            pattern,
        } => {
            put_u32(out, 18);
            put_u64(out, *offset);
            put_u64(out, *length);
            put_bytes(out, pattern)?;
        }
        JournalEvent::CompareAndWrite {
            offset,
            length,
            compare,
            replacement,
        } => {
            put_u32(out, 19);
            put_u64(out, *offset);
            put_u64(out, *length);
            put_bytes(out, compare)?;
            put_bytes(out, replacement)?;
        }
        JournalEvent::OpFinish {
            operation_id,
            repeated_operation_id,
            result,
        } => {
            put_u32(out, 3);
            put_u64(out, *operation_id);
            put_u64(out, *repeated_operation_id);
            put_i32(out, *result);
        }
        JournalEvent::Snapshot {
            kind,
            operation_id,
            name,
            namespace,
        } => {
            put_u32(
                out,
                match kind {
                    JournalEventKind::Create => 4,
                    JournalEventKind::Remove => 5,
                    JournalEventKind::Protect => 7,
                    JournalEventKind::Unprotect => 8,
                    JournalEventKind::Rollback => 9,
                },
            );
            put_u64(out, *operation_id);
            put_bytes(out, name)?;
            out.extend_from_slice(&crate::snapshot_query::encode_snapshot_namespace(
                namespace,
            )?);
        }
        JournalEvent::SnapshotRename {
            operation_id,
            destination_name,
            snapshot_id,
            source_name,
        } => {
            put_u32(out, 6);
            put_u64(out, *operation_id);
            put_bytes(out, destination_name)?;
            put_u64(out, *snapshot_id);
            put_bytes(out, source_name)?;
        }
        JournalEvent::ImageRename {
            operation_id,
            new_name,
        } => {
            put_u32(out, 10);
            put_u64(out, *operation_id);
            put_bytes(out, new_name)?;
        }
        JournalEvent::Resize { operation_id, size } => {
            put_u32(out, 11);
            put_u64(out, *operation_id);
            put_u64(out, *size);
        }
        JournalEvent::Flatten { operation_id } => {
            put_u32(out, 12);
            put_u64(out, *operation_id);
        }
        JournalEvent::MirrorPromoteDemote => put_u32(out, 13),
        JournalEvent::SnapshotLimit {
            operation_id,
            limit,
        } => {
            put_u32(out, 14);
            put_u64(out, *operation_id);
            put_u64(out, *limit);
        }
        JournalEvent::FeatureUpdate {
            operation_id,
            features,
            enabled,
        } => {
            put_u32(out, 15);
            put_u64(out, *operation_id);
            put_u64(out, *features);
            out.push(u8::from(*enabled));
        }
        JournalEvent::MetadataSet {
            operation_id,
            key,
            value,
        } => {
            put_u32(out, 16);
            put_u64(out, *operation_id);
            put_bytes(out, key)?;
            put_bytes(out, value)?;
        }
        JournalEvent::MetadataRemove { operation_id, key } => {
            put_u32(out, 17);
            put_u64(out, *operation_id);
            put_bytes(out, key)?;
        }
    }
    Ok(())
}

fn open_frame(out: &mut Vec<u8>, version: u8, compat: u8) -> denc::Result<usize> {
    out.push(version);
    out.push(compat);
    let len_at = out.len();
    put_u32(out, 0);
    Ok(len_at)
}

fn close_frame(out: &mut [u8], len_at: usize) -> denc::Result<()> {
    let len = u32::try_from(out.len() - len_at - 4).map_err(|_| Error::TooLong)?;
    out[len_at..len_at + 4].copy_from_slice(&len.to_le_bytes());
    Ok(())
}

fn put_count(out: &mut Vec<u8>, count: usize) -> denc::Result<()> {
    put_u32(out, u32::try_from(count).map_err(|_| Error::TooLong)?);
    Ok(())
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> denc::Result<()> {
    put_count(out, bytes.len())?;
    out.extend_from_slice(bytes);
    Ok(())
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}
fn put_i32(out: &mut Vec<u8>, value: i32) {
    out.extend_from_slice(&value.to_le_bytes());
}
fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u32wire(value: u32) -> Vec<u8> {
        value.to_le_bytes().to_vec()
    }

    fn i32wire(value: i32) -> Vec<u8> {
        value.to_le_bytes().to_vec()
    }

    fn u64wire(value: u64) -> Vec<u8> {
        value.to_le_bytes().to_vec()
    }

    fn byteswire(value: &[u8]) -> Vec<u8> {
        let mut out = u32wire(value.len() as u32);
        out.extend_from_slice(value);
        out
    }

    #[test]
    fn journal_object_scan_handles_records_padding_and_offsets() {
        let mut first = Vec::new();
        encode_journal_record(7, 3, b"one", &mut first).unwrap();
        let mut second = Vec::new();
        encode_journal_record(8, 3, b"two", &mut second).unwrap();
        let mut input = first.clone();
        input.resize(4096, 0);
        input.extend_from_slice(&second);

        let scan = scan_journal_object(2, 0, &input).unwrap();
        assert!(!scan.needs_more);
        assert_eq!(scan.consumed, input.len());
        assert_eq!(scan.entries.len(), 2);
        assert_eq!(
            (scan.entries[0].object_number, scan.entries[0].object_offset),
            (2, 0)
        );
        assert_eq!(scan.entries[0].record.data, b"one");
        assert_eq!(scan.entries[1].object_offset, 4096);
        assert_eq!(scan.entries[1].record.data, b"two");
    }

    #[test]
    fn journal_object_scan_retains_partial_record_and_padding() {
        let mut record = Vec::new();
        encode_journal_record(1, 1, b"abc", &mut record).unwrap();
        let partial = scan_journal_object(0, 0, &record[..record.len() - 1]).unwrap();
        assert!(partial.needs_more);
        assert!(partial.entries.is_empty());
        assert_eq!(partial.consumed, 0);

        let aligned_record_len = (record.len() + 7) & !7;
        let padding = aligned_record_len - record.len();
        assert!(padding > 1);
        let tail = vec![0; padding - 1];
        let scan = scan_journal_object(0, record.len() as u64, &tail).unwrap();
        assert!(scan.needs_more);
        assert_eq!(scan.consumed, 0);
    }

    #[test]
    fn journal_object_scan_rejects_nonzero_malformed_tail() {
        let error = scan_journal_object(0, 0, &[0x91, 0x82, 0x73]).unwrap_err();
        assert!(matches!(error, Error::BadValue("journal record preamble")));
    }

    #[test]
    fn incremental_journal_stream_emits_records_across_chunk_and_allocation_padding() {
        let mut first = Vec::new();
        encode_journal_record(7, 3, b"one", &mut first).unwrap();
        let mut wire = first;
        wire.resize(4096, 0);
        let mut second = Vec::new();
        encode_journal_record(8, 3, b"two", &mut second).unwrap();
        wire.extend_from_slice(&second);

        let mut stream = JournalObjectStream::new(2, 0, 8192).unwrap();
        assert!(stream.push(&wire[..17], false).unwrap().is_empty());
        assert_eq!(stream.read_offset(), 17);
        let records = stream.push(&wire[17..], true).unwrap();
        assert_eq!(stream.read_offset(), wire.len() as u64);
        assert_eq!(
            records,
            [
                JournalObjectRecord {
                    object_number: 2,
                    object_offset: 0,
                    entry_tid: 7,
                    tag_tid: 3,
                    data: b"one".to_vec(),
                },
                JournalObjectRecord {
                    object_number: 2,
                    object_offset: 4096,
                    entry_tid: 8,
                    tag_tid: 3,
                    data: b"two".to_vec(),
                },
            ]
        );
        assert!(matches!(
            stream.push(&[], true),
            Err(Error::BadValue("journal stream read state"))
        ));
    }

    #[test]
    fn incremental_journal_stream_rejects_partial_record_at_eof() {
        let mut wire = Vec::new();
        encode_journal_record(1, 1, b"payload", &mut wire).unwrap();
        let mut stream = JournalObjectStream::new(0, 0, 4096).unwrap();
        let split = 20;
        assert!(stream.push(&wire[..split], false).unwrap().is_empty());
        assert!(matches!(
            stream.push(&[], true),
            Err(Error::BadValue("journal incomplete tail"))
        ));
    }

    fn payload(tag: u32, fields: &[Vec<u8>]) -> Vec<u8> {
        let mut out = u32wire(tag);
        for field in fields {
            out.extend_from_slice(field);
        }
        out
    }

    fn frame(version: u8, compat: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![version, compat];
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        out.extend_from_slice(body);
        out
    }

    fn metadata(seconds: u32, nanoseconds: u32) -> Vec<u8> {
        let mut body = seconds.to_le_bytes().to_vec();
        body.extend_from_slice(&nanoseconds.to_le_bytes());
        frame(1, 1, &body)
    }

    #[test]
    fn write_writer_golden_has_two_frames_and_reuses_output() {
        let mut out = vec![0xaa; 64];
        let allocation = out.as_ptr();
        encode_journal_event_entry(
            &JournalEvent::Write {
                offset: 0x0102,
                length: 9,
                data: b"abc",
            },
            0x11223344,
            0x55667788,
            &mut out,
        )
        .unwrap();
        let expected = vec![
            5, 1, 27, 0, 0, 0, 1, 0, 0, 0, 2, 1, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0,
            0, b'a', b'b', b'c', 1, 1, 8, 0, 0, 0, 0x44, 0x33, 0x22, 0x11, 0x88, 0x77, 0x66, 0x55,
        ];
        assert_eq!(out, expected);
        assert_eq!(out.as_ptr(), allocation);
        let decoded = decode_journal_event_entry(&out).unwrap();
        assert_eq!(decoded.version, 5);
        assert_eq!(
            decoded.event,
            Some(JournalEvent::Write {
                offset: 0x0102,
                length: 9,
                data: b"abc"
            })
        );
        assert_eq!(
            (decoded.timestamp_seconds, decoded.timestamp_nanoseconds),
            (0x11223344, 0x55667788)
        );
        assert_eq!(decoded.consumed, expected.len());
        encode_journal_event_entry(&JournalEvent::Flush, 0, 0, &mut out).unwrap();
        assert_eq!(&out[..6], &[5, 1, 4, 0, 0, 0]);
    }

    #[test]
    fn legacy_defaults_and_versioned_fields_match_spec() {
        let mut old_discard = 0u32.to_le_bytes().to_vec();
        old_discard.extend_from_slice(&10u64.to_le_bytes());
        old_discard.extend_from_slice(&20u64.to_le_bytes());
        let old_discard_frame = frame(1, 5, &old_discard);
        let decoded = decode_journal_event_entry(&old_discard_frame).unwrap();
        assert_eq!(
            decoded.event,
            Some(JournalEvent::Discard {
                offset: 10,
                length: 20,
                skip_partial: false,
                discard_granularity: 0,
            })
        );
        assert_eq!(
            (decoded.timestamp_seconds, decoded.timestamp_nanoseconds),
            (0, 0)
        );

        let mut v4 = 0u32.to_le_bytes().to_vec();
        v4.extend_from_slice(&10u64.to_le_bytes());
        v4.extend_from_slice(&20u64.to_le_bytes());
        v4.push(1);
        let mut v4_entry = frame(4, 1, &v4);
        v4_entry.extend_from_slice(&metadata(7, 8));
        let decoded = decode_journal_event_entry(&v4_entry).unwrap();
        assert_eq!(
            decoded.event,
            Some(JournalEvent::Discard {
                offset: 10,
                length: 20,
                skip_partial: true,
                discard_granularity: u32::MAX,
            })
        );
        assert_eq!(
            (decoded.timestamp_seconds, decoded.timestamp_nanoseconds),
            (7, 8)
        );

        let mut old_rename = 6u32.to_le_bytes().to_vec();
        old_rename.extend_from_slice(&42u64.to_le_bytes());
        old_rename.extend_from_slice(&1u32.to_le_bytes());
        old_rename.extend_from_slice(b"d");
        old_rename.extend_from_slice(&9u64.to_le_bytes());
        assert_eq!(
            decode_journal_event_entry(&frame(1, 1, &old_rename))
                .unwrap()
                .event,
            Some(JournalEvent::SnapshotRename {
                operation_id: 42,
                destination_name: b"d",
                snapshot_id: 9,
                source_name: b""
            })
        );

        let mut old_snapshot = 4u32.to_le_bytes().to_vec();
        old_snapshot.extend_from_slice(&42u64.to_le_bytes());
        old_snapshot.extend_from_slice(&1u32.to_le_bytes());
        old_snapshot.extend_from_slice(b"s");
        assert_eq!(
            decode_journal_event_entry(&frame(2, 1, &old_snapshot))
                .unwrap()
                .event,
            Some(JournalEvent::Snapshot {
                kind: JournalEventKind::Create,
                operation_id: 42,
                name: b"s",
                namespace: SnapshotNamespace::User
            })
        );

        // v3 snapshot-create uniquely places its namespace directly after name.
        let mut v3_snapshot = 4u32.to_le_bytes().to_vec();
        v3_snapshot.extend_from_slice(&43u64.to_le_bytes());
        v3_snapshot.extend_from_slice(&1u32.to_le_bytes());
        v3_snapshot.extend_from_slice(b"s");
        v3_snapshot.extend_from_slice(&[1, 1, 4, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            decode_journal_event_entry(&frame(3, 5, &v3_snapshot))
                .unwrap()
                .event,
            Some(JournalEvent::Snapshot {
                kind: JournalEventKind::Create,
                operation_id: 43,
                name: b"s",
                namespace: SnapshotNamespace::User
            })
        );

        let mut v3_remove = 5u32.to_le_bytes().to_vec();
        v3_remove.extend_from_slice(&44u64.to_le_bytes());
        v3_remove.extend_from_slice(&1u32.to_le_bytes());
        v3_remove.extend_from_slice(b"s");
        assert_eq!(
            decode_journal_event_entry(&frame(3, 1, &v3_remove))
                .unwrap()
                .event,
            Some(JournalEvent::Snapshot {
                kind: JournalEventKind::Remove,
                operation_id: 44,
                name: b"s",
                namespace: SnapshotNamespace::User
            })
        );

        // The pinned decoder accepts version 0 when its required fields fit.
        assert_eq!(
            decode_journal_event_entry(&frame(0, 5, &2u32.to_le_bytes()))
                .unwrap()
                .event,
            Some(JournalEvent::Flush)
        );
    }

    #[test]
    fn snapshot_event_namespace_uses_the_snapshot_decoder() {
        let namespace = SnapshotNamespace::Mirror {
            state: 0,
            complete: false,
            peer_uuids: vec![b"a".to_vec()],
            primary_mirror_uuid: b"m".to_vec(),
            primary_snap_id: 3,
            last_copied_object_number: 4,
            snap_seqs: vec![(1, 2)],
        };
        let encoded = crate::snapshot_query::encode_snapshot_namespace(&namespace).unwrap();
        let event = payload(4, &[u64wire(8), byteswire(b"n"), encoded.clone()]);
        let mut entry = frame(5, 1, &event);
        entry.extend_from_slice(&metadata(0, 0));
        assert_eq!(
            decode_journal_event_entry(&entry).unwrap().event,
            Some(JournalEvent::Snapshot {
                kind: JournalEventKind::Create,
                operation_id: 8,
                name: b"n",
                namespace,
            })
        );

        // A mirror state outside the pinned 0..=3 range fails the shared
        // snapshot-namespace decoder, so the event codec must reject it too.
        let mut invalid = encoded;
        invalid[10] = 9;
        let event = payload(4, &[u64wire(8), byteswire(b"n"), invalid]);
        let mut entry = frame(5, 1, &event);
        entry.extend_from_slice(&metadata(0, 0));
        assert!(decode_journal_event_entry(&entry).is_err());
    }

    #[test]
    fn all_twenty_supported_opcodes_match_independent_wire_fixtures() {
        let user_namespace = vec![1, 1, 4, 0, 0, 0, 0, 0, 0, 0];
        let cases = vec![
            (
                payload(0, &[u64wire(1), u64wire(2), vec![1], u32wire(4)]),
                JournalEvent::Discard {
                    offset: 1,
                    length: 2,
                    skip_partial: true,
                    discard_granularity: 4,
                },
            ),
            (
                payload(1, &[u64wire(1), u64wire(2), byteswire(b"d")]),
                JournalEvent::Write {
                    offset: 1,
                    length: 2,
                    data: b"d",
                },
            ),
            (payload(2, &[]), JournalEvent::Flush),
            (
                payload(18, &[u64wire(1), u64wire(2), byteswire(b"p")]),
                JournalEvent::WriteSame {
                    offset: 1,
                    length: 2,
                    pattern: b"p",
                },
            ),
            (
                payload(
                    19,
                    &[u64wire(1), u64wire(2), byteswire(b"c"), byteswire(b"r")],
                ),
                JournalEvent::CompareAndWrite {
                    offset: 1,
                    length: 2,
                    compare: b"c",
                    replacement: b"r",
                },
            ),
            (
                payload(3, &[u64wire(7), u64wire(99), i32wire(-5)]),
                JournalEvent::OpFinish {
                    operation_id: 7,
                    repeated_operation_id: 99,
                    result: -5,
                },
            ),
            (
                payload(4, &[u64wire(8), byteswire(b"n"), user_namespace.clone()]),
                JournalEvent::Snapshot {
                    kind: JournalEventKind::Create,
                    operation_id: 8,
                    name: b"n",
                    namespace: SnapshotNamespace::User,
                },
            ),
            (
                payload(5, &[u64wire(8), byteswire(b"n"), user_namespace.clone()]),
                JournalEvent::Snapshot {
                    kind: JournalEventKind::Remove,
                    operation_id: 8,
                    name: b"n",
                    namespace: SnapshotNamespace::User,
                },
            ),
            (
                payload(
                    6,
                    &[u64wire(8), byteswire(b"new"), u64wire(9), byteswire(b"old")],
                ),
                JournalEvent::SnapshotRename {
                    operation_id: 8,
                    destination_name: b"new",
                    snapshot_id: 9,
                    source_name: b"old",
                },
            ),
            (
                payload(7, &[u64wire(8), byteswire(b"n"), user_namespace.clone()]),
                JournalEvent::Snapshot {
                    kind: JournalEventKind::Protect,
                    operation_id: 8,
                    name: b"n",
                    namespace: SnapshotNamespace::User,
                },
            ),
            (
                payload(8, &[u64wire(8), byteswire(b"n"), user_namespace.clone()]),
                JournalEvent::Snapshot {
                    kind: JournalEventKind::Unprotect,
                    operation_id: 8,
                    name: b"n",
                    namespace: SnapshotNamespace::User,
                },
            ),
            (
                payload(9, &[u64wire(8), byteswire(b"n"), user_namespace.clone()]),
                JournalEvent::Snapshot {
                    kind: JournalEventKind::Rollback,
                    operation_id: 8,
                    name: b"n",
                    namespace: SnapshotNamespace::User,
                },
            ),
            (
                payload(10, &[u64wire(8), byteswire(b"image")]),
                JournalEvent::ImageRename {
                    operation_id: 8,
                    new_name: b"image",
                },
            ),
            (
                payload(11, &[u64wire(8), u64wire(10)]),
                JournalEvent::Resize {
                    operation_id: 8,
                    size: 10,
                },
            ),
            (
                payload(12, &[u64wire(8)]),
                JournalEvent::Flatten { operation_id: 8 },
            ),
            (payload(13, &[]), JournalEvent::MirrorPromoteDemote),
            (
                payload(14, &[u64wire(8), u64wire(10)]),
                JournalEvent::SnapshotLimit {
                    operation_id: 8,
                    limit: 10,
                },
            ),
            (
                payload(15, &[u64wire(8), u64wire(0x15), vec![1]]),
                JournalEvent::FeatureUpdate {
                    operation_id: 8,
                    features: 0x15,
                    enabled: true,
                },
            ),
            (
                payload(16, &[u64wire(8), byteswire(b"k"), byteswire(b"v")]),
                JournalEvent::MetadataSet {
                    operation_id: 8,
                    key: b"k",
                    value: b"v",
                },
            ),
            (
                payload(17, &[u64wire(8), byteswire(b"k")]),
                JournalEvent::MetadataRemove {
                    operation_id: 8,
                    key: b"k",
                },
            ),
        ];

        assert_eq!(cases.len(), 20);
        let mut scratch = Vec::with_capacity(256);
        for (wire_payload, event) in cases {
            let mut expected = frame(5, 1, &wire_payload);
            expected.extend_from_slice(&[1, 1, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            assert_eq!(
                decode_journal_event_entry(&expected).unwrap().event,
                Some(event.clone())
            );
            encode_journal_event_entry(&event, 0, 0, &mut scratch).unwrap();
            assert_eq!(scratch, expected);
        }
    }

    #[test]
    fn unknown_future_and_trailing_frames_follow_boundaries() {
        let mut unknown = 0xfedcba98u32.to_le_bytes().to_vec();
        unknown.extend_from_slice(&[1, 2, 3]);
        let mut input = frame(9, 5, &unknown);
        input.extend_from_slice(&metadata(11, 12));
        input.extend_from_slice(b"next-record");
        let decoded = decode_journal_event_entry(&input).unwrap();
        assert_eq!(decoded.version, 9);
        assert_eq!(decoded.event, None);
        assert_eq!(
            (decoded.timestamp_seconds, decoded.timestamp_nanoseconds),
            (11, 12)
        );
        assert_eq!(&input[decoded.consumed..], b"next-record");

        let mut known = 2u32.to_le_bytes().to_vec();
        known.extend_from_slice(&[0xde, 0xad]);
        let mut input = frame(5, 1, &known);
        input.extend_from_slice(&metadata(0, 0));
        assert_eq!(
            decode_journal_event_entry(&input).unwrap().event,
            Some(JournalEvent::Flush)
        );

        // A write extent and its bufferlist have independent lengths in this codec.
        let mut write = 1u32.to_le_bytes().to_vec();
        write.extend_from_slice(&0u64.to_le_bytes());
        write.extend_from_slice(&100u64.to_le_bytes());
        write.extend_from_slice(&1u32.to_le_bytes());
        write.push(7);
        let mut input = frame(5, 1, &write);
        input.extend_from_slice(&metadata(0, 0));
        assert_eq!(
            decode_journal_event_entry(&input).unwrap().event,
            Some(JournalEvent::Write {
                offset: 0,
                length: 100,
                data: &[7]
            })
        );
    }

    #[test]
    fn malformed_frame_and_required_field_boundaries_are_rejected() {
        // Version 0 still carries the complete standard six-byte envelope.
        assert!(decode_journal_event_entry(&[0, 5, 0, 0, 0]).is_err());
        // Incompatible event frame.
        assert!(decode_journal_event_entry(&[1, 6, 4, 0, 0, 0, 2, 0, 0, 0]).is_err());
        // Declared frame body exceeds physical input.
        assert!(decode_journal_event_entry(&[1, 1, 5, 0, 0, 0, 2, 0, 0, 0]).is_err());
        // The declared body is too short for Flush's type, even though following bytes exist.
        let mut input = frame(5, 1, &[2]);
        input.extend_from_slice(&metadata(0, 0));
        assert!(decode_journal_event_entry(&input).is_err());
        // A payload field cannot consume bytes outside its declared event frame.
        let mut short_write = 1u32.to_le_bytes().to_vec();
        short_write.extend_from_slice(&1u64.to_le_bytes());
        let mut input = frame(5, 1, &short_write);
        input.extend_from_slice(&metadata(0, 0));
        assert!(decode_journal_event_entry(&input).is_err());
        // A v4+ timestamp frame is mandatory, bounded, and compat-checked.
        let mut input = frame(4, 1, &2u32.to_le_bytes());
        assert!(decode_journal_event_entry(&input).is_err());
        input.extend_from_slice(&[1, 2, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert!(decode_journal_event_entry(&input).is_err());
    }

    #[test]
    fn admin_payload_keeps_repeated_operation_id_and_borrowed_fields() {
        let event = JournalEvent::OpFinish {
            operation_id: 0x0102030405060708,
            repeated_operation_id: 0x1112131415161718,
            result: -5,
        };
        let mut raw = Vec::new();
        encode_journal_event_entry(&event, 1, 2, &mut raw).unwrap();
        assert_eq!(&raw[10..18], &0x0102030405060708u64.to_le_bytes());
        assert_eq!(&raw[18..26], &0x1112131415161718u64.to_le_bytes());
        assert_eq!(decode_journal_event_entry(&raw).unwrap().event, Some(event));

        let mut payload = 16u32.to_le_bytes().to_vec();
        payload.extend_from_slice(&5u64.to_le_bytes());
        payload.extend_from_slice(&1u32.to_le_bytes());
        payload.extend_from_slice(b"k");
        payload.extend_from_slice(&1u32.to_le_bytes());
        payload.extend_from_slice(b"v");
        let input = frame(1, 1, &payload);
        let decoded = decode_journal_event_entry(&input).unwrap();
        assert_eq!(
            decoded.event,
            Some(JournalEvent::MetadataSet {
                operation_id: 5,
                key: b"k",
                value: b"v"
            })
        );
        assert_eq!(decoded.consumed, input.len());
    }
}
