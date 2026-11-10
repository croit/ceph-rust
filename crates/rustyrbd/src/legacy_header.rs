// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Legacy (format-1) on-disk codecs: header, snapshot list and `rbd_directory`
//! tmap.
//!
//! Format-1 images store their header as the object `<name>.rbd` in the
//! metadata pool. The fixed 112-byte header is followed by `snap_count` packed
//! `{id, image_size}` records and `snap_names_len` bytes of NUL-terminated
//! snapshot names. This module decodes that object and the `rbd.snap_list`
//! class reply into the same [`ImageSnapContext`] and USER-snapshot shapes the
//! v2 read path consumes, builds the header of a new image, and codes the
//! `rbd_directory` tmap (image names in the object data, v2 entries in its
//! omap). It performs no I/O and issues no mutations.

use crate::{ImageSnapContext, SnapshotInfo, SnapshotNamespace};

/// Size of the packed fixed header, before the snapshot arrays.
pub const LEGACY_HEADER_FIXED_BYTES: usize = 112;

/// Longest data-object block prefix that fits the 24-byte header field with
/// its NUL terminator.
pub const LEGACY_BLOCK_PREFIX_MAX: usize = 23;

/// Signature field of the fixed header (`RBD\0`).
const RBD_SIGNATURE: &[u8; 4] = b"RBD\0";
/// Version field of the fixed header (`001.005\0`).
const RBD_VERSION: &[u8; 8] = b"001.005\0";

/// Format the data-object block prefix of a new format-1 image:
/// `rb.<high>.<low>.<random>` in lowercase hex without padding, truncated to
/// [`LEGACY_BLOCK_PREFIX_MAX`] bytes. `high` and `low` are the two halves of
/// the rados client instance ID and `random` any value below `0xffff_fffe`;
/// uniqueness, not the exact value, is the contract.
pub fn legacy_block_prefix(high: u32, low: u32, random: u32) -> Vec<u8> {
    let mut prefix = format!("rb.{high:x}.{low:x}.{random:x}").into_bytes();
    prefix.truncate(LEGACY_BLOCK_PREFIX_MAX);
    prefix
}

/// Build the 112-byte fixed header of a new format-1 image: ordinary magic,
/// block prefix, `RBD\0`, `001.005\0`, the object order and the image size,
/// with no snapshot arrays. A prefix longer than
/// [`LEGACY_BLOCK_PREFIX_MAX`] is truncated so the field stays NUL-terminated.
pub fn build_legacy_header(
    order: u8,
    image_size: u64,
    block_prefix: &[u8],
) -> [u8; LEGACY_HEADER_FIXED_BYTES] {
    let mut header = [0u8; LEGACY_HEADER_FIXED_BYTES];
    header[..RBD_HEADER_TEXT.len()].copy_from_slice(RBD_HEADER_TEXT);
    let prefix = &block_prefix[..block_prefix.len().min(LEGACY_BLOCK_PREFIX_MAX)];
    header[40..40 + prefix.len()].copy_from_slice(prefix);
    header[64..68].copy_from_slice(RBD_SIGNATURE);
    header[68..76].copy_from_slice(RBD_VERSION);
    header[76] = order;
    header[80..88].copy_from_slice(&image_size.to_le_bytes());
    header
}

/// Patch the little-endian image-size field at offset 80 of an already
/// encoded fixed header (resize writes only these eight bytes).
pub fn set_legacy_image_size(header: &mut [u8; LEGACY_HEADER_FIXED_BYTES], image_size: u64) {
    header[80..88].copy_from_slice(&image_size.to_le_bytes());
}

/// Number of lowercase hex digits in a format-1 data-object name suffix.
/// Format 2 uses 16; the layout carries this width so every object-name
/// formatter produces the right name without a per-call format branch.
pub const LEGACY_OBJECT_NAME_WIDTH: u32 = 12;

/// Ordinary format-1 image magic, compared including its NUL terminator
/// (34 bytes in the 40-byte text slot).
pub const RBD_HEADER_TEXT: &[u8; 34] = b"<<< Rados Block Device Image >>>\n\0";
/// Migration marker, the same byte length as the ordinary magic. Recognized
/// and reported, never handled by this read path (WP-7).
pub const RBD_MIGRATE_HEADER_TEXT: &[u8; 34] = b"<<< Migrating RBD Image      >>>\n\0";

/// One decoded legacy snapshot record (newest first, matching on-disk order).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegacySnapshot {
    /// Stable snapshot ID.
    pub id: u64,
    /// Image size captured when the snapshot was taken.
    pub image_size: u64,
    /// Snapshot name without its NUL terminator.
    pub name: Vec<u8>,
}

impl LegacySnapshot {
    /// The USER-snapshot view of this legacy record: zero timestamps and flags,
    /// no child count, no protection state.
    pub fn as_snapshot_info(&self) -> SnapshotInfo {
        SnapshotInfo {
            id: self.id,
            namespace: SnapshotNamespace::User,
            name: self.name.clone(),
            image_size: self.image_size,
            timestamp_seconds: 0,
            timestamp_nanoseconds: 0,
            child_count: 0,
        }
    }
}

/// Decoded fixed header plus its trailing snapshot arrays.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegacyHeader {
    /// Object order; the object size is `2^order`.
    pub order: u8,
    /// Logical image size in bytes.
    pub image_size: u64,
    /// Data-object block prefix, NUL-terminated inside its 24-byte field.
    pub block_prefix: Vec<u8>,
    /// Highest allocated snapshot ID (the write SnapContext sequence).
    pub snap_seq: u64,
    /// Snapshot records in newest-first order.
    pub snapshots: Vec<LegacySnapshot>,
}

/// Why a legacy header or snapshot list cannot be decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LegacyHeaderError {
    /// The object is shorter than the fixed header or its declared arrays
    /// (`-EIO`).
    Truncated,
    /// The 34-byte magic is neither the ordinary text nor the migration marker
    /// (`-ENXIO`).
    BadMagic,
    /// The header carries the migration marker: recognized, but a migration
    /// source is out of scope for this read path (WP-7).
    Migration,
    /// The snapshot records and names disagree, or a name is not NUL-terminated
    /// inside `snap_names_len` (`-EIO`).
    InconsistentSnapshots,
    /// The SnapContext is invalid: the sequence is below a listed ID, the IDs
    /// are not strictly descending, or an ID reaches `NOSNAP` (`-EIO`).
    InvalidSnapContext,
}

impl std::fmt::Display for LegacyHeaderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => f.write_str("truncated RBD format-1 header"),
            Self::BadMagic => f.write_str("unrecognized RBD format-1 header magic"),
            Self::Migration => f.write_str("RBD format-1 migration marker is not handled"),
            Self::InconsistentSnapshots => f.write_str("inconsistent RBD format-1 snapshot array"),
            Self::InvalidSnapContext => f.write_str("invalid RBD format-1 snapshot context"),
        }
    }
}

impl std::error::Error for LegacyHeaderError {}

fn take_u64(bytes: &[u8], cursor: &mut usize) -> Result<u64, LegacyHeaderError> {
    let end = cursor.checked_add(8).ok_or(LegacyHeaderError::Truncated)?;
    let value = u64::from_le_bytes(
        bytes
            .get(*cursor..end)
            .ok_or(LegacyHeaderError::Truncated)?
            .try_into()
            .expect("fixed-size slice"),
    );
    *cursor = end;
    Ok(value)
}

fn take_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32, LegacyHeaderError> {
    let end = cursor.checked_add(4).ok_or(LegacyHeaderError::Truncated)?;
    let value = u32::from_le_bytes(
        bytes
            .get(*cursor..end)
            .ok_or(LegacyHeaderError::Truncated)?
            .try_into()
            .expect("fixed-size slice"),
    );
    *cursor = end;
    Ok(value)
}

fn take_bytes<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    length: usize,
) -> Result<&'a [u8], LegacyHeaderError> {
    let end = cursor
        .checked_add(length)
        .ok_or(LegacyHeaderError::Truncated)?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(LegacyHeaderError::Truncated)?;
    *cursor = end;
    Ok(value)
}

/// A legacy SnapContext is valid only when the IDs are strictly descending
/// (newest first), the sequence is not below the newest listed ID, and every
/// ID is below `NOSNAP`.
fn validate_snap_context(
    snap_seq: u64,
    snapshots: &[LegacySnapshot],
) -> Result<(), LegacyHeaderError> {
    if snap_seq >= opwire::NOSNAP {
        return Err(LegacyHeaderError::InvalidSnapContext);
    }
    for pair in snapshots.windows(2) {
        if pair[0].id <= pair[1].id {
            return Err(LegacyHeaderError::InvalidSnapContext);
        }
    }
    if snapshots
        .first()
        .is_some_and(|newest| snap_seq < newest.id || newest.id >= opwire::NOSNAP)
    {
        return Err(LegacyHeaderError::InvalidSnapContext);
    }
    Ok(())
}

impl LegacyHeader {
    /// Decode the 112-byte fixed header and its trailing snapshot arrays.
    ///
    /// The ordinary magic (`RBD_HEADER_TEXT`) is accepted; the migration marker
    /// is reported as [`LegacyHeaderError::Migration`] and anything else is
    /// [`LegacyHeaderError::BadMagic`]. An object shorter than the fixed header
    /// or shorter than its declared variable portion is
    /// [`LegacyHeaderError::Truncated`]; names must be NUL-terminated inside
    /// `snap_names_len` and the Snapshot IDs must form a valid SnapContext.
    pub fn decode(bytes: &[u8]) -> Result<Self, LegacyHeaderError> {
        if bytes.len() < LEGACY_HEADER_FIXED_BYTES {
            return Err(LegacyHeaderError::Truncated);
        }
        let magic = &bytes[..RBD_HEADER_TEXT.len()];
        if magic == RBD_HEADER_TEXT {
            // ordinary format-1 image
        } else if magic == RBD_MIGRATE_HEADER_TEXT {
            return Err(LegacyHeaderError::Migration);
        } else {
            return Err(LegacyHeaderError::BadMagic);
        }
        let order = bytes[76];
        let image_size = u64::from_le_bytes(bytes[80..88].try_into().expect("fixed-size slice"));
        let snap_seq = u64::from_le_bytes(bytes[88..96].try_into().expect("fixed-size slice"));
        let snap_count =
            u32::from_le_bytes(bytes[96..100].try_into().expect("fixed-size slice")) as usize;
        let names_len = u64::from_le_bytes(bytes[104..112].try_into().expect("fixed-size slice"));
        let names_len = usize::try_from(names_len).map_err(|_| LegacyHeaderError::Truncated)?;
        let block_prefix = bytes[40..64]
            .split(|byte| *byte == 0)
            .next()
            .unwrap_or_default()
            .to_vec();

        let records_bytes = snap_count
            .checked_mul(16)
            .ok_or(LegacyHeaderError::InconsistentSnapshots)?;
        let required = LEGACY_HEADER_FIXED_BYTES
            .checked_add(records_bytes)
            .and_then(|total| total.checked_add(names_len))
            .ok_or(LegacyHeaderError::InconsistentSnapshots)?;
        if bytes.len() < required {
            return Err(LegacyHeaderError::Truncated);
        }

        let mut snapshots = Vec::with_capacity(snap_count);
        for index in 0..snap_count {
            let offset = LEGACY_HEADER_FIXED_BYTES + 16 * index;
            let id = u64::from_le_bytes(
                bytes[offset..offset + 8]
                    .try_into()
                    .expect("fixed-size slice"),
            );
            let image_size = u64::from_le_bytes(
                bytes[offset + 8..offset + 16]
                    .try_into()
                    .expect("fixed-size slice"),
            );
            snapshots.push(LegacySnapshot {
                id,
                image_size,
                name: Vec::new(),
            });
        }

        // The names block is a run of NUL-terminated strings, one per record.
        let names = &bytes[LEGACY_HEADER_FIXED_BYTES + records_bytes..required];
        let mut start = 0usize;
        for snapshot in &mut snapshots {
            let Some(relative) = names[start..].iter().position(|byte| *byte == 0) else {
                return Err(LegacyHeaderError::InconsistentSnapshots);
            };
            snapshot.name = names[start..start + relative].to_vec();
            start += relative + 1;
        }
        // Every byte must belong to a NUL-terminated name: a trailing
        // unterminated name or surplus data fails here.
        if start != names.len() {
            return Err(LegacyHeaderError::InconsistentSnapshots);
        }

        validate_snap_context(snap_seq, &snapshots)?;
        Ok(Self {
            order,
            image_size,
            block_prefix,
            snap_seq,
            snapshots,
        })
    }
}

/// Decode a `rbd.snap_list` class reply into a write SnapContext and the USER
/// snapshots it describes. The reply is `u64 snap_seq, u32 snap_count`, then
/// per snapshot `{u64 id, u64 image_size, string name}` (denc string: a
/// little-endian u32 length followed by the bytes). An invalid SnapContext or
/// a truncated reply is an error.
pub fn decode_legacy_snap_list(
    reply: &[u8],
) -> Result<(ImageSnapContext, Vec<LegacySnapshot>), LegacyHeaderError> {
    let mut cursor = 0usize;
    let snap_seq = take_u64(reply, &mut cursor)?;
    let snap_count = take_u32(reply, &mut cursor)? as usize;
    let mut snapshots = Vec::with_capacity(snap_count.min(reply.len() / 20)); // >= 20 bytes per record
    for _ in 0..snap_count {
        let id = take_u64(reply, &mut cursor)?;
        let image_size = take_u64(reply, &mut cursor)?;
        let name_length = take_u32(reply, &mut cursor)? as usize;
        let name = take_bytes(reply, &mut cursor, name_length)?.to_vec();
        snapshots.push(LegacySnapshot {
            id,
            image_size,
            name,
        });
    }
    if cursor != reply.len() {
        return Err(LegacyHeaderError::Truncated);
    }
    validate_snap_context(snap_seq, &snapshots)?;
    let ids = snapshots.iter().map(|snapshot| snapshot.id).collect();
    Ok((
        ImageSnapContext {
            sequence: snap_seq,
            ids,
        },
        snapshots,
    ))
}

/// One `rbd_directory` tmap entry: the image name (the key) and its value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegacyDirectoryEntry {
    /// Image name; a nonempty key without NUL bytes.
    pub name: Vec<u8>,
    /// Stored value. librbd always writes an empty value.
    pub value: Vec<u8>,
}

/// Why `rbd_directory` data or a TMAPUP command stream cannot be decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LegacyDirectoryError {
    /// A length prefix or payload runs past the input (`-EIO`).
    Truncated,
    /// The bytes are not a valid map or command stream (`-EIO`), including an
    /// image name that is empty or holds a NUL byte.
    Malformed,
    /// A `'r'` command names a key that is not in the map (`-ENOENT`).
    NotFound,
}

impl std::fmt::Display for LegacyDirectoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => f.write_str("truncated RBD format-1 directory payload"),
            Self::Malformed => f.write_str("malformed RBD format-1 directory payload"),
            Self::NotFound => f.write_str("RBD format-1 directory key is absent"),
        }
    }
}

impl std::error::Error for LegacyDirectoryError {}

fn directory_string<'a>(input: &mut &'a [u8]) -> Result<&'a [u8], LegacyDirectoryError> {
    let length = u32::from_le_bytes(
        input
            .get(..4)
            .ok_or(LegacyDirectoryError::Truncated)?
            .try_into()
            .expect("fixed-size slice"),
    ) as usize;
    let rest = input.get(4..).ok_or(LegacyDirectoryError::Truncated)?;
    let value = rest.get(..length).ok_or(LegacyDirectoryError::Truncated)?;
    *input = &rest[length..];
    Ok(value)
}

fn validate_directory_name(name: &[u8]) -> Result<(), LegacyDirectoryError> {
    if name.is_empty() || name.contains(&0) {
        Err(LegacyDirectoryError::Malformed)
    } else {
        Ok(())
    }
}

/// Decode the map header and its entries; the header is preserved verbatim by
/// a TMAP update that carries no `'h'` command.
fn decode_directory_map(
    data: &[u8],
) -> Result<(&[u8], Vec<LegacyDirectoryEntry>), LegacyDirectoryError> {
    if data.is_empty() {
        return Ok((&[], Vec::new()));
    }
    let mut input = data;
    let header = directory_string(&mut input)?;
    let count = u32::from_le_bytes(
        input
            .get(..4)
            .ok_or(LegacyDirectoryError::Truncated)?
            .try_into()
            .expect("fixed-size slice"),
    ) as usize;
    input = &input[4..];
    // Every pair needs at least its two length prefixes.
    if count > input.len() / 8 {
        return Err(LegacyDirectoryError::Truncated);
    }
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let name = directory_string(&mut input)?;
        let value = directory_string(&mut input)?;
        validate_directory_name(name)?;
        entries.push(LegacyDirectoryEntry {
            name: name.to_vec(),
            value: value.to_vec(),
        });
    }
    Ok((header, entries))
}

/// Decode the data bytes of `rbd_directory`: `bufferlist header` (u32 length
/// plus bytes), `u32 count`, then `count` x (`string` key, `bufferlist`
/// value), keys ascending. Empty data holds no format-1 images; bytes after
/// the map are ignored. Image names must be nonempty and free of NUL bytes.
pub fn decode_legacy_directory(
    data: &[u8],
) -> Result<Vec<LegacyDirectoryEntry>, LegacyDirectoryError> {
    decode_directory_map(data).map(|(_, entries)| entries)
}

fn push_directory_string(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), LegacyDirectoryError> {
    let length = u32::try_from(bytes.len()).map_err(|_| LegacyDirectoryError::Malformed)?;
    out.extend_from_slice(&length.to_le_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn push_command_op(out: &mut Vec<u8>, op: u8, name: &[u8]) -> Result<(), LegacyDirectoryError> {
    validate_directory_name(name)?;
    out.push(op);
    push_directory_string(out, name)
}

/// The TMAPUP command that inserts `name` with an empty value: `'s' name
/// <empty value>`, the stream `create` sends.
pub fn encode_tmap_set(name: &[u8]) -> Result<Vec<u8>, LegacyDirectoryError> {
    let mut out = Vec::new();
    push_command_op(&mut out, b's', name)?;
    push_directory_string(&mut out, &[])?;
    Ok(out)
}

/// The TMAPUP command that removes `name`: `'r' name`, the stream `remove`
/// and a create rollback send.
pub fn encode_tmap_remove(name: &[u8]) -> Result<Vec<u8>, LegacyDirectoryError> {
    let mut out = Vec::new();
    push_command_op(&mut out, b'r', name)?;
    Ok(out)
}

/// The two-command TMAPUP stream `rename` sends in one atomic op: `'s' set`
/// then `'r' remove`.
pub fn encode_tmap_set_and_remove(
    set: &[u8],
    remove: &[u8],
) -> Result<Vec<u8>, LegacyDirectoryError> {
    let mut out = encode_tmap_set(set)?;
    out.extend_from_slice(&encode_tmap_remove(remove)?);
    Ok(out)
}

fn encode_legacy_directory(
    header: &[u8],
    entries: &[LegacyDirectoryEntry],
) -> Result<Vec<u8>, LegacyDirectoryError> {
    let mut out = Vec::new();
    push_directory_string(&mut out, header)?;
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for entry in entries {
        push_directory_string(&mut out, &entry.name)?;
        push_directory_string(&mut out, &entry.value)?;
    }
    Ok(out)
}

/// Apply one TMAPUP command stream to the current `rbd_directory` data bytes
/// with the OSD's semantics: read the whole object (absent object = empty),
/// apply every command in order, then write the result back as one sorted
/// map. The op is atomic per object, so an error leaves the input unchanged:
/// `'s'` inserts or replaces, `'r'` of an absent key fails with
/// [`LegacyDirectoryError::NotFound`], `'R'` ignores absence and an optional
/// leading `'h'` replaces the header. librbd never sends `'c'`; it is
/// rejected as [`LegacyDirectoryError::Malformed`]. This is the reference
/// model the fake provider applies, and the semantics a TMAPUP
/// implementation of our own OSD would have to match.
pub fn apply_tmap_commands(data: &[u8], commands: &[u8]) -> Result<Vec<u8>, LegacyDirectoryError> {
    let (mut header, mut entries) = decode_directory_map(data)?;
    let mut input = commands;
    if input.first() == Some(&b'h') {
        input = &input[1..];
        header = directory_string(&mut input)?;
    }
    while let Some((&op, rest)) = input.split_first() {
        input = rest;
        match op {
            b's' | b'r' | b'R' => {
                let name = directory_string(&mut input)?;
                validate_directory_name(name)?;
                if op == b's' {
                    let value = directory_string(&mut input)?;
                    match entries.iter_mut().find(|entry| entry.name == name) {
                        Some(entry) => entry.value = value.to_vec(),
                        None => entries.push(LegacyDirectoryEntry {
                            name: name.to_vec(),
                            value: value.to_vec(),
                        }),
                    }
                } else {
                    let Some(index) = entries.iter().position(|entry| entry.name == name) else {
                        if op == b'R' {
                            continue;
                        }
                        return Err(LegacyDirectoryError::NotFound);
                    };
                    entries.remove(index);
                }
            }
            _ => return Err(LegacyDirectoryError::Malformed),
        }
    }
    entries.sort_by(|left, right| left.name.cmp(&right.name));
    encode_legacy_directory(header, &entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header_bytes(
        order: u8,
        image_size: u64,
        snap_seq: u64,
        snapshots: &[(&[u8], u64, u64)],
    ) -> Vec<u8> {
        let mut bytes = vec![0u8; LEGACY_HEADER_FIXED_BYTES];
        bytes[..34].copy_from_slice(RBD_HEADER_TEXT);
        bytes[40..40 + 8].copy_from_slice(b"rb.1.1.1");
        bytes[76] = order;
        bytes[80..88].copy_from_slice(&image_size.to_le_bytes());
        bytes[88..96].copy_from_slice(&snap_seq.to_le_bytes());
        bytes[96..100].copy_from_slice(&(snapshots.len() as u32).to_le_bytes());
        let names_len: usize = snapshots.iter().map(|(name, _, _)| name.len() + 1).sum();
        bytes[104..112].copy_from_slice(&(names_len as u64).to_le_bytes());
        for (_name, id, size) in snapshots {
            let record = [id.to_le_bytes().as_slice(), size.to_le_bytes().as_slice()].concat();
            bytes.extend_from_slice(&record);
        }
        for (name, _, _) in snapshots {
            bytes.extend_from_slice(name);
            bytes.push(0);
        }
        bytes
    }

    fn snap_list_reply(snap_seq: u64, snapshots: &[(&[u8], u64, u64)]) -> Vec<u8> {
        let mut reply = Vec::new();
        reply.extend_from_slice(&snap_seq.to_le_bytes());
        reply.extend_from_slice(&(snapshots.len() as u32).to_le_bytes());
        for (name, id, size) in snapshots {
            reply.extend_from_slice(&id.to_le_bytes());
            reply.extend_from_slice(&size.to_le_bytes());
            reply.extend_from_slice(&(name.len() as u32).to_le_bytes());
            reply.extend_from_slice(name);
        }
        reply
    }

    #[test]
    fn magic_constants_are_34_bytes_and_distinct() {
        assert_eq!(RBD_HEADER_TEXT.len(), 34);
        assert_eq!(RBD_MIGRATE_HEADER_TEXT.len(), 34);
        assert_ne!(RBD_HEADER_TEXT, RBD_MIGRATE_HEADER_TEXT);
        assert!(RBD_HEADER_TEXT.ends_with(b"\n\0"));
        assert!(RBD_MIGRATE_HEADER_TEXT.ends_with(b"\n\0"));
    }

    #[test]
    fn decodes_fixed_header_and_snapshot_arrays() {
        for snapshots in [
            Vec::<(&[u8], u64, u64)>::new(),
            vec![(b"s1".as_slice(), 3u64, 1000u64)],
            vec![
                (b"newest".as_slice(), 9u64, 4096u64),
                (b"middle".as_slice(), 5u64, 2048u64),
                (b"oldest".as_slice(), 1u64, 1024u64),
            ],
        ] {
            let snap_seq = snapshots.first().map_or(0, |(_, id, _)| *id);
            let bytes = header_bytes(22, 8192, snap_seq, &snapshots);
            let header = LegacyHeader::decode(&bytes).unwrap();
            assert_eq!(header.order, 22);
            assert_eq!(header.image_size, 8192);
            assert_eq!(header.block_prefix, b"rb.1.1.1");
            assert_eq!(header.snap_seq, snap_seq);
            assert_eq!(header.snapshots.len(), snapshots.len());
            for (decoded, (name, id, size)) in header.snapshots.iter().zip(&snapshots) {
                assert_eq!(decoded.name, *name);
                assert_eq!(decoded.id, *id);
                assert_eq!(decoded.image_size, *size);
            }
        }
    }

    #[test]
    fn truncation_at_every_offset_is_rejected() {
        let snapshots = [(b"s1".as_slice(), 3u64, 1000u64)];
        let full = header_bytes(22, 8192, 3, &snapshots);
        for end in 0..full.len() {
            assert_eq!(
                LegacyHeader::decode(&full[..end]),
                Err(LegacyHeaderError::Truncated)
            );
        }
        assert!(LegacyHeader::decode(&full).is_ok());
    }

    #[test]
    fn wrong_magic_and_migration_marker_are_distinguished() {
        let bytes = header_bytes(22, 8192, 0, &[]);
        let mut wrong = bytes.clone();
        wrong[0] = b'X';
        assert_eq!(
            LegacyHeader::decode(&wrong),
            Err(LegacyHeaderError::BadMagic)
        );
        let mut migrate = bytes;
        migrate[..34].copy_from_slice(RBD_MIGRATE_HEADER_TEXT);
        assert_eq!(
            LegacyHeader::decode(&migrate),
            Err(LegacyHeaderError::Migration)
        );
    }

    #[test]
    fn inconsistent_name_length_and_invalid_context_are_rejected() {
        // A name block that does not end on a record boundary.
        let snapshots = [(b"s1".as_slice(), 3u64, 1000u64)];
        let mut bytes = header_bytes(22, 8192, 3, &snapshots);
        let declared = u64::from_le_bytes(bytes[104..112].try_into().unwrap());
        bytes[104..112].copy_from_slice(&(declared + 1).to_le_bytes());
        bytes.push(0);
        assert_eq!(
            LegacyHeader::decode(&bytes),
            Err(LegacyHeaderError::InconsistentSnapshots)
        );

        // Snap sequence below the newest listed ID.
        let bytes = header_bytes(22, 8192, 2, &snapshots);
        assert_eq!(
            LegacyHeader::decode(&bytes),
            Err(LegacyHeaderError::InvalidSnapContext)
        );

        // Non-descending snapshot IDs.
        let bad = [(b"a".as_slice(), 1u64, 1u64), (b"b".as_slice(), 2u64, 2u64)];
        let bytes = header_bytes(22, 8192, 2, &bad);
        assert_eq!(
            LegacyHeader::decode(&bytes),
            Err(LegacyHeaderError::InvalidSnapContext)
        );
    }

    #[test]
    fn snap_list_reply_decodes_into_context_and_user_snapshots() {
        let snapshots = [
            (b"newest".as_slice(), 9u64, 4096u64),
            (b"middle".as_slice(), 5u64, 2048u64),
        ];
        let reply = snap_list_reply(9, &snapshots);
        let (context, decoded) = decode_legacy_snap_list(&reply).unwrap();
        assert_eq!(context.sequence, 9);
        assert_eq!(context.ids, vec![9, 5]);
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].name, b"newest");
        assert_eq!(decoded[0].image_size, 4096);
        let info = decoded[0].as_snapshot_info();
        assert_eq!(info.namespace, SnapshotNamespace::User);
        assert_eq!(info.timestamp_seconds, 0);
        assert_eq!(info.child_count, 0);
    }

    #[test]
    fn snap_list_reply_rejects_truncation_and_bad_context() {
        let snapshots = [(b"newest".as_slice(), 9u64, 4096u64)];
        let reply = snap_list_reply(9, &snapshots);
        for end in 0..reply.len() {
            assert!(matches!(
                decode_legacy_snap_list(&reply[..end]),
                Err(LegacyHeaderError::Truncated | LegacyHeaderError::InvalidSnapContext)
            ));
        }
        // Sequence below the newest ID.
        let reply = snap_list_reply(4, &snapshots);
        assert_eq!(
            decode_legacy_snap_list(&reply),
            Err(LegacyHeaderError::InvalidSnapContext)
        );
        // Trailing bytes after the declared list.
        let mut trailing = snap_list_reply(9, &snapshots);
        trailing.push(0);
        assert_eq!(
            decode_legacy_snap_list(&trailing),
            Err(LegacyHeaderError::Truncated)
        );
    }

    #[test]
    fn new_image_header_has_the_pinned_golden_bytes() {
        const SIZE: u64 = 3 * 4 * 1024 * 1024;
        let header = build_legacy_header(22, SIZE, b"rb.1.2.3");
        let mut expected = vec![0u8; LEGACY_HEADER_FIXED_BYTES];
        expected[..34].copy_from_slice(b"<<< Rados Block Device Image >>>\n\0");
        expected[40..48].copy_from_slice(b"rb.1.2.3");
        expected[64..68].copy_from_slice(b"RBD\0");
        expected[68..76].copy_from_slice(b"001.005\0");
        expected[76] = 22;
        expected[80..88].copy_from_slice(&SIZE.to_le_bytes());
        assert_eq!(header.as_slice(), expected.as_slice());

        // The builder and the read codec agree on every field.
        let decoded = LegacyHeader::decode(&header).unwrap();
        assert_eq!(decoded.order, 22);
        assert_eq!(decoded.image_size, SIZE);
        assert_eq!(decoded.block_prefix, b"rb.1.2.3");
        assert_eq!(decoded.snap_seq, 0);
        assert!(decoded.snapshots.is_empty());
    }

    #[test]
    fn block_prefix_is_lowercase_hex_and_truncates_at_23_bytes() {
        assert_eq!(legacy_block_prefix(1, 2, 3), b"rb.1.2.3");
        assert_eq!(
            legacy_block_prefix(0xdead_beef, 0x1, 0x2),
            b"rb.deadbeef.1.2"
        );
        // `rb.ffffffff.ffffffff.fffd` is 26 bytes: only 23 are stored, so the
        // header field keeps its NUL terminator.
        assert_eq!(
            legacy_block_prefix(0xffff_ffff, 0xffff_ffff, 0xfffd),
            b"rb.ffffffff.ffffffff.ff"
        );
        assert_eq!(
            legacy_block_prefix(0xffff_ffff, 0xffff_ffff, 0xfffd).len(),
            LEGACY_BLOCK_PREFIX_MAX
        );
        let header = build_legacy_header(
            22,
            0,
            &legacy_block_prefix(0xffff_ffff, 0xffff_ffff, 0xfffd),
        );
        assert_eq!(&header[40..64], b"rb.ffffffff.ffffffff.ff\0");
        assert_eq!(
            LegacyHeader::decode(&header).unwrap().block_prefix,
            b"rb.ffffffff.ffffffff.ff"
        );
    }

    #[test]
    fn resize_patches_only_the_image_size_field() {
        let before = build_legacy_header(22, 4096, b"rb.1.2.3");
        let mut after = before;
        set_legacy_image_size(&mut after, 3 * 4 * 1024 * 1024);
        assert_eq!(&after[..80], &before[..80]);
        assert_eq!(&after[88..], &before[88..]);
        assert_eq!(
            u64::from_le_bytes(after[80..88].try_into().unwrap()),
            3 * 4 * 1024 * 1024
        );
        assert_eq!(
            LegacyHeader::decode(&after).unwrap().image_size,
            3 * 4 * 1024 * 1024
        );
    }

    fn directory_data(header: &[u8], entries: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(header.len() as u32).to_le_bytes());
        out.extend_from_slice(header);
        out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
        for (name, value) in entries {
            out.extend_from_slice(&(name.len() as u32).to_le_bytes());
            out.extend_from_slice(name);
            out.extend_from_slice(&(value.len() as u32).to_le_bytes());
            out.extend_from_slice(value);
        }
        out
    }

    fn directory_names(data: &[u8]) -> Vec<Vec<u8>> {
        decode_legacy_directory(data)
            .unwrap()
            .into_iter()
            .map(|entry| entry.name)
            .collect()
    }

    #[test]
    fn directory_decodes_names_and_values_and_ignores_trailing_bytes() {
        assert_eq!(decode_legacy_directory(&[]), Ok(Vec::new()));
        let mut data = directory_data(b"hdr", &[(b"alpha", b""), (b"beta", b"v")]);
        data.extend_from_slice(b"trailing");
        assert_eq!(
            decode_legacy_directory(&data),
            Ok(vec![
                LegacyDirectoryEntry {
                    name: b"alpha".to_vec(),
                    value: Vec::new(),
                },
                LegacyDirectoryEntry {
                    name: b"beta".to_vec(),
                    value: b"v".to_vec(),
                },
            ])
        );
    }

    #[test]
    fn directory_rejects_malformed_maps() {
        let good = directory_data(b"h", &[(b"alpha", b"")]);
        for cut in 1..good.len() {
            assert_eq!(
                decode_legacy_directory(&good[..cut]),
                Err(LegacyDirectoryError::Truncated),
                "cut {cut}"
            );
        }
        assert_eq!(
            decode_legacy_directory(&directory_data(b"", &[(b"", b"")])),
            Err(LegacyDirectoryError::Malformed)
        );
        assert_eq!(
            decode_legacy_directory(&directory_data(b"", &[(b"a\0b", b"")])),
            Err(LegacyDirectoryError::Malformed)
        );
        let mut huge = directory_data(b"", &[]);
        huge[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            decode_legacy_directory(&huge),
            Err(LegacyDirectoryError::Truncated)
        );
    }

    #[test]
    fn tmap_commands_match_the_three_librbd_streams() {
        // create: 's' name <empty value>
        assert_eq!(
            encode_tmap_set(b"img").unwrap(),
            [b's', 3, 0, 0, 0, b'i', b'm', b'g', 0, 0, 0, 0]
        );
        // remove / create rollback: 'r' name
        assert_eq!(
            encode_tmap_remove(b"img").unwrap(),
            [b'r', 3, 0, 0, 0, b'i', b'm', b'g']
        );
        // rename: 's' dst <empty>, 'r' src in one stream
        let mut rename = encode_tmap_set(b"dst").unwrap();
        rename.extend_from_slice(&encode_tmap_remove(b"src").unwrap());
        assert_eq!(encode_tmap_set_and_remove(b"dst", b"src").unwrap(), rename);
        assert_eq!(rename[0], b's');
        assert_eq!(rename[12], b'r');
        // An empty name is not a valid directory key.
        assert_eq!(encode_tmap_set(b""), Err(LegacyDirectoryError::Malformed));
    }

    #[test]
    fn tmap_set_creates_an_absent_object_and_is_atomic_on_remove_miss() {
        let set = encode_tmap_set(b"first").unwrap();
        let data = apply_tmap_commands(&[], &set).unwrap();
        assert_eq!(directory_names(&data), vec![b"first".to_vec()]);
        // A second SET replaces the value in place.
        let set_value = [&[b's', 5, 0, 0, 0][..], b"first", &[2, 0, 0, 0], b"v2"].concat();
        let replaced = apply_tmap_commands(&data, &set_value).unwrap();
        assert_eq!(
            decode_legacy_directory(&replaced).unwrap(),
            vec![LegacyDirectoryEntry {
                name: b"first".to_vec(),
                value: b"v2".to_vec(),
            }]
        );

        // RM of an absent key fails the whole op and writes nothing.
        let missing = encode_tmap_remove(b"absent").unwrap();
        assert_eq!(
            apply_tmap_commands(&data, &missing),
            Err(LegacyDirectoryError::NotFound)
        );
        // The same stream with a SET first is still atomic: the SET is lost.
        let mixed = [
            encode_tmap_set(b"second").unwrap(),
            encode_tmap_remove(b"absent").unwrap(),
        ]
        .concat();
        assert_eq!(
            apply_tmap_commands(&data, &mixed),
            Err(LegacyDirectoryError::NotFound)
        );
        // RMSLOPPY ignores the absent key.
        let sloppy = [&[b'R', 6, 0, 0, 0][..], b"absent"].concat();
        assert_eq!(apply_tmap_commands(&data, &sloppy).unwrap(), data);
    }

    #[test]
    fn tmap_set_and_remove_sort_identically_in_both_orders() {
        // dst before src in byte order and after it must both end up sorted,
        // with only the destination left.
        for (dst, src) in [("alpha", "zeta"), ("zeta", "alpha")] {
            let existing = directory_data(b"", &[(src.as_bytes(), b""), (b"middle", b"")]);
            let renamed = apply_tmap_commands(
                &existing,
                &encode_tmap_set_and_remove(dst.as_bytes(), src.as_bytes()).unwrap(),
            )
            .unwrap();
            // The destination is inserted and the source removed; the stored
            // map is always rewritten in ascending key order.
            let mut expected = vec![dst.as_bytes().to_vec(), b"middle".to_vec()];
            expected.sort();
            assert_eq!(directory_names(&renamed), expected, "rename {src} -> {dst}");
            let pairs: Vec<(&[u8], &[u8])> =
                expected.iter().map(|name| (&name[..], &[][..])).collect();
            assert_eq!(renamed, directory_data(b"", &pairs));
        }
    }

    #[test]
    fn tmap_replaces_the_header_only_when_a_header_command_is_present() {
        let data = directory_data(b"old", &[(b"img", b"")]);
        let set = encode_tmap_set(b"img").unwrap();
        let kept = apply_tmap_commands(&data, &set).unwrap();
        assert_eq!(kept, directory_data(b"old", &[(b"img", b"")]));
        let header = [&[b'h', 3, 0, 0, 0][..], b"new", &set].concat();
        let replaced = apply_tmap_commands(&data, &header).unwrap();
        assert_eq!(replaced, directory_data(b"new", &[(b"img", b"")]));
    }

    #[test]
    fn tmap_rejects_unknown_commands_and_create() {
        assert_eq!(
            apply_tmap_commands(&[], b"x"),
            Err(LegacyDirectoryError::Malformed)
        );
        // librbd never sends CREATE; the model does not implement it.
        assert_eq!(
            apply_tmap_commands(&[], &[b'c', 1, 0, 0, 0, b'a', 0, 0, 0, 0]),
            Err(LegacyDirectoryError::Malformed)
        );
        // A command without its key is a truncated stream.
        assert_eq!(
            apply_tmap_commands(&[], b"s"),
            Err(LegacyDirectoryError::Truncated)
        );
    }
}
