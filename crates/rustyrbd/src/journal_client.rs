// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Image-client metadata and committed positions stored by cls_journal.
//!
//! Wire forms per `doc/spec/cls_journal.md` section 2: `ObjectPosition`
//! (version 1, 24-byte body), `ObjectSetPosition` (version 1 frame of
//! positions, most-recent first), `Client` (version 1: id, ClientData
//! bufferlist, ObjectSetPosition, state), `ClientData` (version 2: image
//! variant 0 or mirror-peer variant 1), `Tag` (version 1: tid, tag class,
//! data), and the `set<Client>` / `set<Tag>` counts. `TagData` is an
//! unenveloped owner string plus predecessor record.

use denc::{Decoder, Error, Result};

use crate::SnapshotNamespace;

/// `Client.state` values stored by cls_journal.
pub const JOURNAL_CLIENT_STATE_CONNECTED: u8 = 0;
pub const JOURNAL_CLIENT_STATE_DISCONNECTED: u8 = 1;

/// One position in a journal data-object stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JournalObjectPosition {
    pub object_number: u64,
    pub tag_tid: u64,
    pub entry_tid: u64,
}

/// Encode one versioned `ObjectPosition` frame (version 1, 24-byte body).
pub fn encode_object_position(position: JournalObjectPosition, out: &mut Vec<u8>) {
    out.push(1);
    out.push(1);
    out.extend_from_slice(&24u32.to_le_bytes());
    out.extend_from_slice(&position.object_number.to_le_bytes());
    out.extend_from_slice(&position.tag_tid.to_le_bytes());
    out.extend_from_slice(&position.entry_tid.to_le_bytes());
}

fn decode_object_position_frame(decoder: &mut Decoder<'_>) -> Result<JournalObjectPosition> {
    decoder.versioned_min(1, 1, |body, _| {
        if body.remaining() != 24 {
            return Err(Error::BadValue("journal position body"));
        }
        Ok(JournalObjectPosition {
            object_number: body.u64()?,
            tag_tid: body.u64()?,
            entry_tid: body.u64()?,
        })
    })
}

/// Decode one standalone versioned `ObjectPosition`; the input must be
/// exactly one frame.
pub fn decode_object_position(input: &[u8]) -> Result<JournalObjectPosition> {
    let mut decoder = Decoder::new(input);
    let position = decode_object_position_frame(&mut decoder)?;
    if !decoder.is_empty() {
        return Err(Error::TrailingBytes(decoder.remaining()));
    }
    Ok(position)
}

/// Encode an `ObjectSetPosition`: a version 1 frame listing the positions
/// most-recent first.
pub fn encode_positions(positions: &[JournalObjectPosition]) -> Result<Vec<u8>> {
    let count = u32::try_from(positions.len()).map_err(|_| Error::TooLong)?;
    let body_len = count
        .checked_mul(30)
        .and_then(|len| len.checked_add(4))
        .ok_or(Error::TooLong)?;
    let mut out = Vec::with_capacity(6 + body_len as usize);
    out.push(1);
    out.push(1);
    out.extend_from_slice(&body_len.to_le_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    for position in positions {
        encode_object_position(*position, &mut out);
    }
    Ok(out)
}

fn decode_positions_frame(decoder: &mut Decoder<'_>) -> Result<Vec<JournalObjectPosition>> {
    decoder.versioned_min(1, 1, |body, _| {
        let count = body.count()?;
        if count > body.remaining() / 30 {
            return Err(Error::BadLength {
                len: count as u64,
                remaining: body.remaining() / 30,
            });
        }
        let mut positions = Vec::new();
        positions
            .try_reserve_exact(count)
            .map_err(|_| Error::NoSpace)?;
        for _ in 0..count {
            positions.push(decode_object_position_frame(body)?);
        }
        Ok(positions)
    })
}

/// Decode an `ObjectSetPosition`; the input must be exactly one frame.
pub fn decode_positions(input: &[u8]) -> Result<Vec<JournalObjectPosition>> {
    let mut decoder = Decoder::new(input);
    let positions = decode_positions_frame(&mut decoder)?;
    if !decoder.is_empty() {
        return Err(Error::TrailingBytes(decoder.remaining()));
    }
    Ok(positions)
}

/// The image-variant fields of a journal `ClientData`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JournalImageData {
    /// The tag class of this image's journal tags.
    pub tag_class: u64,
    /// A mirror resync was requested for this client.
    pub resync_requested: bool,
}

/// Encode the image `ClientData` (version 2/compat 1, IMAGE variant).
pub fn encode_image_client_data(tag_class: u64, resync_requested: bool) -> Vec<u8> {
    let mut body = Vec::with_capacity(13);
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&tag_class.to_le_bytes());
    body.push(u8::from(resync_requested));
    let mut out = Vec::with_capacity(6 + body.len());
    out.push(2);
    out.push(1);
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&body);
    out
}

/// Decode the image `ClientData`; a different variant is malformed.
pub fn decode_image_client_data(input: &[u8]) -> Result<JournalImageData> {
    let mut decoder = Decoder::new(input);
    let image = decoder.versioned_min(2, 1, |body, _| {
        if body.u32()? != 0 {
            return Err(Error::BadValue("journal client metadata type"));
        }
        Ok(JournalImageData {
            tag_class: body.u64()?,
            resync_requested: body.bool()?,
        })
    })?;
    if !decoder.is_empty() {
        return Err(Error::TrailingBytes(decoder.remaining()));
    }
    Ok(image)
}

/// The predecessor record carried by a journal `TagData`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalTagPredecessor {
    /// The predecessor's owner mirror UUID.
    pub mirror_uuid: Vec<u8>,
    /// Whether the predecessor's commit point is valid.
    pub commit_valid: bool,
    pub tag_tid: u64,
    pub entry_tid: u64,
}

/// A decoded journal `TagData`: the tag owner plus its predecessor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalTagData {
    /// The tag owner's mirror UUID; the empty string is the local owner.
    pub owner: Vec<u8>,
    pub predecessor: JournalTagPredecessor,
}

/// Encode a `TagData`: owner string, then the predecessor record (string,
/// bool, u64, u64). The payload has no version envelope.
pub fn encode_tag_data(owner: &[u8], predecessor: &JournalTagPredecessor) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(25 + owner.len() + predecessor.mirror_uuid.len());
    append_string(&mut out, owner)?;
    append_string(&mut out, &predecessor.mirror_uuid)?;
    out.push(u8::from(predecessor.commit_valid));
    out.extend_from_slice(&predecessor.tag_tid.to_le_bytes());
    out.extend_from_slice(&predecessor.entry_tid.to_le_bytes());
    Ok(out)
}

/// Decode a `TagData`.
pub fn decode_tag_data(input: &[u8]) -> Result<JournalTagData> {
    let mut decoder = Decoder::new(input);
    let owner = decoder.bytes()?.to_vec();
    let mirror_uuid = decoder.bytes()?.to_vec();
    let commit_valid = decoder.bool()?;
    let tag_tid = decoder.u64()?;
    let entry_tid = decoder.u64()?;
    if !decoder.is_empty() {
        return Err(Error::TrailingBytes(decoder.remaining()));
    }
    Ok(JournalTagData {
        owner,
        predecessor: JournalTagPredecessor {
            mirror_uuid,
            commit_valid,
            tag_tid,
            entry_tid,
        },
    })
}

/// A decoded journal `Tag` record; `data` borrows the input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalTag<'a> {
    pub tid: u64,
    pub tag_class: u64,
    /// The raw TagData payload.
    pub data: &'a [u8],
}

fn decode_journal_tag_frame<'a>(decoder: &mut Decoder<'a>) -> Result<JournalTag<'a>> {
    decoder.versioned(u8::MAX, |body, version| {
        if version != 1 {
            return Err(Error::BadValue("journal tag version"));
        }
        Ok(JournalTag {
            tid: body.u64()?,
            tag_class: body.u64()?,
            data: body.bytes()?,
        })
    })
}

/// Decode one `Tag`: a version-1 envelope of tid, tag class, and data.
pub fn decode_journal_tag(input: &[u8]) -> Result<JournalTag<'_>> {
    let mut decoder = Decoder::new(input);
    let tag = decode_journal_tag_frame(&mut decoder)?;
    if !decoder.is_empty() {
        return Err(Error::TrailingBytes(decoder.remaining()));
    }
    Ok(tag)
}

/// Decode a `set<Tag>`: a count followed by Tag records in wire order.
pub fn decode_journal_tag_set(input: &[u8]) -> Result<Vec<JournalTag<'_>>> {
    const MAX_WIRE_ENTRIES: usize = 65_536;
    const MIN_TAG_BYTES: usize = 25;
    let mut decoder = Decoder::new(input);
    let count = decoder.u32()? as usize;
    if count > MAX_WIRE_ENTRIES || count > decoder.remaining() / MIN_TAG_BYTES {
        return Err(Error::BadLength {
            len: count as u64,
            remaining: decoder.remaining() / MIN_TAG_BYTES,
        });
    }
    let mut tags = Vec::new();
    tags.try_reserve_exact(count).map_err(|_| Error::NoSpace)?;
    for _ in 0..count {
        tags.push(decode_journal_tag_frame(&mut decoder)?);
    }
    if !decoder.is_empty() {
        return Err(Error::TrailingBytes(decoder.remaining()));
    }
    Ok(tags)
}

/// One mirror-peer sync point.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalSyncPoint<'a> {
    pub name: &'a [u8],
    pub from_snap_name: &'a [u8],
    pub object_number: Option<u64>,
    pub namespace: SnapshotNamespace,
}

/// The decoded `ClientData` payload of a journal client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JournalClientData<'a> {
    /// The local image client (variant 0).
    Image {
        tag_class: u64,
        resync_requested: bool,
    },
    /// A mirror peer client (variant 1).
    MirrorPeer {
        image_id: &'a [u8],
        state: u32,
        sync_object_count: u64,
        sync_points: Vec<JournalSyncPoint<'a>>,
        /// (snapshot id, object number) pairs, strictly increasing by
        /// snapshot id.
        snap_sequences: Vec<(u64, u64)>,
    },
}

/// A decoded journal `Client` record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalClient<'a> {
    pub id: &'a [u8],
    pub data: JournalClientData<'a>,
    /// Ordered most-recent first, as persisted by cls_journal.
    pub commit_positions: Vec<JournalObjectPosition>,
    pub state: u8,
}

/// The cls-level fields of a `Client` record with the ClientData left
/// undecoded: what the trimmer needs, independent of the client variant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalClientFields<'a> {
    pub id: &'a [u8],
    /// Raw ClientData bytes, not decoded.
    pub data: &'a [u8],
    /// Ordered most-recent first, as persisted by cls_journal.
    pub commit_positions: Vec<JournalObjectPosition>,
    pub state: u8,
}

fn decode_client_fields_frame<'a>(decoder: &mut Decoder<'a>) -> Result<JournalClientFields<'a>> {
    let (id, data, commit_positions, state) = decoder.versioned_min(1, 1, |body, _| {
        let id = body.bytes()?;
        let data = body.bytes()?;
        let commit_positions = decode_positions_frame(body)?;
        let state = body.u8()?;
        Ok((id, data, commit_positions, state))
    })?;
    Ok(JournalClientFields {
        id,
        data,
        commit_positions,
        state,
    })
}

fn decode_journal_client_raw(input: &[u8]) -> Result<JournalClientFields<'_>> {
    let mut decoder = Decoder::new(input);
    let raw = decode_client_fields_frame(&mut decoder)?;
    if !decoder.is_empty() {
        return Err(Error::TrailingBytes(decoder.remaining()));
    }
    Ok(raw)
}

fn decode_client_data(input: &[u8]) -> Result<JournalClientData<'_>> {
    let mut decoder = Decoder::new(input);
    let data = decoder.versioned_min(2, 1, |body, _| match body.u32()? {
        0 => Ok(JournalClientData::Image {
            tag_class: body.u64()?,
            resync_requested: body.bool()?,
        }),
        1 => Ok(JournalClientData::MirrorPeer {
            image_id: body.bytes()?,
            state: body.u32()?,
            sync_object_count: body.u64()?,
            sync_points: decode_sync_points(body)?,
            snap_sequences: decode_snap_sequences(body)?,
        }),
        _ => Err(Error::BadValue("journal client metadata type")),
    })?;
    if !decoder.is_empty() {
        return Err(Error::TrailingBytes(decoder.remaining()));
    }
    Ok(data)
}

fn decode_sync_points<'a>(body: &mut Decoder<'a>) -> Result<Vec<JournalSyncPoint<'a>>> {
    const MIN_SYNC_POINT_BYTES: usize = 19;
    let count = body.count()?;
    if count > body.remaining() / MIN_SYNC_POINT_BYTES {
        return Err(Error::BadLength {
            len: count as u64,
            remaining: body.remaining() / MIN_SYNC_POINT_BYTES,
        });
    }
    let mut points = Vec::new();
    points
        .try_reserve_exact(count)
        .map_err(|_| Error::NoSpace)?;
    for _ in 0..count {
        let name = body.bytes()?;
        let from_snap_name = body.bytes()?;
        let object_number = match body.u8()? {
            0 => None,
            1 => Some(body.u64()?),
            _ => return Err(Error::BadValue("journal sync point object number")),
        };
        let namespace = crate::snapshot_query::decode_namespace(body)?;
        points.push(JournalSyncPoint {
            name,
            from_snap_name,
            object_number,
            namespace,
        });
    }
    Ok(points)
}

fn decode_snap_sequences(body: &mut Decoder<'_>) -> Result<Vec<(u64, u64)>> {
    const MIN_SEQUENCE_BYTES: usize = 16;
    let count = body.count()?;
    if count > body.remaining() / MIN_SEQUENCE_BYTES {
        return Err(Error::BadLength {
            len: count as u64,
            remaining: body.remaining() / MIN_SEQUENCE_BYTES,
        });
    }
    let mut sequences = Vec::new();
    sequences
        .try_reserve_exact(count)
        .map_err(|_| Error::NoSpace)?;
    let mut previous = None;
    for _ in 0..count {
        let snapshot_id = body.u64()?;
        let object_number = body.u64()?;
        if previous.is_some_and(|prior| prior >= snapshot_id) {
            return Err(Error::BadValue("journal snap sequence order"));
        }
        previous = Some(snapshot_id);
        sequences.push((snapshot_id, object_number));
    }
    Ok(sequences)
}

fn decode_journal_client_frame<'a>(decoder: &mut Decoder<'a>) -> Result<JournalClient<'a>> {
    let raw = decode_client_fields_frame(decoder)?;
    Ok(JournalClient {
        id: raw.id,
        data: decode_client_data(raw.data)?,
        commit_positions: raw.commit_positions,
        state: raw.state,
    })
}

/// Decode a `Client` record: id, ClientData, commit positions, state.
pub fn decode_journal_client(input: &[u8]) -> Result<JournalClient<'_>> {
    decode_journal_client_frame(&mut Decoder::new(input))
}

/// Decode a `set<Client>`: a count followed by Client records in wire order.
pub fn decode_journal_client_set(input: &[u8]) -> Result<Vec<JournalClient<'_>>> {
    decode_client_set(input, decode_journal_client_frame)
}

/// Decode a `set<Client>` keeping each ClientData undecoded, so an unknown
/// client variant does not fail the set.
pub fn decode_journal_client_fields_set(input: &[u8]) -> Result<Vec<JournalClientFields<'_>>> {
    decode_client_set(input, decode_client_fields_frame)
}

fn decode_client_set<'a, T>(
    input: &'a [u8],
    decode: impl Fn(&mut Decoder<'a>) -> Result<T>,
) -> Result<Vec<T>> {
    const MIN_CLIENT_BYTES: usize = 6;
    let mut decoder = Decoder::new(input);
    let count = decoder.u32()? as usize;
    if count > decoder.remaining() / MIN_CLIENT_BYTES {
        return Err(Error::BadLength {
            len: count as u64,
            remaining: decoder.remaining() / MIN_CLIENT_BYTES,
        });
    }
    let mut clients = Vec::new();
    clients
        .try_reserve_exact(count)
        .map_err(|_| Error::NoSpace)?;
    for _ in 0..count {
        clients.push(decode(&mut decoder)?);
    }
    if !decoder.is_empty() {
        return Err(Error::TrailingBytes(decoder.remaining()));
    }
    Ok(clients)
}

/// Image client state needed to resume a local journal writer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalClientRecord<'a> {
    pub id: &'a [u8],
    pub data: &'a [u8],
    pub tag_class: u64,
    pub resync_requested: bool,
    /// Ordered most-recent first, as persisted by cls_journal.
    pub commit_positions: Vec<JournalObjectPosition>,
    pub state: u8,
}

/// Decode the `get_client` reply for the local image client.
///
/// The client ID must be the empty string and the client data must contain
/// the v2 IMAGE variant; a different client or metadata variant is
/// malformed.
pub fn decode_journal_image_client(input: &[u8]) -> Result<JournalClientRecord<'_>> {
    let raw = decode_journal_client_raw(input)?;
    if !raw.id.is_empty() {
        return Err(Error::BadValue("journal image client id"));
    }
    let JournalClientData::Image {
        tag_class,
        resync_requested,
    } = decode_client_data(raw.data)?
    else {
        return Err(Error::BadValue("journal client metadata type"));
    };
    Ok(JournalClientRecord {
        id: raw.id,
        data: raw.data,
        tag_class,
        resync_requested,
        commit_positions: raw.commit_positions,
        state: raw.state,
    })
}

fn append_string(out: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    out.extend_from_slice(
        &u32::try_from(value.len())
            .map_err(|_| Error::TooLong)?
            .to_le_bytes(),
    );
    out.extend_from_slice(value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope(version: u8, body: &[u8]) -> Vec<u8> {
        let mut bytes = vec![version, 1];
        bytes.extend_from_slice(&(body.len() as u32).to_le_bytes());
        bytes.extend_from_slice(body);
        bytes
    }

    fn bytes(value: &[u8]) -> Vec<u8> {
        let mut encoded = (value.len() as u32).to_le_bytes().to_vec();
        encoded.extend_from_slice(value);
        encoded
    }

    fn position(object: u64, tag: u64, entry: u64) -> JournalObjectPosition {
        JournalObjectPosition {
            object_number: object,
            tag_tid: tag,
            entry_tid: entry,
        }
    }

    fn fixture() -> Vec<u8> {
        let mut client_data_body = 0u32.to_le_bytes().to_vec();
        client_data_body.extend_from_slice(&0x1234u64.to_le_bytes());
        client_data_body.push(1);
        let client_data = envelope(2, &client_data_body);

        let mut position_body = 1u32.to_le_bytes().to_vec();
        let mut object_position = 17u64.to_le_bytes().to_vec();
        object_position.extend_from_slice(&9u64.to_le_bytes());
        object_position.extend_from_slice(&42u64.to_le_bytes());
        position_body.extend_from_slice(&envelope(1, &object_position));
        let positions = envelope(1, &position_body);

        // The local image client has the empty ID.
        let mut client_body = bytes(b"");
        client_body.extend_from_slice(&bytes(&client_data));
        client_body.extend_from_slice(&positions);
        client_body.push(0);
        envelope(1, &client_body)
    }

    #[test]
    fn decodes_image_client_and_committed_positions() {
        let wire = fixture();
        let record = decode_journal_image_client(&wire).unwrap();
        assert_eq!(record.id, b"");
        assert_eq!(record.tag_class, 0x1234);
        assert!(record.resync_requested);
        assert_eq!(record.state, 0);
        assert_eq!(record.commit_positions, [position(17, 9, 42)]);
    }

    #[test]
    fn rejects_non_image_client_and_truncated_position_lists() {
        let mut bad_type = fixture();
        // Frame (6) + empty id (4) + data length (4) + ClientData header (6).
        let data_type_offset = 6 + 4 + 4 + 6;
        bad_type[data_type_offset..data_type_offset + 4].copy_from_slice(&1u32.to_le_bytes());
        assert!(decode_journal_image_client(&bad_type).is_err());

        let mut bad_positions = fixture();
        bad_positions.truncate(bad_positions.len() - 32);
        assert!(decode_journal_image_client(&bad_positions).is_err());
    }

    #[test]
    fn object_position_wire_has_the_pinned_frame() {
        let mut encoded = Vec::new();
        encode_object_position(position(7, 8, 9), &mut encoded);
        let mut expected = vec![1, 1, 24, 0, 0, 0];
        expected.extend_from_slice(&7u64.to_le_bytes());
        expected.extend_from_slice(&8u64.to_le_bytes());
        expected.extend_from_slice(&9u64.to_le_bytes());
        assert_eq!(encoded, expected);
        assert_eq!(decode_object_position(&encoded), Ok(position(7, 8, 9)));
        assert!(decode_object_position(&encoded[..23]).is_err());
        // A declared body other than 24 bytes is malformed.
        let mut widened = encoded.clone();
        widened[2] = 25;
        widened.push(0);
        assert!(decode_object_position(&widened).is_err());
    }

    #[test]
    fn positions_round_trip_newest_first() {
        let positions = vec![position(11, 2, 3), position(5, 2, 0)];
        let encoded = encode_positions(&positions).unwrap();
        assert_eq!(decode_positions(&encoded).unwrap(), positions);
        assert_eq!(
            &encoded[..16],
            &[1u8, 1, 64, 0, 0, 0, 2, 0, 0, 0, 1, 1, 24, 0, 0, 0]
        );
        assert!(decode_positions(&encoded[..encoded.len() - 1]).is_err());
        assert!(decode_positions(&encoded[10..]).is_err());
    }

    #[test]
    fn oracle_positions_have_the_pinned_wire() {
        // The C writer oracle committed [(1,1,1),(0,1,0)], newest first, for
        // a Write at (object 0, tag 1, entry 0) and a Flush at
        // (object 1, tag 1, entry 1) with splay width 2.
        let encoded = encode_positions(&[position(1, 1, 1), position(0, 1, 0)]).unwrap();
        assert_eq!(
            encoded,
            [
                1u8, 1, 64, 0, 0, 0, 2, 0, 0, 0, 1, 1, 24, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0,
                0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 24, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ]
            .to_vec()
        );
    }

    #[test]
    fn image_client_data_matches_the_create_lifecycle_vector() {
        // Fresh journal create: variant 0, tag class 0, no resync request.
        assert_eq!(
            encode_image_client_data(0, false),
            vec![2, 1, 13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        let decoded = decode_image_client_data(&encode_image_client_data(0xDEAD, true)).unwrap();
        assert_eq!(
            decoded,
            JournalImageData {
                tag_class: 0xDEAD,
                resync_requested: true
            }
        );
        // A different variant cannot initialize the image journal.
        let mut foreign = encode_image_client_data(7, false);
        foreign[6] = 1;
        assert!(decode_image_client_data(&foreign).is_err());
    }

    #[test]
    fn tag_data_matches_the_create_lifecycle_vector() {
        // Fresh journal create: empty local owner, empty predecessor.
        let data = encode_tag_data(
            b"",
            &JournalTagPredecessor {
                mirror_uuid: Vec::new(),
                commit_valid: false,
                tag_tid: 0,
                entry_tid: 0,
            },
        )
        .unwrap();
        assert_eq!(data, vec![0u8; 25]);

        let decoded = decode_tag_data(&data).unwrap();
        assert_eq!(decoded.owner, b"");
        assert!(!decoded.predecessor.commit_valid);
        assert_eq!(decoded.predecessor.tag_tid, 0);
        assert_eq!(decoded.predecessor.entry_tid, 0);
    }

    #[test]
    fn tag_data_round_trips_the_owner() {
        let data = encode_tag_data(
            b"<orphan>",
            &JournalTagPredecessor {
                mirror_uuid: b"".to_vec(),
                commit_valid: true,
                tag_tid: 9,
                entry_tid: 1,
            },
        )
        .unwrap();
        let decoded = decode_tag_data(&data).unwrap();
        assert_eq!(decoded.owner, b"<orphan>");
        assert_eq!(decoded.predecessor.tag_tid, 9);
        assert_eq!(decoded.predecessor.entry_tid, 1);
        // The predecessor fields are validated: a truncated record fails.
        assert!(decode_tag_data(&data[..data.len() - 8]).is_err());
    }

    fn client_record(tag_class: u64, positions: &[JournalObjectPosition]) -> Vec<u8> {
        let data = encode_image_client_data(tag_class, false);
        let mut position = Vec::new();
        position.push(1);
        position.push(1);
        let mut body = Vec::new();
        body.extend_from_slice(&(positions.len() as u32).to_le_bytes());
        for position in positions {
            encode_object_position(*position, &mut body);
        }
        position.extend_from_slice(&(body.len() as u32).to_le_bytes());
        position.extend_from_slice(&body);
        let mut client_body = bytes(b"");
        client_body.extend_from_slice(&bytes(&data));
        client_body.extend_from_slice(&position);
        client_body.push(0); // state
        envelope(1, &client_body)
    }

    #[test]
    fn client_decoding_reads_the_tag_class_and_positions() {
        let record = client_record(7, &[position(11, 2, 3), position(5, 2, 0)]);
        let client = decode_journal_image_client(&record).unwrap();
        assert_eq!(client.tag_class, 7);
        assert_eq!(
            client.commit_positions,
            vec![position(11, 2, 3), position(5, 2, 0)]
        );
    }

    #[test]
    fn client_decoding_rejects_an_unbounded_position_count() {
        let mut record = client_record(7, &[]);
        let count_offset = record.len() - 5;
        record[count_offset..count_offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(decode_journal_image_client(&record).is_err());
    }

    #[test]
    fn client_decoding_rejects_a_foreign_meta_type() {
        let mut record = client_record(7, &[]);
        // Flip the client meta type to the mirror-peer type:
        // frame (6) + id length (4) + data length (4) + ClientData header (6).
        record[20] = 1;
        assert!(decode_journal_image_client(&record).is_err());
    }

    #[test]
    fn client_decoding_rejects_a_reply_for_another_client_id() {
        let mut record = client_record(7, &[]);
        let body_length = u32::from_le_bytes(record[2..6].try_into().unwrap());
        record[2..6].copy_from_slice(&(body_length + 1).to_le_bytes());
        record.splice(6..10, 1u32.to_le_bytes());
        record.insert(10, b'x');
        assert!(decode_journal_image_client(&record).is_err());
    }

    /// One mirror-peer client record whose single sync point carries the
    /// given snapshot namespace.
    fn mirror_peer_record(namespace: &SnapshotNamespace) -> Vec<u8> {
        let ns = crate::snapshot_query::encode_snapshot_namespace(namespace).unwrap();

        // sync point: snap_name "snapp", no from_snap, no object_number
        let mut sync = Vec::new();
        sync.extend_from_slice(&5u32.to_le_bytes());
        sync.extend_from_slice(b"snapp");
        sync.extend_from_slice(&0u32.to_le_bytes()); // from_snap_name empty
        sync.push(0); // object_number absent
        sync.extend_from_slice(&ns);

        // MirrorPeerClientMeta payload
        let mut meta_body = Vec::new();
        meta_body.extend_from_slice(&4u32.to_le_bytes());
        meta_body.extend_from_slice(b"imgx"); // image_id
        meta_body.extend_from_slice(&0u32.to_le_bytes()); // state
        meta_body.extend_from_slice(&0u64.to_le_bytes()); // sync_object_count
        meta_body.extend_from_slice(&1u32.to_le_bytes()); // one sync point
        meta_body.extend_from_slice(&sync);
        meta_body.extend_from_slice(&0u32.to_le_bytes()); // snap_seqs empty

        // ClientData: versioned struct v2, MIRROR_PEER meta
        let mut data = Vec::new();
        data.push(2); // struct_v
        data.push(1); // struct_compat
        let mut data_body = Vec::new();
        data_body.extend_from_slice(&1u32.to_le_bytes());
        data_body.extend_from_slice(&meta_body);
        data.extend_from_slice(&(data_body.len() as u32).to_le_bytes());
        data.extend_from_slice(&data_body);

        // full Client record: id string, data bl, ObjectSetPosition, state
        let mut client_body = Vec::with_capacity(17 + data.len());
        client_body.extend_from_slice(&4u32.to_le_bytes());
        client_body.extend_from_slice(b"peer"); // client id
        client_body.extend_from_slice(&(data.len() as u32).to_le_bytes());
        client_body.extend_from_slice(&data);
        client_body.push(1); // ObjectSetPosition struct_v
        client_body.push(1); // struct_compat
        client_body.extend_from_slice(&4u32.to_le_bytes());
        client_body.extend_from_slice(&0u32.to_le_bytes()); // no positions
        client_body.push(0); // client state
        let mut record = Vec::with_capacity(4 + client_body.len());
        record.extend_from_slice(&1u32.to_le_bytes()); // one client
        record.push(1); // struct_v
        record.push(1); // struct_compat
        record.extend_from_slice(&(client_body.len() as u32).to_le_bytes());
        record.extend_from_slice(&client_body);
        record
    }

    fn mirror_namespace() -> SnapshotNamespace {
        SnapshotNamespace::Mirror {
            state: 1,
            complete: true,
            peer_uuids: vec![b"peer".to_vec()],
            primary_mirror_uuid: Vec::new(),
            primary_snap_id: u64::MAX,
            last_copied_object_number: 0,
            snap_seqs: Vec::new(),
        }
    }

    #[test]
    fn client_set_decodes_mirror_peer_sync_points() {
        let record = mirror_peer_record(&mirror_namespace());
        let clients = decode_journal_client_set(&record).unwrap();
        assert_eq!(clients.len(), 1);
        assert_eq!(clients[0].id, b"peer");
        assert_eq!(clients[0].state, JOURNAL_CLIENT_STATE_CONNECTED);
        let JournalClientData::MirrorPeer {
            image_id,
            state,
            sync_object_count,
            sync_points,
            snap_sequences,
        } = &clients[0].data
        else {
            panic!("expected a mirror peer client");
        };
        assert_eq!(image_id, b"imgx");
        assert_eq!(*state, 0);
        assert_eq!(*sync_object_count, 0);
        assert!(snap_sequences.is_empty());
        assert_eq!(sync_points.len(), 1);
        assert_eq!(sync_points[0].name, b"snapp");
        assert_eq!(sync_points[0].from_snap_name, b"");
        assert_eq!(sync_points[0].object_number, None);
        let SnapshotNamespace::Mirror {
            state, complete, ..
        } = &sync_points[0].namespace
        else {
            panic!("expected a mirror namespace");
        };
        assert_eq!(*state, 1);
        assert!(*complete);
    }

    #[test]
    fn client_set_round_trips_namespace_variants_in_sync_points() {
        let namespaces = [
            SnapshotNamespace::User,
            SnapshotNamespace::Group {
                pool: 7,
                group_id: b"group".to_vec(),
                group_snapshot_id: b"snap".to_vec(),
            },
            SnapshotNamespace::Trash {
                original_name: b"peer-sync".to_vec(),
                original_namespace_type: 3,
            },
            mirror_namespace(),
        ];
        for namespace in namespaces {
            let record = mirror_peer_record(&namespace);
            let clients = decode_journal_client_set(&record).unwrap();
            let JournalClientData::MirrorPeer { sync_points, .. } = &clients[0].data else {
                panic!("expected a mirror peer client");
            };
            assert_eq!(sync_points[0].namespace, namespace);
        }
    }

    #[test]
    fn client_set_keeps_unknown_namespaces_and_rejects_sequence_overruns() {
        // An unknown namespace kind survives the codec as Unknown; the
        // mirror paths reject it before use.
        let record = mirror_peer_record(&SnapshotNamespace::Unknown(9));
        let clients = decode_journal_client_set(&record).unwrap();
        let JournalClientData::MirrorPeer { sync_points, .. } = &clients[0].data else {
            panic!("expected a mirror peer client");
        };
        assert!(matches!(
            sync_points[0].namespace,
            SnapshotNamespace::Unknown(9)
        ));

        // The sequence entries cannot borrow bytes outside the ClientData
        // frame.
        let mut record = mirror_peer_record(&SnapshotNamespace::User);
        let sequence_offset = record.len() - 4;
        record[sequence_offset..sequence_offset + 4].copy_from_slice(&1u32.to_le_bytes());
        assert!(decode_journal_client_set(&record).is_err());
    }

    #[test]
    fn client_set_rejects_unbounded_count_and_frame_overrun() {
        assert!(decode_journal_client_set(&u32::MAX.to_le_bytes()).is_err());
        // The ID bytes exist after the declared frame, but are not part of it.
        let mut record = 1u32.to_le_bytes().to_vec();
        record.extend_from_slice(&[1, 1, 4, 0, 0, 0]);
        record.extend_from_slice(&4u32.to_le_bytes());
        record.extend_from_slice(b"peer");
        assert!(decode_journal_client_set(&record).is_err());
    }

    #[test]
    fn client_set_rejects_a_bad_version() {
        let mut record = vec![1, 0, 0, 0, 2, 1];
        record.extend_from_slice(&0u32.to_le_bytes());
        assert!(decode_journal_client_set(&record).is_err());
    }

    fn tag_record(tid: u64, class: u64, data: &[u8]) -> Vec<u8> {
        let mut body = tid.to_le_bytes().to_vec();
        body.extend_from_slice(&class.to_le_bytes());
        body.extend_from_slice(&bytes(data));
        envelope(1, &body)
    }

    #[test]
    fn tag_decoding_round_trips() {
        let record = tag_record(7, 99, b"xy");
        let tag = decode_journal_tag(&record).unwrap();
        assert_eq!(tag.tid, 7);
        assert_eq!(tag.tag_class, 99);
        assert_eq!(tag.data, b"xy");
    }

    #[test]
    fn tag_decoding_rejects_trailing_bytes() {
        let mut record = tag_record(1, 2, b"");
        record.push(0);
        assert!(decode_journal_tag(&record).is_err());
    }

    #[test]
    fn tag_set_decodes_versioned_tags() {
        let owner = encode_tag_data(
            b"uuid-1",
            &JournalTagPredecessor {
                mirror_uuid: Vec::new(),
                commit_valid: false,
                tag_tid: 0,
                entry_tid: 0,
            },
        )
        .unwrap();
        let record = {
            let mut out = 2u32.to_le_bytes().to_vec();
            out.extend_from_slice(&tag_record(5, 0, b"payload"));
            out.extend_from_slice(&tag_record(9, 0, &owner));
            out
        };
        let tags = decode_journal_tag_set(&record).unwrap();
        assert_eq!(tags.len(), 2);
        assert_eq!(tags[0].tid, 5);
        assert_eq!(tags[0].data, b"payload");
        assert_eq!(tags[1].tid, 9);
        assert_eq!(decode_tag_data(tags[1].data).unwrap().owner, b"uuid-1");
    }

    #[test]
    fn tag_set_rejects_an_unbounded_count() {
        assert!(decode_journal_tag_set(&u32::MAX.to_le_bytes()).is_err());
    }

    #[test]
    fn tag_set_rejects_trailing_bytes() {
        let mut record = 1u32.to_le_bytes().to_vec();
        record.extend_from_slice(&tag_record(1, 0, b"xy"));
        record.push(0);
        assert!(decode_journal_tag_set(&record).is_err());
    }

    #[test]
    fn tag_set_rejects_a_wrong_struct_version() {
        let mut record = 1u32.to_le_bytes().to_vec();
        record.extend_from_slice(&tag_record(1, 0, b"xy"));
        record[4] = 2;
        assert!(decode_journal_tag_set(&record).is_err());
    }

    #[test]
    fn tag_data_reads_the_owner_uuid() {
        let record = encode_tag_data(
            b"",
            &JournalTagPredecessor {
                mirror_uuid: Vec::new(),
                commit_valid: false,
                tag_tid: 0,
                entry_tid: 0,
            },
        )
        .unwrap();
        assert_eq!(decode_tag_data(&record).unwrap().owner, b"");
        let mut trailing = record;
        trailing.push(0);
        assert!(decode_tag_data(&trailing).is_err());
    }
}
