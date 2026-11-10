// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Wire forms for the RBD child and trash class calls and their replies.

use crate::QueryError;
use crate::metadata_query::{HEADER_PREFIX, MAX_OBJECT_NAME_BYTES};
use denc::{Decoder, Encoder};

const MAX_CHILD_ID_BYTES: usize = MAX_OBJECT_NAME_BYTES - HEADER_PREFIX.len();

/// A v2 child registered in the parent header for one snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChildImageSpec {
    /// Pool holding the child.
    pub pool: i64,
    /// Pool namespace holding the child.
    pub namespace: Vec<u8>,
    /// Child image ID.
    pub image_id: Vec<u8>,
}

/// Encode the shared `child_attach` / `child_detach` input. A v2 child
/// identity puts the image ID before its namespace inside the envelope.
pub fn child_link_input(snapshot_id: u64, child: &ChildImageSpec) -> denc::Result<Vec<u8>> {
    let mut encoder = Encoder::with_capacity(64);
    encoder.u64(snapshot_id)?;
    encoder.versioned(2, 1, |body| {
        body.i64(child.pool)?;
        body.bytes(&child.image_id)?;
        body.bytes(&child.namespace)
    })?;
    Ok(encoder.into_vec())
}

/// The class input for `rbd.children_list`: one little-endian snapshot ID.
pub fn children_list_input(snapshot_id: u64) -> Vec<u8> {
    snapshot_id.to_le_bytes().to_vec()
}

/// A class reply is not valid denc for the expected child or trash shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChildrenReplyError {
    /// The reply ran out of bytes before the shape completed.
    Truncated,
    /// A versioned struct carried an unsupported version.
    UnsupportedVersion,
}

impl std::fmt::Display for ChildrenReplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => f.write_str("RBD child or trash reply is truncated"),
            Self::UnsupportedVersion => f.write_str("RBD trash reply uses an unsupported version"),
        }
    }
}

impl std::error::Error for ChildrenReplyError {}

/// Every denc failure means the reply does not carry the expected shape.
fn eof(_: denc::Error) -> ChildrenReplyError {
    ChildrenReplyError::Truncated
}

// Validate the schema's smallest element before reserving owned entries.
// Decoder::count only proves that each element has at least one byte.
fn collection_count(
    decoder: &mut Decoder<'_>,
    minimum_element_bytes: usize,
) -> Result<usize, ChildrenReplyError> {
    let count = decoder.count().map_err(eof)?;
    if count > decoder.remaining() / minimum_element_bytes {
        return Err(ChildrenReplyError::Truncated);
    }
    Ok(count)
}

/// A versioned struct the pinned class never writes is not a truncated reply.
fn version_error(error: denc::Error) -> ChildrenReplyError {
    match error {
        denc::Error::CompatTooNew { .. } | denc::Error::VersionTooOld { .. } => {
            ChildrenReplyError::UnsupportedVersion
        }
        _ => ChildrenReplyError::Truncated,
    }
}

/// Decode a `rbd.children_list` reply: a little-endian u32 count followed by
/// that many child specs.
///
/// Every spec is a versioned `ChildImageSpec` (doc/spec/cls_rbd.md;
/// encoding.md section 4): a 6-byte envelope, then the pool ID, the child
/// image ID and, from struct version 2, the pool namespace. The namespace
/// follows the image ID, not the other way round.
pub fn decode_children_list_reply(reply: &[u8]) -> Result<Vec<ChildImageSpec>, ChildrenReplyError> {
    let mut decoder = Decoder::new(reply);
    // v1 envelope + pool ID + empty image-ID string; v2 adds a namespace.
    let count = collection_count(&mut decoder, 6 + 8 + 4)?;
    let mut specs = Vec::with_capacity(count);
    for _ in 0..count {
        let spec = decoder
            .versioned_min(1, 2, |body, version| {
                let pool = body.i64()?;
                let image_id = body.bytes()?.to_vec();
                let namespace = if version >= 2 {
                    body.bytes()?.to_vec()
                } else {
                    Vec::new()
                };
                Ok(ChildImageSpec {
                    pool,
                    namespace,
                    image_id,
                })
            })
            .map_err(version_error)?;
        specs.push(spec);
    }
    if !decoder.is_empty() {
        return Err(ChildrenReplyError::Truncated);
    }
    Ok(specs)
}

/// The class input for `rbd.get_children`: parent pool ID, image ID and
/// snapshot ID. The parent namespace is not part of the v1 child key.
pub fn get_children_input(
    pool: i64,
    image_id: &[u8],
    snapshot_id: u64,
) -> Result<Vec<u8>, QueryError> {
    if image_id.len() > MAX_CHILD_ID_BYTES {
        return Err(QueryError::InvalidImageId);
    }
    let mut input = Vec::with_capacity(8 + 4 + image_id.len() + 8);
    input.extend_from_slice(&pool.to_le_bytes());
    input.extend_from_slice(&(image_id.len() as u32).to_le_bytes());
    input.extend_from_slice(image_id);
    input.extend_from_slice(&snapshot_id.to_le_bytes());
    Ok(input)
}

/// Decode a `rbd.get_children` reply: a little-endian u32 count followed by
/// that many child image IDs.
pub fn decode_children_set_reply(reply: &[u8]) -> Result<Vec<Vec<u8>>, ChildrenReplyError> {
    let mut decoder = Decoder::new(reply);
    // Even an empty image ID has a four-byte string length.
    let count = collection_count(&mut decoder, 4)?;
    let mut ids = Vec::with_capacity(count);
    for _ in 0..count {
        ids.push(decoder.bytes().map_err(eof)?.to_vec());
    }
    if !decoder.is_empty() {
        return Err(ChildrenReplyError::Truncated);
    }
    Ok(ids)
}

/// The class input for `rbd.trash_list`: an empty start key and no return cap.
pub fn trash_list_input() -> Vec<u8> {
    let mut input = Vec::new();
    input.extend_from_slice(&0u32.to_le_bytes());
    input.extend_from_slice(&u64::MAX.to_le_bytes());
    input
}

/// One trash entry, reduced to the fields child naming consumes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrashEntry {
    /// Image ID as recorded in the trash.
    pub image_id: Vec<u8>,
    /// Original image name.
    pub name: Vec<u8>,
    /// Trash source as an integer (user, mirroring, migration, removing,
    /// user-parent).
    pub source: i32,
    /// Deletion time in seconds since the epoch.
    pub deletion_time: i64,
    /// Deferment end time in seconds since the epoch.
    pub deferment_end_time: i64,
}

/// Decode one `TrashImageSpec` (versioned) after its leading image ID.
/// Returns the name, source, and the two timestamps in seconds.
///
/// The pinned struct (doc/spec/cls_rbd.md; encoding.md section 4) is a 6-byte
/// versioned envelope, then the source as one byte, the name as a string, the
/// deletion and deferment timestamps as `utime_t` (u32 seconds plus u32
/// nanoseconds) and, from struct version 2, the state as one byte.
pub fn decode_trash_spec(
    decoder: &mut Decoder,
) -> Result<(Vec<u8>, i32, i64, i64), ChildrenReplyError> {
    decoder
        .versioned_min(1, 2, |body, version| {
            let source = body.u8()?;
            let name = body.bytes()?.to_vec();
            // utime_t: u32 seconds plus u32 nanoseconds.
            let deletion_time = body.u32()? as i64;
            body.skip(4)?;
            let deferment_end_time = body.u32()? as i64;
            body.skip(4)?;
            if version >= 2 {
                body.u8()?;
            }
            Ok((name, source as i32, deletion_time, deferment_end_time))
        })
        .map_err(version_error)
}

/// Decode a `rbd.trash_get` reply: one `TrashImageSpec` (name, source, and the
/// two timestamps in seconds).
pub fn decode_trash_get_reply(
    reply: &[u8],
) -> Result<(Vec<u8>, i32, i64, i64), ChildrenReplyError> {
    let mut decoder = Decoder::new(reply);
    let result = decode_trash_spec(&mut decoder)?;
    if !decoder.is_empty() {
        return Err(ChildrenReplyError::Truncated);
    }
    Ok(result)
}

/// Decode a `rbd.trash_list` reply: a little-endian u32 count of
/// (image ID, TrashImageSpec) pairs.
pub fn decode_trash_list_reply(reply: &[u8]) -> Result<Vec<TrashEntry>, ChildrenReplyError> {
    let mut decoder = Decoder::new(reply);
    // Empty ID + v1 envelope + source + empty name + two utime_t values.
    let count = collection_count(&mut decoder, 4 + 6 + 1 + 4 + 8 + 8)?;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let image_id = decoder.bytes().map_err(eof)?.to_vec();
        let (name, source, deletion_time, deferment_end_time) = decode_trash_spec(&mut decoder)?;
        entries.push(TrashEntry {
            image_id,
            name,
            source,
            deletion_time,
            deferment_end_time,
        });
    }
    if !decoder.is_empty() {
        return Err(ChildrenReplyError::Truncated);
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn string(bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(bytes);
        out
    }

    /// A pinned versioned struct envelope: u8 version, u8 compat, u32 body
    /// length.
    fn envelope(version: u8, compat: u8, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(6 + body.len());
        out.push(version);
        out.push(compat);
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        out.extend_from_slice(body);
        out
    }

    /// The pinned `ChildImageSpec` body: pool ID, image ID, namespace.
    fn child_spec_body(pool: i64, image_id: &[u8], namespace: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&pool.to_le_bytes());
        body.extend_from_slice(&string(image_id));
        body.extend_from_slice(&string(namespace));
        body
    }

    /// The pinned `TrashImageSpec` body: source byte, name, two `utime_t`
    /// (u32 seconds, u32 nanoseconds) and the state byte from version 2.
    fn trash_spec_body(
        source: u8,
        name: &[u8],
        deletion: (u32, u32),
        deferment: (u32, u32),
        state: Option<u8>,
    ) -> Vec<u8> {
        let mut body = Vec::new();
        body.push(source);
        body.extend_from_slice(&string(name));
        body.extend_from_slice(&deletion.0.to_le_bytes());
        body.extend_from_slice(&deletion.1.to_le_bytes());
        body.extend_from_slice(&deferment.0.to_le_bytes());
        body.extend_from_slice(&deferment.1.to_le_bytes());
        if let Some(state) = state {
            body.push(state);
        }
        body
    }

    #[test]
    fn link_input_preserves_distinct_image_and_namespace_fields() {
        let child = ChildImageSpec {
            pool: 7,
            namespace: b"tenant".to_vec(),
            image_id: b"child1".to_vec(),
        };
        let encoded = child_link_input(9, &child).unwrap();
        assert_eq!(&encoded[..14], &[9, 0, 0, 0, 0, 0, 0, 0, 2, 1, 28, 0, 0, 0]);
        let mut reply = 1u32.to_le_bytes().to_vec();
        reply.extend_from_slice(&encoded[8..]);
        assert_eq!(decode_children_list_reply(&reply).unwrap(), vec![child]);
    }

    #[test]
    fn children_list_input_is_one_le_snapshot_id() {
        assert_eq!(children_list_input(7), 7u64.to_le_bytes().to_vec());
    }

    #[test]
    fn child_spec_bytes_match_the_pinned_encoding() {
        // The image ID precedes the namespace on the wire; a swapped order
        // would decode into the wrong fields.
        let spec = envelope(2, 1, &child_spec_body(11, b"child-a", b"ns"));
        assert_eq!(
            spec,
            vec![
                2, 1, 25, 0, 0, 0, // version, compat, body length
                11, 0, 0, 0, 0, 0, 0, 0, // pool ID
                7, 0, 0, 0, b'c', b'h', b'i', b'l', b'd', b'-', b'a', // image ID
                2, 0, 0, 0, b'n', b's', // namespace
            ]
        );
    }

    #[test]
    fn decode_children_list_round_trips_and_rejects_trailing_bytes() {
        let mut reply = Vec::new();
        reply.extend_from_slice(&2u32.to_le_bytes());
        reply.extend_from_slice(&envelope(2, 1, &child_spec_body(11, b"child-a", b"ns")));
        reply.extend_from_slice(&envelope(2, 1, &child_spec_body(22, b"child-b", b"")));
        let specs = decode_children_list_reply(&reply).unwrap();
        assert_eq!(
            specs,
            vec![
                ChildImageSpec {
                    pool: 11,
                    namespace: b"ns".to_vec(),
                    image_id: b"child-a".to_vec()
                },
                ChildImageSpec {
                    pool: 22,
                    namespace: Vec::new(),
                    image_id: b"child-b".to_vec()
                }
            ]
        );
        let empty = 0u32.to_le_bytes().to_vec();
        assert!(decode_children_list_reply(&empty).unwrap().is_empty());
        let mut trailing = reply;
        trailing.push(0);
        assert_eq!(
            decode_children_list_reply(&trailing).unwrap_err(),
            ChildrenReplyError::Truncated
        );
    }

    #[test]
    fn decode_children_list_reads_a_version_1_spec_without_a_namespace() {
        let mut body = Vec::new();
        body.extend_from_slice(&11i64.to_le_bytes());
        body.extend_from_slice(&string(b"child-a"));
        let mut reply = Vec::new();
        reply.extend_from_slice(&1u32.to_le_bytes());
        reply.extend_from_slice(&envelope(1, 1, &body));
        assert_eq!(
            decode_children_list_reply(&reply).unwrap(),
            vec![ChildImageSpec {
                pool: 11,
                namespace: Vec::new(),
                image_id: b"child-a".to_vec()
            }]
        );
    }

    #[test]
    fn decode_children_list_rejects_truncated_spec() {
        let mut reply = Vec::new();
        reply.extend_from_slice(&1u32.to_le_bytes());
        reply.extend_from_slice(&envelope(
            2,
            1,
            // The image ID length claims four bytes that are not present.
            &[11, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0],
        ));
        assert_eq!(
            decode_children_list_reply(&reply).unwrap_err(),
            ChildrenReplyError::Truncated
        );
    }

    #[test]
    fn decode_children_list_rejects_an_unsupported_compat_version() {
        let mut reply = Vec::new();
        reply.extend_from_slice(&1u32.to_le_bytes());
        reply.extend_from_slice(&envelope(2, 3, &child_spec_body(11, b"child-a", b"")));
        assert_eq!(
            decode_children_list_reply(&reply).unwrap_err(),
            ChildrenReplyError::UnsupportedVersion
        );
    }

    #[test]
    fn get_children_input_encodes_pool_id_and_snapshot() {
        let input = get_children_input(9, b"parent1", 3).unwrap();
        let mut expected = Vec::new();
        expected.extend_from_slice(&9i64.to_le_bytes());
        expected.extend_from_slice(&string(b"parent1"));
        expected.extend_from_slice(&3u64.to_le_bytes());
        assert_eq!(input, expected);
    }

    #[test]
    fn get_children_input_rejects_oversized_id_as_an_invalid_input() {
        let long = vec![b'x'; MAX_CHILD_ID_BYTES + 1];
        assert_eq!(
            get_children_input(9, &long, 3),
            Err(QueryError::InvalidImageId),
            "an oversized input image ID is a request error, not a reply error"
        );
    }

    #[test]
    fn decode_children_set_round_trips() {
        let mut reply = Vec::new();
        reply.extend_from_slice(&2u32.to_le_bytes());
        reply.extend_from_slice(&string(b"a"));
        reply.extend_from_slice(&string(b"bc"));
        assert_eq!(
            decode_children_set_reply(&reply).unwrap(),
            vec![b"a".to_vec(), b"bc".to_vec()]
        );
        assert!(matches!(
            decode_children_set_reply(&[]).unwrap_err(),
            ChildrenReplyError::Truncated
        ));
    }

    #[test]
    fn decode_children_set_reports_a_count_above_the_bytes() {
        let mut reply = Vec::new();
        reply.extend_from_slice(&9u32.to_le_bytes());
        reply.extend_from_slice(&string(b"a"));
        assert_eq!(
            decode_children_set_reply(&reply).unwrap_err(),
            ChildrenReplyError::Truncated
        );
    }

    #[test]
    fn trash_list_input_is_empty_start_and_unbounded() {
        assert_eq!(
            trash_list_input(),
            vec![0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255]
        );
    }

    /// A pinned `TrashImageSpec` with the given struct version.
    fn trash_spec(source: u8, name: &[u8], struct_version: u8) -> Vec<u8> {
        let state = (struct_version >= 2).then_some(0u8);
        envelope(
            struct_version,
            1,
            &trash_spec_body(source, name, (100, 50), (200, 60), state),
        )
    }

    #[test]
    fn trash_spec_bytes_match_the_pinned_encoding() {
        let spec = trash_spec(0, b"n", 2);
        assert_eq!(
            spec,
            vec![
                2, 1, 23, 0, 0, 0, // version, compat, body length
                0, // source
                1, 0, 0, 0, b'n', // name
                100, 0, 0, 0, // deletion seconds
                50, 0, 0, 0, // deletion nanoseconds
                200, 0, 0, 0, // deferment seconds
                60, 0, 0, 0, // deferment nanoseconds
                0, // state
            ]
        );
    }

    #[test]
    fn decode_trash_list_keeps_id_name_and_source() {
        let mut reply = Vec::new();
        reply.extend_from_slice(&2u32.to_le_bytes());
        reply.extend_from_slice(&string(b"id-1"));
        reply.extend_from_slice(&trash_spec(0, b"orig-1", 1));
        reply.extend_from_slice(&string(b"id-2"));
        reply.extend_from_slice(&trash_spec(3, b"orig-2", 2));
        let entries = decode_trash_list_reply(&reply).unwrap();
        assert_eq!(
            entries,
            vec![
                TrashEntry {
                    image_id: b"id-1".to_vec(),
                    name: b"orig-1".to_vec(),
                    source: 0,
                    deletion_time: 100,
                    deferment_end_time: 200
                },
                TrashEntry {
                    image_id: b"id-2".to_vec(),
                    name: b"orig-2".to_vec(),
                    source: 3,
                    deletion_time: 100,
                    deferment_end_time: 200
                }
            ]
        );
        let empty = 0u32.to_le_bytes().to_vec();
        assert!(decode_trash_list_reply(&empty).unwrap().is_empty());
    }

    #[test]
    fn decode_trash_get_reads_one_spec() {
        let reply = trash_spec(4, b"gone", 2);
        assert_eq!(
            decode_trash_get_reply(&reply).unwrap(),
            (b"gone".to_vec(), 4, 100, 200)
        );
        assert_eq!(
            decode_trash_get_reply(&reply[..reply.len() - 2]).unwrap_err(),
            ChildrenReplyError::Truncated
        );
    }

    #[test]
    fn decode_trash_list_rejects_unknown_versions_and_truncation() {
        let count = 1u32.to_le_bytes().to_vec();
        let key = string(b"id");
        let spec = trash_spec(0, b"n", 1);
        let mut reply = Vec::new();
        reply.extend_from_slice(&count);
        reply.extend_from_slice(&key);
        reply.extend_from_slice(&spec);
        // The compat field starts right after the count and the key.
        let compat_byte = count.len() + key.len() + 1;
        reply[compat_byte] = 3;
        assert_eq!(
            decode_trash_list_reply(&reply).unwrap_err(),
            ChildrenReplyError::UnsupportedVersion
        );
        let mut truncated = Vec::new();
        truncated.extend_from_slice(&count);
        truncated.extend_from_slice(&key);
        truncated.extend_from_slice(&spec);
        truncated.truncate(truncated.len() - 4);
        assert_eq!(
            decode_trash_list_reply(&truncated).unwrap_err(),
            ChildrenReplyError::Truncated
        );
    }
}
