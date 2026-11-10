// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Snapshot record observation from the image header.

use crate::{
    QueryError, Versioned,
    metadata_query::{compound_reply, header_target, single_class_reply},
};
use denc::{Decoder, Encoder, Error};
use opwire::OsdOp;
use rustyrados::{Access, CompoundRequest, ReadCompletion, RequestContext, RequestToken};

/// Exact snapshot namespace fields returned by the pinned class method.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SnapshotNamespace {
    User,
    Group {
        pool: i64,
        group_id: Vec<u8>,
        group_snapshot_id: Vec<u8>,
    },
    Trash {
        original_name: Vec<u8>,
        original_namespace_type: u32,
    },
    Mirror {
        state: u8,
        complete: bool,
        peer_uuids: Vec<Vec<u8>>,
        primary_mirror_uuid: Vec<u8>,
        primary_snap_id: u64,
        last_copied_object_number: u64,
        snap_seqs: Vec<(u64, u64)>,
    },
    Unknown(u32),
}

/// Encode the pinned namespace variant frame used by snapshot creation and
/// administrative forwarding. Mirror peer sets and sequence maps must already
/// be strictly ordered without duplicate keys, as returned by the decoder.
/// Unknown tags must not alias one of the four known variants.
pub fn encode_snapshot_namespace(namespace: &SnapshotNamespace) -> denc::Result<Vec<u8>> {
    let mut encoder = Encoder::new();
    encoder.versioned(1, 1, |body| {
        match namespace {
            SnapshotNamespace::User => body.u32(0)?,
            SnapshotNamespace::Group {
                pool,
                group_id,
                group_snapshot_id,
            } => {
                body.u32(1)?;
                body.i64(*pool)?;
                body.bytes(group_id)?;
                body.bytes(group_snapshot_id)?;
            }
            SnapshotNamespace::Trash {
                original_name,
                original_namespace_type,
            } => {
                body.u32(2)?;
                body.bytes(original_name)?;
                body.u32(*original_namespace_type)?;
            }
            SnapshotNamespace::Mirror {
                state,
                complete,
                peer_uuids,
                primary_mirror_uuid,
                primary_snap_id,
                last_copied_object_number,
                snap_seqs,
            } => {
                if *state > 3 {
                    return Err(Error::BadValue("mirror snapshot state"));
                }
                if peer_uuids.windows(2).any(|pair| pair[0] >= pair[1]) {
                    return Err(Error::BadValue("mirror peer set order"));
                }
                if snap_seqs.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
                    return Err(Error::BadValue("mirror snapshot map order"));
                }
                body.u32(3)?;
                body.u8(*state)?;
                body.u8(u8::from(*complete))?;
                body.u32(
                    u32::try_from(peer_uuids.len())
                        .map_err(|_| Error::BadValue("mirror peer set size"))?,
                )?;
                for peer in peer_uuids {
                    body.bytes(peer)?;
                }
                body.bytes(primary_mirror_uuid)?;
                body.u64(*primary_snap_id)?;
                body.u64(*last_copied_object_number)?;
                body.u32(
                    u32::try_from(snap_seqs.len())
                        .map_err(|_| Error::BadValue("mirror snapshot map size"))?,
                )?;
                for (id, sequence) in snap_seqs {
                    body.u64(*id)?;
                    body.u64(*sequence)?;
                }
            }
            SnapshotNamespace::Unknown(tag) => {
                if *tag <= 3 {
                    return Err(Error::BadValue(
                        "unknown snapshot namespace aliases known tag",
                    ));
                }
                body.u32(*tag)?;
            }
        }
        Ok(())
    })?;
    Ok(encoder.into_vec())
}

/// SnapshotInfo returned by `rbd.snapshot_get`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotInfo {
    pub id: u64,
    pub namespace: SnapshotNamespace,
    pub name: Vec<u8>,
    pub image_size: u64,
    pub timestamp_seconds: u32,
    pub timestamp_nanoseconds: u32,
    pub child_count: u32,
}

/// Minimum encoded `snapshot_get` reply: an empty-user-namespace SnapshotInfo.
pub(crate) const MIN_SNAPSHOT_REPLY_BYTES: u32 = 48;

/// Query a specific snapshot record. `max_output_bytes` bounds the complete
/// encoded SnapshotInfo, including namespace fields and variable strings.
pub fn snapshot_query(
    pool: i64,
    namespace: Vec<u8>,
    image_id: &[u8],
    snapshot_id: u64,
    max_output_bytes: u32,
) -> Result<CompoundRequest, QueryError> {
    if snapshot_id >= opwire::NOSNAP {
        return Err(QueryError::InvalidSnapshot);
    }
    if max_output_bytes < MIN_SNAPSHOT_REPLY_BYTES {
        return Err(QueryError::InvalidOutputLimit);
    }
    let target = header_target(pool, namespace, image_id)?;
    Ok(CompoundRequest {
        target,
        access: Access::Read,
        context: RequestContext::default(),
        operations: vec![OsdOp::call(
            b"rbd",
            b"snapshot_get",
            &snapshot_id.to_le_bytes(),
        )],
        max_output_bytes,
    })
}

/// Query a snapshot's protection state (0 unprotected, 1 unprotecting,
/// 2 protected). The header and record must already exist.
pub fn snapshot_protection_query(
    pool: i64,
    namespace: Vec<u8>,
    image_id: &[u8],
    snapshot_id: u64,
) -> Result<CompoundRequest, QueryError> {
    if snapshot_id >= opwire::NOSNAP {
        return Err(QueryError::InvalidSnapshot);
    }
    let target = header_target(pool, namespace, image_id)?;
    Ok(CompoundRequest {
        target,
        access: Access::Read,
        context: RequestContext::default(),
        operations: vec![OsdOp::call(
            b"rbd",
            b"get_protection_status",
            &snapshot_id.to_le_bytes(),
        )],
        max_output_bytes: 1,
    })
}

/// Decode only the matching ordinary protection-status reply.
pub fn decode_snapshot_protection_completion(
    expected: RequestToken,
    completion: ReadCompletion,
) -> Result<Versioned<u8>, QueryError> {
    let (result, user_version, operations) = compound_reply(expected, completion)?;
    Ok(Versioned {
        value: decode_snapshot_protection_query(result, operations)?,
        user_version,
    })
}

/// Decode an exact, valid protection-status byte.
pub fn decode_snapshot_protection_query(
    overall_result: i32,
    operations: Vec<OsdOp>,
) -> Result<u8, QueryError> {
    let operation = single_class_reply(overall_result, operations)?;
    match operation.outdata.as_ref() {
        [status @ 0..=2] => Ok(*status),
        _ => Err(QueryError::InvalidSnapshot),
    }
}

/// Decode only a matching ordinary reply, retaining the header user version.
pub fn decode_snapshot_completion(
    expected: RequestToken,
    expected_snapshot_id: u64,
    completion: ReadCompletion,
) -> Result<Versioned<SnapshotInfo>, QueryError> {
    let (result, user_version, operations) = compound_reply(expected, completion)?;
    Ok(Versioned {
        value: decode_snapshot_query(result, operations, expected_snapshot_id)?,
        user_version,
    })
}

/// Decode one bounded SnapshotInfo from a verified class reply. Compatible
/// frame and physical tails are accepted. The returned ID must equal the
/// requested one before it can be used for snapshot reads.
pub fn decode_snapshot_query(
    overall_result: i32,
    operations: Vec<OsdOp>,
    expected_snapshot_id: u64,
) -> Result<SnapshotInfo, QueryError> {
    let operation = single_class_reply(overall_result, operations)?;
    let mut decoder = Decoder::new(&operation.outdata);
    let info = decoder
        .versioned(1, |body, _| {
            let id = body.u64()?;
            let namespace = decode_namespace(body)?;
            let name = body.bytes()?.to_vec();
            let image_size = body.u64()?;
            let timestamp_seconds = body.u32()?;
            let timestamp_nanoseconds = body.u32()?;
            let child_count = body.u32()?;
            Ok(SnapshotInfo {
                id,
                namespace,
                name,
                image_size,
                timestamp_seconds,
                timestamp_nanoseconds,
                child_count,
            })
        })
        .map_err(|_| QueryError::InvalidSnapshot)?;
    if info.id != expected_snapshot_id
        || info.id >= opwire::NOSNAP
        || info.timestamp_nanoseconds >= 1_000_000_000
    {
        return Err(QueryError::InvalidSnapshot);
    }
    Ok(info)
}

/// Decode one framed snapshot namespace, leaving subsequent fields untouched.
pub fn decode_namespace(decoder: &mut Decoder<'_>) -> denc::Result<SnapshotNamespace> {
    decoder.versioned(1, |body, _| {
        let kind = body.u32()?;
        let namespace = match kind {
            0 => SnapshotNamespace::User,
            1 => SnapshotNamespace::Group {
                pool: body.i64()?,
                group_id: body.bytes()?.to_vec(),
                group_snapshot_id: body.bytes()?.to_vec(),
            },
            2 => SnapshotNamespace::Trash {
                original_name: body.bytes()?.to_vec(),
                original_namespace_type: body.u32()?,
            },
            3 => decode_mirror_namespace(body)?,
            _ => SnapshotNamespace::Unknown(kind),
        };
        Ok(namespace)
    })
}

fn decode_mirror_namespace(body: &mut Decoder<'_>) -> denc::Result<SnapshotNamespace> {
    let state = body.u8()?;
    if state > 3 {
        return Err(Error::BadValue("mirror snapshot state"));
    }
    let complete = match body.u8()? {
        0 => false,
        1 => true,
        _ => return Err(Error::BadValue("mirror snapshot complete")),
    };
    let peer_count = body.count()?;
    if peer_count > body.remaining() / 4 {
        return Err(Error::BadValue("mirror peer count"));
    }
    let mut peer_uuids: Vec<Vec<u8>> = Vec::new();
    peer_uuids
        .try_reserve_exact(peer_count)
        .map_err(|_| Error::BadValue("mirror peer allocation"))?;
    for _ in 0..peer_count {
        let peer = body.bytes()?.to_vec();
        if peer_uuids
            .last()
            .is_some_and(|previous| previous.as_slice() >= peer.as_slice())
        {
            return Err(Error::BadValue("mirror peer set order"));
        }
        peer_uuids.push(peer);
    }
    let primary_mirror_uuid = body.bytes()?.to_vec();
    let primary_snap_id = body.u64()?;
    let last_copied_object_number = body.u64()?;
    let sequence_count = body.count()?;
    if sequence_count > body.remaining() / 16 {
        return Err(Error::BadValue("mirror sequence count"));
    }
    let mut snap_seqs: Vec<(u64, u64)> = Vec::new();
    snap_seqs
        .try_reserve_exact(sequence_count)
        .map_err(|_| Error::BadValue("mirror sequence allocation"))?;
    for _ in 0..sequence_count {
        let snap_id = body.u64()?;
        let sequence = body.u64()?;
        if snap_seqs
            .last()
            .is_some_and(|previous| previous.0 >= snap_id)
        {
            return Err(Error::BadValue("mirror snapshot map order"));
        }
        snap_seqs.push((snap_id, sequence));
    }
    Ok(SnapshotNamespace::Mirror {
        state,
        complete,
        peer_uuids,
        primary_mirror_uuid,
        primary_snap_id,
        last_copied_object_number,
        snap_seqs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustyrados::{ObjectQueue, ReadOutcome, ReadPublication};

    fn reply(bytes: &[u8]) -> Vec<OsdOp> {
        let query = snapshot_query(7, vec![], b"image1", 1, 4096).unwrap();
        let mut operation = OsdOp::echo(&query.operations[0]);
        operation.outdata = bytes.to_vec().into();
        vec![operation]
    }

    #[test]
    fn mirror_namespace_rejects_impossible_counts_before_reserving() {
        let namespace = SnapshotNamespace::Mirror {
            state: 0,
            complete: false,
            peer_uuids: vec![],
            primary_mirror_uuid: vec![],
            primary_snap_id: 0,
            last_copied_object_number: 0,
            snap_seqs: vec![],
        };
        let mut peers = encode_snapshot_namespace(&namespace).unwrap();
        peers[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(decode_namespace(&mut Decoder::new(&peers)).is_err());
        let mut sequences = encode_snapshot_namespace(&namespace).unwrap();
        sequences[36..40].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(decode_namespace(&mut Decoder::new(&sequences)).is_err());
    }

    #[test]
    fn namespace_encoder_matches_independent_pinned_variant_vectors() {
        let cases = [
            (SnapshotNamespace::User, vec![1, 1, 4, 0, 0, 0, 0, 0, 0, 0]),
            (
                SnapshotNamespace::Group {
                    pool: 7,
                    group_id: b"g".to_vec(),
                    group_snapshot_id: b"s".to_vec(),
                },
                vec![
                    1, 1, 22, 0, 0, 0, 1, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, b'g', 1, 0,
                    0, 0, b's',
                ],
            ),
            (
                SnapshotNamespace::Trash {
                    original_name: b"n".to_vec(),
                    original_namespace_type: 1,
                },
                vec![1, 1, 13, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, b'n', 1, 0, 0, 0],
            ),
            (
                SnapshotNamespace::Unknown(4),
                vec![1, 1, 4, 0, 0, 0, 4, 0, 0, 0],
            ),
        ];
        for (namespace, wire) in cases {
            assert_eq!(encode_snapshot_namespace(&namespace).unwrap(), wire);
            let mut decoder = Decoder::new(&wire);
            assert_eq!(decode_namespace(&mut decoder).unwrap(), namespace);
            assert!(decoder.is_empty());
        }
    }

    #[test]
    fn mirror_namespace_encoder_preserves_canonical_sets_and_rejects_ambiguous_inputs() {
        let mut namespace = SnapshotNamespace::Mirror {
            state: 0,
            complete: false,
            peer_uuids: vec![],
            primary_mirror_uuid: vec![],
            primary_snap_id: 13,
            last_copied_object_number: 14,
            snap_seqs: vec![],
        };
        let wire = vec![
            1, 1, 34, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 13, 0, 0, 0, 0, 0, 0, 0,
            14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert_eq!(encode_snapshot_namespace(&namespace).unwrap(), wire);
        if let SnapshotNamespace::Mirror {
            peer_uuids,
            snap_seqs,
            ..
        } = &mut namespace
        {
            *peer_uuids = vec![b"a".to_vec(), b"z".to_vec()];
            *snap_seqs = vec![(1, 9), (2, 8)];
        }
        let wire = encode_snapshot_namespace(&namespace).unwrap();
        assert_eq!(
            decode_namespace(&mut Decoder::new(&wire)).unwrap(),
            namespace
        );
        for peers in [
            vec![b"z".to_vec(), b"a".to_vec()],
            vec![b"a".to_vec(), b"a".to_vec()],
        ] {
            let mut invalid = namespace.clone();
            if let SnapshotNamespace::Mirror { peer_uuids, .. } = &mut invalid {
                *peer_uuids = peers;
            }
            assert!(encode_snapshot_namespace(&invalid).is_err());
        }
        for sequences in [vec![(2, 8), (1, 9)], vec![(1, 8), (1, 9)]] {
            let mut invalid = namespace.clone();
            if let SnapshotNamespace::Mirror { snap_seqs, .. } = &mut invalid {
                *snap_seqs = sequences;
            }
            assert!(encode_snapshot_namespace(&invalid).is_err());
        }
        if let SnapshotNamespace::Mirror { state, .. } = &mut namespace {
            *state = 4;
        }
        assert!(encode_snapshot_namespace(&namespace).is_err());
        for tag in 0..=3 {
            assert!(encode_snapshot_namespace(&SnapshotNamespace::Unknown(tag)).is_err());
        }
    }

    #[test]
    fn query_selects_exact_snapshot_id() {
        let query = snapshot_query(7, b"ns".to_vec(), b"image1", 3, 4096).unwrap();
        assert_eq!(query.target.object, b"rbd_header.image1");
        assert_eq!(query.target.namespace, b"ns");
        assert_eq!(
            query.operations[0].cls_call().unwrap().method,
            b"snapshot_get"
        );
        assert_eq!(
            query.operations[0].cls_call().unwrap().input,
            &3u64.to_le_bytes()
        );
        assert!(query.preflight(1 << 20).is_ok());
        assert!(matches!(
            snapshot_query(7, vec![], b"image1", opwire::NOSNAP, 4096),
            Err(QueryError::InvalidSnapshot)
        ));
        assert!(matches!(
            snapshot_query(7, vec![], b"image1", 1, 47),
            Err(QueryError::InvalidOutputLimit)
        ));
    }

    #[test]
    fn protection_status_query_and_reply_are_exact() {
        let query = snapshot_protection_query(7, b"ns".to_vec(), b"image1", 3).unwrap();
        assert_eq!(query.target.object, b"rbd_header.image1");
        assert_eq!(query.target.namespace, b"ns");
        assert_eq!(
            query.operations[0].cls_call().unwrap().method,
            b"get_protection_status"
        );
        assert_eq!(
            query.operations[0].cls_call().unwrap().input,
            &3u64.to_le_bytes()
        );
        assert!(query.preflight(1 << 20).is_ok());
        for status in 0..=2 {
            let mut operation = OsdOp::echo(&query.operations[0]);
            operation.outdata = vec![status].into();
            assert_eq!(
                decode_snapshot_protection_query(0, vec![operation]),
                Ok(status)
            );
        }
        let mut operation = OsdOp::echo(&query.operations[0]);
        operation.outdata = vec![3].into();
        assert_eq!(
            decode_snapshot_protection_query(0, vec![operation]),
            Err(QueryError::InvalidSnapshot)
        );
        assert_eq!(
            decode_snapshot_protection_query(-2, vec![]),
            Err(QueryError::Remote(-2))
        );
    }

    #[test]
    fn decodes_pinned_snapshot_info_vectors() {
        let vectors: [&[u8]; 5] = [
            include_bytes!("../../../testdata/cls/dencoder/SnapshotInfo/1.bin"),
            include_bytes!("../../../testdata/cls/dencoder/SnapshotInfo/2.bin"),
            include_bytes!("../../../testdata/cls/dencoder/SnapshotInfo/3.bin"),
            include_bytes!("../../../testdata/cls/dencoder/SnapshotInfo/4.bin"),
            include_bytes!("../../../testdata/cls/dencoder/SnapshotInfo/5.bin"),
        ];
        let ids = [1, 2, 3, 1, 1];
        for (bytes, id) in vectors.into_iter().zip(ids) {
            let info = decode_snapshot_query(0, reply(bytes), id).unwrap();
            assert_eq!(info.id, id);
            assert_eq!(info.name, if id == 3 { b"12345" } else { b"snap1" });
            assert_eq!(info.image_size, 123);
            assert_eq!(info.timestamp_seconds, 123456);
            assert_eq!(info.timestamp_nanoseconds, 0);
        }
        assert!(matches!(
            decode_snapshot_query(0, reply(vectors[0]), 1)
                .unwrap()
                .namespace,
            SnapshotNamespace::User
        ));
        assert!(matches!(
            decode_snapshot_query(0, reply(vectors[1]), 2)
                .unwrap()
                .namespace,
            SnapshotNamespace::Group { pool: 567, .. }
        ));
        assert!(matches!(
            decode_snapshot_query(0, reply(vectors[2]), 3)
                .unwrap()
                .namespace,
            SnapshotNamespace::Trash {
                original_namespace_type: 0,
                ..
            }
        ));
        assert!(matches!(
            decode_snapshot_query(0, reply(vectors[3]), 1)
                .unwrap()
                .namespace,
            SnapshotNamespace::Mirror {
                state: 0,
                primary_snap_id: opwire::NOSNAP,
                ..
            }
        ));
        assert!(matches!(
            decode_snapshot_query(0, reply(vectors[4]), 1)
                .unwrap()
                .namespace,
            SnapshotNamespace::Mirror {
                state: 2,
                primary_snap_id: 123,
                ..
            }
        ));
    }

    #[test]
    fn rejects_malformed_or_mismatched_snapshot() {
        let bytes = include_bytes!("../../../testdata/cls/dencoder/SnapshotInfo/1.bin");
        assert_eq!(
            decode_snapshot_query(-2, vec![], 1),
            Err(QueryError::Remote(-2))
        );
        assert_eq!(
            decode_snapshot_query(0, reply(bytes), 2),
            Err(QueryError::InvalidSnapshot)
        );
        let truncated = &bytes[..bytes.len() - 1];
        assert_eq!(
            decode_snapshot_query(0, reply(truncated), 1),
            Err(QueryError::InvalidSnapshot)
        );
    }

    #[test]
    fn compatible_snapshot_and_namespace_frames_skip_independent_tails() {
        let original = include_bytes!("../../../testdata/cls/dencoder/SnapshotInfo/1.bin");
        let expected = decode_snapshot_query(0, reply(original), 1).unwrap();
        // The namespace begins after the outer envelope and snapshot ID.
        let namespace = 6 + 8;
        let namespace_length =
            u32::from_le_bytes(original[namespace + 2..namespace + 6].try_into().unwrap());
        let namespace_end = namespace + 6 + namespace_length as usize;
        for outer_version in [0, 1, 255] {
            for inner_version in [0, 1, 255] {
                for compat in [0, 1] {
                    let mut bytes = original.to_vec();
                    bytes[0] = outer_version;
                    bytes[1] = compat;
                    bytes[namespace] = inner_version;
                    bytes[namespace + 1] = compat;
                    bytes.splice(namespace_end..namespace_end, [0xdd, 0xee]);
                    bytes[namespace + 2..namespace + 6]
                        .copy_from_slice(&(namespace_length + 2).to_le_bytes());
                    let body_length = u32::from_le_bytes(bytes[2..6].try_into().unwrap()) + 5;
                    bytes.extend([0xaa, 0xbb, 0xcc]);
                    bytes[2..6].copy_from_slice(&body_length.to_le_bytes());
                    bytes.extend([0xff, 0xfe]);
                    assert_eq!(
                        decode_snapshot_query(0, reply(&bytes), 1).unwrap(),
                        expected
                    );
                }
            }
        }
        let mut unknown = original.to_vec();
        unknown[namespace + 6..namespace + 10].copy_from_slice(&99u32.to_le_bytes());
        assert_eq!(
            decode_snapshot_query(0, reply(&unknown), 1)
                .unwrap()
                .namespace,
            SnapshotNamespace::Unknown(99)
        );
    }

    #[test]
    fn compatible_snapshot_decoding_still_enforces_frame_bounds_and_semantics() {
        let original = include_bytes!("../../../testdata/cls/dencoder/SnapshotInfo/1.bin");
        for end in 0..original.len() {
            assert_eq!(
                decode_snapshot_query(0, reply(&original[..end]), 1),
                Err(QueryError::InvalidSnapshot)
            );
        }
        for offset in [1, 15] {
            let mut incompatible = original.to_vec();
            incompatible[offset] = 2;
            assert_eq!(
                decode_snapshot_query(0, reply(&incompatible), 1),
                Err(QueryError::InvalidSnapshot)
            );
        }
        let mut short_namespace = original.to_vec();
        short_namespace[16..20].copy_from_slice(&3u32.to_le_bytes());
        assert_eq!(
            decode_snapshot_query(0, reply(&short_namespace), 1),
            Err(QueryError::InvalidSnapshot)
        );
        let mut short_outer = original.to_vec();
        let length = u32::from_le_bytes(short_outer[2..6].try_into().unwrap()) - 1;
        short_outer[2..6].copy_from_slice(&length.to_le_bytes());
        short_outer.extend([0; 8]);
        assert_eq!(
            decode_snapshot_query(0, reply(&short_outer), 1),
            Err(QueryError::InvalidSnapshot)
        );
        let mut invalid_time = original.to_vec();
        let nanos = invalid_time.len() - 8;
        invalid_time[nanos..nanos + 4].copy_from_slice(&1_000_000_000u32.to_le_bytes());
        assert_eq!(
            decode_snapshot_query(0, reply(&invalid_time), 1),
            Err(QueryError::InvalidSnapshot)
        );
    }

    #[test]
    fn completion_checks_token_provenance_and_preserves_version() {
        let mut queue = ObjectQueue::new(2, 1 << 20, 1).unwrap();
        let expected = queue
            .submit_compound(snapshot_query(7, vec![], b"image1", 1, 4096).unwrap())
            .unwrap();
        let other = queue
            .submit_compound(snapshot_query(7, vec![], b"image2", 1, 4096).unwrap())
            .unwrap();
        let bytes = include_bytes!("../../../testdata/cls/dencoder/SnapshotInfo/1.bin");
        let completion = |token, publication| {
            ReadCompletion::new(
                token,
                ReadOutcome::RemoteCompound {
                    publication,
                    result: 0,
                    user_version: 37,
                    replay_version: Default::default(),
                    operations: reply(bytes),
                },
            )
        };
        assert_eq!(
            decode_snapshot_completion(expected, 1, completion(other, ReadPublication::Reply)),
            Err(QueryError::WrongCompletion)
        );
        assert_eq!(
            decode_snapshot_completion(
                expected,
                1,
                completion(expected, ReadPublication::OutputLimit)
            ),
            Err(QueryError::InvalidPublication)
        );
        let observed =
            decode_snapshot_completion(expected, 1, completion(expected, ReadPublication::Reply))
                .unwrap();
        assert_eq!(observed.user_version, 37);
        assert_eq!(observed.value.id, 1);
    }
}
