// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Administrative image-header messages for the pinned Ceph 21.2.0 protocol.
//! Decoding borrows names and original namespace frames. An acceptance response
//! is separate from [`AdminNotify::Complete`] and never grants ownership.

use crate::{LockClientId, SnapshotNamespace};
use denc::{Decoder, Encoder, Error, Result};

/// Full identity used for pending requests and owner-side duplicate detection.
/// Sequence alone is insufficient across different image watches or clients.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AsyncRequestId {
    pub client: LockClientId,
    pub sequence: u64,
}
impl AsyncRequestId {
    /// A fully zero identity selects the legacy final-result-in-ACK protocol.
    pub const fn is_zero(self) -> bool {
        self.client.instance == 0 && self.client.watch_cookie == 0 && self.sequence == 0
    }
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self> {
        Ok(Self {
            client: LockClientId {
                instance: decoder.u64()?,
                watch_cookie: decoder.u64()?,
            },
            sequence: decoder.u64()?,
        })
    }
    fn encode(self, encoder: &mut Encoder) -> Result<()> {
        encoder.u64(self.client.instance)?;
        encoder.u64(self.client.watch_cookie)?;
        encoder.u64(self.sequence)
    }
}

const USER_NAMESPACE: &[u8] = &[1, 1, 4, 0, 0, 0, 0, 0, 0, 0];

/// A validated namespace and its original, bounded wire frame. Keeping both
/// avoids re-encoding compatible future fields when relaying a request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdminSnapshotNamespace<'a> {
    encoded: &'a [u8],
    value: SnapshotNamespace,
}
impl<'a> AdminSnapshotNamespace<'a> {
    pub const fn user() -> Self {
        Self {
            encoded: USER_NAMESPACE,
            value: SnapshotNamespace::User,
        }
    }
    /// Validate exactly one namespace frame, including known variant fields.
    pub fn from_encoded(encoded: &'a [u8]) -> Result<Self> {
        let mut decoder = Decoder::new(encoded);
        let value = Self::decode(&mut decoder, encoded)?;
        if !decoder.is_empty() {
            return Err(Error::TrailingBytes(decoder.remaining()));
        }
        Ok(value)
    }
    pub fn value(&self) -> &SnapshotNamespace {
        &self.value
    }
    pub fn encoded(&self) -> &'a [u8] {
        self.encoded
    }
    fn decode(decoder: &mut Decoder<'a>, input: &'a [u8]) -> Result<Self> {
        let start = decoder.position();
        let value = crate::snapshot_query::decode_namespace(decoder)?;
        Ok(Self {
            encoded: &input[start..decoder.position()],
            value,
        })
    }
}

/// Operation payload; admission, per-kind serialization and execution are
/// responsibilities of the image coordinator, not of this wire codec.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdminOperation<'a> {
    Flatten,
    Resize {
        size: u64,
        allow_shrink: bool,
    },
    SnapshotCreate {
        name: &'a [u8],
        namespace: AdminSnapshotNamespace<'a>,
        flags: u64,
    },
    SnapshotRemove {
        name: &'a [u8],
        namespace: AdminSnapshotNamespace<'a>,
    },
    RebuildObjectMap,
    SnapshotRename {
        source_id: u64,
        destination: &'a [u8],
        namespace: AdminSnapshotNamespace<'a>,
    },
    SnapshotProtect {
        name: &'a [u8],
        namespace: AdminSnapshotNamespace<'a>,
    },
    SnapshotUnprotect {
        name: &'a [u8],
        namespace: AdminSnapshotNamespace<'a>,
    },
    ImageRename {
        destination: &'a [u8],
    },
    UpdateFeatures {
        features: u64,
        enabled: bool,
    },
    Migrate,
    Sparsify {
        sparse_size: u64,
    },
    MetadataUpdate {
        key: &'a [u8],
        /// None removes the key; Some(empty) stores an empty value.
        value: Option<&'a [u8]>,
    },
}

/// Administrative notification; completion can arrive before the initial
/// acceptance notify finishes. Receivers must settle pending state once.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdminNotify<'a> {
    Progress {
        id: AsyncRequestId,
        offset: u64,
        total: u64,
    },
    Complete {
        id: AsyncRequestId,
        result: i32,
    },
    Request {
        id: AsyncRequestId,
        operation: AdminOperation<'a>,
    },
    /// Broadcast to every watcher. Its ACK is the FINAL quiesce result,
    /// independent of exclusive ownership; there is no AsyncComplete channel.
    Quiesce {
        id: AsyncRequestId,
    },
    /// Broadcast cancellation of the matching quiesce cycle; ACK is empty.
    Unquiesce {
        id: AsyncRequestId,
    },
    /// Not an administrative opcode implemented by this decoder. No action is
    /// implied, and the unknown body is not interpreted or re-encoded.
    Other(u32),
}

/// Decode inside NotifyMessage's declared body boundary, accepting compatible
/// trailing fields. Pre-v7 snapshot requests have a zero legacy identity;
/// other administrative requests always contain the full unframed identity.
pub fn decode_admin_notify(input: &[u8]) -> Result<AdminNotify<'_>> {
    Decoder::new(input).versioned(1, |body, version| {
        let opcode = body.u32()?;
        if opcode == 4 {
            return Ok(AdminNotify::Progress {
                id: AsyncRequestId::decode(body)?,
                offset: body.u64()?,
                total: body.u64()?,
            });
        }
        if opcode == 5 {
            return Ok(AdminNotify::Complete {
                id: AsyncRequestId::decode(body)?,
                result: body.i32()?,
            });
        }
        if opcode == 18 {
            return Ok(AdminNotify::Quiesce {
                id: AsyncRequestId::decode(body)?,
            });
        }
        if opcode == 19 {
            return Ok(AdminNotify::Unquiesce {
                id: AsyncRequestId::decode(body)?,
            });
        }
        let (id, operation) = match opcode {
            6 => (AsyncRequestId::decode(body)?, AdminOperation::Flatten),
            7 => {
                let size = body.u64()?;
                let id = AsyncRequestId::decode(body)?;
                let allow_shrink = version < 4 || body.u8()? != 0;
                (id, AdminOperation::Resize { size, allow_shrink })
            }
            8 | 9 | 11..=13 => {
                let source_id = if opcode == 11 { body.u64()? } else { 0 };
                let name = body.bytes()?;
                let namespace = if version >= 6 || (opcode == 8 && version == 5) {
                    AdminSnapshotNamespace::decode(body, input)?
                } else {
                    AdminSnapshotNamespace::user()
                };
                let id = if version >= 7 {
                    AsyncRequestId::decode(body)?
                } else {
                    AsyncRequestId::default()
                };
                let operation = match opcode {
                    8 => AdminOperation::SnapshotCreate {
                        name,
                        namespace,
                        flags: if version >= 7 { body.u64()? } else { 0 },
                    },
                    9 => AdminOperation::SnapshotRemove { name, namespace },
                    11 => AdminOperation::SnapshotRename {
                        source_id,
                        destination: name,
                        namespace,
                    },
                    12 => AdminOperation::SnapshotProtect { name, namespace },
                    13 => AdminOperation::SnapshotUnprotect { name, namespace },
                    _ => unreachable!("snapshot opcode matched above"),
                };
                (id, operation)
            }
            10 => (
                AsyncRequestId::decode(body)?,
                AdminOperation::RebuildObjectMap,
            ),
            14 | 15 | 20 => {
                let operation = match opcode {
                    14 => AdminOperation::ImageRename {
                        destination: body.bytes()?,
                    },
                    15 => AdminOperation::UpdateFeatures {
                        features: body.u64()?,
                        enabled: body.u8()? != 0,
                    },
                    20 => AdminOperation::MetadataUpdate {
                        key: body.bytes()?,
                        value: if body.u8()? == 0 {
                            None
                        } else {
                            Some(body.bytes()?)
                        },
                    },
                    _ => unreachable!("versioned trailing identity opcode matched above"),
                };
                let id = if version >= 7 {
                    AsyncRequestId::decode(body)?
                } else {
                    AsyncRequestId::default()
                };
                (id, operation)
            }
            16 => (AsyncRequestId::decode(body)?, AdminOperation::Migrate),
            17 => (
                AsyncRequestId::decode(body)?,
                AdminOperation::Sparsify {
                    sparse_size: body.u64()?,
                },
            ),
            _ => return Ok(AdminNotify::Other(opcode)),
        };
        Ok(AdminNotify::Request { id, operation })
    })
}

/// Encode modern v7 messages. Unknown opcodes cannot be synthesized from a
/// decoded [`AdminNotify::Other`] because their uninterpreted body is absent.
pub fn encode_admin_notify(notification: &AdminNotify<'_>) -> Result<Vec<u8>> {
    let mut encoder = Encoder::new();
    encoder.versioned(7, 1, |body| {
        match notification {
            AdminNotify::Progress { id, offset, total } => {
                body.u32(4)?;
                id.encode(body)?;
                body.u64(*offset)?;
                body.u64(*total)?;
            }
            AdminNotify::Complete { id, result } => {
                body.u32(5)?;
                id.encode(body)?;
                body.i32(*result)?;
            }
            AdminNotify::Quiesce { id } => {
                body.u32(18)?;
                id.encode(body)?;
            }
            AdminNotify::Unquiesce { id } => {
                body.u32(19)?;
                id.encode(body)?;
            }
            AdminNotify::Request { id, operation } => match operation {
                AdminOperation::Flatten => {
                    body.u32(6)?;
                    id.encode(body)?;
                }
                AdminOperation::Resize { size, allow_shrink } => {
                    body.u32(7)?;
                    body.u64(*size)?;
                    id.encode(body)?;
                    body.u8(u8::from(*allow_shrink))?;
                }
                AdminOperation::RebuildObjectMap => {
                    body.u32(10)?;
                    id.encode(body)?;
                }
                AdminOperation::SnapshotCreate {
                    name,
                    namespace,
                    flags,
                } => {
                    body.u32(8)?;
                    body.bytes(name)?;
                    body.raw(namespace.encoded())?;
                    id.encode(body)?;
                    body.u64(*flags)?;
                }
                AdminOperation::SnapshotRemove { name, namespace } => {
                    body.u32(9)?;
                    body.bytes(name)?;
                    body.raw(namespace.encoded())?;
                    id.encode(body)?;
                }
                AdminOperation::SnapshotRename {
                    source_id,
                    destination,
                    namespace,
                } => {
                    body.u32(11)?;
                    body.u64(*source_id)?;
                    body.bytes(destination)?;
                    body.raw(namespace.encoded())?;
                    id.encode(body)?;
                }
                AdminOperation::SnapshotProtect { name, namespace } => {
                    body.u32(12)?;
                    body.bytes(name)?;
                    body.raw(namespace.encoded())?;
                    id.encode(body)?;
                }
                AdminOperation::SnapshotUnprotect { name, namespace } => {
                    body.u32(13)?;
                    body.bytes(name)?;
                    body.raw(namespace.encoded())?;
                    id.encode(body)?;
                }
                AdminOperation::ImageRename { destination } => {
                    body.u32(14)?;
                    body.bytes(destination)?;
                    id.encode(body)?;
                }
                AdminOperation::UpdateFeatures { features, enabled } => {
                    body.u32(15)?;
                    body.u64(*features)?;
                    body.u8(u8::from(*enabled))?;
                    id.encode(body)?;
                }
                AdminOperation::Migrate => {
                    body.u32(16)?;
                    id.encode(body)?;
                }
                AdminOperation::Sparsify { sparse_size } => {
                    body.u32(17)?;
                    id.encode(body)?;
                    body.u64(*sparse_size)?;
                }
                AdminOperation::MetadataUpdate { key, value } => {
                    body.u32(20)?;
                    body.bytes(key)?;
                    body.u8(u8::from(value.is_some()))?;
                    if let Some(value) = value {
                        body.bytes(value)?;
                    }
                    id.encode(body)?;
                }
            },
            AdminNotify::Other(_) => return Err(Error::BadValue("unknown administrative opcode")),
        }
        Ok(())
    })?;
    Ok(encoder.into_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    const ID: AsyncRequestId = AsyncRequestId {
        client: LockClientId {
            instance: 11,
            watch_cookie: 22,
        },
        sequence: 33,
    };
    fn frame(version: u8, opcode: u32, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![version, 1];
        bytes.extend_from_slice(&(4u32 + payload.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&opcode.to_le_bytes());
        bytes.extend_from_slice(payload);
        bytes
    }
    fn identity() -> Vec<u8> {
        [11u64, 22, 33]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect()
    }
    #[test]
    fn resize_golden_wire_places_size_before_full_id_and_shrink_last() {
        let bytes = [
            7, 1, 37, 0, 0, 0, 7, 0, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 11, 0, 0, 0, 0, 0, 0, 0, 22, 0,
            0, 0, 0, 0, 0, 0, 33, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let value = AdminNotify::Request {
            id: ID,
            operation: AdminOperation::Resize {
                size: 4096,
                allow_shrink: false,
            },
        };
        assert_eq!(decode_admin_notify(&bytes).unwrap(), value);
        assert_eq!(encode_admin_notify(&value).unwrap(), bytes);
        for end in 0..bytes.len() {
            assert!(decode_admin_notify(&bytes[..end]).is_err());
        }
    }
    #[test]
    fn completion_is_signed_and_does_not_use_the_acceptance_response_format() {
        let mut body = identity();
        body.extend_from_slice(&(-30i32).to_le_bytes());
        let bytes = frame(7, 5, &body);
        assert_eq!(bytes.len(), 38);
        let value = AdminNotify::Complete {
            id: ID,
            result: -30,
        };
        assert_eq!(decode_admin_notify(&bytes).unwrap(), value);
        assert_eq!(encode_admin_notify(&value).unwrap(), bytes);
        // A response has no message discriminator: its signed zero can also
        // be read as an unrelated operation. It must never settle a request.
        assert_eq!(
            decode_admin_notify(&crate::encode_notify_response(0)).unwrap(),
            AdminNotify::Other(0)
        );
    }
    #[test]
    fn full_identity_distinguishes_clients_cookies_and_legacy_zero() {
        use std::collections::HashSet;
        let ids = [
            ID,
            AsyncRequestId { sequence: 0, ..ID },
            AsyncRequestId {
                client: LockClientId {
                    instance: 12,
                    ..ID.client
                },
                ..ID
            },
            AsyncRequestId {
                client: LockClientId {
                    watch_cookie: 23,
                    ..ID.client
                },
                ..ID
            },
        ];
        assert_eq!(ids.into_iter().collect::<HashSet<_>>().len(), 4);
        assert!(AsyncRequestId::default().is_zero());
        assert!(ids.into_iter().all(|id| !id.is_zero()));
    }
    #[test]
    fn resize_legacy_versions_keep_full_id_and_default_shrink_permission() {
        let mut body = 4096u64.to_le_bytes().to_vec();
        body.extend(identity());
        for version in [0, 1, 2, 3] {
            assert_eq!(
                decode_admin_notify(&frame(version, 7, &body)).unwrap(),
                AdminNotify::Request {
                    id: ID,
                    operation: AdminOperation::Resize {
                        size: 4096,
                        allow_shrink: true
                    }
                }
            );
        }
        body.push(9);
        assert!(matches!(
            decode_admin_notify(&frame(4, 7, &body)).unwrap(),
            AdminNotify::Request {
                operation: AdminOperation::Resize {
                    allow_shrink: true,
                    ..
                },
                ..
            }
        ));
        assert!(decode_admin_notify(&frame(4, 7, &body[..32])).is_err());
    }
    #[test]
    fn snapshot_legacy_base_and_v5_create_namespace_have_no_async_identity() {
        let mut body = vec![4, 0, 0, 0, b'b', b'a', b's', b'e'];
        for version in [0, 1, 4] {
            assert_eq!(
                decode_admin_notify(&frame(version, 8, &body)).unwrap(),
                AdminNotify::Request {
                    id: AsyncRequestId::default(),
                    operation: AdminOperation::SnapshotCreate {
                        name: b"base",
                        namespace: AdminSnapshotNamespace::user(),
                        flags: 0
                    }
                }
            );
        }
        body.extend(USER_NAMESPACE);
        for version in [5, 6] {
            assert!(
                matches!(decode_admin_notify(&frame(version, 8, &body)).unwrap(), AdminNotify::Request { id, operation: AdminOperation::SnapshotCreate { flags: 0, .. } } if id.is_zero())
            );
        }
        assert!(
            matches!(decode_admin_notify(&frame(6, 9, &body)).unwrap(), AdminNotify::Request { id, operation: AdminOperation::SnapshotRemove { .. } } if id.is_zero())
        );
    }
    #[test]
    fn rename_user_namespace_is_the_full_variant_frame_and_names_borrow_bytes() {
        let mut body = 42u64.to_le_bytes().to_vec();
        body.extend([2, 0, 0, 0, 0xff, 0xfe]);
        body.extend(USER_NAMESPACE);
        body.extend(identity());
        let bytes = frame(7, 11, &body);
        match decode_admin_notify(&bytes).unwrap() {
            AdminNotify::Request {
                id,
                operation:
                    AdminOperation::SnapshotRename {
                        source_id,
                        destination,
                        namespace,
                    },
            } => {
                assert_eq!((id, source_id, destination), (ID, 42, &[0xff, 0xfe][..]));
                assert_eq!(destination.as_ptr(), bytes[22..].as_ptr());
                assert_eq!(namespace.encoded(), USER_NAMESPACE);
                assert_eq!(namespace.value(), &SnapshotNamespace::User);
            }
            other => panic!("unexpected rename {other:?}"),
        }
        assert!(
            matches!(decode_admin_notify(&frame(5, 11, &body[..14])).unwrap(), AdminNotify::Request { id, operation: AdminOperation::SnapshotRename { .. } } if id.is_zero())
        );
        assert!(
            matches!(decode_admin_notify(&frame(6, 11, &body[..24])).unwrap(), AdminNotify::Request { id, operation: AdminOperation::SnapshotRename { .. } } if id.is_zero())
        );
    }
    #[test]
    fn all_known_modern_messages_roundtrip_and_outer_future_fields_are_bounded() {
        let user = AdminSnapshotNamespace::user;
        let operations = [
            AdminOperation::Flatten,
            AdminOperation::RebuildObjectMap,
            AdminOperation::SnapshotCreate {
                name: b"new",
                namespace: user(),
                flags: 0x1234,
            },
            AdminOperation::SnapshotRemove {
                name: b"old",
                namespace: user(),
            },
            AdminOperation::SnapshotProtect {
                name: b"s",
                namespace: user(),
            },
            AdminOperation::SnapshotUnprotect {
                name: b"s",
                namespace: user(),
            },
            AdminOperation::ImageRename {
                destination: b"renamed",
            },
            AdminOperation::UpdateFeatures {
                features: 0x1234,
                enabled: true,
            },
            AdminOperation::Migrate,
            AdminOperation::Sparsify { sparse_size: 4096 },
            AdminOperation::MetadataUpdate {
                key: b"key",
                value: None,
            },
            AdminOperation::MetadataUpdate {
                key: b"key",
                value: Some(b""),
            },
            AdminOperation::MetadataUpdate {
                key: b"key",
                value: Some(b"value"),
            },
        ];
        for operation in operations {
            let value = AdminNotify::Request { id: ID, operation };
            let mut bytes = encode_admin_notify(&value).unwrap();
            assert_eq!(decode_admin_notify(&bytes).unwrap(), value);
            let length = u32::from_le_bytes(bytes[2..6].try_into().unwrap()) + 2;
            bytes[0] = 8;
            bytes[2..6].copy_from_slice(&length.to_le_bytes());
            bytes.extend([9, 8, 7]);
            assert_eq!(decode_admin_notify(&bytes).unwrap(), value);
        }
        let progress = AdminNotify::Progress {
            id: ID,
            offset: 7,
            total: 91,
        };
        let bytes = encode_admin_notify(&progress).unwrap();
        assert_eq!(decode_admin_notify(&bytes).unwrap(), progress);
        for value in [
            AdminNotify::Quiesce { id: ID },
            AdminNotify::Unquiesce { id: ID },
        ] {
            let bytes = encode_admin_notify(&value).unwrap();
            assert_eq!(decode_admin_notify(&bytes).unwrap(), value);
            for version in [0, 1, 6, 7] {
                let mut older = bytes.clone();
                older[0] = version;
                assert_eq!(decode_admin_notify(&older).unwrap(), value);
            }
            for end in 0..bytes.len() {
                assert!(decode_admin_notify(&bytes[..end]).is_err());
            }
        }
        assert_eq!(
            decode_admin_notify(&frame(7, 99, &[1, 2])).unwrap(),
            AdminNotify::Other(99)
        );
        assert!(encode_admin_notify(&AdminNotify::Other(99)).is_err());
    }
    #[test]
    fn additional_operations_keep_their_distinct_identity_and_optional_value_rules() {
        let rename = [1, 0, 0, 0, b'n'];
        let mut features = 0x1234u64.to_le_bytes().to_vec();
        features.push(7); // any nonzero bool is true
        let remove = [1, 0, 0, 0, b'k', 0];
        let empty_value = [1, 0, 0, 0, b'k', 9, 0, 0, 0, 0];
        for version in [0, 1, 6, 7] {
            for (opcode, payload, operation) in [
                (
                    14,
                    &rename[..],
                    AdminOperation::ImageRename { destination: b"n" },
                ),
                (
                    15,
                    &features[..],
                    AdminOperation::UpdateFeatures {
                        features: 0x1234,
                        enabled: true,
                    },
                ),
                (
                    20,
                    &remove[..],
                    AdminOperation::MetadataUpdate {
                        key: b"k",
                        value: None,
                    },
                ),
                (
                    20,
                    &empty_value[..],
                    AdminOperation::MetadataUpdate {
                        key: b"k",
                        value: Some(b""),
                    },
                ),
            ] {
                let mut payload = payload.to_vec();
                let id = if version >= 7 {
                    payload.extend(identity());
                    ID
                } else {
                    AsyncRequestId::default()
                };
                let bytes = frame(version, opcode, &payload);
                assert_eq!(
                    decode_admin_notify(&bytes).unwrap(),
                    AdminNotify::Request { id, operation }
                );
                for end in 0..bytes.len() {
                    assert!(decode_admin_notify(&bytes[..end]).is_err());
                }
            }
            let bytes = frame(version, 16, &identity());
            assert_eq!(
                decode_admin_notify(&bytes).unwrap(),
                AdminNotify::Request {
                    id: ID,
                    operation: AdminOperation::Migrate
                }
            );
            let mut sparse = identity();
            sparse.extend(65536u64.to_le_bytes());
            let bytes = frame(version, 17, &sparse);
            assert_eq!(
                decode_admin_notify(&bytes).unwrap(),
                AdminNotify::Request {
                    id: ID,
                    operation: AdminOperation::Sparsify { sparse_size: 65536 }
                }
            );
            for end in 0..bytes.len() {
                assert!(decode_admin_notify(&bytes[..end]).is_err());
            }
        }
        let bytes = encode_admin_notify(&AdminNotify::Request {
            id: ID,
            operation: AdminOperation::Sparsify { sparse_size: 65536 },
        })
        .unwrap();
        assert_eq!(&bytes[10..34], identity());
        assert_eq!(&bytes[34..42], &65536u64.to_le_bytes());
    }

    #[test]
    fn notification_namespace_keeps_compatible_frame_tail_when_reencoded() {
        for version in [0, 1, 255] {
            let namespace = [version, 1, 6, 0, 0, 0, 0, 0, 0, 0, 0xaa, 0xbb];
            let value = AdminNotify::Request {
                id: ID,
                operation: AdminOperation::SnapshotCreate {
                    name: b"s",
                    namespace: AdminSnapshotNamespace::from_encoded(&namespace).unwrap(),
                    flags: 0x1234,
                },
            };
            let bytes = encode_admin_notify(&value).unwrap();
            let decoded = decode_admin_notify(&bytes).unwrap();
            assert_eq!(decoded, value);
            assert_eq!(encode_admin_notify(&decoded).unwrap(), bytes);
        }
    }
    #[test]
    fn nested_namespace_validation_and_declared_lengths_reject_malformed_fields() {
        assert_eq!(
            AdminSnapshotNamespace::from_encoded(USER_NAMESPACE)
                .unwrap()
                .value(),
            &SnapshotNamespace::User
        );
        let mut trailing = USER_NAMESPACE.to_vec();
        trailing.push(0);
        assert!(AdminSnapshotNamespace::from_encoded(&trailing).is_err());
        let mut malformed = vec![1, 1, 4, 0, 0, 0, 1, 0, 0, 0]; // GROUP lacks pool and IDs.
        assert!(AdminSnapshotNamespace::from_encoded(&malformed).is_err());
        malformed = vec![7, 1, 255, 255, 255, 255, 8, 0, 0, 0];
        assert!(decode_admin_notify(&malformed).is_err());
        let mut incompatible =
            encode_admin_notify(&AdminNotify::Complete { id: ID, result: 0 }).unwrap();
        incompatible[1] = 2;
        assert_eq!(
            decode_admin_notify(&incompatible),
            Err(Error::CompatTooNew {
                compat: 2,
                supported: 1
            })
        );
    }
}
