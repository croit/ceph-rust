// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Native RBD image primitives. The transport and application ABI are separate layers.
#![deny(clippy::print_stderr, clippy::print_stdout)]
#![cfg_attr(test, allow(clippy::print_stderr, clippy::print_stdout))]

mod admin_notify;
mod admin_request;
mod children_query;
mod data_read;
mod data_sparse;
mod data_write;
#[cfg(any(test, feature = "journal-testkit", feature = "migration-testkit"))]
pub mod fault_plan;
mod flags_query;
mod group_query;
mod head_observation;
mod head_refresh;
mod header_query;
mod journal_append;
mod journal_backend;
mod journal_client;
mod journal_event;
#[cfg(any(test, feature = "journal-testkit"))]
pub mod journal_mem;
mod journal_meta;
mod journal_player;
mod journal_recovery;
mod journal_writer;
mod layout;
mod legacy_header;
mod lock_takeover;
mod lock_wire;
pub mod luks;
mod metadata_query;
pub mod migration_children;
#[cfg(feature = "migration-testkit")]
pub mod migration_mem;
pub mod migration_revert;
pub mod migration_source;
pub mod migration_store;
pub mod migration_terminal;
mod name_lookup;
mod object_diff;
mod object_map;
mod object_map_rebuild;
mod parent_query;
mod snapcontext_query;
mod snapshot_observation;
mod snapshot_parent;
mod snapshot_query;
mod snapshot_refresh;
mod stripe_query;
mod timestamp_query;
mod watch_notify;
pub mod write_around;

pub use admin_notify::{
    AdminNotify, AdminOperation, AdminSnapshotNamespace, AsyncRequestId, decode_admin_notify,
    encode_admin_notify,
};
pub use admin_request::{
    ADMIN_REQUEST_RESTART, ADMIN_REQUEST_TIMED_OUT, AdminRequest, AdminRequestError,
    AdminRequestEvent, AdminRequests,
};
pub use children_query::{
    ChildImageSpec, ChildrenReplyError, TrashEntry, child_link_input, children_list_input,
    decode_children_list_reply, decode_children_set_reply, decode_trash_get_reply,
    decode_trash_list_reply, get_children_input, trash_list_input,
};
pub use data_read::{
    DataLocator, PlannedRead, RawReadResult, ReadPayload, ReadResolution,
    decode_data_read_completion, resolve_raw_read,
};
pub use data_sparse::{
    RawSparseResult, SparseExtent, SparseReadPayload, decode_sparse_read_completion,
    resolve_sparse_read,
};
pub use data_write::{
    PlannedWrite, PlannedWriteGroup, RawWriteSegments, RawWriteVectorSegments,
    decode_data_write_completion, decode_data_write_group_completion,
};
pub use flags_query::{
    decode_flags_completion, decode_flags_query, decode_op_features_completion, flags_query,
    op_features_query,
};
pub use group_query::{
    ImageGroupSpec, decode_image_group_completion, decode_image_group_query, image_group_query,
};
pub use head_observation::{HeadInputs, HeadObservation, HeadObservationError};
pub use head_refresh::{
    HeadRefreshError, HeadRefreshReceipt, decode_head_refresh_completion,
    decode_head_refresh_query, head_refresh_query, head_refresh_query_allocated,
};
pub use header_query::{
    HEADER_REPLY_CAPACITIES, decode_header_completion, decode_header_query, header_query,
};
pub use journal_append::JournalAppendCursor;
pub use journal_backend::{
    EBADMSG, EBLOCKLISTED, EBUSY, EEXIST, EILSEQ, EINVAL, EIO, ENOENT, ENOMSG, EOPNOTSUPP,
    EOVERFLOW, EPERM, ERANGE, ESTALE, JournalBackend,
};
pub use journal_client::{
    JOURNAL_CLIENT_STATE_CONNECTED, JOURNAL_CLIENT_STATE_DISCONNECTED, JournalClient,
    JournalClientData, JournalClientFields, JournalClientRecord, JournalImageData,
    JournalObjectPosition, JournalSyncPoint, JournalTag, JournalTagData, JournalTagPredecessor,
    decode_image_client_data, decode_journal_client, decode_journal_client_fields_set,
    decode_journal_client_set, decode_journal_image_client, decode_journal_tag,
    decode_journal_tag_set, decode_object_position, decode_positions, decode_tag_data,
    encode_image_client_data, encode_object_position, encode_positions, encode_tag_data,
};
pub use journal_event::{
    JOURNAL_EVENT_VERSION, JournalEvent, JournalEventEntry, JournalEventKind, JournalObjectEntry,
    JournalObjectRecord, JournalObjectScan, JournalObjectStream, JournalRecord,
    decode_journal_event_entry, decode_journal_record, encode_journal_event_entry,
    encode_journal_record, scan_journal_object,
};
pub use journal_meta::{
    JOURNAL_TAG_CLASS_NEW, JournalGeometry, journal_append_input, journal_client_commit_input,
    journal_client_list_input, journal_client_register_input, journal_client_unregister_input,
    journal_client_update_data_input, journal_client_update_state_input, journal_create_input,
    journal_get_client_input, journal_get_tag_input, journal_guard_append_input,
    journal_set_active_set_input, journal_set_minimum_set_input, journal_tag_create_input,
    journal_tag_list_input,
};
pub use journal_player::{JournalPlayer, OBJECT_READ_CHUNK, ReplayRecord};
pub use journal_recovery::{
    RecoveryError, RecoveryStage, ReplayTarget, journaled_append, journaled_complete,
    journaled_mutation, journaled_op, recover, write_events,
};
pub use journal_writer::{
    AIO_COMPARE_AND_WRITE_EVENT_FIXED_SIZE, AIO_WRITE_EVENT_FIXED_SIZE, CLIENT_LIST_PAGE,
    JOURNAL_ENTRY_FIXED_SIZE, JournalClock, JournalWriter, JournalWriterConfig, Ticket,
    WriterState,
};
pub use layout::{CryptoObjectFragment, ImageLayout, LayoutError, ObjectExtent};
pub use legacy_header::{
    LEGACY_BLOCK_PREFIX_MAX, LEGACY_HEADER_FIXED_BYTES, LEGACY_OBJECT_NAME_WIDTH,
    LegacyDirectoryEntry, LegacyDirectoryError, LegacyHeader, LegacyHeaderError, LegacySnapshot,
    RBD_HEADER_TEXT, RBD_MIGRATE_HEADER_TEXT, apply_tmap_commands, build_legacy_header,
    decode_legacy_directory, decode_legacy_snap_list, encode_tmap_remove, encode_tmap_set,
    encode_tmap_set_and_remove, legacy_block_prefix, set_legacy_image_size,
};
pub use lock_takeover::{
    HolderReportError, LOCK_NAME, LockHolder, ManagedHolderError, ManagedLockHolder, Takeover,
    WATCHER_COOKIE_PREFIX, WATCHER_LOCK_TAG, break_request, decide, decode_holders,
    decode_managed_holder, decode_watchers, holders_request, watch_handle, watchers_request,
};
pub use lock_wire::{HeaderLockWire, ObjectMapLockWire, break_lock, info};
pub use metadata_query::QueryError;
pub use name_lookup::{
    IMAGE_ID_REPLY_CAPACITY, IMAGE_NAME_REPLY_CAPACITY, decode_image_id_completion,
    decode_image_id_query, decode_image_name_query, image_id_query, image_name_query,
};
pub use object_diff::{ObjectDiff, ObjectDiffExtent};
pub use object_map::{LoadedObjectMap, MAX_OBJECT_MAP_OBJECTS, ObjectMapDecodeError, ObjectState};
pub use object_map_rebuild::ObjectMapRebuild;
pub use parent_query::{
    ParentSpec, decode_parent_completion, decode_parent_overlap_completion,
    decode_parent_overlap_query, decode_parent_query, parent_attach_input, parent_overlap_query,
    parent_query,
};
pub use snapcontext_query::{
    ImageSnapContext, decode_snapcontext_completion, decode_snapcontext_query, snapcontext_query,
};
pub use snapshot_observation::{SnapshotInputs, SnapshotObservation, SnapshotObservationError};
pub use snapshot_query::{
    SnapshotInfo, SnapshotNamespace, decode_namespace as decode_snapshot_namespace,
    decode_snapshot_completion, decode_snapshot_protection_completion,
    decode_snapshot_protection_query, decode_snapshot_query, encode_snapshot_namespace,
    snapshot_protection_query, snapshot_query,
};
pub use snapshot_refresh::{
    SnapshotRefreshError, SnapshotRefreshReceipt, decode_snapshot_refresh_completion,
    decode_snapshot_refresh_query, snapshot_refresh_query, snapshot_refresh_query_allocated,
};
pub use stripe_query::{
    StripeGeometry, decode_stripe_completion, decode_stripe_query, stripe_query,
};
pub use timestamp_query::{
    IMAGE_TIMESTAMP_REPLY_CAPACITIES, ImageTimestamp, ImageTimestamps,
    decode_image_timestamps_completion, decode_image_timestamps_query, image_timestamps_query,
};
pub use watch_notify::{
    HEADER_UPDATE_NOTIFY, HeaderNotify, LockClientId, LockOwnerReplyError, NotifyAggregateError,
    NotifyDecodeError, NotifyReply, QuiesceReplyError, decode_header_notify,
    decode_lock_owner_reply, decode_quiesce_reply, encode_lock_acquired, encode_lock_released,
    encode_lock_request, encode_notify_response,
};

/// The RBD layering feature bit. An image without it cannot have children.
pub const FEATURE_LAYERING: u64 = 1;

/// STRIPINGV2: the stripe unit and count are stored by their own class getter.
pub(crate) const FEATURE_STRIPING_V2: u64 = 1 << 1;

/// OPERATIONS: the operation feature bits are stored by their own class getter.
pub(crate) const FEATURE_OPERATIONS: u64 = 1 << 8;

/// A value and the OSD user version of the object that produced it. Versions
/// from different objects are not a cluster-wide snapshot or ordering proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Versioned<T> {
    /// Decoded value from the verified completion.
    pub value: T,
    /// OSD user version for the target object at this reply.
    pub user_version: u64,
}

/// Exact replies of the pinned `rbd` class methods used to obtain image geometry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderReplies {
    /// `get_size`: one order byte followed by the image size as little-endian u64.
    pub size: Vec<u8>,
    /// `get_features`: two little-endian u64 values.
    pub features: Vec<u8>,
    /// `get_object_prefix`: a little-endian u32 byte count followed by those bytes.
    pub object_prefix: Vec<u8>,
    /// `get_data_pool`: a little-endian i64; -1 selects the metadata pool.
    pub data_pool: Vec<u8>,
}

/// Decoded RBD image header fields. The prefix remains raw bytes until a caller
/// chooses an object-name representation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageHeader {
    /// Object order returned by `get_size`.
    pub order: u8,
    /// Logical image size in bytes.
    pub size: u64,
    /// Feature bits returned by `get_features`.
    pub features: u64,
    /// Incompatible feature bits returned by `get_features` for the requested mode.
    pub incompatible_features: u64,
    /// Data-object prefix returned by `get_object_prefix`.
    pub object_prefix: Vec<u8>,
    /// Data pool ID returned by `get_data_pool`; -1 means the metadata pool.
    pub data_pool_id: i64,
}

/// A class reply cannot be decoded without inventing missing metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderDecodeError {
    /// The reply did not have the documented length or had trailing bytes.
    InvalidLength,
    /// The class returned an empty data-object prefix.
    EmptyPrefix,
    /// The class returned a data pool ID below the documented -1 sentinel.
    InvalidDataPool,
}

impl std::fmt::Display for HeaderDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidLength => f.write_str("invalid RBD header reply length"),
            Self::EmptyPrefix => f.write_str("empty RBD data-object prefix"),
            Self::InvalidDataPool => f.write_str("invalid RBD data pool ID"),
        }
    }
}

impl std::error::Error for HeaderDecodeError {}

impl ImageHeader {
    /// Decode the four class replies without accepting truncation or
    /// trailing data. This method does not declare the image safe to open: feature,
    /// snapshot, parent and lock policy belong to the image owner.
    pub fn decode(replies: HeaderReplies) -> Result<Self, HeaderDecodeError> {
        let size: [u8; 9] = replies
            .size
            .as_slice()
            .try_into()
            .map_err(|_| HeaderDecodeError::InvalidLength)?;
        let features: [u8; 16] = replies
            .features
            .as_slice()
            .try_into()
            .map_err(|_| HeaderDecodeError::InvalidLength)?;
        let data_pool: [u8; 8] = replies
            .data_pool
            .as_slice()
            .try_into()
            .map_err(|_| HeaderDecodeError::InvalidLength)?;
        let prefix_length: [u8; 4] = replies
            .object_prefix
            .get(..4)
            .ok_or(HeaderDecodeError::InvalidLength)?
            .try_into()
            .map_err(|_| HeaderDecodeError::InvalidLength)?;
        let prefix_length = u32::from_le_bytes(prefix_length) as usize;
        let prefix = &replies.object_prefix[4..];
        if prefix.len() != prefix_length {
            return Err(HeaderDecodeError::InvalidLength);
        }
        if prefix.is_empty() {
            return Err(HeaderDecodeError::EmptyPrefix);
        }
        let data_pool_id = i64::from_le_bytes(data_pool);
        if data_pool_id < -1 {
            return Err(HeaderDecodeError::InvalidDataPool);
        }

        Ok(Self {
            order: size[0],
            size: u64::from_le_bytes(size[1..].try_into().expect("fixed-size slice")),
            features: u64::from_le_bytes(features[..8].try_into().expect("fixed-size slice")),
            incompatible_features: u64::from_le_bytes(
                features[8..].try_into().expect("fixed-size slice"),
            ),
            object_prefix: prefix.to_vec(),
            data_pool_id,
        })
    }

    /// Select the pool for data objects after header validation. A stored -1
    /// uses the metadata pool; a nonnegative ID selects that data pool.
    pub fn data_pool(&self, metadata_pool: i64) -> Result<i64, HeaderDecodeError> {
        if metadata_pool < 0 || self.data_pool_id < -1 {
            return Err(HeaderDecodeError::InvalidDataPool);
        }
        Ok(if self.data_pool_id == -1 {
            metadata_pool
        } else {
            self.data_pool_id
        })
    }
}

pub use snapshot_parent::{SnapshotParentError, snapshot_parent_to_detach};

#[cfg(test)]
mod tests {
    use super::*;

    fn replies() -> HeaderReplies {
        let mut size = vec![22];
        size.extend_from_slice(&123_456_789u64.to_le_bytes());
        let mut features = Vec::new();
        features.extend_from_slice(&0x3du64.to_le_bytes());
        features.extend_from_slice(&0x1u64.to_le_bytes());
        let prefix = b"rbd_data.native";
        let mut object_prefix = (prefix.len() as u32).to_le_bytes().to_vec();
        object_prefix.extend_from_slice(prefix);
        HeaderReplies {
            size,
            features,
            object_prefix,
            data_pool: (-1i64).to_le_bytes().to_vec(),
        }
    }

    #[test]
    fn decodes_owned_exact_header_replies() {
        let header = ImageHeader::decode(replies()).unwrap();
        assert_eq!(header.order, 22);
        assert_eq!(header.size, 123_456_789);
        assert_eq!(header.features, 0x3d);
        assert_eq!(header.incompatible_features, 1);
        assert_eq!(header.object_prefix, b"rbd_data.native");
        assert_eq!(header.data_pool_id, -1);
        assert_eq!(header.data_pool(7), Ok(7));
        assert_eq!(
            header.data_pool(-1),
            Err(HeaderDecodeError::InvalidDataPool)
        );
    }

    #[test]
    fn rejects_truncation_and_trailing_bytes() {
        let original = replies();
        for field in 0..4 {
            for extra in [false, true] {
                let mut malformed = original.clone();
                let bytes = match field {
                    0 => &mut malformed.size,
                    1 => &mut malformed.features,
                    2 => &mut malformed.object_prefix,
                    _ => &mut malformed.data_pool,
                };
                if extra {
                    bytes.push(0);
                } else {
                    bytes.pop();
                }
                assert_eq!(
                    ImageHeader::decode(malformed),
                    Err(HeaderDecodeError::InvalidLength)
                );
            }
        }
    }

    #[test]
    fn rejects_empty_and_forged_prefix_lengths() {
        let mut empty = replies();
        empty.object_prefix = 0u32.to_le_bytes().to_vec();
        assert_eq!(
            ImageHeader::decode(empty),
            Err(HeaderDecodeError::EmptyPrefix)
        );

        let mut forged = replies();
        forged.object_prefix[..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            ImageHeader::decode(forged),
            Err(HeaderDecodeError::InvalidLength)
        );

        let mut separate_pool = replies();
        separate_pool.data_pool = 37i64.to_le_bytes().to_vec();
        let separate = ImageHeader::decode(separate_pool).unwrap();
        assert_eq!(separate.data_pool_id, 37);
        assert_eq!(separate.data_pool(7), Ok(37));

        let mut invalid_pool = replies();
        invalid_pool.data_pool = (-2i64).to_le_bytes().to_vec();
        assert_eq!(
            ImageHeader::decode(invalid_pool),
            Err(HeaderDecodeError::InvalidDataPool)
        );
    }
}
