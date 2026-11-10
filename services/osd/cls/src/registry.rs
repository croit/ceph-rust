// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Static class/method registry (spec/cls.md s1, s2) with static dispatch.
//!
//! Two phases, no `dyn`, no dlopen, no allocation:
//! 1. classification: [`lookup`]`(class, method) -> Option<&'static Method>` (flags for the cap check
//!    and the RD/WR enforcement; `None` = `-EOPNOTSUPP` for the whole message);
//! 2. execution: [`call`]`::<C>(ctx, method, input)` is a monomorphized `match` on the method's
//!    enum id (a jump table), no string compare.

use crate::ctx::ClsCtx;
use crate::errno::*;
use crate::rgw::{
    bi as rb, gc as rgc, index as ri, lc as rlc, mp as rmp, obj as ro, olh as rolh, reshard as rr,
    usage as ru,
};

use crate::{
    cas, cephfs, cmpomap, fifo, hello, journal, lock, log, numops, otp, queue, rbd, refcount,
    rgw_gc, sdk, sem_set, timeindex, tpc_queue, user, version,
};

pub const RD: u8 = 1;
pub const WR: u8 = 2;
/// Cache-tier hint (cls.md s2): carried, ignored.
pub const PROMOTE: u8 = 8;
pub const RW: u8 = RD | WR;

/// One registered method.
#[derive(Debug, Clone, Copy)]
pub struct Method {
    pub class: &'static str,
    pub name: &'static str,
    /// RD | WR (| PROMOTE).
    pub flags: u8,
    id: Id,
}
impl Method {
    pub fn rd(&self) -> bool {
        self.flags & RD != 0
    }
    pub fn wr(&self) -> bool {
        self.flags & WR != 0
    }
}

/// Result of a method run: `ret` (0 / negative errno) and the out bytes (empty on error here; the
/// executor appends them to the op's outdata regardless of `ret`, cls.md s3 step 6).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Reply {
    pub ret: i32,
    pub out: Vec<u8>,
}

/// Handler result: `Result<Vec<u8>, Errno>` (out only on success) or a full [`Reply`] (methods that
/// deliver output with a negative return, e.g. rgw `bucket_list` -EFBIG).
pub trait IntoReply {
    fn into_reply(self) -> Reply;
}
impl IntoReply for Result<Vec<u8>, Errno> {
    fn into_reply(self) -> Reply {
        match self {
            Ok(out) => Reply { ret: 0, out },
            Err(e) => Reply {
                ret: e,
                out: Vec::new(),
            },
        }
    }
}
/// Methods without output bytes.
impl IntoReply for Result<(), Errno> {
    fn into_reply(self) -> Reply {
        Reply {
            ret: self.err().unwrap_or(0),
            out: Vec::new(),
        }
    }
}
impl IntoReply for Reply {
    fn into_reply(self) -> Reply {
        self
    }
}

/// One class: its method enum, the method table (`METHODS`) and the dispatch `match`.
macro_rules! class_table {
    ($(#[$em:meta])* $enum:ident;
     $( $variant:ident $name:literal $flags:expr => $f:path; )*) => {
        #[derive(Debug, Clone, Copy)]
        $(#[$em])*
        enum $enum { $($variant),* }
        impl $enum {
            const METHODS: &[Method] = &[
                $(Method { class: $enum::CLASS, name: $name, flags: $flags,
                           id: Id::$enum($enum::$variant) }),*
            ];
            fn dispatch<C: ClsCtx>(self, c: &mut C, input: &[u8]) -> Reply {
                match self { $($enum::$variant => $f(c, input).into_reply()),* }
            }
        }
    };
}

/// The class list (the only one): class name -> method enum. Generates [`CLASSES`], [`methods`]
/// and [`call`].
macro_rules! classes {
    ($($class:literal => $enum:ident,)*) => {
        #[derive(Debug, Clone, Copy)]
        #[expect(clippy::enum_variant_names)]
        enum Id { $($enum($enum)),* }
        $(impl $enum { const CLASS: &str = $class; })*

        /// Classes known to the registry = the classes this binary could serve; `osd_class_load_list` decides which
        /// are served and `osd_class_default_list` which plain class-read/-write caps reach (cls.md s2.1).
        pub const CLASSES: &[&str] = &[$($class),*];

        /// All methods of `class` (empty for an unknown class).
        pub fn methods(class: &str) -> &'static [Method] {
            match class {
                $($class => $enum::METHODS,)*
                _ => &[],
            }
        }

        /// Execute a looked-up method. Input decode failures are `-EINVAL` inside the handlers.
        /// Flag enforcement (RD/WR counters) is the executor's job (cls.md s3 step 5).
        pub fn call<C: ClsCtx>(ctx: &mut C, m: &'static Method, input: &[u8]) -> Reply {
            match m.id {
                $(Id::$enum(id) => id.dispatch(ctx, input)),*
            }
        }
    };
}

classes! {
    "lock" => LockId,
    "rbd" => RbdId,
    "version" => VersionId,
    "refcount" => RefcountId,
    "rgw" => RgwId,
    "queue" => QueueId,
    "rgw_gc" => RgwGcId,
    "user" => UserId,
    "log" => LogId,
    "timeindex" => TimeindexId,
    "fifo" => FifoId,
    "journal" => JournalId,
    "hello" => HelloId,
    "sdk" => SdkId,
    "numops" => NumopsId,
    "cmpomap" => CmpomapId,
    "sem_set" => SemSetId,
    "cas" => CasId,
    "otp" => OtpId,
    "cephfs" => CephfsId,
    "2pc_queue" => TpcQueueId,
}

class_table! { VersionId;
    Set "set" RW => version::set;
    Inc "inc" RW => version::inc;
    IncConds "inc_conds" RW => version::inc;
    Read "read" RD => version::read;
    CheckConds "check_conds" RD => version::check_conds_m;
}

class_table! { RgwId;
    BucketInitIndex "bucket_init_index" RW => ri::init_index;
    BucketInitIndex2 "bucket_init_index2" RW => ri::init_index;
    BucketSetTagTimeout "bucket_set_tag_timeout" RW => ri::set_tag_timeout;
    BucketList "bucket_list" RD => ri::bucket_list;
    BucketCheckIndex "bucket_check_index" RD => ri::check_index;
    BucketRebuildIndex "bucket_rebuild_index" RW => ri::rebuild_index;
    BucketUpdateStats "bucket_update_stats" RW => ri::update_stats;
    BucketPrepareOp "bucket_prepare_op" RW => ri::prepare_op;
    BucketCompleteOp "bucket_complete_op" RW => ri::complete_op;
    ObjRemove "obj_remove" RW => ro::obj_remove;
    ObjStorePgVer "obj_store_pg_ver" WR => ro::obj_store_pg_ver;
    ObjCheckAttrsPrefix "obj_check_attrs_prefix" RD => ro::obj_check_attrs_prefix;
    ObjCheckMtime "obj_check_mtime" RD => ro::obj_check_mtime;
    ReshardLogTrim "reshard_log_trim" RW => ri::reshard_log_trim;
    DirSuggestChanges "dir_suggest_changes" RW => ri::dir_suggest_changes;
    SetBucketResharding "set_bucket_resharding" RW => ri::set_bucket_resharding;
    ClearBucketResharding "clear_bucket_resharding" RW => ri::clear_bucket_resharding;
    GuardBucketResharding "guard_bucket_resharding" RD => ri::guard_bucket_resharding;
    GetBucketResharding "get_bucket_resharding" RD => ri::get_bucket_resharding;
    ReshardAdd "reshard_add" RW => rr::reshard_add;
    ReshardList "reshard_list" RD => rr::reshard_list;
    ReshardGet "reshard_get" RD => rr::reshard_get;
    ReshardRemove "reshard_remove" RW => rr::reshard_remove;
    BucketLinkOlh "bucket_link_olh" RW => rolh::link_olh;
    BucketUnlinkInstance "bucket_unlink_instance" RW => rolh::unlink_instance;
    BucketReadOlhLog "bucket_read_olh_log" RD => rolh::read_olh_log;
    BucketTrimOlhLog "bucket_trim_olh_log" RW => rolh::trim_olh_log;
    BucketClearOlh "bucket_clear_olh" RW => rolh::clear_olh;
    BiGet "bi_get" RD => rb::bi_get;
    BiPut "bi_put" RW => rb::bi_put;
    BiPutEntries "bi_put_entries" RW => rb::bi_put_entries;
    BiList "bi_list" RD => rb::bi_list;
    BiLogList "bi_log_list" RD => rb::bi_log_list;
    BiLogTrim "bi_log_trim" RW => rb::bi_log_trim;
    BiLogResync "bi_log_resync" RW => rb::bi_log_resync;
    BiLogStop "bi_log_stop" RW => rb::bi_log_stop;
    UserUsageLogAdd "user_usage_log_add" RW => ru::user_usage_log_add;
    UserUsageLogRead "user_usage_log_read" RD => ru::user_usage_log_read;
    UserUsageLogTrim "user_usage_log_trim" RW => ru::user_usage_log_trim;
    UsageLogClear "usage_log_clear" WR => ru::usage_log_clear;
    GcSetEntry "gc_set_entry" RW => rgc::gc_set_entry;
    GcDeferEntry "gc_defer_entry" RW => rgc::gc_defer_entry;
    GcList "gc_list" RD => rgc::gc_list;
    GcRemove "gc_remove" RW => rgc::gc_remove;
    LcGetEntry "lc_get_entry" RD => rlc::lc_get_entry;
    LcSetEntry "lc_set_entry" RW => rlc::lc_set_entry;
    LcRmEntry "lc_rm_entry" RW => rlc::lc_rm_entry;
    LcGetNextEntry "lc_get_next_entry" RD => rlc::lc_get_next_entry;
    LcPutHead "lc_put_head" RW => rlc::lc_put_head;
    LcGetHead "lc_get_head" RD => rlc::lc_get_head;
    LcListEntries "lc_list_entries" RD => rlc::lc_list_entries;
    MpUploadPartInfoUpdate "mp_upload_part_info_update" RW => rmp::mp_upload_part_info_update;
}

class_table! { QueueId;
    Init "queue_init" RW => queue::m_init;
    GetCapacity "queue_get_capacity" RD => queue::m_get_capacity;
    Enqueue "queue_enqueue" RW => queue::m_enqueue;
    ListEntries "queue_list_entries" RD => queue::m_list_entries;
    RemoveEntries "queue_remove_entries" RW => queue::m_remove_entries;
}

class_table! { #[expect(clippy::enum_variant_names)] RgwGcId;
    QueueInit "rgw_gc_queue_init" RW => rgw_gc::queue_init;
    QueueEnqueue "rgw_gc_queue_enqueue" RW => rgw_gc::queue_enqueue;
    QueueListEntries "rgw_gc_queue_list_entries" RD => rgw_gc::queue_list_entries;
    QueueRemoveEntries "rgw_gc_queue_remove_entries" RW => rgw_gc::queue_remove_entries;
    QueueUpdateEntry "rgw_gc_queue_update_entry" RW => rgw_gc::queue_update_entry;
}

class_table! { UserId;
    SetBucketsInfo "set_buckets_info" RW => user::set_buckets_info;
    CompleteStatsSync "complete_stats_sync" RW => user::complete_stats_sync;
    RemoveBucket "remove_bucket" RW => user::remove_bucket;
    ListBuckets "list_buckets" RD => user::list_buckets;
    GetHeader "get_header" RD => user::get_header;
    ResetUserStats "reset_user_stats" RW => user::reset_user_stats;
    ResetUserStats2 "reset_user_stats2" RW => user::reset_user_stats2;
    AccountResourceAdd "account_resource_add" RW => user::account_resource_add;
    AccountResourceGet "account_resource_get" RD => user::account_resource_get;
    AccountResourceRm "account_resource_rm" RW => user::account_resource_rm;
    AccountResourceList "account_resource_list" RD => user::account_resource_list;
}

class_table! { LogId;
    Add "add" RW => log::add;
    List "list" RD => log::list;
    Trim "trim" RW => log::trim;
    Info "info" RD => log::info;
}

class_table! { TimeindexId;
    Add "add" RW => timeindex::add;
    List "list" RD => timeindex::list;
    Trim "trim" RW => timeindex::trim;
}

class_table! { FifoId;
    CreateMeta "create_meta" RW => fifo::create_meta;
    GetMeta "get_meta" RD => fifo::get_meta;
    UpdateMeta "update_meta" RW => fifo::update_meta;
    InitPart "init_part" RW => fifo::init_part;
    PushPart "push_part" RW => fifo::push_part;
    TrimPart "trim_part" RW => fifo::trim_part;
    PartList "part_list" RD => fifo::part_list;
    GetPartInfo "get_part_info" RD => fifo::get_part_info;
}

class_table! { JournalId;
    Create "create" RW => journal::create;
    GetOrder "get_order" RD => journal::get_order;
    GetSplayWidth "get_splay_width" RD => journal::get_splay_width;
    GetPoolId "get_pool_id" RD => journal::get_pool_id;
    GetMinimumSet "get_minimum_set" RD => journal::get_minimum_set;
    SetMinimumSet "set_minimum_set" RW => journal::set_minimum_set;
    GetActiveSet "get_active_set" RD => journal::get_active_set;
    SetActiveSet "set_active_set" RW => journal::set_active_set;
    GetClient "get_client" RD => journal::get_client;
    ClientRegister "client_register" RW => journal::client_register;
    ClientUpdateData "client_update_data" RW => journal::client_update_data;
    ClientUpdateState "client_update_state" RW => journal::client_update_state;
    ClientUnregister "client_unregister" RW => journal::client_unregister;
    ClientCommit "client_commit" RW => journal::client_commit;
    ClientList "client_list" RD => journal::client_list;
    GetNextTagTid "get_next_tag_tid" RD => journal::get_next_tag_tid;
    GetTag "get_tag" RD => journal::get_tag;
    TagCreate "tag_create" RW => journal::tag_create;
    TagList "tag_list" RD => journal::tag_list;
    GuardAppend "guard_append" RW => journal::guard_append;
    Append "append" RW => journal::append;
}

class_table! { HelloId;
    SayHello "say_hello" RD => hello::say_hello;
    RecordHello "record_hello" WR | PROMOTE => hello::record_hello;
    WriteReturnData "write_return_data" WR => hello::write_return_data;
    WritesDontReturnData "writes_dont_return_data" WR => hello::write_return_data;
    WriteTooMuchReturnData "write_too_much_return_data" WR => hello::write_too_much_return_data;
    Replay "replay" RD => hello::replay;
    TurnItTo11 "turn_it_to_11" RW | PROMOTE => hello::turn_it_to_11;
    BadReader "bad_reader" WR => hello::bad_reader;
    BadWriter "bad_writer" RD => hello::bad_writer;
}
class_table! { SdkId;
    TestCoverageWrite "test_coverage_write" RW => sdk::test_coverage_write;
    TestCoverageReplay "test_coverage_replay" RW => sdk::test_coverage_replay;
}
class_table! { NumopsId;
    Add "add" RW => numops::add;
    Mul "mul" RW => numops::mul;
}
class_table! { #[expect(clippy::enum_variant_names)] CmpomapId;
    CmpVals "cmp_vals" RD => cmpomap::cmp_vals;
    CmpSetVals "cmp_set_vals" RW => cmpomap::cmp_set_vals;
    CmpRmKeys "cmp_rm_keys" RW => cmpomap::cmp_rm_keys;
}
class_table! { SemSetId;
    Increment "increment" RW => sem_set::increment;
    Decrement "decrement" RW => sem_set::decrement;
    Reset "reset" RW => sem_set::reset;
    List "list" RD => sem_set::list;
}
class_table! { CasId;
    ChunkCreateOrGetRef "chunk_create_or_get_ref" RW => cas::chunk_create_or_get_ref;
    ChunkGetRef "chunk_get_ref" RW => cas::chunk_get_ref;
    ChunkPutRef "chunk_put_ref" RW => cas::chunk_put_ref;
    ReferencesChunk "references_chunk" RD => cas::references_chunk;
}
class_table! { TpcQueueId;
    Init "2pc_queue_init" RW => tpc_queue::init;
    GetCapacity "2pc_queue_get_capacity" RD => queue::m_get_capacity;
    GetTopicStats "2pc_queue_get_topic_stats" RD => tpc_queue::get_topic_stats;
    Reserve "2pc_queue_reserve" RW => tpc_queue::reserve;
    Commit "2pc_queue_commit" RW => tpc_queue::commit;
    Abort "2pc_queue_abort" RW => tpc_queue::abort;
    ListReservations "2pc_queue_list_reservations" RD => tpc_queue::list_reservations;
    ListEntries "2pc_queue_list_entries" RD => queue::m_list_entries;
    RemoveEntries "2pc_queue_remove_entries" RW => tpc_queue::remove_entries;
    ExpireReservations "2pc_queue_expire_reservations" RW => tpc_queue::expire_reservations;
}
class_table! { OtpId;
    OtpSet "otp_set" RW => otp::otp_set;
    OtpGet "otp_get" RD => otp::otp_get;
    OtpCheck "otp_check" RW => otp::otp_check;
    OtpGetResult "otp_get_result" RD => otp::otp_get_result;
    OtpRemove "otp_remove" RW => otp::otp_remove;
    GetCurrentTime "get_current_time" RD => otp::get_current_time;
}
class_table! { CephfsId;
    AccumulateInodeMetadata "accumulate_inode_metadata" RW => cephfs::accumulate_inode_metadata;
}
class_table! { RefcountId;
    Get "get" RW => refcount::get;
    Put "put" RW => refcount::put;
    Set "set" RW => refcount::set;
    Read "read" RD => refcount::read;
}

class_table! { LockId;
    Lock "lock" RW | PROMOTE => lock::lock;
    Unlock "unlock" RW | PROMOTE => lock::unlock;
    BreakLock "break_lock" RW => lock::break_lock;
    GetInfo "get_info" RD => lock::get_info;
    ListLocks "list_locks" RD => lock::list_locks;
    AssertLocked "assert_locked" RD | PROMOTE => lock::assert_locked;
    SetCookie "set_cookie" RW | PROMOTE => lock::set_cookie;
}

use rbd::{
    data, header as h, layering as l, mirror as m, mirror_status as ms, objmap as o, snap as s,
    trash as t,
};
use rbd::{group as g, migration as mg, oldfmt as of};

class_table! { RbdId;
    Create "create" RW => h::create;
    GetFeatures "get_features" RD => h::get_features;
    SetFeatures "set_features" RW => h::set_features;
    GetSize "get_size" RD => h::get_size;
    SetSize "set_size" RW => h::set_size;
    GetObjectPrefix "get_object_prefix" RD => h::get_object_prefix;
    GetDataPool "get_data_pool" RD => h::get_data_pool;
    GetAllFeatures "get_all_features" RD => h::get_all_features;
    GetCreateTimestamp "get_create_timestamp" RD => h::get_create_timestamp;
    GetAccessTimestamp "get_access_timestamp" RD => h::get_access_timestamp;
    GetModifyTimestamp "get_modify_timestamp" RD => h::get_modify_timestamp;
    SetAccessTimestamp "set_access_timestamp" RW => h::set_access_timestamp;
    SetModifyTimestamp "set_modify_timestamp" RW => h::set_modify_timestamp;
    GetFlags "get_flags" RD => h::get_flags;
    SetFlags "set_flags" RW => h::set_flags;
    OpFeaturesGet "op_features_get" RD => h::op_features_get;
    OpFeaturesSet "op_features_set" RW => h::op_features_set;
    GetStripeUnitCount "get_stripe_unit_count" RD => h::get_stripe_unit_count;
    SetStripeUnitCount "set_stripe_unit_count" RW => h::set_stripe_unit_count;
    GetSnapcontext "get_snapcontext" RD => h::get_snapcontext;
    MetadataList "metadata_list" RD => h::metadata_list;
    MetadataSet "metadata_set" RW => h::metadata_set;
    MetadataGet "metadata_get" RD => h::metadata_get;
    MetadataRemove "metadata_remove" RW => h::metadata_remove;
    GetId "get_id" RD => h::get_id;
    SetId "set_id" RW => h::set_id;
    DirAddImage "dir_add_image" RW => h::dir_add_image;
    DirRemoveImage "dir_remove_image" RW => h::dir_remove_image;
    DirRenameImage "dir_rename_image" RW => h::dir_rename_image;
    DirGetId "dir_get_id" RD => h::dir_get_id;
    DirGetName "dir_get_name" RD => h::dir_get_name;
    DirList "dir_list" RD => h::dir_list;
    DirStateAssert "dir_state_assert" RD => h::dir_state_assert;
    DirStateSet "dir_state_set" RW => h::dir_state_set;
    ImageGroupGet "image_group_get" RD => h::image_group_get;
    ImageGroupAdd "image_group_add" RW => h::image_group_add;
    ImageGroupRemove "image_group_remove" RW => h::image_group_remove;
    SnapshotGet "snapshot_get" RD => s::snapshot_get;
    GetSnapshotName "get_snapshot_name" RD => s::get_snapshot_name;
    GetSnapshotTimestamp "get_snapshot_timestamp" RD => s::get_snapshot_timestamp;
    SnapshotAdd "snapshot_add" RW => s::snapshot_add;
    SnapshotRemove "snapshot_remove" RW => s::snapshot_remove;
    SnapshotRename "snapshot_rename" RW => s::snapshot_rename;
    SnapshotTrashAdd "snapshot_trash_add" RW => s::snapshot_trash_add;
    SnapshotGetLimit "snapshot_get_limit" RD => s::snapshot_get_limit;
    SnapshotSetLimit "snapshot_set_limit" RW => s::snapshot_set_limit;
    SetProtectionStatus "set_protection_status" RW => s::set_protection_status;
    GetProtectionStatus "get_protection_status" RD => s::get_protection_status;
    ParentGet "parent_get" RD => l::parent_get;
    ParentOverlapGet "parent_overlap_get" RD => l::parent_overlap_get;
    ParentAttach "parent_attach" RW => l::parent_attach;
    ParentDetach "parent_detach" RW => l::parent_detach;
    GetParent "get_parent" RD => l::get_parent;
    SetParent "set_parent" RW => l::set_parent;
    RemoveParent "remove_parent" RW => l::remove_parent;
    AddChild "add_child" RW => l::add_child;
    RemoveChild "remove_child" RW => l::remove_child;
    GetChildren "get_children" RD => l::get_children;
    ChildAttach "child_attach" RW => l::child_attach;
    ChildDetach "child_detach" RW => l::child_detach;
    ChildrenList "children_list" RD => l::children_list;
    TrashAdd "trash_add" RW => t::trash_add;
    TrashRemove "trash_remove" RW => t::trash_remove;
    TrashList "trash_list" RD => t::trash_list;
    TrashGet "trash_get" RD => t::trash_get;
    TrashStateSet "trash_state_set" RW => t::trash_state_set;
    NamespaceAdd "namespace_add" RW => t::namespace_add;
    NamespaceRemove "namespace_remove" RW => t::namespace_remove;
    NamespaceList "namespace_list" RD => t::namespace_list;
    ObjectMapLoad "object_map_load" RD => o::object_map_load;
    ObjectMapSave "object_map_save" RW => o::object_map_save;
    ObjectMapResize "object_map_resize" RW => o::object_map_resize;
    ObjectMapUpdate "object_map_update" RW => o::object_map_update;
    ObjectMapSnapAdd "object_map_snap_add" RW => o::object_map_snap_add;
    ObjectMapSnapRemove "object_map_snap_remove" RW => o::object_map_snap_remove;
    Copyup "copyup" RW => data::copyup;
    SparseCopyup "sparse_copyup" RW => data::sparse_copyup;
    AssertSnapcSeq "assert_snapc_seq" RW => data::assert_snapc_seq;
    Sparsify "sparsify" RW => data::sparsify;
    MirrorImageGet "mirror_image_get" RD => m::mirror_image_get;
    MirrorImageRemove "mirror_image_remove" RW => m::mirror_image_remove;
    MirrorModeGet "mirror_mode_get" RD => m::mirror_mode_get;
    MirrorUuidGet "mirror_uuid_get" RD => m::mirror_uuid_get;
    MirrorPeerList "mirror_peer_list" RD => m::mirror_peer_list;
    MirrorImageList "mirror_image_list" RD => m::mirror_image_list;
    MirrorImageGetImageId "mirror_image_get_image_id" RD => m::mirror_image_get_image_id;
    // mirroring block (cls_rbd.md C.3); PROMOTE ignored
    MirrorImageSet "mirror_image_set" RW => m::mirror_image_set;
    MirrorImageSnapshotSetCopyProgress "mirror_image_snapshot_set_copy_progress" RW => m::mirror_image_snapshot_set_copy_progress;
    MirrorImageSnapshotUnlinkPeer "mirror_image_snapshot_unlink_peer" RW => m::mirror_image_snapshot_unlink_peer;
    MirrorImageMapList "mirror_image_map_list" RD => m::mirror_image_map_list;
    MirrorImageMapUpdate "mirror_image_map_update" WR => m::mirror_image_map_update;
    MirrorImageMapRemove "mirror_image_map_remove" WR => m::mirror_image_map_remove;
    MirrorImageStatusGet "mirror_image_status_get" RD => ms::mirror_image_status_get;
    MirrorImageStatusGetSummary "mirror_image_status_get_summary" RD => ms::mirror_image_status_get_summary;
    MirrorImageStatusList "mirror_image_status_list" RD => ms::mirror_image_status_list;
    MirrorImageStatusRemove "mirror_image_status_remove" RW => ms::mirror_image_status_remove;
    MirrorImageStatusRemoveDown "mirror_image_status_remove_down" RW => ms::mirror_image_status_remove_down;
    MirrorImageStatusSet "mirror_image_status_set" RW | PROMOTE => ms::mirror_image_status_set;
    MirrorImageInstanceGet "mirror_image_instance_get" RD => ms::mirror_image_instance_get;
    MirrorImageInstanceList "mirror_image_instance_list" RD => ms::mirror_image_instance_list;
    MirrorInstancesAdd "mirror_instances_add" RW | PROMOTE => m::mirror_instances_add;
    MirrorInstancesList "mirror_instances_list" RD => m::mirror_instances_list;
    MirrorInstancesRemove "mirror_instances_remove" RW => m::mirror_instances_remove;
    MirrorModeSet "mirror_mode_set" RW => m::mirror_mode_set;
    MirrorPeerAdd "mirror_peer_add" RW => m::mirror_peer_add;
    MirrorPeerPing "mirror_peer_ping" RW => m::mirror_peer_ping;
    MirrorPeerRemove "mirror_peer_remove" RW => m::mirror_peer_remove;
    MirrorPeerSetClient "mirror_peer_set_client" RW => m::mirror_peer_set_client;
    MirrorPeerSetCluster "mirror_peer_set_cluster" RW => m::mirror_peer_set_cluster;
    MirrorPeerSetDirection "mirror_peer_set_direction" RW => m::mirror_peer_set_direction;
    MirrorRemoteNamespaceGet "mirror_remote_namespace_get" RD => m::mirror_remote_namespace_get;
    MirrorRemoteNamespaceSet "mirror_remote_namespace_set" RW => m::mirror_remote_namespace_set;
    MirrorUuidSet "mirror_uuid_set" RW => m::mirror_uuid_set;
    // ---- groups, migration, v1-format snapshots (cls_rbd.md B.9-B.9b) ----
    GroupDirList "group_dir_list" RD => g::group_dir_list;
    GroupDirAdd "group_dir_add" RW => g::group_dir_add;
    GroupDirRemove "group_dir_remove" RW => g::group_dir_remove;
    GroupDirRename "group_dir_rename" RW => g::group_dir_rename;
    GroupImageRemove "group_image_remove" RW => g::group_image_remove;
    GroupImageList "group_image_list" RD => g::group_image_list;
    GroupImageSet "group_image_set" RW => g::group_image_set;
    GroupSnapSet "group_snap_set" RW => g::group_snap_set;
    GroupSnapRemove "group_snap_remove" RW => g::group_snap_remove;
    GroupSnapGetById "group_snap_get_by_id" RD => g::group_snap_get_by_id;
    GroupSnapList "group_snap_list" RD => g::group_snap_list;
    GroupSnapListOrder "group_snap_list_order" RD => g::group_snap_list_order;
    MigrationSet "migration_set" RW => mg::migration_set;
    MigrationSetState "migration_set_state" RW => mg::migration_set_state;
    MigrationGet "migration_get" RD => mg::migration_get;
    MigrationRemove "migration_remove" RW => mg::migration_remove;
    SnapList "snap_list" RD => of::snap_list;
    SnapAdd "snap_add" RW => of::snap_add;
    SnapRemove "snap_remove" RW => of::snap_remove;
    SnapRename "snap_rename" RW => of::snap_rename;
}

/// Classification lookup. `None`: unknown class or method -> `-EOPNOTSUPP` for the whole message.
pub fn lookup(class: &str, method: &str) -> Option<&'static Method> {
    methods(class).iter().find(|m| m.name == method)
}

/// Convenience: classification + execution by name (`-EOPNOTSUPP` if unregistered).
pub fn call_by_name<C: ClsCtx>(ctx: &mut C, class: &str, method: &str, input: &[u8]) -> Reply {
    match lookup(class, method) {
        Some(m) => call(ctx, m, input),
        None => Reply {
            ret: EOPNOTSUPP,
            out: Vec::new(),
        },
    }
}
