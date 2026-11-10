// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
use crate::Access;
/// Native access policy for stock class definitions in the pinned Ceph version.
/// Unknown pairs remain conservatively ReadWrite; this never grants server access.
pub fn pinned_class_access(class: &[u8], method: &[u8]) -> Access {
    let reader = match class {
        b"lock" => matches!(method, b"get_info" | b"list_locks" | b"assert_locked"),
        b"hello" => matches!(method, b"say_hello" | b"replay"),
        b"journal" => matches!(
            method,
            b"get_order"
                | b"get_splay_width"
                | b"get_pool_id"
                | b"get_minimum_set"
                | b"get_active_set"
                | b"get_client"
                | b"client_list"
                | b"get_next_tag_tid"
                | b"get_tag"
                | b"tag_list"
        ),
        b"version" => matches!(method, b"read" | b"check_conds"),
        b"refcount" => method == b"read",
        b"cas" => method == b"references_chunk",
        b"otp" => matches!(method, b"otp_get" | b"otp_get_result" | b"get_current_time"),
        b"cmpomap" => method == b"cmp_vals",
        b"log" => matches!(method, b"list" | b"info"),
        b"timeindex" => method == b"list",
        b"queue" => matches!(method, b"queue_get_capacity" | b"queue_list_entries"),
        b"2pc_queue" => matches!(
            method,
            b"2pc_queue_get_capacity"
                | b"2pc_queue_get_topic_stats"
                | b"2pc_queue_list_reservations"
                | b"2pc_queue_list_entries"
        ),
        b"rgw_gc" => method == b"rgw_gc_queue_list_entries",
        b"fifo" => matches!(method, b"get_meta" | b"part_list" | b"get_part_info"),
        b"sem_set" => method == b"list",
        b"user" => matches!(
            method,
            b"list_buckets" | b"get_header" | b"account_resource_get" | b"account_resource_list"
        ),
        b"rgw" => matches!(
            method,
            b"bucket_list"
                | b"bucket_check_index"
                | b"bucket_read_olh_log"
                | b"obj_check_attrs_prefix"
                | b"obj_check_mtime"
                | b"bi_get"
                | b"bi_list"
                | b"bi_log_list"
                | b"user_usage_log_read"
                | b"gc_list"
                | b"lc_get_entry"
                | b"lc_get_next_entry"
                | b"lc_get_head"
                | b"lc_list_entries"
                | b"reshard_list"
                | b"reshard_get"
                | b"guard_bucket_resharding"
                | b"get_bucket_resharding"
        ),
        b"rbd" => matches!(
            method,
            b"children_list"
                | b"dir_get_id"
                | b"dir_get_name"
                | b"dir_list"
                | b"dir_state_assert"
                | b"get_access_timestamp"
                | b"get_all_features"
                | b"get_children"
                | b"get_create_timestamp"
                | b"get_data_pool"
                | b"get_features"
                | b"get_flags"
                | b"get_id"
                | b"get_modify_timestamp"
                | b"get_object_prefix"
                | b"get_parent"
                | b"get_protection_status"
                | b"get_size"
                | b"get_snapcontext"
                | b"get_snapshot_name"
                | b"get_snapshot_timestamp"
                | b"get_stripe_unit_count"
                | b"group_dir_list"
                | b"group_image_list"
                | b"group_snap_get_by_id"
                | b"group_snap_list"
                | b"group_snap_list_order"
                | b"image_group_get"
                | b"metadata_get"
                | b"metadata_list"
                | b"migration_get"
                | b"mirror_image_get"
                | b"mirror_image_get_image_id"
                | b"mirror_image_instance_get"
                | b"mirror_image_instance_list"
                | b"mirror_image_list"
                | b"mirror_image_map_list"
                | b"mirror_image_status_get"
                | b"mirror_image_status_get_summary"
                | b"mirror_image_status_list"
                | b"mirror_instances_list"
                | b"mirror_mode_get"
                | b"mirror_peer_list"
                | b"mirror_remote_namespace_get"
                | b"mirror_uuid_get"
                | b"namespace_list"
                | b"object_map_load"
                | b"op_features_get"
                | b"parent_get"
                | b"parent_overlap_get"
                | b"snap_list"
                | b"snapshot_get"
                | b"snapshot_get_limit"
                | b"trash_get"
                | b"trash_list"
        ),
        _ => false,
    };
    if reader {
        Access::Read
    } else {
        Access::ReadWrite
    }
}
