// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Byte-exact decode/re-encode of fixtures generated once from a Ceph container with
//! `ceph-dencoder` (testdata/gen-dencoder.sh, TEMPORARY oracle; the .bin files are OUR fixtures).
//! Every `select_test` instance of each type must survive `decode -> encode` unchanged.
mod common;
use common::rt;

#[test]
fn version_refcount_types() {
    use cls::{refcount as rc, version as v};
    rt::<v::ObjVersion>("obj_version");
    rt::<v::SetOp>("cls_version_set_op");
    rt::<v::IncOp>("cls_version_inc_op");
    rt::<v::CheckOp>("cls_version_check_op");
    rt::<v::ReadRet>("cls_version_read_ret");
    rt::<rc::GetOp>("cls_refcount_get_op");
    rt::<rc::PutOp>("cls_refcount_put_op");
    rt::<rc::SetOp>("cls_refcount_set_op");
    rt::<rc::ReadOp>("cls_refcount_read_op");
    rt::<rc::ReadRet>("cls_refcount_read_ret");
    rt::<rc::ObjRefcount>("obj_refcount"); // the persisted `refcount` xattr
}

#[test]
fn rgw_stored_types() {
    use cls::rgw::types::*;
    rt::<DirEntry>("rgw_bucket_dir_entry");
    rt::<DirEntryMeta>("rgw_bucket_dir_entry_meta");
    rt::<DirHeader>("rgw_bucket_dir_header");
    rt::<Dir>("rgw_bucket_dir");
    rt::<CategoryStats>("rgw_bucket_category_stats");
    rt::<EntryVer>("rgw_bucket_entry_ver");
    rt::<PendingInfo>("rgw_bucket_pending_info");
    rt::<InstanceEntry>("cls_rgw_bucket_instance_entry");
    rt::<ObjKey>("cls_rgw_obj_key");
    rt::<OlhEntry>("rgw_bucket_olh_entry");
    rt::<OlhLogEntry>("rgw_bucket_olh_log_entry");
    rt::<DeletedEntry>("rgw_bucket_deleted_entry");
    rt::<BiEntry>("rgw_cls_bi_entry");
    rt::<BiLogEntry>("rgw_bi_log_entry");
}

#[test]
fn rgw_method_io_types() {
    use cls::rgw::types::*;
    rt::<TagTimeoutOp>("rgw_cls_tag_timeout_op");
    rt::<ObjPrepareOp>("rgw_cls_obj_prepare_op");
    rt::<ObjCompleteOp>("rgw_cls_obj_complete_op");
    rt::<LinkOlhOp>("rgw_cls_link_olh_op");
    rt::<UnlinkInstanceOp>("rgw_cls_unlink_instance_op");
    rt::<ReadOlhLogOp>("rgw_cls_read_olh_log_op");
    rt::<ReadOlhLogRet>("rgw_cls_read_olh_log_ret");
    rt::<TrimOlhLogOp>("rgw_cls_trim_olh_log_op");
    rt::<ClearOlhOp>("rgw_cls_bucket_clear_olh_op");
    rt::<ListOp>("rgw_cls_list_op");
    rt::<ListRet>("rgw_cls_list_ret");
    rt::<CheckIndexRet>("rgw_cls_check_index_ret");
    rt::<ObjRemoveOp>("rgw_cls_obj_remove_op");
    rt::<StorePgVerOp>("rgw_cls_obj_store_pg_ver_op");
    rt::<CheckAttrsPrefixOp>("rgw_cls_obj_check_attrs_prefix");
    rt::<BiGetOp>("rgw_cls_bi_get_op");
    rt::<BiGetRet>("rgw_cls_bi_get_ret");
    rt::<BiPutOp>("rgw_cls_bi_put_op");
    rt::<BiPutEntriesOp>("rgw_cls_bi_put_entries_op");
    rt::<BiListOp>("rgw_cls_bi_list_op");
    rt::<BiListRet>("rgw_cls_bi_list_ret");
    rt::<BiLogListOp>("cls_rgw_bi_log_list_op");
    rt::<BiLogListRet>("cls_rgw_bi_log_list_ret");
    rt::<BiLogTrimOp>("cls_rgw_bi_log_trim_op");
    rt::<GuardOp>("cls_rgw_guard_bucket_resharding_op");
    rt::<SetReshardingOp>("cls_rgw_set_bucket_resharding_op");
    rt::<EmptyOp>("cls_rgw_clear_bucket_resharding_op");
    rt::<ReshardEntry>("cls_rgw_reshard_entry");
    rt::<ReshardAddOp>("cls_rgw_reshard_add_op");
    rt::<ReshardListOp>("cls_rgw_reshard_list_op");
    rt::<ReshardListRet>("cls_rgw_reshard_list_ret");
    rt::<ReshardGetOp>("cls_rgw_reshard_get_op");
    rt::<ReshardGetRet>("cls_rgw_reshard_get_ret");
    rt::<ReshardRemoveOp>("cls_rgw_reshard_remove_op");
}
