// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! ceph-dencoder fixtures (see dencoder.rs): queue and rgw_gc types, byte-exact round trips.
mod common;
use common::rt;

#[test]
fn queue_and_gc_types() {
    use cls::{queue as q, rgw_gc as g};
    rt::<q::Head>("cls_queue_head");
    rt::<q::Marker>("cls_queue_marker");
    rt::<q::InitOp>("cls_queue_init_op");
    rt::<q::EnqueueOp>("cls_queue_enqueue_op");
    rt::<q::ListOp>("cls_queue_list_op");
    rt::<q::ListRet>("cls_queue_list_ret");
    rt::<q::RemoveOp>("cls_queue_remove_op");
    rt::<q::GetCapacityRet>("cls_queue_get_capacity_ret");
    rt::<q::Entry>("cls_queue_entry");
    rt::<g::GcObjInfo>("cls_rgw_gc_obj_info");
    rt::<g::GcObj>("cls_rgw_obj");
    rt::<g::GcChain>("cls_rgw_obj_chain");
    rt::<g::SetEntryOp>("cls_rgw_gc_set_entry_op");
    rt::<g::ListOp>("cls_rgw_gc_list_op");
    rt::<g::ListRet>("cls_rgw_gc_list_ret");
    rt::<g::QueueInitOp>("cls_rgw_gc_queue_init_op");
    rt::<g::UrgentData>("cls_rgw_gc_urgent_data");
}
