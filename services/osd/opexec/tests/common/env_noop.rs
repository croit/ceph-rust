// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Test-only inert bodies for [`opexec::Env`] hooks a test env does not model. The trait has no default bodies (an
//! env that forgets a hook fails to compile); a test env names each hook it leaves inert inside its `impl Env`:
//! `env_noop!(eio_clear, settle);`. Shared by the opexec and peering test crates.

macro_rules! env_noop {
    (@one dup_op_returns) => {
        fn dup_op_returns(&self, _r: &::denc::types::OsdReqId) -> Vec<::pgwire::LogOpReturnItem> {
            Vec::new()
        }
    };
    (@one local_damage) => {
        fn local_damage(&mut self, _soid: &::denc::types::Hobject, _known: Option<::denc::types::Eversion>) -> bool {
            false
        }
    };
    (@one eio_clear) => {
        fn eio_clear(&self) {}
    };
    (@one send_first) => {
        fn send_first(&mut self, _on: bool) {}
    };
    (@one note_io) => {
        fn note_io(&mut self, _io: &::pgwire::IoCount) {}
    };
    (@one run_start) => {
        fn run_start(&mut self, _r: &::denc::types::OsdReqId) {}
    };
    (@one gate_in) => {
        fn gate_in(&mut self, _r: &::denc::types::OsdReqId, _why: u8) {}
    };
    (@one settle) => {
        fn settle(&mut self) {}
    };
    (@one locate) => {
        fn locate(&self, _name: &[u8], _oloc: &::denc::types::ObjectLocator) -> Option<(::denc::types::SpgT, u32)> {
            None
        }
    };
    (@one whoami) => {
        fn whoami(&self) -> i64 {
            0
        }
    };
    (@one blocklisted) => {
        fn blocklisted(&self, _addr: &::denc::types::EntityAddr) -> bool {
            false
        }
    };
    (@one removed_snaps) => {
        fn removed_snaps(&self) -> Vec<(u64, u64)> {
            Vec::new()
        }
    };
    (@one pool_snapc) => {
        fn pool_snapc(&self) -> Option<::replwire::SnapContext> {
            None
        }
    };
    (@one write_room) => {
        fn write_room(&self, _bytes: usize, _entries: usize) -> bool {
            true
        }
    };
    (@one admission_ready) => {
        fn admission_ready(&self) -> bool {
            true
        }
    };
    (@one marked_full_epoch) => {
        fn marked_full_epoch(&self) -> u32 {
            0
        }
    };
    (@one require_osd_release) => {
        fn require_osd_release(&self) -> u8 {
            0
        }
    };
    (@one is_unfound) => {
        fn is_unfound(&self, _head: &::denc::types::Hobject) -> bool {
            false
        }
    };
    (@one kick_recovery) => {
        fn kick_recovery(&mut self, _head: &::denc::types::Hobject) {}
    };
    (@one failsafe_full) => {
        fn failsafe_full(&self) -> bool {
            false
        }
    };
    (@one pool_eio) => {
        fn pool_eio(&self) -> bool {
            false
        }
    };
    (@one pool_full) => {
        fn pool_full(&self) -> (bool, bool) {
            (false, false)
        }
    };
    (@one cls_map) => {
        fn cls_map(&self) -> ::opexec::ClsMap {
            ::opexec::ClsMap::default()
        }
    };
    (@one scrub_ls) => {
        fn scrub_ls(&self, _arg: &::peering::scrubls::LsArg) -> Result<(u32, Vec<Vec<u8>>), i32> {
            Err(2)
        }
    };
    (@one pg_blocked) => {
        fn pg_blocked(&self) -> bool {
            false
        }
    };
    (@one op_stale) => {
        fn op_stale(&self, _op_epoch: u32) -> bool {
            false
        }
    };
    (@one warm) => {
        fn warm(&self, _head: &::denc::types::Hobject, _off: u64, _len: u64) -> bool {
            true
        }
    };
    (@one warm_rm) => {
        fn warm_rm(&self, _head: &::denc::types::Hobject) -> bool {
            true
        }
    };
    (@one warm_log) => {
        fn warm_log(&self) -> bool {
            true
        }
    };
    (@one probe_meta) => {
        fn probe_meta(&self) -> bool {
            true
        }
    };
    (@one warm_data) => {
        fn warm_data(&self, _head: &::denc::types::Hobject, _off: u64, _len: u64) -> bool {
            true
        }
    };
    (@one obj_cache) => {
        fn obj_cache(&self) -> Option<(u64, usize)> {
            None
        }
    };
    (@one ec_pool) => {
        fn ec_pool(&self) -> bool {
            false
        }
    };
    (@one ec_caps) => {
        fn ec_caps(&self) -> ::opexec::EcCaps {
            ::opexec::EcCaps::default()
        }
    };
    (@one copy_stripe_width) => {
        fn copy_stripe_width(&self) -> u64 {
            1
        }
    };
    (@one ec_wait) => {
        fn ec_wait(&mut self, _head: &::denc::types::Hobject, _snapid: u64, _off: u64, _len: u64) -> Option<u64> {
            None
        }
    };
    (@one pool_caps_info) => {
        fn pool_caps_info(&self) -> (&[u8], Option<&::opexec::caps::AppMeta>) {
            (b"", None)
        }
    };
    (@one trim_poll) => {
        fn trim_poll(&mut self) -> ::peering::TrimPoll {
            ::peering::TrimPoll::No
        }
    };
    (@one trim_cfg) => {
        fn trim_cfg(&self) -> ::opexec::trim::TrimCfg {
            ::opexec::trim::TrimCfg::default()
        }
    };
    (@one snap_mapper_next) => {
        fn snap_mapper_next(&self, _snap: u64, _max: usize) -> Result<Vec<::denc::types::Hobject>, ::peering::StoreReadError> {
            Ok(Vec::new())
        }
    };
    (@one trim_snap_done) => {
        fn trim_snap_done(&mut self, _snap: u64) {}
    };
    (@one trim_stop) => {
        fn trim_stop(&mut self, _error: bool) {}
    };
    (@one trim_counted) => {
        fn trim_counted(&mut self, _n: i64) {}
    };
    (@one trim_unmap) => {
        fn trim_unmap(&mut self, _clone: &::denc::types::Hobject) {}
    };
    (@one trim_note) => {
        fn trim_note(&mut self, _msg: String) {}
    };
    (@one list_turn) => {
        fn list_turn(&mut self, _held: bool) -> bool {
            true
        }
    };
    (@one list_ran) => {
        fn list_ran(&mut self) {}
    };
    ($($m:ident),* $(,)?) => {
        $(env_noop!(@one $m);)*
    };
}
