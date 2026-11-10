// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! osd: sans-IO OSD core (spec: doc/spec/osd-lifecycle.md). M1 = identity, boot state machine,
//! messengers (public / cluster / heartbeat), heartbeats + failure reports, beacon, mgr client,
//! tell commands. Hosts no PGs.
//!
//! Driver contract (like `monc`/`msgr2`): the driver owns sockets and time. It binds the four
//! listeners ([`Listener`]), calls [`Osd::on_accept`] for each accepted socket, drains
//! [`Osd::poll_io`] (`Dial` / `Close`), reports [`Osd::on_connected`] / [`Osd::on_dial_failed`] /
//! [`Osd::on_closed`], feeds [`Osd::on_bytes`], writes [`Osd::poll_output`] per connection id,
//! calls [`Osd::on_timer`] at [`Osd::next_timer`], and drains [`Osd::poll_log`]. `now` is a
//! monotonic [`std::time::Duration`] since an arbitrary origin (`OsdConfig::wall_origin_unix`
//! maps it to unix time).
pub mod asok;
mod attempt;
pub mod auth;
pub mod backend;
mod boot;
pub mod child;
pub mod config;
mod copy;
pub mod crash;
pub mod crushloc;
mod ctrsnap;
mod dedupwire;
mod devmeta;
#[cfg(any(feature = "lab", test))]
pub mod devstore;
mod flow;
mod frame_wait;
mod hb;
pub mod keysrc;
pub mod liveness;
pub mod memory;
pub mod meta;
mod mgrc;
mod mig;
pub mod monboot;
pub mod nvmestore;
mod ops;
pub mod optval;
mod storeid;
pub use ingress::IngressCredits;
pub use xcore::input_credits;
mod optrack;
mod osd;
mod perf;
mod perfx;
mod pgs;
mod pipe;
pub mod portsel;
mod prewrite;
mod rdmastat;
pub mod utilization;
/// PG info as classic JSON (offline tools).
pub use pgs::{info_json, utime_str};
pub mod release;
pub mod schema;
pub mod sysinfo;
mod tell;
mod tellx;
pub mod trace;
mod tracehook;
pub mod version;
pub mod xcore;
#[cfg(test)]
mod xcore_tests;

pub use backend::Backend;
#[cfg(any(feature = "lab", test))]
pub use backend::LabDir;
#[cfg(any(feature = "lab", test))]
pub use devstore::DevMemStore;
#[cfg(any(feature = "lab", test))]
pub use meta::FileMetaStore;
pub use meta::{Identity, MapKind, MetaStore};
pub use nvmestore::{Nvme, NvmeMeta, NvmeStores, open_nvme};
pub use osd::{ACTIVE_MARKER, IoCmd, Listener, LogLine, Osd, OsdConfig, State};
pub use xcore::{CoreSpec, XMsg};

static LOG_REOPEN: std::sync::OnceLock<fn()> = std::sync::OnceLock::new();

/// Register what `log reopen` (admin socket / tell) does: the driver reopens its log file.
pub fn set_log_reopen(f: fn()) {
    let _ = LOG_REOPEN.set(f);
}

static LOG_FLUSH: std::sync::OnceLock<fn()> = std::sync::OnceLock::new();

/// Register what `log flush` does: the driver flushes its log queue and sinks (bounded).
pub fn set_log_flush(f: fn()) {
    let _ = LOG_FLUSH.set(f);
}

static LOG_DUMP: std::sync::OnceLock<fn(String)> = std::sync::OnceLock::new();

/// Register what `log dump` does: the driver writes its recent ring plus the given `logging levels` section to every
/// sink (bounded).
pub fn set_log_dump(f: fn(String)) {
    let _ = LOG_DUMP.set(f);
}

/// `(counter name, value)` list of a process-wide counter source.
pub type NamedCounters = Vec<(String, u64)>;

static PAYLOAD_POOL: std::sync::OnceLock<fn() -> NamedCounters> = std::sync::OnceLock::new();

/// Register the process-wide payload block pool counters (hugepage heap memory, adr 0163 am. 2): `perf dump` logger
/// `flashstore_payload_pool`, one monotonic counter per `(name, value)`.
pub fn set_payload_pool_counters(f: fn() -> NamedCounters) {
    let _ = PAYLOAD_POOL.set(f);
}

pub(crate) fn payload_pool_counters() -> NamedCounters {
    PAYLOAD_POOL.get().map_or_else(Vec::new, |f| f())
}

static DMA_POOL: std::sync::OnceLock<fn() -> NamedCounters> = std::sync::OnceLock::new();

/// Register the SPDK DMA buffer pool counters (adr 0163 am. 3): `perf dump` logger `flashstore_dma_pool`.
pub fn set_dma_pool_counters(f: fn() -> NamedCounters) {
    let _ = DMA_POOL.set(f);
}

static READ_SHARED: std::sync::OnceLock<fn() -> (u64, u64)> = std::sync::OnceLock::new();

/// Register the gauge of store read buffers held as shared reply data (`nvme::shared_pinned`: `(pieces, bytes)`): the
/// `dump_mempools` pool `read_shared` (adr 0043 am. 13).
pub fn set_read_shared_gauge(f: fn() -> (u64, u64)) {
    let _ = READ_SHARED.set(f);
}

pub(crate) fn read_shared() -> (u64, u64) {
    READ_SHARED.get().map_or((0, 0), |f| f())
}

pub(crate) fn dma_pool_counters() -> NamedCounters {
    DMA_POOL.get().map_or_else(Vec::new, |f| f())
}

static HELPER_THREAD_START: std::sync::OnceLock<fn()> = std::sync::OnceLock::new();

/// Register what a helper thread of the OSD (admin socket accept, workers, render) runs first: the driver moves it off
/// the cores' CPUs (it would inherit the CPU of the control core that starts it).
pub fn set_helper_thread_start(f: fn()) {
    let _ = HELPER_THREAD_START.set(f);
}

pub(crate) fn helper_thread_start() {
    if let Some(f) = HELPER_THREAD_START.get() {
        f();
    }
}

pub(crate) fn log_reopen() {
    if let Some(f) = LOG_REOPEN.get() {
        f();
    }
}

pub(crate) fn log_flush() {
    if let Some(f) = LOG_FLUSH.get() {
        f();
    }
}

pub(crate) fn log_dump(levels: String) {
    if let Some(f) = LOG_DUMP.get() {
        f(levels);
    }
}

#[cfg(feature = "mon-std")]
pub mod kdrv;

#[cfg(test)]
mod send_probe {
    fn is_send<T: Send>() {}
    #[test]
    fn probe() {
        is_send::<messages::AnyMessage>();
        is_send::<opwire::MOSDOp>();
        is_send::<peering::Body>();
        is_send::<osdmap::OsdMap>();
        is_send::<std::sync::Arc<osdmap::OsdMap>>();
        is_send::<cephx::monclient::MonAuthClient>();
        is_send::<crate::config::ConfigDb>();
        is_send::<opexec::caps::Caps>();
        is_send::<messages::Segments>();
        is_send::<messages::MOSDMap>();
        is_send::<opwire::MOSDBackoff>();
        is_send::<crate::xcore::XMsg>();
        is_send::<store::shard::HelperJob>();
    }
}
