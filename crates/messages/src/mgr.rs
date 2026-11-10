// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Mgr-facing messages and perf-counter encoding helpers (spec osd-lifecycle.md section 8).

use crate::meta;
use crate::msg::{Message, Segments, end, front_with, get_psm, put_psm};
use crate::types::{OsdStat, StoreStatfs};
use denc::types::{EntityAddrVec, PgT, UTime, Uuid};
use denc::{BufMut, Decode, Decoder, Encode, Encoder, Result};
use std::collections::BTreeMap;

// ---------------------------------------------------------------- MgrMap

/// Parsed prefix of a MgrMap (v>=6 layout); the remainder is skipped via the struct length.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MgrMapPrefix {
    pub epoch: u32,
    pub active_addrs: EntityAddrVec,
    pub active_gid: u64,
    pub available: bool,
    pub active_name: String,
}

impl MgrMapPrefix {
    /// Highest MgrMap struct_compat we understand.
    pub const MAX_COMPAT: u8 = 6;

    /// Parse the first five fields of an encoded MgrMap.
    pub fn parse(raw: &[u8]) -> Result<Self> {
        Decoder::new(raw).versioned_min(6, Self::MAX_COMPAT, |d, _| {
            Ok(MgrMapPrefix {
                epoch: d.u32()?,
                active_addrs: EntityAddrVec::decode(d)?,
                active_gid: d.u64()?,
                available: d.bool()?,
                active_name: String::decode(d)?,
            })
        })
    }
}

/// MMgrMap (0x704): the bare MgrMap. Kept opaque (`raw`) with the parsed prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MMgrMap {
    pub raw: Vec<u8>,
    pub prefix: MgrMapPrefix,
}
impl Default for MMgrMap {
    /// Minimal valid MgrMap (epoch 0, no active mgr): the prefix is encoded as given, so `raw` always matches it.
    fn default() -> Self {
        let prefix = MgrMapPrefix::default();
        let mut e = Encoder::new();
        let r = e.versioned(14, MgrMapPrefix::MAX_COMPAT, |e| {
            prefix.epoch.encode(e)?;
            prefix.active_addrs.encode(e)?;
            prefix.active_gid.encode(e)?;
            prefix.available.encode(e)?;
            prefix.active_name.encode(e)
        });
        debug_assert!(r.is_ok());
        MMgrMap {
            raw: e.into_vec(),
            prefix,
        }
    }
}
impl MMgrMap {
    /// Wrap an encoded MgrMap (parses the prefix).
    pub fn from_raw(raw: Vec<u8>) -> Result<Self> {
        let prefix = MgrMapPrefix::parse(&raw)?;
        Ok(MMgrMap { raw, prefix })
    }
}
impl Message for MMgrMap {
    meta!(0x704, 1, 1);
    fn encode(&self, _f: u64) -> Result<Segments> {
        Ok(Segments::front(self.raw.clone()))
    }
    fn decode(_v: u16, front: &[u8], _m: &[u8], _d: &[u8]) -> Result<Self> {
        MMgrMap::from_raw(front.to_vec())
    }
}

// ---------------------------------------------------------------- config blobs

/// `config_bl` content of MMgrOpen: non-default options with per-level values + ignored mon values.
/// Levels: 0 default, 1 mon, 2 file, 3 env, 4 cmdline, 5 override, 6 final.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ConfigBl {
    pub options: Vec<(String, Vec<(i32, String)>)>,
    pub ignored_mon_values: BTreeMap<String, String>,
}
impl ConfigBl {
    pub fn encode(&self) -> Result<Vec<u8>> {
        front_with(denc::features::ALL, |e| {
            e.count(self.options.len())?;
            for (name, levels) in &self.options {
                name.encode(e)?;
                e.count(levels.len())?;
                for (lvl, val) in levels {
                    e.i32(*lvl)?;
                    val.encode(e)?;
                }
            }
            self.ignored_mon_values.encode(e)
        })
    }
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(b);
        let n = d.count()?;
        let mut options = Vec::with_capacity(n.min(1024));
        for _ in 0..n {
            let name = String::decode(&mut d)?;
            let m = d.count()?;
            let mut levels = Vec::with_capacity(m.min(8));
            for _ in 0..m {
                levels.push((d.i32()?, String::decode(&mut d)?));
            }
            options.push((name, levels));
        }
        Ok(ConfigBl {
            options,
            ignored_mon_values: BTreeMap::decode(&mut d)?,
        })
    }
}

/// `config_defaults_bl` content of MMgrOpen: `(name, default_value)` pairs.
pub fn encode_config_defaults_bl(defaults: &[(String, String)]) -> Result<Vec<u8>> {
    front_with(denc::features::ALL, |e| {
        e.count(defaults.len())?;
        defaults.iter().try_for_each(|(k, v)| {
            k.encode(e)?;
            v.encode(e)
        })
    })
}

/// Inverse of [`encode_config_defaults_bl`].
pub fn decode_config_defaults_bl(b: &[u8]) -> Result<Vec<(String, String)>> {
    let mut d = Decoder::new(b);
    let n = d.count()?;
    let mut v = Vec::with_capacity(n.min(1024));
    for _ in 0..n {
        v.push((String::decode(&mut d)?, String::decode(&mut d)?));
    }
    Ok(v)
}

/// Wire form of an empty [`ConfigBl`]: empty options vec (`u32 0`) + empty ignored-mon-values map (`u32 0`).
const EMPTY_CONFIG_BL: [u8; 8] = [0; 8];
/// Wire form of an empty config-defaults list: empty `vec<(string, string)>` (`u32 0`).
const EMPTY_CONFIG_DEFAULTS_BL: [u8; 4] = [0; 4];

// ---------------------------------------------------------------- MMgrOpen / Configure / Close

/// MMgrOpen (0x700, hv=3 hc=1). For a plain OSD: `service_name=""`, `service_daemon=false`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MMgrOpenPayload<S> {
    /// OSD id as decimal text.
    pub daemon_name: S,
    pub service_name: S,
    pub service_daemon: bool,
    /// Only encoded when `service_daemon`.
    pub daemon_metadata: BTreeMap<S, S>,
    /// Only encoded when `service_daemon`.
    pub daemon_status: BTreeMap<S, S>,
    /// Encoded [`ConfigBl`] (empty form: [`ConfigBl::default`]).
    pub config_bl: Vec<u8>,
    /// Encoded defaults (empty form: 4 zero bytes).
    pub config_defaults_bl: Vec<u8>,
}
/// Text surface used by native OSD/server callers.
pub type MMgrOpen = MMgrOpenPayload<String>;
/// Service application strings are length-prefixed bytes, not Unicode.
/// `Vec<u8>` and `String` share the u32-length/raw-byte wire form.
pub type ByteMMgrOpen = MMgrOpenPayload<Vec<u8>>;

impl<S: Default> Default for MMgrOpenPayload<S> {
    /// A wire-valid empty message: both config bls carry the encoded empty forms, never a zero-length blob a peer's
    /// `ConfigBl::decode` / defaults decoder would reject.
    fn default() -> Self {
        MMgrOpenPayload {
            daemon_name: S::default(),
            service_name: S::default(),
            service_daemon: false,
            daemon_metadata: BTreeMap::new(),
            daemon_status: BTreeMap::new(),
            config_bl: EMPTY_CONFIG_BL.to_vec(),
            config_defaults_bl: EMPTY_CONFIG_DEFAULTS_BL.to_vec(),
        }
    }
}

impl MMgrOpen {
    /// Open message for a plain OSD with empty config blobs.
    pub fn osd(id: i32) -> Self {
        MMgrOpen {
            daemon_name: id.to_string(),
            ..Default::default()
        }
    }
}
impl<S: Encode + for<'a> Decode<'a> + Default + Ord> Message for MMgrOpenPayload<S> {
    meta!(0x700, 3, 1);
    fn encode(&self, f: u64) -> Result<Segments> {
        Ok(Segments::front(front_with(f, |e| {
            self.daemon_name.encode(e)?;
            self.service_name.encode(e)?;
            e.bool(self.service_daemon)?;
            if self.service_daemon {
                self.daemon_metadata.encode(e)?;
                self.daemon_status.encode(e)?;
            }
            e.bytes(&self.config_bl)?;
            e.bytes(&self.config_defaults_bl)
        })?))
    }
    fn decode(v: u16, front: &[u8], _m: &[u8], _d: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(front);
        let daemon_name = S::decode(&mut d)?;
        let mut m = Self {
            daemon_name,
            service_name: S::default(),
            service_daemon: false,
            daemon_metadata: BTreeMap::new(),
            daemon_status: BTreeMap::new(),
            // absent in v1/v2 senders: the config was never sent, not sent empty
            config_bl: Vec::new(),
            config_defaults_bl: Vec::new(),
        };
        if v >= 2 {
            m.service_name = S::decode(&mut d)?;
            m.service_daemon = d.bool()?;
            if m.service_daemon {
                m.daemon_metadata = BTreeMap::decode(&mut d)?;
                m.daemon_status = BTreeMap::decode(&mut d)?;
            }
        }
        if v >= 3 {
            m.config_bl = d.bytes()?.to_vec();
            m.config_defaults_bl = d.bytes()?.to_vec();
        }
        Ok(m)
    }
}

/// MMgrConfigure (0x701, hv=4 hc=1). First two fields parsed; `tail` = everything after them
/// (osd_perf_metric_queries, metric config) kept verbatim and ignored (M1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MMgrConfigure {
    /// Seconds; 0 = stop reporting.
    pub stats_period: u32,
    /// Minimum counter priority to report.
    pub stats_threshold: u32,
    pub tail: Vec<u8>,
}
impl Default for MMgrConfigure {
    /// The wire-valid empty v4 message (both counters 0 plus the v4 tail).
    fn default() -> Self {
        MMgrConfigure {
            stats_period: 0,
            stats_threshold: 0,
            tail: Self::EMPTY_TAIL.to_vec(),
        }
    }
}
impl MMgrConfigure {
    /// `map<..>` empty (u32 0) + absent optional metric config (u8 0): the v4 tail.
    pub const EMPTY_TAIL: [u8; 5] = [0; 5];

    pub fn new(stats_period: u32, stats_threshold: u32) -> Self {
        MMgrConfigure {
            stats_period,
            stats_threshold,
            ..Default::default()
        }
    }
}
impl Message for MMgrConfigure {
    meta!(0x701, 4, 1);
    fn encode(&self, f: u64) -> Result<Segments> {
        Ok(Segments::front(front_with(f, |e| {
            e.u32(self.stats_period)?;
            e.u32(self.stats_threshold)?;
            e.raw(&self.tail)
        })?))
    }
    fn decode(v: u16, front: &[u8], _m: &[u8], _d: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(front);
        let stats_period = d.u32()?;
        let stats_threshold = if v >= 2 { d.u32()? } else { 0 };
        Ok(MMgrConfigure {
            stats_period,
            stats_threshold,
            tail: d.peek_rest().to_vec(),
        })
    }
}

/// MMgrClose (0x708): mgr ends the session (service daemons only; ignored by OSDs). Body kept raw.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MMgrClose {
    pub raw: Vec<u8>,
}
impl Message for MMgrClose {
    meta!(0x708, 1, 1);
    fn encode(&self, _f: u64) -> Result<Segments> {
        Ok(Segments::front(self.raw.clone()))
    }
    fn decode(_v: u16, front: &[u8], _m: &[u8], _d: &[u8]) -> Result<Self> {
        Ok(MMgrClose {
            raw: front.to_vec(),
        })
    }
}

// ---------------------------------------------------------------- perf counters

/// PerfCounterType flag bits (`type` field).
pub mod pct {
    pub const TIME: u8 = 1;
    pub const U64: u8 = 2;
    pub const LONGRUNAVG: u8 = 4;
    pub const COUNTER: u8 = 8;
    pub const HISTOGRAM: u8 = 0x10;
    /// gauge u64
    pub const GAUGE: u8 = U64;
    /// monotonic counter u64
    pub const COUNTER_U64: u8 = U64 | COUNTER;
    /// time average (sum of ns + count)
    pub const TIME_AVG: u8 = TIME | LONGRUNAVG;
    /// u64 average
    pub const U64_AVG: u8 = U64 | LONGRUNAVG;
    pub const PRIO_CRITICAL: u8 = 10;
    pub const PRIO_INTERESTING: u8 = 8;
    pub const PRIO_USEFUL: u8 = 5;
    pub const PRIO_UNINTERESTING: u8 = 2;
    pub const PRIO_DEBUGONLY: u8 = 0;
    pub const UNIT_BYTES: u8 = 0;
    pub const UNIT_NONE: u8 = 1;
}

/// Counter schema entry (v3, compat 1).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PerfCounterType {
    /// `<logger>.<counter>`, e.g. `osd.op`.
    pub path: String,
    pub description: String,
    pub nick: String,
    pub ty: u8,
    pub priority: u8,
    pub unit: u8,
}
impl PerfCounterType {
    pub fn new(path: &str, ty: u8, priority: u8, unit: u8) -> Self {
        PerfCounterType {
            path: path.to_owned(),
            ty,
            priority,
            unit,
            ..Default::default()
        }
    }
    pub fn is_longrunavg(&self) -> bool {
        self.ty & pct::LONGRUNAVG != 0
    }
}
impl Encode for PerfCounterType {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.versioned(3, 1, |e| {
            self.path.encode(e)?;
            self.description.encode(e)?;
            self.nick.encode(e)?;
            e.u8(self.ty)?;
            e.u8(self.priority)?;
            e.u8(self.unit)
        })
    }
}
impl<'a> Decode<'a> for PerfCounterType {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        d.versioned(1, |d, v| {
            let mut t = PerfCounterType {
                path: String::decode(d)?,
                description: String::decode(d)?,
                nick: String::decode(d)?,
                ty: d.u8()?,
                ..Default::default()
            };
            if v >= 2 {
                t.priority = d.u8()?;
            }
            if v >= 3 {
                t.unit = d.u8()?;
            }
            Ok(t)
        })
    }
}

/// Current value of one counter. `avgcount`/`avgcount2` only for LONGRUNAVG types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CounterValue {
    /// Value / sum; TIME values are nanoseconds.
    pub value: u64,
    pub avgcount: u64,
    pub avgcount2: u64,
}

/// `packed` blob: ENCODE_START(1,1) with, per declared counter in ascending path order, the
/// value (+ avgcount, avgcount2 for LONGRUNAVG). `entries` must already be sorted by path.
pub fn encode_packed(entries: &[(&PerfCounterType, CounterValue)]) -> Result<Vec<u8>> {
    front_with(denc::features::ALL, |e| {
        e.versioned(1, 1, |e| {
            for (t, v) in entries {
                e.u64(v.value)?;
                if t.is_longrunavg() {
                    e.u64(v.avgcount)?;
                    e.u64(v.avgcount2)?;
                }
            }
            Ok(())
        })
    })
}

/// Decode a `packed` blob against the (path-sorted) declared types. The body must hold exactly one value per declared
/// counter: a longer blob would be decoded from the wrong offsets on a receiver with a stale schema.
pub fn decode_packed(declared: &[&PerfCounterType], b: &[u8]) -> Result<Vec<CounterValue>> {
    Decoder::new(b).versioned(1, |d, _| {
        let values: Vec<CounterValue> = declared
            .iter()
            .map(|t| {
                let value = d.u64()?;
                let (avgcount, avgcount2) = if t.is_longrunavg() {
                    (d.u64()?, d.u64()?)
                } else {
                    (0, 0)
                };
                Ok(CounterValue {
                    value,
                    avgcount,
                    avgcount2,
                })
            })
            .collect::<Result<_>>()?;
        end(d)?;
        Ok(values)
    })
}

/// Per-mgr-session perf counter reporter. Tracks the declared schema (`path -> type byte`) so that
/// `declare_types`, `undeclare_types` and `packed` always agree with what the mgr has accumulated. Create a new
/// one (or [`reset`](Self::reset)) on every new session.
#[derive(Debug, Clone, Default)]
pub struct PerfReporter {
    declared: BTreeMap<String, u8>,
}

/// Counter parts of one MMgrReport produced by [`PerfReporter::build`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PerfReport {
    pub declare_types: Vec<PerfCounterType>,
    pub packed: Vec<u8>,
    pub undeclare_types: Vec<String>,
}

impl PerfReporter {
    pub fn new() -> Self {
        Self::default()
    }
    /// New session: declared set empty on both sides.
    pub fn reset(&mut self) {
        self.declared.clear();
    }

    /// Build the counter fields of the next report from the full counter set (`path -> (type,
    /// value)`). Counters with `priority < threshold` or the HISTOGRAM bit are not reported;
    /// previously declared counters that are now absent/filtered are undeclared.
    pub fn build(
        &mut self,
        counters: &BTreeMap<String, (PerfCounterType, CounterValue)>,
        threshold: u32,
    ) -> Result<PerfReport> {
        self.build_with(counters, threshold, encode_packed)
    }

    /// [`build`](Self::build) with the pack step injected. The declared schema is committed only after the pack
    /// succeeded: a failed encode must not leave the reporter out of sync with the mgr's accumulated set.
    fn build_with(
        &mut self,
        counters: &BTreeMap<String, (PerfCounterType, CounterValue)>,
        threshold: u32,
        pack: impl FnOnce(&[(&PerfCounterType, CounterValue)]) -> Result<Vec<u8>>,
    ) -> Result<PerfReport> {
        let mut rep = PerfReport::default();
        let mut next = BTreeMap::new();
        // Undeclare: a declared counter that disappeared, is filtered out now, or changed its schema (only the type
        // byte decides the packed layout). A path is never undeclared and declared in the same report; a changed type is
        // re-declared by the next one.
        for (path, ty) in &self.declared {
            if counters
                .get(path)
                .is_some_and(|(t, _)| wanted(t, threshold) && t.ty == *ty)
            {
                next.insert(path.clone(), *ty);
            } else {
                rep.undeclare_types.push(path.clone());
            }
        }
        for (path, (t, _)) in counters {
            if wanted(t, threshold) && !self.declared.contains_key(path) {
                rep.declare_types.push(t.clone());
                next.insert(path.clone(), t.ty);
            }
        }
        let entries: Vec<(&PerfCounterType, CounterValue)> = next
            .keys()
            .filter_map(|p| counters.get(p).map(|(t, v)| (t, *v)))
            .collect();
        rep.packed = pack(&entries)?;
        self.declared = next;
        Ok(rep)
    }
}

/// A counter at `priority >= threshold` without the HISTOGRAM bit is reported.
fn wanted(t: &PerfCounterType, threshold: u32) -> bool {
    u32::from(t.priority) >= threshold && t.ty & pct::HISTOGRAM == 0
}

/// DaemonHealthMetric (v1, compat 1). `value` for SLOW_OPS: low32 = count, high32 = oldest age s.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DaemonHealthMetric {
    pub ty: u8,
    pub value: u64,
}
impl DaemonHealthMetric {
    pub const SLOW_OPS: u8 = 0;
    pub const PENDING_CREATING_PGS: u8 = 1;
    pub const NONE: u8 = 2;
}
impl Encode for DaemonHealthMetric {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.versioned(1, 1, |e| {
            e.u8(self.ty)?;
            e.u64(self.value)
        })
    }
}
impl<'a> Decode<'a> for DaemonHealthMetric {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        d.versioned(1, |d, _| {
            Ok(DaemonHealthMetric {
                ty: d.u8()?,
                value: d.u64()?,
            })
        })
    }
}

/// MMgrReport (0x702, hv=9 hc=1). Decodes only the v9 layout (the mgr never sends it to us).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MMgrReportPayload<S> {
    pub daemon_name: S,
    pub declare_types: Vec<PerfCounterType>,
    pub packed: Vec<u8>,
    pub undeclare_types: Vec<String>,
    pub service_name: S,
    /// `opt<map>`; `None` for an OSD.
    pub daemon_status: Option<BTreeMap<S, S>>,
    pub daemon_health_metrics: Vec<DaemonHealthMetric>,
    /// Full non-default config snapshot when it changed since the last send, empty (`u32 0`) otherwise.
    pub config_bl: Vec<u8>,
    /// `osd_perf_metric_reports`, `task_status`, `metric_report_message` kept verbatim.
    pub tail: Vec<u8>,
}
pub type MMgrReport = MMgrReportPayload<String>;
pub type ByteMMgrReport = MMgrReportPayload<Vec<u8>>;

impl<S: Default> MMgrReportPayload<S> {
    /// u32 0 (empty map) + two absent optionals.
    pub const EMPTY_TAIL: [u8; 6] = [0; 6];
    /// Wire form of [`encode_packed`] with no declared counters: ENCODE_START(1,1) with an empty body.
    pub const EMPTY_PACKED: [u8; 6] = [1, 1, 0, 0, 0, 0];

    pub fn new(daemon_name: S) -> Self {
        Self {
            daemon_name,
            ..Default::default()
        }
    }
    /// Fill the counter fields from a [`PerfReport`].
    pub fn set_perf(&mut self, p: PerfReport) {
        self.declare_types = p.declare_types;
        self.packed = p.packed;
        self.undeclare_types = p.undeclare_types;
    }
}

impl<S: Default> Default for MMgrReportPayload<S> {
    /// A wire-valid empty report: `packed` is the empty packed blob and the v9 tail is present, so a peer can decode it
    /// with an empty declared set instead of hitting `Eof`.
    fn default() -> Self {
        MMgrReportPayload {
            daemon_name: S::default(),
            declare_types: Vec::new(),
            packed: Self::EMPTY_PACKED.to_vec(),
            undeclare_types: Vec::new(),
            service_name: S::default(),
            daemon_status: None,
            daemon_health_metrics: Vec::new(),
            config_bl: Vec::new(),
            tail: Self::EMPTY_TAIL.to_vec(),
        }
    }
}
impl<S: Encode + for<'a> Decode<'a> + Default + Ord> Message for MMgrReportPayload<S> {
    meta!(0x702, 9, 1, oldest 9);
    fn encode(&self, f: u64) -> Result<Segments> {
        Ok(Segments::front(front_with(f, |e| {
            self.daemon_name.encode(e)?;
            self.declare_types.encode(e)?;
            e.bytes(&self.packed)?;
            self.undeclare_types.encode(e)?;
            self.service_name.encode(e)?;
            self.daemon_status.encode(e)?;
            self.daemon_health_metrics.encode(e)?;
            e.bytes(&self.config_bl)?;
            e.raw(&self.tail)
        })?))
    }
    fn decode(v: u16, front: &[u8], _m: &[u8], _d: &[u8]) -> Result<Self> {
        Self::check_version(v)?;
        let mut d = Decoder::new(front);
        Ok(Self {
            daemon_name: S::decode(&mut d)?,
            declare_types: Vec::decode(&mut d)?,
            packed: d.bytes()?.to_vec(),
            undeclare_types: Vec::decode(&mut d)?,
            service_name: S::decode(&mut d)?,
            daemon_status: Option::decode(&mut d)?,
            daemon_health_metrics: Vec::decode(&mut d)?,
            config_bl: d.bytes()?.to_vec(),
            tail: d.peek_rest().to_vec(),
        })
    }
}

#[cfg(test)]
mod service_byte_tests {
    use super::*;

    #[test]
    fn service_open_byte_wire_vector_and_text_decoder_stays_strict() {
        let open = ByteMMgrOpen {
            daemon_name: b"d\0\xff".to_vec(),
            service_name: b"s\x80".to_vec(),
            service_daemon: true,
            daemon_metadata: [(vec![], b"\xff\0".to_vec())].into(),
            daemon_status: [(vec![0x80], b"\0\xfe".to_vec())].into(),
            config_bl: Vec::new(),
            config_defaults_bl: Vec::new(),
        };
        let vector = [
            3, 0, 0, 0, b'd', 0, 0xff, // daemon
            2, 0, 0, 0, b's', 0x80, 1, // service, service_daemon
            1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0xff, 0, // metadata
            1, 0, 0, 0, 1, 0, 0, 0, 0x80, 2, 0, 0, 0, 0, 0xfe, // status
            0, 0, 0, 0, 0, 0, 0, 0, // config blobs
        ];
        assert_eq!(open.encode(0).unwrap().front, vector);
        assert_eq!(ByteMMgrOpen::decode(3, &vector, &[], &[]).unwrap(), open);
        assert!(MMgrOpen::decode(3, &vector, &[], &[]).is_err());
        let old = ByteMMgrOpen::decode(1, &vector[..7], &[], &[]).unwrap();
        assert_eq!(old.daemon_name, b"d\0\xff");
        assert!(!old.service_daemon);
        let v2 = ByteMMgrOpen::decode(2, &vector[..43], &[], &[]).unwrap();
        assert_eq!(v2.daemon_metadata, open.daemon_metadata);
        assert_eq!(v2.daemon_status, open.daemon_status);
        assert!(v2.config_bl.is_empty());
    }

    #[test]
    fn service_report_byte_wire_vector_distinguishes_omitted_and_empty_status() {
        let mut report = ByteMMgrReport::new(b"d\0\xff".to_vec());
        report.service_name = b"s\x80".to_vec();
        report.packed = encode_packed(&[]).unwrap();
        report.daemon_status =
            Some([(vec![], b"\0\xff".to_vec()), (b"k\0".to_vec(), vec![0xfe])].into());
        let vector = [
            3, 0, 0, 0, b'd', 0, 0xff, 0, 0, 0, 0, // declarations
            6, 0, 0, 0, 1, 1, 0, 0, 0, 0, // packed
            0, 0, 0, 0, // undeclarations
            2, 0, 0, 0, b's', 0x80, 1, 2, 0, 0, 0, // present status, two entries
            0, 0, 0, 0, 2, 0, 0, 0, 0, 0xff, 2, 0, 0, 0, b'k', 0, 1, 0, 0, 0, 0xfe, 0, 0, 0,
            0, // health metrics
            0, 0, 0, 0, // config
            0, 0, 0, 0, 0, 0, // tail
        ];
        assert_eq!(report.encode(0).unwrap().front, vector);
        assert_eq!(
            ByteMMgrReport::decode(9, &vector, &[], &[]).unwrap(),
            report
        );
        assert!(MMgrReport::decode(9, &vector, &[], &[]).is_err());
        assert!(ByteMMgrReport::decode(8, &vector, &[], &[]).is_err());
        report.daemon_status = Some(BTreeMap::new());
        let clear = report.encode(0).unwrap().front;
        assert_eq!(&clear[31..36], &[1, 0, 0, 0, 0]);
        report.daemon_status = None;
        let omitted = report.encode(0).unwrap().front;
        assert_eq!(omitted[31], 0);
        assert_eq!(clear.len(), omitted.len() + 4);
    }

    #[test]
    fn default_osd_text_and_byte_surfaces_share_wire_codec() {
        let text = MMgrOpen::osd(7);
        let bytes = ByteMMgrOpen {
            daemon_name: b"7".to_vec(),
            config_bl: text.config_bl.clone(),
            config_defaults_bl: text.config_defaults_bl.clone(),
            ..Default::default()
        };
        let encoded = text.encode(0).unwrap();
        assert_eq!(encoded, bytes.encode(0).unwrap());
        assert_eq!(MMgrOpen::decode(3, &encoded.front, &[], &[]).unwrap(), text);
        assert_eq!(&encoded.front[..10], &[1, 0, 0, 0, b'7', 0, 0, 0, 0, 0]);
        let text = MMgrReport::new("7".into());
        let bytes = ByteMMgrReport::new(b"7".to_vec());
        assert_eq!(text.encode(0).unwrap(), bytes.encode(0).unwrap());
        assert_eq!(
            MMgrReport::decode(9, &text.encode(0).unwrap().front, &[], &[]).unwrap(),
            text
        );
    }
}

// ---------------------------------------------------------------- MPGStats

/// MPGStats (87, hv=2 hc=1), sent to the mgr. `pg_stat` values are complete encoded `pg_stat_t`
/// envelopes (opaque; empty in M1).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MPGStats {
    pub version: u64,
    pub fsid: Uuid,
    pub osd_stat: OsdStat,
    pub pg_stat: Vec<(PgT, Vec<u8>)>,
    pub epoch: u32,
    /// Always zero on the wire.
    pub dummy: UTime,
    pub pool_stat: BTreeMap<i64, StoreStatfs>,
}
impl Message for MPGStats {
    meta!(87, 2, 1);
    fn encode(&self, f: u64) -> Result<Segments> {
        Ok(Segments::front(front_with(f, |e| {
            put_psm(e, self.version)?;
            self.fsid.encode(e)?;
            self.osd_stat.encode(e)?;
            e.count(self.pg_stat.len())?;
            for (pg, raw) in &self.pg_stat {
                pg.encode(e)?;
                e.raw(raw)?;
            }
            e.u32(self.epoch)?;
            self.dummy.encode(e)?;
            self.pool_stat.encode(e)
        })?))
    }
    fn decode(v: u16, front: &[u8], _m: &[u8], _d: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(front);
        let version = get_psm(&mut d)?;
        let fsid = Uuid::decode(&mut d)?;
        let osd_stat = OsdStat::decode(&mut d)?;
        let n = d.count()?;
        let mut pg_stat = Vec::with_capacity(n.min(1024));
        for _ in 0..n {
            let pg = PgT::decode(&mut d)?;
            pg_stat.push((pg, d.envelope_raw()?.to_vec()));
        }
        let epoch = d.u32()?;
        let dummy = UTime::decode(&mut d)?;
        let pool_stat = if v >= 2 {
            BTreeMap::decode(&mut d)?
        } else {
            BTreeMap::new()
        };
        Ok(MPGStats {
            version,
            fsid,
            osd_stat,
            pg_stat,
            epoch,
            dummy,
            pool_stat,
        })
    }
}

#[cfg(test)]
mod build_tests {
    use super::*;

    /// MSG-11: a failed pack leaves the declared schema untouched, so the next report still matches what the mgr has.
    #[test]
    fn failed_pack_keeps_the_declared_schema() {
        let counters: BTreeMap<String, (PerfCounterType, CounterValue)> = [(
            "osd.op".to_string(),
            (
                PerfCounterType::new("osd.op", pct::COUNTER_U64, 10, pct::UNIT_NONE),
                CounterValue {
                    value: 1,
                    ..Default::default()
                },
            ),
        )]
        .into();
        let mut reporter = PerfReporter::new();
        assert!(matches!(
            reporter.build_with(&counters, 0, |_| Err(crate::Error::TooLong)),
            Err(crate::Error::TooLong)
        ));
        let report = reporter.build(&counters, 0).unwrap();
        assert_eq!(report.declare_types.len(), 1);
        assert!(report.undeclare_types.is_empty());
    }
}
