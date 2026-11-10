// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Write-around admission of the RBD client cache (adr 0694-rustyrbd-client-cache).
//!
//! The cache never holds data. A write that the policy admits is submitted to
//! RADOS at once and acknowledged to the application before the object write
//! commits ("early ack"); the image tracks it until the commit so that a flush
//! can wait for it. This module is the pure admission state: configuration
//! mapping, the one-way activation latch, the in-flight extent set and the
//! `max_dirty` byte budget. It performs no I/O.
//!
//! The budget bounds what the application may believe is written before it is:
//! the bytes of early-acknowledged writes that have not committed. It never
//! delays a send. A write the budget does not cover is submitted at once like
//! every other pipelined write and completes on its own commit, so a queue
//! depth above `max_dirty / write size` keeps the full RADOS pipeline. Only an
//! overlap with a tracked write holds a write back.
//!
//! Extents are tracked in image byte space. The image-to-object mapping is
//! bijective, so two image ranges overlap exactly when their object extents
//! overlap on some object.

/// `rbd_cache_policy`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CachePolicy {
    /// Early ack of admitted writes, no data cache (the default).
    WriteAround,
    /// Mapped to write-around semantics: data is submitted at once instead of
    /// being held dirty, which exposes strictly less unwritten data.
    WriteBack,
    /// Every write completes on commit; `max_dirty` is forced to 0.
    WriteThrough,
}

impl CachePolicy {
    /// Parse an `rbd_cache_policy` value; anything else is not accepted.
    pub fn parse(value: &[u8]) -> Option<Self> {
        match value {
            b"writearound" => Some(Self::WriteAround),
            b"writeback" => Some(Self::WriteBack),
            b"writethrough" => Some(Self::WriteThrough),
            _ => None,
        }
    }
}

/// The effective `rbd_cache*` options read at open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CacheConfig {
    /// `rbd_cache`.
    pub enabled: bool,
    /// `rbd_cache_policy`.
    pub policy: CachePolicy,
    /// `rbd_cache_writethrough_until_flush`.
    pub writethrough_until_flush: bool,
    /// `rbd_cache_max_dirty`.
    pub max_dirty: u64,
}

impl CacheConfig {
    /// The reference defaults.
    pub const DEFAULT: Self = Self {
        enabled: true,
        policy: CachePolicy::WriteAround,
        writethrough_until_flush: true,
        max_dirty: 24 << 20,
    };

    /// The admission state for this configuration. Disabled, write-through
    /// and `max_dirty == 0` never acknowledge early. With
    /// `writethrough_until_flush` the cache starts passive until the first
    /// user flush.
    pub fn write_around(&self) -> WriteAround {
        let max_dirty = if self.enabled && self.policy != CachePolicy::WriteThrough {
            self.max_dirty
        } else {
            0
        };
        WriteAround {
            max_dirty,
            live: !self.writethrough_until_flush,
            flights: Vec::new(),
            early_bytes: 0,
        }
    }
}

/// One tracked write: an image byte range that is in flight.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Flight {
    start: u64,
    end: u64,
    early: bool,
}

impl Flight {
    /// Whether the write may be acknowledged before its commit.
    pub fn early(&self) -> bool {
        self.early
    }
}

/// Admission decision of one write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    /// The cache is not active for this write: it is untracked and completes
    /// on commit.
    Passive,
    /// Tracked until [`WriteAround::finish`]; acknowledge early when
    /// [`Flight::early`], else on its own commit. Either way it is submitted
    /// at once.
    Track(Flight),
    /// An overlapping write is in flight: the write must not be sent before
    /// every earlier write committed, and completes on its own commit.
    Held,
}

/// Admission state of one image.
#[derive(Debug)]
pub struct WriteAround {
    max_dirty: u64,
    live: bool,
    /// Disjoint in-flight ranges sorted by start. A sorted vector keeps its
    /// capacity: the steady state neither allocates nor frees.
    flights: Vec<Flight>,
    /// Bytes of tracked early-ack writes.
    early_bytes: u64,
}

impl Default for WriteAround {
    /// Never acknowledges early (images that are not public handles).
    fn default() -> Self {
        Self {
            max_dirty: 0,
            live: false,
            flights: Vec::new(),
            early_bytes: 0,
        }
    }
}

impl WriteAround {
    /// The user-flush latch: from now on writes are admitted. One-way; a
    /// no-op when the cache never acknowledges early.
    pub fn latch(&mut self) {
        self.live = true;
    }

    /// Whether writes can currently be acknowledged early.
    pub fn is_live(&self) -> bool {
        self.live && self.max_dirty != 0
    }

    /// Number of tracked writes.
    pub fn in_flight(&self) -> usize {
        self.flights.len()
    }

    /// Bytes of tracked early-ack writes.
    pub fn in_flight_bytes(&self) -> u64 {
        self.early_bytes
    }

    /// Whether any tracked write overlaps `[start, end)`.
    fn overlaps(&self, start: u64, end: u64) -> bool {
        let next = self.flights.partition_point(|f| f.start < start);
        // Disjoint and sorted: only the neighbours can overlap.
        self.flights[..next]
            .last()
            .is_some_and(|before| before.end > start)
            || self
                .flights
                .get(next)
                .is_some_and(|after| after.start < end)
    }

    /// Decide one write of `len` bytes at image `offset`. A write that
    /// overlaps a tracked write is held. Any other write is tracked and
    /// submitted at once; it is acknowledged early when the bytes of
    /// early-acknowledged uncommitted writes plus `len` stay within
    /// `max_dirty` (or none are in flight: one write above the limit is
    /// admitted when idle). A write the budget does not cover, and a write
    /// with the FUA flag (write-through), is tracked (later overlapping writes
    /// wait for it) but completes on its own commit and is not counted against
    /// the budget.
    pub fn admit(&mut self, offset: u64, len: u64, fua: bool) -> Admission {
        if !self.is_live() || len == 0 {
            return Admission::Passive;
        }
        let end = offset.saturating_add(len);
        if self.overlaps(offset, end) {
            return Admission::Held;
        }
        let early = !fua
            && (self.early_bytes == 0 || self.early_bytes.saturating_add(len) <= self.max_dirty);
        let flight = Flight {
            start: offset,
            end,
            early,
        };
        let at = self.flights.partition_point(|f| f.start < offset);
        self.flights.insert(at, flight);
        if early {
            self.early_bytes += end - offset;
        }
        Admission::Track(flight)
    }

    /// A tracked write settled (committed or failed): release its range and
    /// budget.
    pub fn finish(&mut self, flight: Flight) {
        let at = self.flights.partition_point(|f| f.start < flight.start);
        debug_assert_eq!(self.flights.get(at), Some(&flight));
        if self.flights.get(at) == Some(&flight) {
            self.flights.remove(at);
            if flight.early {
                self.early_bytes -= flight.end - flight.start;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAX: u64 = 24 << 20;

    fn live() -> WriteAround {
        let mut cache = CacheConfig::DEFAULT.write_around();
        cache.latch();
        cache
    }

    fn track(admission: Admission) -> Flight {
        match admission {
            Admission::Track(flight) => flight,
            other => panic!("expected a tracked write, got {other:?}"),
        }
    }

    #[test]
    fn defaults_are_passive_until_the_latch() {
        let mut cache = CacheConfig::DEFAULT.write_around();
        assert_eq!(cache.admit(0, 4096, false), Admission::Passive);
        cache.latch();
        assert!(track(cache.admit(0, 4096, false)).early());
    }

    #[test]
    fn writethrough_until_flush_false_is_live_from_open() {
        let config = CacheConfig {
            writethrough_until_flush: false,
            ..CacheConfig::DEFAULT
        };
        let mut cache = config.write_around();
        assert!(track(cache.admit(0, 4096, false)).early());
    }

    #[test]
    fn disabled_writethrough_and_zero_max_dirty_never_early_ack() {
        for config in [
            CacheConfig {
                enabled: false,
                ..CacheConfig::DEFAULT
            },
            CacheConfig {
                policy: CachePolicy::WriteThrough,
                ..CacheConfig::DEFAULT
            },
            CacheConfig {
                max_dirty: 0,
                ..CacheConfig::DEFAULT
            },
        ] {
            let mut cache = CacheConfig {
                writethrough_until_flush: false,
                ..config
            }
            .write_around();
            cache.latch();
            assert_eq!(
                cache.admit(0, 4096, false),
                Admission::Passive,
                "{config:?}"
            );
        }
    }

    #[test]
    fn writeback_maps_to_write_around() {
        let mut cache = CacheConfig {
            policy: CachePolicy::WriteBack,
            ..CacheConfig::DEFAULT
        }
        .write_around();
        cache.latch();
        assert!(track(cache.admit(0, 4096, false)).early());
    }

    #[test]
    fn policy_parse_accepts_only_the_three_names() {
        assert_eq!(
            CachePolicy::parse(b"writearound"),
            Some(CachePolicy::WriteAround)
        );
        assert_eq!(
            CachePolicy::parse(b"writeback"),
            Some(CachePolicy::WriteBack)
        );
        assert_eq!(
            CachePolicy::parse(b"writethrough"),
            Some(CachePolicy::WriteThrough)
        );
        assert_eq!(CachePolicy::parse(b"bogus"), None);
        assert_eq!(CachePolicy::parse(b""), None);
    }

    #[test]
    fn overlap_holds_and_adjacent_does_not() {
        let mut cache = live();
        track(cache.admit(4096, 4096, false));
        assert_eq!(cache.admit(4096, 4096, false), Admission::Held);
        assert_eq!(cache.admit(0, 4097, false), Admission::Held);
        assert_eq!(cache.admit(8191, 10, false), Admission::Held);
        assert!(matches!(cache.admit(0, 4096, false), Admission::Track(_)));
        assert!(matches!(
            cache.admit(8192, 4096, false),
            Admission::Track(_)
        ));
    }

    #[test]
    fn finish_releases_the_range_and_budget() {
        let mut cache = live();
        let flight = track(cache.admit(0, 4096, false));
        assert_eq!(cache.in_flight(), 1);
        assert_eq!(cache.in_flight_bytes(), 4096);
        assert_eq!(cache.admit(0, 4096, false), Admission::Held);
        cache.finish(flight);
        assert_eq!(cache.in_flight(), 0);
        assert_eq!(cache.in_flight_bytes(), 0);
        assert!(matches!(cache.admit(0, 4096, false), Admission::Track(_)));
    }

    #[test]
    fn early_bytes_never_exceed_the_budget_except_a_single_op_when_idle() {
        let mut cache = live();
        // A single op larger than the limit is acknowledged early when idle.
        let big = track(cache.admit(0, MAX + 4096, false));
        assert!(big.early());
        assert_eq!(cache.in_flight_bytes(), MAX + 4096);
        let beyond = track(cache.admit(MAX + 4096, 4096, false));
        assert!(!beyond.early(), "over budget: completes on its commit");
        assert_eq!(cache.in_flight_bytes(), MAX + 4096, "not charged");
        cache.finish(beyond);
        cache.finish(big);
        // Fill to exactly the limit, then one byte more is not early.
        let fill = track(cache.admit(0, MAX, false));
        assert!(fill.early());
        assert_eq!(cache.in_flight_bytes(), MAX);
        let one = track(cache.admit(MAX, 1, false));
        assert!(!one.early());
        assert_eq!(cache.in_flight_bytes(), MAX);
        cache.finish(fill);
        cache.finish(one);
        assert_eq!(cache.in_flight_bytes(), 0);
        assert!(track(cache.admit(MAX, 1, false)).early());
    }

    #[test]
    fn writes_beyond_the_budget_are_sent_at_once_and_never_held_except_by_overlap() {
        let mut cache = live();
        // Six 4 MiB writes fill the default budget, the rest of a queue of 16
        // is tracked without early acknowledgement: nothing is held.
        let mut early = 0;
        let mut flights = Vec::new();
        for slot in 0..16u64 {
            let flight = track(cache.admit(slot << 22, 4 << 20, false));
            early += usize::from(flight.early());
            flights.push(flight);
        }
        assert_eq!(early, 6);
        assert_eq!(cache.in_flight(), 16);
        assert_eq!(cache.in_flight_bytes(), 6 * (4 << 20));
        // Overlap with a write beyond the budget still holds.
        assert_eq!(cache.admit((10 << 22) + 100, 8, false), Admission::Held);
        // A commit of an early write frees budget for the next write.
        cache.finish(flights.remove(0));
        assert!(track(cache.admit(16 << 22, 4 << 20, false)).early());
        // The commit of a write that was never charged frees none.
        let before = cache.in_flight_bytes();
        cache.finish(flights.pop().unwrap());
        assert_eq!(cache.in_flight_bytes(), before);
    }

    #[test]
    fn many_non_overlapping_writes_stay_disjoint_and_sorted() {
        let mut cache = live();
        let mut flights = Vec::new();
        for slot in [5u64, 1, 9, 3, 7, 0, 8, 2, 6, 4] {
            flights.push(track(cache.admit(slot * 4096, 4096, false)));
        }
        assert_eq!(cache.in_flight(), 10);
        for slot in 0..10u64 {
            assert_eq!(cache.admit(slot * 4096 + 100, 8, false), Admission::Held);
        }
        for flight in flights {
            cache.finish(flight);
        }
        assert_eq!(cache.in_flight(), 0);
    }

    #[test]
    fn fua_is_tracked_never_early_and_free_of_budget() {
        let mut cache = live();
        let fua = track(cache.admit(0, 4096, true));
        assert!(!fua.early());
        assert_eq!(cache.in_flight_bytes(), 0);
        // Later overlapping writes wait for it.
        assert_eq!(cache.admit(0, 4096, false), Admission::Held);
        // A FUA write waits for an overlapping early write.
        let early = track(cache.admit(8192, 4096, false));
        assert_eq!(cache.admit(8192, 4096, true), Admission::Held);
        cache.finish(early);
        cache.finish(fua);
    }

    #[test]
    fn passive_cache_tracks_nothing() {
        let mut cache = CacheConfig::DEFAULT.write_around();
        assert_eq!(cache.admit(0, 4096, false), Admission::Passive);
        assert_eq!(cache.in_flight(), 0);
        let mut live = live();
        assert_eq!(live.admit(0, 0, false), Admission::Passive);
    }

    #[test]
    fn extent_end_saturates() {
        let mut cache = live();
        let tail = track(cache.admit(u64::MAX - 10, 100, false));
        assert_eq!(cache.admit(u64::MAX - 5, 1, false), Admission::Held);
        cache.finish(tail);
    }
}
