// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
//! A bounded owned logical read window, not a physical page cache or live cursor.
use super::{Answer, Bytes, MAX_SCAN_ROWS, PAGE, Query};
use std::sync::Arc;

/// Same logical stream: object, prefix, overlay revisions and projection. The
/// request session is deliberately not part of the match: a paginated listing
/// sends every page as a new request, and window contents depend only on the
/// matched state (materialization invalidates it separately).
fn same(a: &Query, b: &Query) -> bool {
    match (a, b) {
        (
            Query::Page {
                id: a,
                prefix: ap,
                versions: av,
                keys_only: ak,
                ..
            },
            Query::Page {
                id: b,
                prefix: bp,
                versions: bv,
                keys_only: bk,
                ..
            },
        ) => a == b && ap == bp && av == bv && ak == bk,
        _ => false,
    }
}
fn cost(v: &[(Bytes, Bytes)]) -> u64 {
    v.iter().map(|(k, v)| (k.len() + v.len() + 64) as u64).sum()
}
#[derive(Debug)]
struct Window {
    q: Query,
    answer: Arc<Answer>,
    used: u16,
}
#[derive(Debug, Default)]
struct Stats {
    hits: u64,
    retries: u64,
    submitted: u64,
    useful: u64,
    unused: u64,
    useful_bytes: u64,
    unused_bytes: u64,
}
#[derive(Debug)]
pub(super) struct ScanCache {
    window: Option<Window>,
    // Demand progress survives pressure; future pages may be discarded separately.
    last: Option<(Query, Arc<Answer>)>,
    streak: usize,
    target: usize,
    max: usize,
    pressure: bool,
    stats: Stats,
}
impl ScanCache {
    pub fn new(max: usize) -> Self {
        Self {
            window: None,
            last: None,
            streak: 0,
            target: 1,
            max,
            pressure: false,
            stats: Stats::default(),
        }
    }
    /// The new worker request starts exactly where the current window's rows end
    /// (its answer was cut short): an exclusive start at the window's last key, or
    /// an inclusive start at that key's immediate successor (key + one 0x00 byte,
    /// how a listing reopens after `start_after`). How the owner consumed the
    /// window in between (slices, the one-row look-ahead) does not matter.
    fn continues_window(&self, q: &Query) -> bool {
        let Some(w) = &self.window else {
            return false;
        };
        let (Query::Page { from, excl, .. }, Answer::Entries(v, true)) = (q, &*w.answer) else {
            return false;
        };
        let Some((last, _)) = v.last() else {
            return false;
        };
        same(&w.q, q)
            && if *excl {
                from == last
            } else {
                from.len() == last.len() + 1 && from.ends_with(&[0]) && from.starts_with(last)
            }
    }
    /// Remembers the latest demanded answer for exact retries.
    fn note(&mut self, q: Query, a: Arc<Answer>) {
        self.last = Some((q, a));
    }
    fn discard_window(&mut self) -> bool {
        let Some(w) = self.window.take() else {
            return false;
        };
        self.count_unused(&w)
    }
    /// Counts the window's never-served predicted pages; true when any exist.
    fn count_unused(&mut self, w: &Window) -> bool {
        let Answer::Entries(v, _) = &*w.answer else {
            return false;
        };
        let mut wasted = false;
        for (p, chunk) in v.chunks(PAGE).enumerate().skip(w.q.demand().div_ceil(PAGE)) {
            if w.used & (1u16 << p) == 0 {
                wasted = true;
                self.stats.unused += 1;
                self.stats.unused_bytes = self.stats.unused_bytes.saturating_add(cost(chunk));
            }
        }
        wasted
    }
    /// Called once, only when a new worker request is actually admitted.
    /// Returns the window width in demand-sized pages; the rows never exceed
    /// `MAX_SCAN_ROWS` (the page-use bitmap's capacity).
    /// Width grows by one page per continuation once a previous request was also a
    /// continuation (two in a row); any other request, pressure or an unused
    /// predicted page resets it to the demand alone.
    pub fn prepare(&mut self, q: &Query) -> usize {
        let cap = (MAX_SCAN_ROWS / q.demand()).clamp(1, self.max);
        let continues = !self.pressure && self.continues_window(q);
        self.streak = if continues {
            self.streak.saturating_add(1)
        } else {
            0
        };
        let next = if !continues {
            1
        } else if self.streak >= 2 {
            (self.target + 1).min(cap)
        } else {
            self.target.min(cap)
        };
        let wasted = self.discard_window();
        self.target = if wasted { 1 } else { next };
        self.target
    }
    pub fn insert(&mut self, q: Query, a: Arc<Answer>) {
        self.discard_window();
        let Answer::Entries(v, more) = &*a else {
            return;
        };
        let n = v.len().min(q.demand());
        let first = if n == v.len() {
            a.clone()
        } else {
            Arc::new(Answer::Entries(v[..n].to_vec(), *more || n < v.len()))
        };
        self.stats.submitted += v.len().saturating_sub(q.demand()).div_ceil(PAGE) as u64;
        let used = ((1u32 << n.div_ceil(PAGE)) - 1) as u16;
        self.note(q.clone(), first);
        self.window = Some(Window { q, answer: a, used });
        if self.pressure {
            self.discard_prediction();
        }
    }
    #[cfg(test)]
    pub fn get(&mut self, q: &Query) -> Option<Arc<Answer>> {
        self.get_take(q, usize::MAX)
    }
    /// A window hit copies at most `take` rows of the demand (`more` marks the rest).
    pub fn get_take(&mut self, q: &Query, take: usize) -> Option<Arc<Answer>> {
        if let Some((old, a)) = &self.last
            && old == q
        {
            self.stats.retries += 1;
            return Some(a.clone());
        }
        let w = self.window.as_mut()?;
        if !same(&w.q, q) {
            return None;
        }
        let (
            Query::Page { from, excl, .. },
            Query::Page {
                from: old,
                excl: oe,
                ..
            },
        ) = (q, &w.q)
        else {
            return None;
        };
        if from < old || (from == old && *oe && !*excl) {
            return None;
        }
        let Answer::Entries(v, more) = &*w.answer else {
            return None;
        };
        let lo = v.partition_point(|(k, _)| k < from || (*excl && k == from));
        if lo == v.len() && *more {
            return None;
        }
        let end = lo.saturating_add(q.demand().min(take.max(1))).min(v.len());
        if lo < end {
            for p in lo / PAGE..=(end - 1) / PAGE {
                let bit = 1u16 << p;
                if p >= w.q.demand().div_ceil(PAGE) && w.used & bit == 0 {
                    self.stats.useful += 1;
                    self.stats.useful_bytes = self
                        .stats
                        .useful_bytes
                        .saturating_add(cost(&v[p * PAGE..((p + 1) * PAGE).min(v.len())]));
                }
                w.used |= bit;
            }
        }
        let a = Arc::new(Answer::Entries(v[lo..end].to_vec(), *more || end < v.len()));
        self.stats.hits += 1;
        self.note(q.clone(), a.clone());
        Some(a)
    }
    pub fn pressure(&mut self, on: bool) {
        self.pressure = on;
        if on {
            self.discard_prediction();
            self.streak = 0;
            self.target = 1;
        }
    }
    /// Point work interrupts prediction without losing a parked scan's demand answer.
    pub fn interrupt(&mut self) {
        self.discard_prediction();
        self.streak = 0;
        self.target = 1;
    }
    pub fn clear(&mut self) {
        self.discard_window();
        self.streak = 0;
        self.target = 1;
        self.last = None;
    }
    fn discard_prediction(&mut self) {
        // Wide windows contain demanded rows, including the continuation entry.
        // Keep their owned tail through owner slices, but crop rows predicted
        // beyond that demand; invalidation/expiry still clears all.
        let Some(w) = &self.window else {
            return;
        };
        let demand = w.q.demand();
        if demand == PAGE {
            self.discard_window();
            return;
        }
        let Answer::Entries(v, _) = &*w.answer else {
            return;
        };
        if v.len() <= demand {
            return;
        }
        let kept = Arc::new(Answer::Entries(v[..demand].to_vec(), true));
        let Some(w) = self.window.take() else {
            return;
        };
        self.count_unused(&w);
        let used = w.used & (((1u32 << demand.div_ceil(PAGE)) - 1) as u16);
        self.window = Some(Window {
            q: w.q,
            answer: kept,
            used,
        });
    }
    pub fn invalidate(&mut self, ids: &[u64]) {
        if self.last.as_ref().is_some_and(|(q, _)| q.touches(ids))
            || self.window.as_ref().is_some_and(|w| w.q.touches(ids))
        {
            self.clear();
        }
    }
    pub fn bytes(&self) -> usize {
        self.window
            .as_ref()
            .map_or(0, |w| w.q.bytes() + w.answer.bytes())
            .saturating_add(self.last.as_ref().map_or(0, |(q, a)| {
                // Keep the conservative header charge even when a complete
                // answer shares its Arc. After dropping the window, charge demand fully.
                q.bytes()
                    + if self.window.is_some() {
                        match &**a {
                            Answer::Entries(v, _) => v.len() * 64,
                            _ => a.bytes(),
                        }
                    } else {
                        a.bytes()
                    }
            }))
    }
    /// Whole hinted pages are useful at first demand, not exact consumed bytes.
    pub fn counters(&self) -> [u64; 9] {
        [
            self.stats.hits,
            self.stats.retries,
            self.stats.submitted,
            self.stats.useful,
            self.stats.unused,
            self.stats.useful_bytes,
            self.stats.unused_bytes,
            self.bytes() as u64,
            self.target as u64,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn q(i: u32, excl: bool) -> Query {
        Query::Page {
            id: 1,
            from: Bytes::copy_from_slice(&i.to_be_bytes()),
            excl,
            prefix: Bytes::new(),
            versions: [(1, 1); 3],
            session: Some((1, 1)),
            keys_only: false,
            demand: PAGE,
        }
    }
    fn a(start: u32, n: u32, more: bool) -> Arc<Answer> {
        Arc::new(Answer::Entries(
            (start..start + n)
                .map(|i| {
                    (
                        Bytes::copy_from_slice(&i.to_be_bytes()),
                        Bytes::copy_from_slice(&i.to_le_bytes()),
                    )
                })
                .collect(),
            more,
        ))
    }
    #[test]
    fn complete_demand_reuses_immutable_answer_without_reducing_admission_charge() {
        for (width, rows, more) in [
            (PAGE, 0, false),
            (PAGE, 3, true),
            (PAGE, PAGE, false),
            (PAGE, PAGE, true),
            (1025, 1025, true),
        ] {
            let mut query = q(0, false);
            if let Query::Page { demand, .. } = &mut query {
                *demand = width;
            }
            let answer = a(0, rows as u32, more);
            let charged = 2 * query.bytes() + answer.bytes() + rows * 64;
            let mut cache = ScanCache::new(4);
            cache.insert(query.clone(), answer.clone());
            assert_eq!(cache.bytes(), charged, "keep the old conservative charge");
            let got = cache.get(&query).unwrap();
            assert!(
                Arc::ptr_eq(&got, &answer),
                "complete answers need no new row vector"
            );
            assert!(matches!(&*got, Answer::Entries(v, m) if v.len() == rows && *m == more));
            assert_eq!(&cache.counters()[..7], &[0, 1, 0, 0, 0, 0, 0]);
            cache.pressure(true);
            assert_eq!(
                cache.bytes(),
                if width == PAGE {
                    query.bytes() + answer.bytes()
                } else {
                    charged
                }
            );
            assert!(Arc::ptr_eq(&cache.get(&query).unwrap(), &answer));
            cache.invalidate(&[1]);
            assert!(cache.get(&query).is_none());
            assert_eq!(cache.bytes(), 0);
            // A consumer may still own the immutable result after cache retirement.
            assert!(matches!(&*got, Answer::Entries(v, m) if v.len() == rows && *m == more));
        }
    }

    #[test]
    fn shared_demand_can_retain_spare_capacity_after_prediction_is_discarded() {
        // Model a worker that reserved prediction capacity but returned demand only.
        // Sharing saves clones, not necessarily retained bytes after pressure.
        for already_under_pressure in [false, true] {
            let query = q(0, false);
            let mut rows = Vec::with_capacity(8 * PAGE);
            for id in 0..PAGE as u32 {
                rows.push((
                    Bytes::copy_from_slice(&id.to_be_bytes()),
                    Bytes::copy_from_slice(&id.to_le_bytes()),
                ));
            }
            let capacity = rows.capacity();
            let answer = Arc::new(Answer::Entries(rows, true));
            let mut cache = ScanCache::new(4);
            cache.pressure(already_under_pressure);
            cache.insert(query.clone(), answer.clone());
            cache.pressure(true);
            assert!(cache.window.is_none());
            let got = cache.get(&query).unwrap();
            assert!(Arc::ptr_eq(&got, &answer));
            let Answer::Entries(rows, true) = &*got else {
                panic!("demand")
            };
            assert_eq!((rows.len(), rows.capacity()), (PAGE, capacity));
            assert!(rows.capacity() > rows.len());
            assert_eq!(cache.bytes(), query.bytes() + answer.bytes());
            assert_eq!(&cache.counters()[2..7], &[0; 5]);
            cache.clear();
            assert_eq!(cache.bytes(), 0);
            assert_eq!(rows.last().unwrap().0[..], (PAGE as u32 - 1).to_be_bytes());
        }
    }

    #[test]
    fn prefetched_answer_still_crops_demand_and_marks_more_before_pressure() {
        let query = q(0, false);
        let answer = a(0, 3 * PAGE as u32, false);
        let mut cache = ScanCache::new(4);
        cache.insert(query.clone(), answer.clone());
        let got = cache.get(&query).unwrap();
        assert!(
            !Arc::ptr_eq(&got, &answer),
            "prediction must not leak into demand"
        );
        let Answer::Entries(rows, true) = &*got else {
            panic!("cropped answer must have more")
        };
        assert_eq!(rows.len(), PAGE);
        assert_eq!(rows[0].0[..], 0u32.to_be_bytes());
        assert_eq!(rows.last().unwrap().0[..], (PAGE as u32 - 1).to_be_bytes());
        assert_eq!(
            cache.bytes(),
            2 * query.bytes() + answer.bytes() + PAGE * 64
        );
        cache.pressure(true);
        assert_eq!(cache.bytes(), query.bytes() + got.bytes());
        assert!(Arc::ptr_eq(&cache.get(&query).unwrap(), &got));
        assert!(cache.get(&q(PAGE as u32 - 1, true)).is_none());
        assert_eq!(&cache.counters()[2..5], &[2, 0, 2]);
        assert!(matches!(&*answer, Answer::Entries(v, false) if v.len() == 3 * PAGE));
    }

    #[test]
    fn owned_window_preserves_bounds_projection_and_demand_under_pressure() {
        let mut c = ScanCache::new(4);
        c.insert(q(0, false), a(0, 768, true));
        let r = c.get(&q(255, true)).unwrap();
        let Answer::Entries(v, true) = &*r else {
            panic!()
        };
        assert_eq!(v[0].0[..], 256u32.to_be_bytes());
        assert_eq!(v.len(), 256);
        let count = c.counters();
        assert_eq!(count[3], 1);
        c.get(&q(255, true)).unwrap();
        assert_eq!(c.counters()[3], 1);
        let mut other = q(511, true);
        if let Query::Page { keys_only, .. } = &mut other {
            *keys_only = true;
        }
        assert!(c.get(&other).is_none());
        c.pressure(true);
        assert!(c.window.is_none());
        assert!(c.get(&q(255, true)).is_some());
        assert_eq!(c.counters()[4], 1);
        c.invalidate(&[1]);
        assert!(c.get(&q(255, true)).is_none());
        assert_eq!(c.bytes(), 0);
    }
    #[test]
    fn wide_demand_tail_survives_owner_slices_without_becoming_prediction() {
        let mut c = ScanCache::new(4);
        let mut first = q(0, false);
        if let Query::Page { demand, .. } = &mut first {
            *demand = 1025;
        }
        assert_eq!(c.prepare(&first), 1);
        c.insert(first, a(0, 1025, false));
        c.pressure(true);
        for from in [255, 511, 767, 1023] {
            let mut next = q(from, true);
            if let Query::Page { demand, .. } = &mut next {
                *demand = 1024 - from as usize;
            }
            let Answer::Entries(v, false) = &*c.get(&next).unwrap() else {
                panic!()
            };
            assert_eq!(v.len(), 1024 - from as usize);
            assert_eq!(v[0].0[..], (from + 1).to_be_bytes());
            assert_eq!(v.last().unwrap().0[..], 1024u32.to_be_bytes());
        }
        assert_eq!(
            c.counters()[2..7],
            [0; 5],
            "demand is not unused speculation"
        );
        let mut changed = q(1023, true);
        if let Query::Page { versions, .. } = &mut changed {
            versions[0].1 += 1;
        }
        assert!(c.get(&changed).is_none());
        c.clear();
        assert_eq!(c.bytes(), 0);
    }

    #[test]
    fn changed_demand_width_is_not_an_exact_retry_or_false_eof() {
        let mut c = ScanCache::new(4);
        let mut small = q(0, false);
        if let Query::Page { demand, .. } = &mut small {
            *demand = 2;
        }
        c.insert(small.clone(), a(0, 2, true));
        let mut wider = small;
        if let Query::Page { demand, .. } = &mut wider {
            *demand = 5;
        }
        assert!(matches!(&*c.get(&wider).unwrap(), Answer::Entries(v, true) if v.len() == 2));
        assert_eq!(c.counters()[1], 0);
        assert!(
            c.get(&q(1, true)).is_none(),
            "uncertain end needs another worker turn"
        );
    }

    #[test]
    fn locality_grows_only_after_observed_continuations_and_resets_on_seek() {
        let mut c = ScanCache::new(4);
        assert_eq!(c.prepare(&q(0, false)), 1);
        c.insert(q(0, false), a(0, 256, true));
        assert_eq!(c.prepare(&q(255, true)), 1);
        c.insert(q(255, true), a(256, 256, true));
        assert_eq!(c.prepare(&q(511, true)), 2);
        c.insert(q(511, true), a(512, 512, true));
        c.get(&q(767, true)).unwrap();
        assert_eq!(c.prepare(&q(1023, true)), 3);
        c.insert(q(1023, true), a(1024, 768, true));
        assert_eq!(c.prepare(&q(2, false)), 1);
        assert_eq!(c.counters()[4], 2);
    }
    fn wide(i: u32, excl: bool, request: u64) -> Query {
        let mut x = q(i, excl);
        if let Query::Page {
            demand, session, ..
        } = &mut x
        {
            *demand = 4 * PAGE;
            *session = Some((request, 1));
        }
        x
    }

    #[test]
    fn wide_pages_of_one_listing_share_a_growing_window_across_requests() {
        let mut c = ScanCache::new(4);
        let (mut start, mut widths) = (0u32, Vec::new());
        // Every page is a new request (session), as for a paginated client listing.
        for page in 0..16u64 {
            let req = if page == 0 {
                wide(0, false, page)
            } else {
                wide(start - 1, true, page)
            };
            let got = match c.get(&req) {
                Some(a) => a,
                None => {
                    let pages = c.prepare(&req);
                    widths.push(pages);
                    c.insert(req.clone(), a(start, (4 * PAGE * pages) as u32, true));
                    c.get(&req).expect("demand retry")
                }
            };
            let Answer::Entries(v, true) = &*got else {
                panic!("full page with more")
            };
            assert_eq!(v.len(), 4 * PAGE);
            assert_eq!(v[0].0[..], start.to_be_bytes());
            start += 4 * PAGE as u32;
        }
        // Capped by MAX_SCAN_ROWS / demand, not by the 256-row page count.
        assert_eq!(widths, [1, 1, 2, 3, 4, 4, 4]);
        assert_eq!(c.counters()[0], 9, "pages served without a worker turn");
        assert_eq!(c.counters()[4], 0, "no predicted page was wasted");
    }

    /// Worker answer over keys `0..keys` (u32 big-endian) for `q`, at most `rows`.
    fn answer_for(q: &Query, rows: usize, keys: u32) -> Arc<Answer> {
        let Query::Page { from, excl, .. } = q else {
            panic!("page query")
        };
        let start = (0..keys)
            .find(|i| {
                let k = i.to_be_bytes();
                if *excl {
                    k[..] > from[..]
                } else {
                    k[..] >= from[..]
                }
            })
            .unwrap_or(keys);
        let end = start.saturating_add(rows as u32).min(keys);
        a(start, end - start, end < keys)
    }

    /// Models the OSD listing stage over `keys` keys: each client page (a new
    /// request) reopens inclusively at `start_after` + 0x00, asks for
    /// `max - n + 1` rows, consumes at most 256 rows per owner pass and peeks one
    /// row beyond `max` to decide `more`. Returns (listed keys, worker turns).
    fn listing(c: &mut ScanCache, keys: u32, max: usize) -> (Vec<u32>, usize) {
        let (mut listed, mut turns, mut after) = (Vec::new(), 0, None::<Bytes>);
        for request in 1u64.. {
            let (mut from, mut excl) = match &after {
                None => (Bytes::new(), false),
                Some(k) => {
                    let mut succ = k.to_vec();
                    succ.push(0);
                    (Bytes::from(succ), false)
                }
            };
            let (mut n, mut more_pages) = (0usize, true);
            'page: loop {
                let mut taken = 0;
                loop {
                    let mut q = q(0, false);
                    if let Query::Page {
                        from: f,
                        excl: e,
                        demand,
                        session,
                        ..
                    } = &mut q
                    {
                        (*f, *e, *demand) = (from.clone(), excl, max - n + 1);
                        *session = Some((request, 1));
                    }
                    let got = match c.get(&q) {
                        Some(got) => got,
                        None => {
                            turns += 1;
                            let pages = c.prepare(&q);
                            let rows = q.demand().saturating_mul(pages).min(MAX_SCAN_ROWS);
                            c.insert(q.clone(), answer_for(&q, rows, keys));
                            c.get(&q).expect("demand retry")
                        }
                    };
                    let Answer::Entries(v, more) = &*got else {
                        panic!("entries")
                    };
                    for (k, _) in v {
                        if n >= max {
                            break 'page; // the look-ahead row: more pages follow
                        }
                        listed.push(u32::from_be_bytes(k[..].try_into().unwrap()));
                        (from, excl, n, taken) = (k.clone(), true, n + 1, taken + 1);
                        if taken >= PAGE {
                            continue 'page; // owner slice: the next pass re-queries
                        }
                    }
                    if !more {
                        more_pages = false;
                        break 'page;
                    }
                }
            }
            if !more_pages {
                return (listed, turns);
            }
            after = Some(from.clone());
        }
        unreachable!()
    }

    #[test]
    fn real_listing_pattern_grows_one_window_across_pages_and_slices() {
        let keys = 64 * 1024;
        let mut c = ScanCache::new(4);
        let (listed, turns) = listing(&mut c, keys, 1024);
        assert_eq!(
            listed,
            (0..keys).collect::<Vec<_>>(),
            "every key once, in order"
        );
        // 64 client pages; windows grow to MAX_SCAN_ROWS (4 pages), so roughly one
        // worker turn per 4 pages instead of one or two per page.
        assert!(turns <= 24, "{turns} worker turns for 64 pages");
        assert_eq!(c.counters()[4], 0, "no predicted page was wasted");
        // A width of 1 keeps the old one-turn-per-page behaviour.
        let mut one = ScanCache::new(1);
        let (listed, turns) = listing(&mut one, keys, 1024);
        assert_eq!(listed.len(), keys as usize);
        assert!(turns >= 64, "{turns}");
    }

    #[test]
    fn wide_window_needs_matching_revisions_and_crops_prediction_under_pressure() {
        let mut c = ScanCache::new(4);
        let first = wide(0, false, 1);
        c.insert(first.clone(), a(0, 16 * PAGE as u32, true));
        let mut changed = wide(4 * PAGE as u32 - 1, true, 2);
        if let Query::Page { versions, .. } = &mut changed {
            versions[1].1 += 1;
        }
        assert!(c.get(&changed).is_none(), "overlay revision changed");
        let before = c.bytes();
        c.pressure(true);
        assert!(c.bytes() < before);
        assert_eq!(c.counters()[4], 12, "predicted 256-row pages dropped");
        assert!(c.get(&wide(4 * PAGE as u32 - 1, true, 2)).is_none());
        let got = c.get(&first).expect("demand survives pressure");
        assert!(matches!(&*got, Answer::Entries(v, true) if v.len() == 4 * PAGE));
    }

    #[test]
    fn inclusive_seek_and_uncertain_end_do_not_fabricate_absence() {
        let mut c = ScanCache::new(4);
        c.insert(q(2, true), a(3, 256, true));
        assert!(c.get(&q(2, false)).is_none());
        assert!(c.get(&q(258, true)).is_none());
        c.clear();
        c.insert(q(2, true), a(3, 3, false));
        let r = c.get(&q(99, false)).unwrap();
        assert!(matches!(&*r,Answer::Entries(v,false) if v.is_empty()));
    }
}
