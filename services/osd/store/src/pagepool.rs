// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Tree page budget of one device, following demand across its shards (adr 0062 am. 3).
//!
//! [`crate::obj::StoreCfg::for_memory`] sizes every shard's tree page cache from an even share of the cache budget. A
//! shard brings that share into the device's [`PagePool`] as credits when it mounts ([`PageShare::join`]) and from then
//! on holds `cap` of them: the page budget its CLOCK evicts to ([`crate::tree::Tree::set_cap`]). Credits no shard holds
//! are the pool's free count. Credits move only through that counter, so the caps of all shards plus the free count
//! always equal the shares the shards brought: the device total never grows. Within a shard the budget stays soft as
//! before (adr 0175): pages that cannot go yet (dirty, in flight, pinned, just loaded) may hold it over its cap.
//!
//! The exchange approximates one CLOCK over the pages of all shards, without a lock: a page the CLOCK evicts was not
//! referenced for one revolution of its hand, so a shard whose hand turns faster evicts younger pages than a slower one,
//! and budget should move from the slower to the faster until their hands turn at the same pace. Every store sweep
//! (`obj::store::SWEEP_NS`: the period in which a store visits each of its shards, idle ones included) each shard runs
//! [`PageShare::exchange`] on its own core, between operations:
//! 1. Want: a full cache (`resident >= cap`) wants the point pages it loaded since its last exchange (listing leaves are
//!    cached scan-resistant and never ask) plus what it holds over its cap; one exchange grows a cache by what it
//!    missed, as one cache with free room would.
//! 2. Hand period: the sweep interval x slots / hand steps in it, the time one revolution takes at that pace (none if
//!    the hand stood still). Published with the unmet part of the want while the shard is short.
//! 3. A shard that wants nothing, or whose hand is slower than another short shard's, gives up to the outstanding want
//!    of the others (less the free count), never below its floor: first the part of its cap it has not filled (a cache's
//!    free room, used before it evicts; the data cache borrowing it gives way, adr 0633), then the pages its hand finds
//!    unreferenced while it advances at the fastest short shard's pace (slots x interval / that period steps): the pages
//!    one CLOCK over both shards would evict.
//! 4. Otherwise (it is the fastest short shard) it takes up to its want from the free count.
//!
//! The floor is the smallest cache a shard is sized with ([`crate::obj::MIN_CACHE_PAGES`], at most its own share). A
//! shard that leaves holding less than it brought leaves the pool in debt (free < 0): shards holding more than they
//! brought give the difference back at their next exchange.
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering::Relaxed};

/// What the exchange needs of a shard's tree page cache ([`crate::tree::Tree`]).
pub trait PageCache {
    /// Set the page budget the CLOCK evicts to.
    fn set_cap(&mut self, cap: usize);
    /// Pages cached.
    fn resident(&self) -> usize;
    /// Slots the CLOCK hand covers.
    fn slots(&self) -> usize;
    /// Running totals: point page loads (listing leaves excepted) and CLOCK hand steps.
    fn loads(&self) -> u64;
    fn hand_steps(&self) -> u64;
    /// Advance the CLOCK hand by up to `steps` slots as the eviction does (a referenced page loses its reference, an
    /// unreferenced evictable one goes), stopping after `max` evictions. Returns the pages evicted.
    fn age(&mut self, steps: usize, max: usize) -> usize;
}

impl PageCache for crate::tree::Tree {
    fn set_cap(&mut self, cap: usize) {
        crate::tree::Tree::set_cap(self, cap);
    }
    fn resident(&self) -> usize {
        self.resident_pages()
    }
    fn slots(&self) -> usize {
        crate::tree::Tree::slots(self)
    }
    fn loads(&self) -> u64 {
        self.stats.loads - self.stats.scan_loads
    }
    fn hand_steps(&self) -> u64 {
        self.stats.hand_steps
    }
    fn age(&mut self, steps: usize, max: usize) -> usize {
        crate::tree::Tree::age(self, steps, max)
    }
}

/// One shard's slot, written only by that shard's core.
#[repr(align(128))]
#[derive(Debug)]
struct Slot {
    /// Pages the shard wanted at its last exchange and did not get.
    want: AtomicU64,
    /// Its hand period (ns) while short; `u64::MAX` = not short or the hand stood still.
    period: AtomicU64,
}

impl Default for Slot {
    fn default() -> Self {
        Slot {
            want: AtomicU64::new(0),
            period: AtomicU64::new(u64::MAX),
        }
    }
}

/// The free count on a cache line (pair) of its own.
#[repr(align(128))]
#[derive(Debug, Default)]
struct Free(AtomicI64);

/// Tree page budget of the shards of one device (`ShardCfg::page_pool`).
#[derive(Debug, Default)]
pub struct PagePool {
    slots: OnceLock<Box<[Slot]>>,
    free: Free,
}

impl PagePool {
    /// Size the pool for the device's `n` shards (the first mount; a later mount of the same device agrees). False = the
    /// pool was sized for another device: the caller uses one of its own.
    pub fn init(&self, n: usize) -> bool {
        self.slots
            .get_or_init(|| (0..n).map(|_| Slot::default()).collect())
            .len()
            == n
    }

    /// Credits no shard holds (negative: a shard left holding less than it brought).
    fn free(&self) -> i64 {
        self.free.0.load(Relaxed)
    }

    /// Up to `n` free credits; returns how many.
    fn take(&self, n: u64) -> u64 {
        let mut got = 0;
        let _ = self.free.0.try_update(Relaxed, Relaxed, |f| {
            got = (f.max(0) as u64).min(n);
            (got > 0).then_some(f - got as i64)
        });
        got
    }

    fn give(&self, n: u64) {
        self.free.0.fetch_add(n as i64, Relaxed);
    }
}

/// Revolution time (ns, at least 1) of a hand that took `steps` steps over `slots` slots in `dt` ns; `u64::MAX` = it
/// stood still.
fn period(dt: u64, slots: usize, steps: u64) -> u64 {
    if steps == 0 {
        return u64::MAX;
    }
    (u128::from(dt) * slots as u128 / u128::from(steps)).clamp(1, u128::from(u64::MAX - 1)) as u64
}

/// Exchange counters of a shard (running totals, pages).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ShareStats {
    /// Credits taken from the pool.
    pub taken: u64,
    /// Credits given to it; of them, pages evicted to give them (`aged`).
    pub given: u64,
    pub aged: u64,
}

/// A shard's membership in its device's [`PagePool`]: the credits it holds and the state of its exchange.
#[derive(Debug)]
pub struct PageShare {
    pool: Arc<PagePool>,
    me: usize,
    /// Pages the shard brought, the least it keeps, and the pages it holds now (its cache's cap).
    base: usize,
    floor: usize,
    cap: usize,
    /// Clock, point loads and hand steps at the last exchange (`None` = none yet).
    at: Option<u64>,
    loads: u64,
    steps: u64,
    /// Hand steps owed to the aging pace, in step x period units (a slow pace takes fewer than one step per interval).
    owed: u128,
    pub stats: ShareStats,
}

impl PageShare {
    /// Join `pool` as shard `me` bringing `base` pages, keeping at least `floor` (at most `base`). `None`: the pool has no
    /// slot `me` (sized for another device); the shard keeps its own budget.
    pub fn join(pool: Arc<PagePool>, me: usize, base: usize, floor: usize) -> Option<PageShare> {
        let s = pool.slots.get()?.get(me)?;
        s.want.store(0, Relaxed);
        s.period.store(u64::MAX, Relaxed);
        Some(PageShare {
            pool,
            me,
            base,
            floor: floor.min(base),
            cap: base,
            at: None,
            loads: 0,
            steps: 0,
            owed: 0,
            stats: ShareStats::default(),
        })
    }

    /// Pages this shard holds.
    pub fn cap(&self) -> usize {
        self.cap
    }

    fn slots(&self) -> &[Slot] {
        self.pool.slots.get().expect("joined pools are sized")
    }

    /// One exchange (module docs) at clock time `now`, between operations of the shard's core.
    pub fn exchange<C: PageCache>(&mut self, now: u64, c: &mut C) {
        let (loads, steps) = (c.loads(), c.hand_steps());
        let Some(at) = self.at.filter(|&a| a < now) else {
            if self.at.is_none() {
                (self.at, self.loads, self.steps) = (Some(now), loads, steps);
            }
            return;
        };
        let dt = now - at;
        let (dl, ds) = (loads - self.loads, steps - self.steps);
        (self.at, self.loads, self.steps) = (Some(now), loads, steps);
        let res = c.resident();
        let want = if res >= self.cap {
            dl + (res - self.cap) as u64
        } else {
            0
        };
        let slots = c.slots();
        let own = period(dt, slots, ds);
        let (mut need, mut fastest) = (0u64, u64::MAX);
        for (j, s) in self.slots().iter().enumerate() {
            if j != self.me {
                need += s.want.load(Relaxed);
                fastest = fastest.min(s.period.load(Relaxed));
            }
        }
        let free = self.pool.free();
        // the pool is in debt (a shard left holding less than it brought): what this shard holds above its own share
        // goes back (the shrink evicts it)
        let mut give = if free < 0 {
            self.cap
                .saturating_sub(self.base)
                .min(free.unsigned_abs() as usize)
        } else {
            0
        };
        let mut got = 0;
        if want == 0 || fastest < own {
            let left = self.cap - give;
            let room = (need.saturating_sub(free.max(0) as u64) as usize)
                .min(left.saturating_sub(self.floor));
            let unused = room.min(left.saturating_sub(res));
            let mut aged = 0;
            if room > unused && fastest < own {
                self.owed += slots as u128 * u128::from(dt);
                let mut n = self.owed / u128::from(fastest);
                if n >= slots as u128 {
                    // a whole revolution: nothing older is left to age
                    (n, self.owed) = (slots as u128, 0);
                } else {
                    self.owed -= n * u128::from(fastest);
                }
                aged = c.age(n as usize, room - unused);
            } else {
                self.owed = 0;
            }
            give += unused + aged;
            self.stats.aged += aged as u64;
        } else if free > 0 {
            got = self.pool.take(want);
        }
        self.cap = self.cap + got as usize - give;
        if give > 0 {
            self.pool.give(give as u64);
        }
        self.stats.taken += got;
        self.stats.given += give as u64;
        c.set_cap(self.cap);
        let short = want - got;
        let s = &self.slots()[self.me];
        s.want.store(short, Relaxed);
        s.period
            .store(if short > 0 { own } else { u64::MAX }, Relaxed);
    }
}

impl Drop for PageShare {
    fn drop(&mut self) {
        // what it holds goes back, what it brought leaves with it
        self.pool
            .free
            .0
            .fetch_add(self.cap as i64 - self.base as i64, Relaxed);
        let s = &self.slots()[self.me];
        s.want.store(0, Relaxed);
        s.period.store(u64::MAX, Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::Rng;
    use std::collections::HashMap;

    /// A shard's page cache as the tree keeps it: CLOCK over a slab, evict to the cap after every load; free slots keep
    /// their buffer (`free[..released]` have none) until the cap leaves no room for them ([`crate::tree::Tree::set_cap`]).
    #[derive(Default)]
    struct Model {
        slab: Vec<Option<(u64, bool)>>,
        map: HashMap<u64, usize>,
        free: Vec<usize>,
        released: usize,
        hand: usize,
        cap: usize,
        loads: u64,
        steps: u64,
    }

    impl Model {
        fn new(cap: usize) -> Model {
            Model {
                cap,
                ..Default::default()
            }
        }
        fn held(&self) -> usize {
            self.slab.len() - self.released
        }
        fn step(&mut self) -> bool {
            self.hand = (self.hand + 1) % self.slab.len();
            self.steps += 1;
            match &mut self.slab[self.hand] {
                None => false,
                Some((_, r)) if *r => {
                    *r = false;
                    false
                }
                Some((k, _)) => {
                    self.map.remove(k);
                    self.slab[self.hand] = None;
                    self.free.push(self.hand);
                    true
                }
            }
        }
        fn access(&mut self, k: u64) {
            if let Some(&s) = self.map.get(&k) {
                self.slab[s].as_mut().unwrap().1 = true;
                return;
            }
            self.loads += 1;
            let s = match self.free.pop() {
                Some(s) => {
                    self.released = self.released.min(self.free.len());
                    s
                }
                None => {
                    self.slab.push(None);
                    self.slab.len() - 1
                }
            };
            self.slab[s] = Some((k, true));
            self.map.insert(k, s);
            let mut budget = self.slab.len();
            while self.map.len() > self.cap && budget > 0 {
                budget -= 1;
                self.step();
            }
        }
    }

    impl PageCache for Model {
        fn set_cap(&mut self, cap: usize) {
            self.cap = cap;
            let keep = crate::tree::buffer_mark(cap).max(self.resident());
            while self.held() > keep && self.released < self.free.len() {
                self.released += 1;
            }
        }
        fn resident(&self) -> usize {
            self.map.len()
        }
        fn slots(&self) -> usize {
            self.slab.len()
        }
        fn loads(&self) -> u64 {
            self.loads
        }
        fn hand_steps(&self) -> u64 {
            self.steps
        }
        fn age(&mut self, steps: usize, max: usize) -> usize {
            let mut got = 0;
            for _ in 0..steps.min(self.slab.len()) {
                if got == max {
                    break;
                }
                got += usize::from(self.step());
            }
            got
        }
    }

    /// Shards of one device: a model cache and its share each.
    struct Dev {
        pool: Arc<PagePool>,
        sh: Vec<(Model, Option<PageShare>)>,
        total: i64,
        now: u64,
    }

    /// One store sweep.
    const TICK: u64 = 1_000_000;

    impl Dev {
        fn new(n: usize, base: usize, floor: usize) -> Dev {
            let pool = Arc::new(PagePool::default());
            assert!(pool.init(n));
            let sh = (0..n)
                .map(|i| {
                    (
                        Model::new(base),
                        Some(PageShare::join(pool.clone(), i, base, floor).unwrap()),
                    )
                })
                .collect();
            Dev {
                pool,
                sh,
                total: (n * base) as i64,
                now: 0,
            }
        }
        fn cap(&self, i: usize) -> usize {
            self.sh[i].1.as_ref().map_or(0, PageShare::cap)
        }
        /// `ticks` sweeps; in each, shard `i` makes the accesses `load(i, rng)` returns, then every shard exchanges.
        /// Returns (loads, accesses) per shard over the run.
        fn run(
            &mut self,
            ticks: usize,
            rng: &mut Rng,
            load: impl Fn(usize, &mut Rng) -> Vec<u64>,
        ) -> Vec<(u64, u64)> {
            let mut acc = vec![(0, 0); self.sh.len()];
            let l0: Vec<u64> = self.sh.iter().map(|s| s.0.loads).collect();
            for _ in 0..ticks {
                self.now += TICK;
                for (i, a) in acc.iter_mut().enumerate() {
                    let keys = load(i, rng);
                    a.1 += keys.len() as u64;
                    for k in keys {
                        self.sh[i].0.access(k);
                    }
                }
                for i in 0..self.sh.len() {
                    let (m, s) = &mut self.sh[i];
                    if let Some(s) = s {
                        s.exchange(self.now, m);
                    }
                    self.check();
                }
            }
            for (i, s) in self.sh.iter().enumerate() {
                acc[i].0 = s.0.loads - l0[i];
            }
            acc
        }
        /// The device budget is exact: the caps plus the free count = what the shards brought; every model honours its
        /// cap but for what it cannot evict, and keeps no buffers beyond the mark.
        fn check(&self) {
            let held: usize = self
                .sh
                .iter()
                .filter_map(|s| s.1.as_ref())
                .map(PageShare::cap)
                .sum();
            assert_eq!(
                held as i64 + self.pool.free(),
                self.total,
                "budget not conserved"
            );
            for (m, s) in &self.sh {
                if let Some(s) = s {
                    assert_eq!(m.cap, s.cap());
                    assert!(s.cap() >= s.floor, "below floor");
                    assert!(
                        m.held() <= crate::tree::buffer_mark(m.cap).max(m.resident()),
                        "buffers above the budget"
                    );
                }
            }
        }
    }

    fn uniform(n: u64, k: usize, off: u64) -> impl Fn(&mut Rng) -> Vec<u64> {
        move |r: &mut Rng| (0..k).map(|_| off + r.below(n)).collect()
    }

    #[test]
    fn pool_take_never_overdraws() {
        let p = PagePool::default();
        assert!(p.init(1));
        p.give(5);
        assert_eq!((p.take(10), p.free()), (5, 0));
        assert_eq!(p.take(1), 0);
        p.free.0.store(-3, Relaxed);
        assert_eq!((p.take(1), p.free()), (0, -3));
        assert!(!p.init(2), "sized for another device");
        assert!(
            PageShare::join(Arc::new(p), 1, 10, 1).is_none(),
            "no slot 1"
        );
    }

    #[test]
    fn hot_shard_grows_to_most_of_the_budget_cold_shards_shrink() {
        // 6 shards of 10k pages, floor 1k; shard 0 cycles over 100k keys (more than the device holds), the others keep a
        // small hot set of 100 pages each
        let (n, base, floor) = (6, 10_000, 1_000);
        let mut d = Dev::new(n, base, floor);
        let mut rng = Rng::new(1);
        let hot = uniform(100_000, 2000, 0);
        let cold = |i: usize| uniform(100, 20, 1_000_000 * i as u64);
        d.run(
            400,
            &mut rng,
            |i, r| if i == 0 { hot(r) } else { cold(i)(r) },
        );
        assert_eq!(
            d.cap(0),
            n * base - (n - 1) * floor,
            "the hot shard holds all but the floors"
        );
        for i in 1..n {
            assert_eq!(d.cap(i), floor, "cold shard {i}");
            assert_eq!(
                d.sh[i].0.resident(),
                100,
                "a cold shard keeps its own hot set"
            );
        }
        assert_eq!(d.pool.free(), 0);
        // the cold shards' hot sets stayed: no misses after warm-up
        let r = d.run(
            50,
            &mut rng,
            |i, r| if i == 0 { hot(r) } else { cold(i)(r) },
        );
        for (i, &(loads, _)) in r.iter().enumerate().skip(1) {
            assert_eq!(loads, 0, "cold shard {i} lost referenced pages");
        }
    }

    #[test]
    fn misses_drop_when_the_working_set_exceeds_the_even_share() {
        // shard 0's working set (40k) is 4x its share and fits the device (60k): its miss rate falls from the even-share
        // CLOCK's ~75 % to the compulsory misses only
        let (n, base, floor) = (6, 10_000, 1_000);
        let mut d = Dev::new(n, base, floor);
        let mut rng = Rng::new(2);
        let hot = uniform(40_000, 2000, 0);
        let first = d.run(5, &mut rng, |i, r| if i == 0 { hot(r) } else { vec![] });
        d.run(200, &mut rng, |i, r| if i == 0 { hot(r) } else { vec![] });
        let last = d.run(50, &mut rng, |i, r| if i == 0 { hot(r) } else { vec![] });
        let rate = |x: (u64, u64)| x.0 as f64 / x.1 as f64;
        assert!(rate(first[0]) > 0.5, "cold start {}", rate(first[0]));
        assert!(rate(last[0]) < 0.01, "warm miss rate {}", rate(last[0]));
        assert!(d.cap(0) >= 39_000, "cap {}", d.cap(0));
        // the same load on even shares: the share misses ~3/4
        let mut e = Dev::new(1, base, floor);
        e.run(200, &mut rng, |_, r| hot(r));
        let even = e.run(50, &mut rng, |_, r| hot(r));
        assert!(
            rate(even[0]) > 0.7,
            "even-share miss rate {}",
            rate(even[0])
        );
    }

    #[test]
    fn budget_comes_back_when_the_hot_shard_cools() {
        let (n, base, floor) = (4, 10_000, 1_000);
        let mut d = Dev::new(n, base, floor);
        let mut rng = Rng::new(3);
        let a = uniform(100_000, 2000, 0);
        let b = uniform(100_000, 2000, 1 << 40);
        d.run(300, &mut rng, |i, r| if i == 0 { a(r) } else { vec![] });
        assert_eq!(d.cap(0), n * base - (n - 1) * floor);
        // shard 0 goes idle, shard 1 gets hot: shard 0's pages age out at shard 1's pace and move over
        d.run(400, &mut rng, |i, r| if i == 1 { b(r) } else { vec![] });
        assert_eq!(d.cap(1), n * base - (n - 1) * floor, "the new hot shard");
        assert_eq!(d.cap(0), floor, "the cooled shard");
        let s0 = d.sh[0].1.as_ref().unwrap().stats;
        assert!(s0.aged > 0 && s0.given >= s0.aged, "{s0:?}");
    }

    #[test]
    fn a_shard_keeps_pages_it_reuses_faster_than_the_thrashing_one() {
        // one CLOCK over both shards: shard 0 re-references each of its 5k pages about twice per sweep, shard 1 cycles
        // over 200k keys and its hand takes several sweeps per revolution: shard 0 keeps its set, its unused budget
        // moves over. (A page reused more slowly than the thrashing hand turns goes, as in one shared cache.)
        let (n, base, floor) = (2, 10_000, 1_000);
        let mut d = Dev::new(n, base, floor);
        let mut rng = Rng::new(4);
        let a = uniform(5_000, 10_000, 0);
        let b = uniform(200_000, 2000, 1 << 40);
        d.run(400, &mut rng, |i, r| if i == 0 { a(r) } else { b(r) });
        let last = d.run(100, &mut rng, |i, r| if i == 0 { a(r) } else { b(r) });
        let rate0 = last[0].0 as f64 / last[0].1 as f64;
        assert!(rate0 < 0.005, "shard 0 miss rate {rate0}");
        assert!(
            d.cap(0) < base && d.cap(1) > base,
            "caps {} {}",
            d.cap(0),
            d.cap(1)
        );
        assert!(d.cap(0) >= 4_500, "cap 0 {}", d.cap(0));
    }

    #[test]
    fn equally_hot_shards_share_evenly() {
        let (n, base, floor) = (3, 10_000, 1_000);
        let mut d = Dev::new(n, base, floor);
        let mut rng = Rng::new(5);
        let hot = |i: usize| uniform(100_000, 2000, (i as u64) << 40);
        d.run(400, &mut rng, |i, r| if i < 2 { hot(i)(r) } else { vec![] });
        let (a, b) = (d.cap(0), d.cap(1));
        assert_eq!(d.cap(2), floor);
        assert!(a.abs_diff(b) * 4 < a.min(b), "uneven {a} {b}");
    }

    #[test]
    fn a_shard_leaving_short_is_paid_back() {
        let (n, base, floor) = (2, 10_000, 1_000);
        let mut d = Dev::new(n, base, floor);
        let mut rng = Rng::new(6);
        let hot = uniform(100_000, 2000, 0);
        d.run(200, &mut rng, |i, r| if i == 0 { hot(r) } else { vec![] });
        assert_eq!((d.cap(0), d.cap(1)), (2 * base - floor, floor));
        d.sh[1].1 = None; // leaves holding its floor: the pool owes what shard 0 took
        d.total -= base as i64;
        assert_eq!(d.pool.free(), floor as i64 - base as i64);
        d.run(3, &mut rng, |_, _| vec![]);
        assert_eq!((d.cap(0), d.pool.free()), (base, 0));
    }

    #[test]
    fn concurrent_exchanges_conserve_the_budget() {
        // one core per shard, unsynchronized: the caps and the free count always add up, no cap below its floor
        let (n, base, floor) = (4usize, 4_000, 500);
        let pool = Arc::new(PagePool::default());
        assert!(pool.init(n));
        let hs: Vec<_> = (0..n)
            .map(|i| {
                let pool = pool.clone();
                std::thread::spawn(move || {
                    let mut m = Model::new(base);
                    let mut s = PageShare::join(pool, i, base, floor).unwrap();
                    let mut rng = Rng::new(10 + i as u64);
                    for t in 1..=3000u64 {
                        // phases: shard i is hot in its own quarter of the run
                        let hot = (t * n as u64 / 3000) as usize == i;
                        let k = if hot { 400 } else { 5 };
                        for _ in 0..k {
                            m.access(if hot {
                                rng.below(30_000)
                            } else {
                                rng.below(50)
                            });
                        }
                        s.exchange(t * TICK, &mut m);
                        assert!(s.cap() >= floor && m.cap == s.cap());
                    }
                    s
                })
            })
            .collect();
        let shares: Vec<PageShare> = hs.into_iter().map(|h| h.join().unwrap()).collect();
        let held: usize = shares.iter().map(PageShare::cap).sum();
        assert_eq!(held as i64 + pool.free(), (n * base) as i64);
        assert!(pool.free() >= 0);
        drop(shares);
        assert_eq!(pool.free(), 0);
    }
}
