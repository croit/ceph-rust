// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! pg_history_t (spec peering.md 2.2).

use denc::types::{Eversion, Timespan, UTime};
use denc::{BufMut, Decode, Decoder, Encode, Encoder, Result};

/// pg_history_t, ENCODE v11 (v12 with the fork start stamp) compat 4 (peering.md 2.2, adr 0628-pg-history-v12).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PgHistory {
    pub epoch_created: u32,
    pub last_epoch_started: u32,
    pub last_epoch_clean: u32,
    pub last_epoch_split: u32,
    pub same_interval_since: u32,
    pub same_up_since: u32,
    pub same_primary_since: u32,
    pub last_scrub: Eversion,
    pub last_scrub_stamp: UTime,
    pub last_deep_scrub: Eversion,
    pub last_deep_scrub_stamp: UTime,
    pub last_clean_scrub_stamp: UTime,
    pub last_epoch_marked_full: u32,
    pub last_interval_started: u32,
    pub last_interval_clean: u32,
    pub epoch_pool_created: u32,
    /// Relative to the sender's monotonic clock at encode time (peering.md 8.3).
    pub prior_readable_until_ub: Timespan,
    /// v11: onset of the current / last vulnerability window (degraded, undersized or objects degraded / misplaced);
    /// latched by the acting primary, never moved while the window is open (peering.md 2.2 field 18).
    pub last_degraded: UTime,
    /// v11: `vuln_window_reported` of the last window close (kept max-merged for older peers, not read by 21.2.0 logic).
    pub last_clean: UTime,
    /// v11: time of the clean publish that closed the last window ("recorded up to"). A window is open while
    /// `last_degraded > vuln_window_reported`.
    pub vuln_window_reported: UTime,
    /// v11: onset of the current active-rebuild span (Recovering / Backfilling); open while `> rebuild_span_reported`.
    pub last_rebuild_active_start: UTime,
    /// v11: time of the last rebuild-span transition (pause or close).
    pub rebuild_span_reported: UTime,
    /// v11: active-rebuild time of the already paused spans of the current episode (a duration in a utime).
    pub rebuild_active_accum: UTime,
    /// Start of the deep scrub that set `last_deep_scrub_stamp` (croit fork `wip-ifed-dedup`, dedup-listing.md 5.1;
    /// adr 0593-dedup-deep-scrub-reformat, adr 0628-pg-history-v12): dedup records of that scrub are not older. Zero =
    /// unknown; encoded (v12, after the v11 fields) only when set, so a PG without it keeps the upstream v11 bytes.
    pub last_deep_scrub_start_stamp: UTime,
}

impl PgHistory {
    pub const STRUCT_V: u8 = 11;
    /// With `last_deep_scrub_start_stamp` (fork); compat unchanged, so upstream decoders skip the field.
    pub const STRUCT_V_START_STAMP: u8 = 12;
    pub const STRUCT_COMPAT: u8 = 4;

    /// History of a freshly created PG (peering.md 2.2 constructor).
    pub fn new_pg(create_epoch: u32, stamp: UTime) -> Self {
        PgHistory {
            epoch_created: create_epoch,
            epoch_pool_created: create_epoch,
            same_up_since: create_epoch,
            same_interval_since: create_epoch,
            same_primary_since: create_epoch,
            last_scrub_stamp: stamp,
            last_deep_scrub_stamp: stamp,
            last_clean_scrub_stamp: stamp,
            ..Default::default()
        }
    }

    /// Field-wise max merge (`pg_history_t::merge`). Returns true if anything changed. The interval-local facts
    /// `same_interval_since` / `same_up_since` / `same_primary_since` are never merged: each OSD derives them from its
    /// own map history.
    /// `prior_readable_until_ub`: a newer `last_interval_started` in `other` replaces ours; for the
    /// same interval the smaller (tighter) bound wins.
    pub fn merge(&mut self, o: &PgHistory) -> bool {
        let mut changed = false;
        macro_rules! mx {
            ($($f:ident),*) => {$(
                if o.$f > self.$f { self.$f = o.$f; changed = true; }
            )*};
        }
        // prior bound first: it depends on the *old* last_interval_started
        if o.last_interval_started > self.last_interval_started {
            if self.prior_readable_until_ub != o.prior_readable_until_ub {
                changed = true;
            }
            self.prior_readable_until_ub = o.prior_readable_until_ub;
        } else if o.last_interval_started == self.last_interval_started
            && o.prior_readable_until_ub < self.prior_readable_until_ub
        {
            self.prior_readable_until_ub = o.prior_readable_until_ub;
            changed = true;
        }
        mx!(
            epoch_created,
            last_epoch_started,
            last_epoch_clean,
            last_epoch_split,
            last_scrub,
            last_scrub_stamp,
            last_deep_scrub,
            last_clean_scrub_stamp,
            last_epoch_marked_full,
            last_interval_started,
            last_interval_clean,
            epoch_pool_created
        );
        // the deep scrub start stamp travels with its completion stamp (dedup-listing.md 5.1)
        if o.last_deep_scrub_stamp > self.last_deep_scrub_stamp {
            self.last_deep_scrub_stamp = o.last_deep_scrub_stamp;
            self.last_deep_scrub_start_stamp = o.last_deep_scrub_start_stamp;
            changed = true;
        } else if o.last_deep_scrub_stamp == self.last_deep_scrub_stamp
            && o.last_deep_scrub_start_stamp > self.last_deep_scrub_start_stamp
        {
            self.last_deep_scrub_start_stamp = o.last_deep_scrub_start_stamp;
            changed = true;
        }
        changed |= self.merge_latches(o);
        changed
    }

    /// Merge of the v11 vulnerability-window and rebuild-span fields (peering.md 2.2 merge, rules W2). Order matters:
    /// the window onset is judged against the MERGED `vuln_window_reported`; the rebuild onset and accum move together.
    fn merge_latches(&mut self, o: &PgHistory) -> bool {
        let before = (
            self.last_degraded,
            self.last_clean,
            self.vuln_window_reported,
            self.last_rebuild_active_start,
            self.rebuild_span_reported,
            self.rebuild_active_accum,
        );
        self.vuln_window_reported = self.vuln_window_reported.max(o.vuln_window_reported);
        self.last_clean = self.last_clean.max(o.last_clean);
        let r = self.vuln_window_reported;
        self.last_degraded = match (self.last_degraded > r, o.last_degraded > r) {
            (true, true) => self.last_degraded.min(o.last_degraded),
            (true, false) => self.last_degraded,
            (false, true) => o.last_degraded,
            (false, false) => self.last_degraded.max(o.last_degraded),
        };
        let take = if o.rebuild_span_reported > self.rebuild_span_reported {
            self.rebuild_span_reported = o.rebuild_span_reported;
            true
        } else if o.rebuild_span_reported == self.rebuild_span_reported {
            let rep = self.rebuild_span_reported;
            let ours = self.last_rebuild_active_start > rep;
            o.last_rebuild_active_start > rep
                && (!ours || o.last_rebuild_active_start < self.last_rebuild_active_start)
        } else {
            false
        };
        if take {
            self.last_rebuild_active_start = o.last_rebuild_active_start;
            self.rebuild_active_accum = o.rebuild_active_accum;
        }
        before
            != (
                self.last_degraded,
                self.last_clean,
                self.vuln_window_reported,
                self.last_rebuild_active_start,
                self.rebuild_span_reported,
                self.rebuild_active_accum,
            )
    }

    /// A vulnerability window is open (onset after the last recorded close).
    pub fn vuln_open(&self) -> bool {
        self.last_degraded > self.vuln_window_reported
    }

    /// An active-rebuild span is open (onset after the last pause / close).
    pub fn rebuild_open(&self) -> bool {
        self.last_rebuild_active_start > self.rebuild_span_reported
    }
}

impl Encode for PgHistory {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        let start = self.last_deep_scrub_start_stamp != UTime::default();
        let v = if start {
            Self::STRUCT_V_START_STAMP
        } else {
            Self::STRUCT_V
        };
        e.versioned(v, Self::STRUCT_COMPAT, |e| {
            e.u32(self.epoch_created)?;
            e.u32(self.last_epoch_started)?;
            e.u32(self.last_epoch_clean)?;
            e.u32(self.last_epoch_split)?;
            e.u32(self.same_interval_since)?;
            e.u32(self.same_up_since)?;
            e.u32(self.same_primary_since)?;
            self.last_scrub.encode(e)?;
            self.last_scrub_stamp.encode(e)?;
            self.last_deep_scrub.encode(e)?;
            self.last_deep_scrub_stamp.encode(e)?;
            self.last_clean_scrub_stamp.encode(e)?;
            e.u32(self.last_epoch_marked_full)?;
            e.u32(self.last_interval_started)?;
            e.u32(self.last_interval_clean)?;
            e.u32(self.epoch_pool_created)?;
            self.prior_readable_until_ub.encode(e)?;
            self.last_degraded.encode(e)?;
            self.last_clean.encode(e)?;
            self.vuln_window_reported.encode(e)?;
            self.last_rebuild_active_start.encode(e)?;
            self.rebuild_span_reported.encode(e)?;
            self.rebuild_active_accum.encode(e)?;
            if start {
                self.last_deep_scrub_start_stamp.encode(e)?;
            }
            Ok(())
        })
    }
}

impl<'a> Decode<'a> for PgHistory {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        d.versioned_min(4, Self::STRUCT_COMPAT, |d, v| {
            let mut h = PgHistory {
                epoch_created: d.u32()?,
                last_epoch_started: d.u32()?,
                last_epoch_clean: d.u32()?,
                last_epoch_split: d.u32()?,
                same_interval_since: d.u32()?,
                same_up_since: d.u32()?,
                same_primary_since: d.u32()?,
                ..Default::default()
            };
            if v >= 2 {
                h.last_scrub = Eversion::decode(d)?;
                h.last_scrub_stamp = UTime::decode(d)?;
            }
            if v >= 5 {
                h.last_deep_scrub = Eversion::decode(d)?;
                h.last_deep_scrub_stamp = UTime::decode(d)?;
            }
            if v >= 6 {
                h.last_clean_scrub_stamp = UTime::decode(d)?;
            }
            if v >= 7 {
                h.last_epoch_marked_full = d.u32()?;
            }
            if v >= 8 {
                h.last_interval_started = d.u32()?;
                h.last_interval_clean = d.u32()?;
            } else {
                // old writers: guess from the epochs (peering.md 2.2)
                h.last_interval_started = h.last_epoch_started;
                h.last_interval_clean = h.last_epoch_clean;
            }
            h.epoch_pool_created = if v >= 9 { d.u32()? } else { h.epoch_created };
            if v >= 10 {
                h.prior_readable_until_ub = Timespan::decode(d)?;
            }
            // v < 11: no window open, nothing pending (all six zero; never invent a pre-upgrade window)
            if v >= 11 {
                h.last_degraded = UTime::decode(d)?;
                h.last_clean = UTime::decode(d)?;
                h.vuln_window_reported = UTime::decode(d)?;
                h.last_rebuild_active_start = UTime::decode(d)?;
                h.rebuild_span_reported = UTime::decode(d)?;
                h.rebuild_active_accum = UTime::decode(d)?;
            }
            // v12 (croit, adr 0628-pg-history-v12); newer versions: our fields, the rest skipped by the envelope
            if v >= 12 {
                h.last_deep_scrub_start_stamp = UTime::decode(d)?;
            }
            Ok(h)
        })
    }
}

#[cfg(test)]
mod start_stamp_tests {
    use super::*;

    fn h() -> PgHistory {
        PgHistory {
            epoch_created: 5,
            last_deep_scrub_stamp: UTime { sec: 100, nsec: 1 },
            ..Default::default()
        }
    }

    #[test]
    fn v11_bytes_without_the_stamp_v12_with_it() {
        let a = denc::to_vec(&h()).unwrap();
        // upstream v11: fixed 148 B payload after the 6 B envelope
        assert_eq!((a[0], a[1], a.len()), (11, 4, 6 + 148));
        let b = denc::to_vec(&PgHistory {
            last_deep_scrub_start_stamp: UTime { sec: 13, nsec: 14 },
            ..h()
        })
        .unwrap();
        // v12 = v11 + 8 stamp bytes, envelope length + 8, struct_v 12, compat 4
        assert_eq!((b[0], b[1]), (12, 4));
        assert_eq!(b.len(), a.len() + 8);
        assert_eq!(
            u32::from_le_bytes(b[2..6].try_into().unwrap()),
            u32::from_le_bytes(a[2..6].try_into().unwrap()) + 8
        );
        assert_eq!(&b[6..a.len()], &a[6..]);
        assert_eq!(&b[a.len()..], &[13, 0, 0, 0, 14, 0, 0, 0]);
        let d: PgHistory = denc::from_slice(&b).unwrap();
        assert_eq!(d.last_deep_scrub_start_stamp, UTime { sec: 13, nsec: 14 });
        let d: PgHistory = denc::from_slice(&a).unwrap();
        assert_eq!(d, h());
    }

    fn latched() -> PgHistory {
        PgHistory {
            last_degraded: UTime::new(19, 20),
            last_clean: UTime::new(21, 22),
            vuln_window_reported: UTime::new(21, 22),
            last_rebuild_active_start: UTime::new(23, 24),
            rebuild_span_reported: UTime::new(25, 26),
            rebuild_active_accum: UTime::new(0, 27),
            ..h()
        }
    }

    #[test]
    fn v11_fields_in_upstream_order_and_v12_after_them() {
        let a = denc::to_vec(&latched()).unwrap();
        let tail: Vec<u8> = [19u32, 20, 21, 22, 21, 22, 23, 24, 25, 26, 0, 27]
            .iter()
            .flat_map(|x| x.to_le_bytes())
            .collect();
        assert_eq!(&a[a.len() - 48..], &tail[..]);
        let s = PgHistory {
            last_deep_scrub_start_stamp: UTime::new(13, 14),
            ..latched()
        };
        let b = denc::to_vec(&s).unwrap();
        assert_eq!(&b[b.len() - 56..b.len() - 8], &tail[..]);
        assert_eq!(denc::from_slice::<PgHistory>(&b).unwrap(), s);
        assert_eq!(denc::from_slice::<PgHistory>(&a).unwrap(), latched());
    }

    /// v10 (upstream <= 21.1.x): the six v11 fields decode as zero (no window open, nothing pending).
    #[test]
    fn v10_decodes_with_zero_latches() {
        let a = denc::to_vec(&latched()).unwrap();
        let mut v10 = a[..a.len() - 48].to_vec();
        v10[0] = 10;
        let l = u32::from_le_bytes(v10[2..6].try_into().unwrap()) - 48;
        v10[2..6].copy_from_slice(&l.to_le_bytes());
        assert_eq!(denc::from_slice::<PgHistory>(&v10).unwrap(), h());
    }

    /// A newer writer (v13+, compat 4): our fields decode, the unknown tail is skipped.
    #[test]
    fn newer_version_tail_skipped() {
        let s = PgHistory {
            last_deep_scrub_start_stamp: UTime::new(13, 14),
            ..latched()
        };
        let mut b = denc::to_vec(&s).unwrap();
        b[0] = 13;
        let l = u32::from_le_bytes(b[2..6].try_into().unwrap()) + 5;
        b[2..6].copy_from_slice(&l.to_le_bytes());
        b.extend([0xab; 5]);
        b.push(0x77);
        let mut d = denc::Decoder::new(&b);
        assert_eq!(PgHistory::decode(&mut d).unwrap(), s);
        assert_eq!(d.remaining(), 1);
    }

    fn w(ld: u32, rep: u32) -> PgHistory {
        PgHistory {
            last_degraded: UTime::new(ld, 0),
            vuln_window_reported: UTime::new(rep, 0),
            last_clean: UTime::new(rep, 0),
            ..Default::default()
        }
    }

    /// The interval-local fields stay ours (a peer that loaded the PG at another epoch must not move our interval).
    #[test]
    fn merge_keeps_interval_local_fields() {
        let mut a = PgHistory {
            same_interval_since: 10,
            same_up_since: 9,
            same_primary_since: 8,
            ..Default::default()
        };
        let b = PgHistory {
            same_interval_since: 20,
            same_up_since: 20,
            same_primary_since: 20,
            last_epoch_started: 15,
            ..Default::default()
        };
        assert!(a.merge(&b));
        assert_eq!(
            (a.same_interval_since, a.same_up_since, a.same_primary_since),
            (10, 9, 8)
        );
        assert_eq!(a.last_epoch_started, 15);
    }

    #[test]
    fn merge_vulnerability_window() {
        // both open (same reported): the earliest onset
        let mut a = w(30, 10);
        assert!(a.merge(&w(20, 10)));
        assert_eq!(a.last_degraded.sec, 20);
        assert!(!a.merge(&w(25, 10)));
        // only theirs open
        let mut a = w(5, 10);
        assert!(a.merge(&w(20, 10)));
        assert_eq!(a.last_degraded.sec, 20);
        // only ours open
        let mut a = w(20, 10);
        assert!(!a.merge(&w(5, 10)));
        assert_eq!(a.last_degraded.sec, 20);
        // none open: max
        let mut a = w(3, 10);
        assert!(a.merge(&w(7, 10)));
        assert_eq!(a.last_degraded.sec, 7);
        // judged against the MERGED reported: their close (reported 40) closes our open window (onset 30)
        let mut a = w(30, 10);
        assert!(a.merge(&w(25, 40)));
        assert_eq!(
            (
                a.last_degraded.sec,
                a.vuln_window_reported.sec,
                a.last_clean.sec
            ),
            (30, 40, 40)
        );
        assert!(!a.vuln_open());
        // a window opened after their close survives
        let mut a = w(50, 10);
        assert!(a.merge(&w(25, 40)));
        assert_eq!((a.last_degraded.sec, a.vuln_window_reported.sec), (50, 40));
        assert!(a.vuln_open());
    }

    fn r(onset: u32, rep: u32, acc: u32) -> PgHistory {
        PgHistory {
            last_rebuild_active_start: UTime::new(onset, 0),
            rebuild_span_reported: UTime::new(rep, 0),
            rebuild_active_accum: UTime::new(acc, 0),
            ..Default::default()
        }
    }

    #[test]
    fn merge_rebuild_span() {
        let key = |h: &PgHistory| {
            (
                h.last_rebuild_active_start.sec,
                h.rebuild_span_reported.sec,
                h.rebuild_active_accum.sec,
            )
        };
        // theirs reported later: take theirs wholesale (also a smaller onset / accum)
        let mut a = r(30, 20, 9);
        assert!(a.merge(&r(5, 25, 1)));
        assert_eq!(key(&a), (5, 25, 1));
        // theirs reported earlier: keep ours
        let mut a = r(30, 20, 9);
        assert!(!a.merge(&r(40, 15, 3)));
        assert_eq!(key(&a), (30, 20, 9));
        // equal reported, only theirs open: take onset + accum
        let mut a = r(10, 20, 9);
        assert!(a.merge(&r(30, 20, 4)));
        assert_eq!(key(&a), (30, 20, 4));
        // equal reported, both open: the earlier onset
        let mut a = r(35, 20, 9);
        assert!(a.merge(&r(30, 20, 4)));
        assert_eq!(key(&a), (30, 20, 4));
        assert!(!a.merge(&r(33, 20, 1)));
        // equal reported, only ours open: keep
        let mut a = r(30, 20, 9);
        assert!(!a.merge(&r(10, 20, 4)));
        assert_eq!(key(&a), (30, 20, 9));
        // equal reported, none open: keep
        let mut a = r(10, 20, 9);
        assert!(!a.merge(&r(15, 20, 4)));
        assert_eq!(key(&a), (10, 20, 9));
    }

    #[test]
    fn merge_carries_the_start_with_its_completion() {
        let mut ours = PgHistory {
            last_deep_scrub_start_stamp: UTime { sec: 90, nsec: 0 },
            ..h()
        };
        // newer completion: take both, also a zero start
        let theirs = PgHistory {
            last_deep_scrub_stamp: UTime { sec: 200, nsec: 0 },
            ..Default::default()
        };
        assert!(ours.clone().merge(&theirs));
        let mut x = ours.clone();
        x.merge(&theirs);
        assert_eq!(
            (x.last_deep_scrub_stamp, x.last_deep_scrub_start_stamp),
            (UTime { sec: 200, nsec: 0 }, UTime::default())
        );
        // same completion, newer start: take the start
        let theirs = PgHistory {
            last_deep_scrub_start_stamp: UTime { sec: 95, nsec: 0 },
            ..h()
        };
        assert!(ours.merge(&theirs));
        assert_eq!(ours.last_deep_scrub_start_stamp, UTime { sec: 95, nsec: 0 });
        // older start, same completion: unchanged
        let theirs = PgHistory {
            last_deep_scrub_start_stamp: UTime { sec: 1, nsec: 0 },
            ..h()
        };
        assert!(!ours.merge(&theirs));
    }
}
