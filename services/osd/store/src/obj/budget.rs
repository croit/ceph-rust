// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! One preparation budget for all shards of a Store (one Store per owning core).
use crate::fastclock::Mono;
use std::time::{Duration, Instant};

pub(crate) const PREP_STEPS: usize = 128;
pub(crate) struct Budget {
    clock: Mono,
    /// Wall-clock allowance per poll; `None` (virtual time, `Clock::wall_time`) = step bound only, reproducible IO.
    allow: Option<Duration>,
    until: Duration,
    left: usize,
    visited: bool,
    data_taken: bool,
}
impl Budget {
    pub fn new(wall: bool) -> Self {
        let allow = wall.then_some(Duration::from_micros(100));
        let clock = Mono::at(Instant::now());
        Self {
            clock,
            allow,
            until: Duration::ZERO,
            left: 0,
            visited: false,
            data_taken: false,
        }
    }
    pub fn reset(&mut self) {
        if let Some(a) = self.allow {
            self.until = self.clock.elapsed() + a;
        }
        self.left = PREP_STEPS;
        self.visited = false;
        self.data_taken = false;
    }
    pub fn visit(&mut self) -> bool {
        if self.left == 0 || (self.visited && self.late()) {
            return false;
        }
        self.visited = true;
        self.left -= 1;
        true
    }
    pub fn take(&mut self) -> bool {
        if self.left == 0 || (self.data_taken && self.late()) {
            return false;
        }
        self.data_taken = true;
        self.left -= 1;
        true
    }
    pub fn exhausted(&self) -> bool {
        self.left == 0 || (self.visited && self.late())
    }
    /// Override the allowance (tests: `Some(ZERO)` = most fragmented schedule, every poll prepares one head/quantum).
    pub fn set_allowance(&mut self, allow: Option<Duration>) {
        self.allow = allow;
    }
    fn late(&self) -> bool {
        self.allow.is_some() && self.clock.elapsed() >= self.until
    }
}

/// Drop contained/empty views; pointer and end order makes retained-slice lookup logarithmic.
pub(crate) fn payload_owners(mut owners: Vec<bytes::Bytes>) -> Vec<bytes::Bytes> {
    owners.sort_unstable_by_key(|b| (b.as_ptr() as usize, std::cmp::Reverse(b.len())));
    let mut end = 0;
    owners.retain(|b| {
        let limit = (b.as_ptr() as usize).checked_add(b.len()).unwrap_or(0);
        if !b.is_empty() && limit > end {
            end = limit;
            true
        } else {
            false
        }
    });
    owners
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::obj::dirty::Data;

    #[test]
    fn retained_views_keep_the_owner_without_copying() {
        let source = bytes::Bytes::from(vec![7; 128]);
        let owners = payload_owners(vec![
            source.slice(0..64),
            source.slice(32..128),
            source.slice(40..48),
            bytes::Bytes::new(),
        ]);
        assert_eq!(owners.len(), 2);
        let retained = Data::Borrowed(&source[48..120]).retained(&owners);
        assert_eq!(retained.as_ptr(), source[48..].as_ptr());
        drop(owners);
        drop(source);
        assert_eq!(&*retained, &[7; 72]);
    }

    #[test]
    fn owned_and_shared_values_compare_by_content() {
        let borrowed = Data::Borrowed(b"abc");
        let owned = Data::Owned(b"abc".to_vec());
        let shared = Data::Shared(bytes::Bytes::from_static(b"abc"));
        assert_eq!(borrowed, owned);
        assert_eq!(owned, shared);
        assert_eq!(borrowed.cmp(&shared), std::cmp::Ordering::Equal);
        assert!(shared < Data::Borrowed(b"abd"));
    }
}
