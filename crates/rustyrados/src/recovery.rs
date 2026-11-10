// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
use crate::{ReadRoute, RequestToken};
use std::collections::VecDeque;
/// Typed upper-layer classification. Rejection must dominate subsequent close events.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionFailure {
    Transport,
    Reset,
    Rejected,
}
impl SessionFailure {
    pub fn recoverable(self) -> bool {
        self != Self::Rejected
    }
    pub fn merge(self, next: Self) -> Self {
        if self == Self::Rejected || next == Self::Rejected {
            Self::Rejected
        } else {
            next
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryCause {
    BackoffReleased,
    ConnectionLost,
    Remap,
    TryAgain,
    /// Redirect already invalidated the route and allocated a new wire TID.
    Redirect,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryItem {
    pub token: RequestToken,
    pub previous: ReadRoute,
    pub cause: RecoveryCause,
}
#[derive(Debug)]
pub struct RecoveryQueue {
    ready: VecDeque<(RecoveryItem, u64)>,
    limit: usize,
}
impl RecoveryQueue {
    pub fn new(limit: usize) -> Self {
        Self {
            ready: VecDeque::with_capacity(limit),
            limit,
        }
    }
    /// false=already queued; Err=no credit. Never evicts a live item.
    pub fn push(&mut self, item: RecoveryItem) -> Result<bool, RecoveryItem> {
        self.push_at(item, 0)
    }
    pub fn push_at(
        &mut self,
        item: RecoveryItem,
        not_before_us: u64,
    ) -> Result<bool, RecoveryItem> {
        if self.ready.iter().any(|(old, _)| old.token == item.token) {
            return Ok(false);
        }
        if self.ready.len() >= self.limit {
            return Err(item);
        }
        self.ready.push_back((item, not_before_us));
        Ok(true)
    }
    pub fn pop(&mut self) -> Option<RecoveryItem> {
        self.ready.pop_front().map(|(item, _)| item)
    }
    /// Rotate delayed work without shortening its timer or starving ready work.
    pub fn pop_ready(&mut self, now_us: u64) -> Option<RecoveryItem> {
        for _ in 0..self.ready.len() {
            let (item, due) = self.ready.pop_front().unwrap();
            if due <= now_us {
                return Some(item);
            }
            self.ready.push_back((item, due));
        }
        None
    }
    pub fn next_timer_us(&self) -> Option<u64> {
        self.ready.iter().map(|(_, due)| *due).min()
    }
    pub fn len(&self) -> usize {
        self.ready.len()
    }
    pub fn is_empty(&self) -> bool {
        self.ready.is_empty()
    }
    pub fn contains(&self, token: RequestToken) -> bool {
        self.ready.iter().any(|(item, _)| item.token == token)
    }
    pub fn remove(&mut self, token: RequestToken) {
        self.ready.retain(|(item, _)| item.token != token);
    }
    /// Reclaim terminal tokens before admitting new wakes; never evict live work.
    pub fn retain_live(&mut self, mut live: impl FnMut(RequestToken) -> bool) {
        self.ready.retain(|(item, _)| live(item.token));
    }
}
