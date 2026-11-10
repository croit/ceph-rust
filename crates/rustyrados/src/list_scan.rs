// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
use crate::{ListNamespace, PgListPage, PgListRequest, ReadCompletion, ReadOutcome, RequestToken};
use denc::types::{Hobject, Uuid};
use osdmap::{
    OsdMap,
    hash::{STR_HASH_LINUX, STR_HASH_RJENKINS, hash_key, stable_mod},
};
use std::{marker::PhantomData, rc::Rc};

#[path = "list_range.rs"]
mod range;
pub use range::*;

use crate::time::{self, MAX_TIME_US as MAX_TIME};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListScanError {
    Overflow,
    NotReady,
    Layout,
    Identity,
    Clock,
    Limits,
    Busy,
    Deadline,
    PageBudget,
    StateBudget,
    ForeignCompletion,
    Protocol,
    Range,
}
/// Scalar view of a trusted map. Transport drivers must authenticate the source map.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ListLayout {
    fsid: Uuid,
    pool: i64,
    epoch: u32,
    pg_num: u32,
    mask: u32,
    hash: u8,
}
impl ListLayout {
    pub fn from_map(map: &OsdMap, pool: i64) -> Result<Self, ListScanError> {
        let p = map.pool(pool).ok_or(ListScanError::Layout)?;
        if pool < 0
            || pool > u32::MAX as i64
            || map.fsid == Uuid::default()
            || map.epoch == 0
            || map.flags & osdmap::consts::map_flags::SORTBITWISE == 0
            || (!p.is_replicated() && !p.is_erasure())
            || p.pg_num == 0
            || !matches!(p.object_hash, STR_HASH_LINUX | STR_HASH_RJENKINS)
        {
            return Err(ListScanError::Layout);
        }
        Ok(Self {
            fsid: map.fsid,
            pool,
            epoch: map.epoch,
            pg_num: p.pg_num,
            mask: p.pg_num_mask(),
            hash: p.object_hash,
        })
    }
    pub fn pool(self) -> i64 {
        self.pool
    }
    pub fn epoch(self) -> u32 {
        self.epoch
    }
    pub fn pg_num(self) -> u32 {
        self.pg_num
    }
    /// Hash a raw listing identity using this authenticated pool layout.
    /// Nonempty locator replaces object; namespace always remains significant.
    pub fn hash_object(self, namespace: &[u8], object: &[u8], locator: &[u8]) -> u32 {
        hash_key(
            self.hash,
            namespace,
            if locator.is_empty() { object } else { locator },
        )
    }
    /// Map a raw placement hash to a current PG in this validated layout.
    pub fn pg_for_hash(self, hash: u32) -> u32 {
        self.pg(hash)
    }
    fn pg(self, hash: u32) -> u32 {
        stable_mod(hash, self.pg_num, self.mask)
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListQuery {
    pub pool: i64,
    pub namespace: ListNamespace,
    pub filter: Option<crate::ListFilter>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ListLimits {
    pub entries: u32,
    pub output_bytes: u32,
    pub state_bytes: u64,
    pub max_pages: u64,
}
impl Default for ListLimits {
    fn default() -> Self {
        Self {
            entries: 128,
            output_bytes: 64 * 1024,
            state_bytes: 16 * 1024,
            max_pages: 1_000_000,
        }
    }
}
#[derive(Debug)]
pub struct RejectedListQuery {
    pub reason: ListScanError,
    pub query: ListQuery,
}
#[derive(Debug)]
pub enum ListSubmitError<E> {
    Scan(ListScanError),
    Admission(E),
}
#[derive(Debug)]
pub struct RejectedListCompletion {
    pub error: ListScanError,
    pub completion: ReadCompletion,
}
#[derive(Debug)]
pub enum ListScanStep {
    Page(PgListPage),
    Failure(ReadOutcome),
}
#[derive(Clone, Copy, Debug)]
struct Pending {
    token: RequestToken,
    layout: ListLayout,
    entries: u32,
    output: u32,
}
/// One owner, one in-flight page. Mutation is observable; this is not a snapshot.
#[derive(Debug)]
pub struct ListScan {
    query: ListQuery,
    layout: ListLayout,
    limits: ListLimits,
    bounded: bool,
    position: Hobject,
    end: Hobject,
    pending: Option<Pending>,
    pages: u64,
    deadline: u64,
    started: u64,
    now: u64,
    error: Option<ListScanError>,
    _local: PhantomData<Rc<()>>,
}
impl ListScan {
    pub fn new(
        layout: ListLayout,
        query: ListQuery,
        limits: ListLimits,
        deadline_us: u64,
        now_us: u64,
    ) -> Result<Self, RejectedListQuery> {
        Self::new_range(
            layout,
            query,
            ListRange::full(),
            limits,
            deadline_us,
            now_us,
        )
        .map_err(|e| RejectedListQuery {
            reason: e.reason,
            query: e.query,
        })
    }
    #[expect(
        clippy::result_large_err,
        reason = "Rejected requests return caller-owned input without allocation"
    )]
    pub fn new_range(
        layout: ListLayout,
        query: ListQuery,
        range: ListRange,
        limits: ListLimits,
        deadline_us: u64,
        now_us: u64,
    ) -> Result<Self, RejectedListRange> {
        Self::new_range_policy(layout, query, range, limits, deadline_us, now_us, true)
    }
    /// Librados scan: per-page wire bounds, no scan-wide state/page budget.
    #[expect(
        clippy::result_large_err,
        reason = "Rejected queries retain caller-owned inputs"
    )]
    pub fn new_compatible_range(
        layout: ListLayout,
        query: ListQuery,
        range: ListRange,
        entries: u32,
        deadline_us: u64,
        now_us: u64,
    ) -> Result<Self, RejectedListRange> {
        Self::new_range_policy(
            layout,
            query,
            range,
            ListLimits {
                entries,
                output_bytes: u32::MAX,
                state_bytes: 0,
                max_pages: 0,
            },
            deadline_us,
            now_us,
            false,
        )
    }
    #[expect(
        clippy::result_large_err,
        reason = "Rejected queries retain caller-owned inputs"
    )]
    fn new_range_policy(
        layout: ListLayout,
        query: ListQuery,
        range: ListRange,
        limits: ListLimits,
        deadline_us: u64,
        now_us: u64,
        bounded: bool,
    ) -> Result<Self, RejectedListRange> {
        let reason = if now_us > MAX_TIME {
            Some(ListScanError::Clock)
        } else if time::validate_deadline(deadline_us).is_err() {
            Some(ListScanError::Overflow)
        } else if time::is_due(deadline_us, now_us) {
            diag::diag!(
                "WARNING TIMEOUT object listing exceeded {}s (admission, deadline_us={deadline_us})",
                time::budget_seconds(deadline_us.saturating_sub(now_us))
            );
            Some(ListScanError::Deadline)
        } else if limits.entries == 0
            || limits.output_bytes == 0
            || (bounded && (limits.state_bytes == 0 || limits.max_pages == 0))
        {
            Some(ListScanError::Limits)
        } else if query.pool != layout.pool {
            Some(ListScanError::Identity)
        } else if matches!(&query.namespace,ListNamespace::Exact(n) if n.as_slice() == crate::listing::ALL_NAMESPACES || n.len() > u32::MAX as usize)
            || query.filter.as_ref().is_some_and(|f| f.validate().is_err())
        {
            Some(ListScanError::Limits)
        } else if range.validate(query.pool).is_err() {
            Some(ListScanError::Range)
        } else if scan_charge(&query, &range.start, &range.end)
            .is_none_or(|n| bounded && n > limits.state_bytes)
        {
            Some(ListScanError::StateBudget)
        } else {
            None
        };
        if let Some(reason) = reason {
            return Err(RejectedListRange {
                reason,
                query,
                range,
            });
        }
        Ok(Self {
            query,
            layout,
            limits,
            bounded,
            position: range.start,
            end: range.end,
            pending: None,
            pages: 0,
            deadline: deadline_us,
            started: now_us,
            now: now_us,
            error: None,
            _local: PhantomData,
        })
    }
    pub fn pool(&self) -> i64 {
        self.query.pool
    }
    pub fn deadline_us(&self) -> u64 {
        self.deadline
    }
    /// Set the deadline for the next page without resetting scan budgets or cursor.
    /// An admitted page keeps its original deadline until its completion arrives.
    pub fn set_deadline_us(&mut self, deadline_us: u64) -> Result<(), ListScanError> {
        if let Some(e) = self.error {
            return Err(e);
        }
        if self.pending.is_some() {
            return Err(ListScanError::Busy);
        }
        time::validate_deadline(deadline_us).map_err(|_| ListScanError::Overflow)?;
        self.deadline = deadline_us;
        Ok(())
    }
    pub fn position(&self) -> &Hobject {
        &self.position
    }
    pub fn is_done(&self) -> bool {
        self.position >= self.end
    }
    pub fn range_end(&self) -> &Hobject {
        &self.end
    }
    pub fn in_flight(&self) -> Option<RequestToken> {
        self.pending.map(|p| p.token)
    }
    pub fn pages_submitted(&self) -> u64 {
        self.pages
    }
    pub fn error(&self) -> Option<ListScanError> {
        self.error
    }
    pub fn set_page_limits(
        &mut self,
        entries: u32,
        output_bytes: u32,
    ) -> Result<(), ListScanError> {
        if let Some(e) = self.error {
            return Err(e);
        }
        if self.pending.is_some() {
            return Err(ListScanError::Busy);
        }
        if entries == 0 || output_bytes == 0 {
            return Err(ListScanError::Limits);
        }
        self.limits.entries = entries;
        self.limits.output_bytes = output_bytes;
        Ok(())
    }
    fn observe(&mut self, layout: ListLayout, now: u64) -> Result<(), ListScanError> {
        let error = if now < self.now || now > MAX_TIME {
            Some(ListScanError::Clock)
        } else if layout.fsid != self.layout.fsid
            || layout.pool != self.layout.pool
            || layout.hash != self.layout.hash
        {
            Some(ListScanError::Identity)
        } else if layout.epoch < self.layout.epoch
            || (layout.epoch == self.layout.epoch && layout != self.layout)
        {
            Some(ListScanError::Layout)
        } else {
            None
        };
        if let Some(e) = error {
            self.error = Some(e);
            return Err(e);
        }
        self.now = now;
        self.layout = layout;
        Ok(())
    }
    pub fn submit_with<E>(
        &mut self,
        layout: ListLayout,
        now: u64,
        admission: impl FnOnce(PgListRequest) -> Result<RequestToken, E>,
    ) -> Result<Option<RequestToken>, ListSubmitError<E>> {
        use ListSubmitError::Scan;
        if let Some(e) = self.error {
            return Err(Scan(e));
        }
        if self.pending.is_some() {
            return Err(Scan(ListScanError::Busy));
        }
        self.observe(layout, now).map_err(Scan)?;
        if self.is_done() {
            return Ok(None);
        }
        if time::is_due(self.deadline, now) {
            diag::diag!(
                "WARNING TIMEOUT object listing exceeded {}s (between pages, pages={} deadline_us={})",
                time::budget_seconds(self.deadline.saturating_sub(self.started)),
                self.pages,
                self.deadline
            );
            return Err(Scan(ListScanError::Deadline));
        }
        if self.bounded && self.pages >= self.limits.max_pages {
            return Err(Scan(ListScanError::PageBudget));
        }
        let mut request = PgListRequest::new(
            self.query.pool,
            self.query.namespace.clone(),
            layout.pg(self.position.hash),
            layout.pg_num,
            self.position.clone(),
            self.limits.entries,
            self.limits.output_bytes,
        );
        if let Some(filter) = &self.query.filter {
            request = request.with_filter(filter.clone());
        }
        let token = admission(request).map_err(ListSubmitError::Admission)?;
        self.pending = Some(Pending {
            token,
            layout,
            entries: self.limits.entries,
            output: self.limits.output_bytes,
        });
        self.pages = self.pages.saturating_add(1);
        Ok(Some(token))
    }
    #[expect(
        clippy::result_large_err,
        reason = "Rejected requests return caller-owned input without allocation"
    )]
    pub fn accept(
        &mut self,
        layout: Result<ListLayout, ListScanError>,
        now: u64,
        completion: ReadCompletion,
    ) -> Result<ListScanStep, RejectedListCompletion> {
        // Foreign data cannot consume a known token or poison the clock/layout.
        let Some(pending) = self.pending.filter(|p| p.token == completion.token) else {
            return Err(RejectedListCompletion {
                error: ListScanError::ForeignCompletion,
                completion,
            });
        };
        self.pending = None;
        let mut validated_next = None;
        let mut visible = 0usize;
        let check = (|| {
            if let Some(e) = self.error {
                return Err(e);
            }
            self.observe(layout?, now)?;
            match &completion.outcome {
                ReadOutcome::RemotePgList {
                    result,
                    op_result,
                    map_epoch,
                    page: Some(page),
                    error_data,
                    ..
                } if *result >= 0 && *op_result >= 0 => {
                    if !(0..=1).contains(result)
                        || !(0..=1).contains(op_result)
                        || !error_data.is_empty()
                        || *map_epoch != page.map_epoch
                        || page.map_epoch < pending.layout.epoch
                        || page.pool != self.query.pool
                        || page.pg != pending.layout.pg(self.position.hash)
                        || page.pg_num != pending.layout.pg_num
                        || page.len() > pending.entries as usize
                        || page.wire_len() > pending.output as usize
                        || page.next_cursor() <= &self.position
                    {
                        return Err(ListScanError::Protocol);
                    }
                    let start = object_key(&self.position);
                    let end = object_key(page.next_cursor());
                    let mut previous = None;
                    for entry in page.entries() {
                        if matches!(&self.query.namespace,ListNamespace::Exact(n) if n.as_slice()!=entry.namespace)
                        {
                            return Err(ListScanError::Protocol);
                        }
                        let effective = if entry.locator.is_empty() {
                            entry.object
                        } else {
                            entry.locator
                        };
                        let hash = hash_key(pending.layout.hash, entry.namespace, effective);
                        let key = (
                            false,
                            self.query.pool,
                            hash.reverse_bits(),
                            entry.namespace,
                            effective,
                            entry.object,
                            opwire::NOSNAP,
                        );
                        if pending.layout.pg(hash) != page.pg
                            || key < start
                            || key >= end
                            || previous.is_some_and(|p| key <= p)
                        {
                            return Err(ListScanError::Protocol);
                        }
                        if key < object_key(&self.end) {
                            visible += 1;
                        }
                        previous = Some(key);
                    }
                    let next = if page.next_cursor() >= &self.end {
                        &self.end
                    } else {
                        page.next_cursor()
                    };
                    let charge = query_charge(&self.query)
                        .ok_or(ListScanError::StateBudget)?
                        .checked_add(cursor_charge(&self.end).ok_or(ListScanError::StateBudget)?)
                        .and_then(|n| n.checked_add(next.key.len() as u64))
                        .and_then(|n| n.checked_add(next.oid.len() as u64))
                        .and_then(|n| n.checked_add(next.nspace.len() as u64))
                        .ok_or(ListScanError::StateBudget)?;
                    if self.bounded && charge > self.limits.state_bytes {
                        return Err(ListScanError::StateBudget);
                    }
                    let owned = next.clone();
                    let actual = scan_charge(&self.query, &owned, &self.end)
                        .ok_or(ListScanError::StateBudget)?;
                    if self.bounded && actual > self.limits.state_bytes {
                        return Err(ListScanError::StateBudget);
                    }
                    validated_next = Some(owned);
                    Ok(())
                }
                ReadOutcome::RemotePgList {
                    result,
                    op_result,
                    page: None,
                    ..
                } if *result < 0 || *op_result < 0 => Ok(()),
                ReadOutcome::LocalRejected { .. }
                | ReadOutcome::ListingTooLarge { .. }
                | ReadOutcome::ListingChanged { .. }
                | ReadOutcome::CanceledUnsent
                | ReadOutcome::PossiblySent
                | ReadOutcome::Deadline { .. } => Ok(()),
                _ => Err(ListScanError::Protocol),
            }
        })();
        if let Err(error) = check {
            self.error = Some(error);
            return Err(RejectedListCompletion { error, completion });
        }
        match completion.outcome {
            ReadOutcome::RemotePgList {
                page: Some(mut page),
                ..
            } => {
                self.position = validated_next.expect("validated successful page");
                // byte identity, not `Hobject` equality (which follows the wire order): the caller gets back the very
                // end cursor it passed, also when an equal-ordering encoding came from the OSD
                if self.is_done() && !same_encoding(page.next_cursor(), &self.end) {
                    page.clip(visible, self.end.clone());
                }
                Ok(ListScanStep::Page(page))
            }
            outcome => {
                if matches!(outcome, ReadOutcome::Deadline { .. }) {
                    self.error = Some(ListScanError::Deadline);
                }
                Ok(ListScanStep::Failure(outcome))
            }
        }
    }
}
/// Field-wise identity of two cursors (what [`Hobject`] encodes), unlike `==`, which treats encodings of one wire
/// position as equal.
fn same_encoding(a: &Hobject, b: &Hobject) -> bool {
    a.key == b.key
        && a.oid == b.oid
        && a.nspace == b.nspace
        && a.snap == b.snap
        && a.hash == b.hash
        && a.max == b.max
        && a.pool == b.pool
}
fn query_charge(query: &ListQuery) -> Option<u64> {
    let ns = match &query.namespace {
        ListNamespace::Exact(n) => n.capacity() as u64,
        ListNamespace::All => 0,
    };
    ns.checked_add(match &query.filter {
        Some(f) => f.retained_bytes()?,
        None => 0,
    })
}
fn cursor_charge(h: &Hobject) -> Option<u64> {
    (h.key.capacity() as u64)
        .checked_add(h.oid.capacity() as u64)?
        .checked_add(h.nspace.capacity() as u64)
}
fn scan_charge(query: &ListQuery, position: &Hobject, end: &Hobject) -> Option<u64> {
    query_charge(query)?
        .checked_add(cursor_charge(position)?)?
        .checked_add(cursor_charge(end)?)
}
type ObjectKey<'a> = (bool, i64, u32, &'a [u8], &'a [u8], &'a [u8], u64);
fn object_key(h: &Hobject) -> ObjectKey<'_> {
    (
        h.max,
        h.pool,
        h.hash.reverse_bits(),
        &h.nspace,
        if h.key.is_empty() { &h.oid } else { &h.key },
        &h.oid,
        h.snap.0,
    )
}

#[cfg(test)]
#[path = "list_scan_tests.rs"]
mod tests;
