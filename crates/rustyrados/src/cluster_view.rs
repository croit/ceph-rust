// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Shared cluster view (adr 0467 am. 4, step 1): the OSD map, the OSD service ticket and the client identity as one
//! immutable, epoch-versioned snapshot. The leader (the owner with the monitor session) publishes a new snapshot when
//! the map or the ticket changes; follower owners read it without a monitor session of their own.
//!
//! Publication is an `ArcSwapOption` store (cold: once per map or ticket change); a reader's check for news is one
//! atomic load, no lock and no allocation.

use arc_swap::ArcSwapOption;
use cephx::{none::ByteEntityName, ticket::TicketHandler};
use denc::types::Uuid;
use osdmap::OsdMap;
use std::{
    sync::{
        Arc, Condvar, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

/// One published snapshot. Immutable; a change is a new snapshot with `generation + 1`.
#[derive(Debug)]
pub struct ClusterView {
    /// Publication counter, starts at 1 and advances by exactly 1 per publication.
    pub generation: u64,
    /// Newest OSD map the leader holds. Its epoch never decreases between snapshots.
    pub map: Option<Arc<OsdMap>>,
    /// OSD service ticket at publication time (cephx only). A session snapshots this when it connects.
    pub osd_ticket: Option<TicketHandler>,
    /// Global id of the client, shared by every owner (one client address, one fence target).
    pub identity: u64,
    /// Authentication principal.
    pub entity: ByteEntityName,
    /// Completed monitor authentication method (`AUTH_NONE` / `AUTH_CEPHX`).
    pub method: u32,
    pub fsid: Option<Uuid>,
}

/// A second follower asked to follow a [`ViewCell::new_sole`] view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SoleViewFollowed;

/// Single-writer, many-reader cell holding the newest [`ClusterView`].
pub struct ViewCell {
    nonce: u32,
    /// The publisher dials no OSD and exactly one owner follows the view
    /// ([`ViewCell::new_sole`]): that owner is the only one using the address.
    sole: bool,
    /// A follower claimed this sole view ([`ViewCell::follow`]).
    followed: AtomicBool,
    current: ArcSwapOption<ClusterView>,
    peer_features: crate::PeerFeatures,
    barrier: OnceLock<PublishBarrier>,
    /// Wakes [`ViewCell::wait_after`] once a snapshot is visible.
    published: (Mutex<()>, Condvar),
}

impl std::fmt::Debug for ViewCell {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ViewCell")
            .field("nonce", &self.nonce)
            .field("generation", &self.generation())
            .finish_non_exhaustive()
    }
}

/// Runs on the publishing thread after the next snapshot is built and before readers can load it: the first phase of
/// the two-phase publication of a sharded client (adr 0693, "Map change"). It returns when every owner holding
/// requests has retargeted them against the snapshot, or has been reported as failed.
pub type PublishBarrier = Box<dyn Fn(&Arc<ClusterView>) + Send + Sync>;

/// Inputs of one publication attempt (what the leader currently holds).
#[derive(Debug)]
pub struct ViewInput<'a> {
    pub map: Option<&'a Arc<OsdMap>>,
    pub osd_ticket: Option<&'a TicketHandler>,
    pub identity: u64,
    pub entity: &'a ByteEntityName,
    pub method: u32,
    pub fsid: Option<Uuid>,
}

fn same_ticket(a: Option<&TicketHandler>, b: Option<&TicketHandler>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => {
            a.blob() == b.blob()
                && a.expires() == b.expires()
                && a.renew_after() == b.renew_after()
                && a.session_key() == b.session_key()
        }
        _ => false,
    }
}

impl ViewCell {
    /// `nonce` is the leader's advertised address nonce; every owner connects with it.
    pub fn new(nonce: u32) -> Arc<Self> {
        Self::build(nonce, false)
    }
    /// View of a publisher that dials no OSD itself (a monitor-only owner, e.g. a CephFS mount) and is followed
    /// by exactly one data owner: that owner is the only one presenting `nonce` to the OSDs, so it dials them
    /// directly instead of only as a hub member.
    pub fn new_sole(nonce: u32) -> Arc<Self> {
        Self::build(nonce, true)
    }
    fn build(nonce: u32, sole: bool) -> Arc<Self> {
        Arc::new(Self {
            nonce,
            sole,
            followed: AtomicBool::new(false),
            current: ArcSwapOption::empty(),
            peer_features: Default::default(),
            barrier: OnceLock::new(),
            published: (Mutex::new(()), Condvar::new()),
        })
    }
    /// Install the first phase of the publication (once, before the first request of a sharded client).
    pub fn set_publish_barrier(&self, barrier: PublishBarrier) {
        assert!(
            self.barrier.set(barrier).is_ok(),
            "publish barrier set once"
        );
    }
    pub fn nonce(&self) -> u32 {
        self.nonce
    }
    /// Register a follower: `Ok(true)` for the one follower of a sole view (it owns the address alone),
    /// `Ok(false)` for a follower of a shared view. A second follower of a sole view is refused
    /// ([`SoleViewFollowed`]), even after the first one is gone: it would share the address the first
    /// one dialed alone.
    pub fn follow(&self) -> Result<bool, SoleViewFollowed> {
        if !self.sole {
            return Ok(false);
        }
        if self.followed.swap(true, Ordering::AcqRel) {
            return Err(SoleViewFollowed);
        }
        Ok(true)
    }
    /// Features negotiated with each OSD (owners record, preparing threads read).
    pub fn peer_features(&self) -> &crate::PeerFeatures {
        &self.peer_features
    }
    /// Newest snapshot, `None` before the first publication. Lock-free.
    pub fn load(&self) -> Option<Arc<ClusterView>> {
        self.current.load_full()
    }
    /// Generation of the newest snapshot (0 = none yet): one atomic load, the follower's "anything new?" check.
    pub fn generation(&self) -> u64 {
        self.current.load().as_ref().map_or(0, |v| v.generation)
    }
    /// Leader only (single writer). Publishes a snapshot if map, ticket or identity differ from the current one.
    /// A map with a lower epoch than the published one is ignored: epochs never go backwards for readers.
    /// Returns whether a snapshot was published.
    pub fn publish(&self, input: ViewInput<'_>) -> bool {
        let prev = self.current.load_full();
        let map = match (prev.as_ref().and_then(|p| p.map.as_ref()), input.map) {
            (Some(old), Some(new)) if new.epoch < old.epoch => Some(old.clone()),
            (_, Some(new)) => Some(new.clone()),
            (old, None) => old.cloned(),
        };
        if let Some(p) = &prev {
            let map_same = match (&p.map, &map) {
                (Some(a), Some(b)) => Arc::ptr_eq(a, b),
                (None, None) => true,
                _ => false,
            };
            if map_same
                && same_ticket(p.osd_ticket.as_ref(), input.osd_ticket)
                && p.identity == input.identity
                && p.method == input.method
                && p.entity.ty == input.entity.ty
                && p.entity.id == input.entity.id
            {
                return false;
            }
        }
        let next = Arc::new(ClusterView {
            generation: prev.map_or(0, |p| p.generation) + 1,
            map,
            osd_ticket: input.osd_ticket.cloned(),
            identity: input.identity,
            entity: input.entity.clone(),
            method: input.method,
            fsid: input.fsid,
        });
        if let Some(barrier) = self.barrier.get() {
            barrier(&next);
        }
        self.current.store(Some(next));
        drop(self.published.0.lock().unwrap_or_else(|e| e.into_inner()));
        self.published.1.notify_all();
        true
    }
    /// Block until a snapshot newer than `generation` is visible; `false` when `limit` passed first (the caller
    /// reports the loud timeout, it knows the operation).
    pub fn wait_after(&self, generation: u64, limit: Duration) -> bool {
        let deadline = Instant::now() + limit;
        let mut guard = self.published.0.lock().unwrap_or_else(|e| e.into_inner());
        while self.generation() <= generation {
            let Some(left) = deadline.checked_duration_since(Instant::now()) else {
                return false;
            };
            guard = self
                .published
                .1
                .wait_timeout(guard, left)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn input<'a>(entity: &'a ByteEntityName, identity: u64) -> ViewInput<'a> {
        ViewInput {
            map: None,
            osd_ticket: None,
            identity,
            entity,
            method: 0,
            fsid: None,
        }
    }

    /// The barrier runs before the snapshot is visible; a waiter is released only after it is.
    #[test]
    fn publish_runs_the_barrier_before_readers_see_the_snapshot_and_wakes_waiters() {
        let cell = ViewCell::new(1);
        let entity = ByteEntityName {
            ty: cephx::none::ENTITY_CLIENT,
            id: b"v".to_vec(),
        };
        let seen_inside = Arc::new(AtomicU64::new(u64::MAX));
        let (hook_cell, hook_seen) = (cell.clone(), seen_inside.clone());
        cell.set_publish_barrier(Box::new(move |next| {
            hook_seen.store(hook_cell.generation(), Ordering::SeqCst);
            assert_eq!(next.generation, 1);
        }));
        assert!(
            !cell.wait_after(0, Duration::from_millis(20)),
            "nothing published"
        );
        let waiter = {
            let cell = cell.clone();
            std::thread::spawn(move || cell.wait_after(0, Duration::from_secs(10)))
        };
        assert!(cell.publish(input(&entity, 5)));
        assert!(waiter.join().unwrap());
        assert_eq!(
            seen_inside.load(Ordering::SeqCst),
            0,
            "readers saw nothing yet"
        );
        assert_eq!(cell.generation(), 1);
        assert!(cell.wait_after(0, Duration::ZERO));
    }

    #[test]
    fn a_sole_view_takes_exactly_one_follower() {
        let shared = ViewCell::new(3);
        assert_eq!(shared.follow(), Ok(false));
        assert_eq!(
            shared.follow(),
            Ok(false),
            "a shared view takes any number of followers"
        );
        let sole = ViewCell::new_sole(3);
        assert_eq!(sole.follow(), Ok(true));
        assert_eq!(sole.follow(), Err(SoleViewFollowed));
    }
}
