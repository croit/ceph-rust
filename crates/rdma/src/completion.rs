// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Fixed-SQ completion identity allocated with an unadvertised window on the control path.
use std::sync::{
    Arc,
    atomic::{AtomicU8, AtomicU64, AtomicUsize, Ordering},
};

pub(crate) const IDLE: u8 = 0;
pub(crate) const BINDING: u8 = 1;
pub(crate) const BOUND: u8 = 2;
pub(crate) const INVALIDATING: u8 = 3;
pub(crate) const RETIRED: u8 = 4;
pub(crate) const FAILED: u8 = 5;
pub(crate) const WRITE_PENDING: u8 = 6;
pub(crate) const WRITE_DONE: u8 = 7;
pub(crate) const READ_PENDING: u8 = 8;
pub(crate) const READ_DONE: u8 = 9;
/// WRITE source retention and CQ state share one atomic allocation. The high bit records
/// that either the abandoned handle or failed CQ path counted its source once.
pub(crate) const WRITE_QUARANTINED: u8 = 0x80;
pub(crate) const WRITE_STATE_MASK: u8 = !WRITE_QUARANTINED;
pub(crate) static QUARANTINED_WRITE_SOURCES: AtomicU64 = AtomicU64::new(0);

/// Bound/in-flight MWs retain a provider QP reference until successful invalidation.
#[derive(Debug, Default)]
pub(crate) struct WindowQpScope {
    pub bindings: AtomicUsize,
}

pub(crate) struct Marker {
    pub state: Arc<AtomicU8>,
    pub ready: u8,
    pub retire_qp: Option<Arc<WindowQpScope>>,
    /// WRITE registration, retained permanently on uncertain completion. A permanent
    /// arena registration does not own individual payload leases; WriteHandle must
    /// also retain its exact Bytes owner through pending and failed states.
    pub source: Option<Arc<dyn Send + Sync>>,
}

impl std::fmt::Debug for Marker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Marker")
            .field("ready", &self.ready)
            .field("retire_qp", &self.retire_qp)
            .field("has_source", &self.source.is_some())
            .finish_non_exhaustive()
    }
}

impl Marker {
    pub fn finish(self, success: bool) {
        let write = self.source.is_some();
        if let Some(source) = self.source {
            if success {
                // The handle still owns the registration, or abandoned it by permanently retaining
                // its reference. Never run provider deregistration from the CQ progress path.
                drop(source);
            } else {
                std::mem::forget(source);
                if quarantine_write_source(&self.state) {
                    use std::io::Write;
                    let _ = writeln!(
                        std::io::stderr().lock(),
                        "rdma: uncertain WRITE source quarantined (registration, backing and device retained)"
                    );
                }
            }
        }
        if success && let Some(scope) = self.retire_qp {
            let previous = scope.bindings.fetch_sub(1, Ordering::AcqRel);
            assert!(previous > 0, "window QP ownership released exactly once");
        }
        let next = if success { self.ready } else { FAILED };
        if write {
            self.state
                .try_update(Ordering::Release, Ordering::Relaxed, |old| {
                    Some((old & WRITE_QUARANTINED) | next)
                })
                .expect("unconditional WRITE completion transition");
        } else {
            self.state.store(next, Ordering::Release);
        }
    }
}

/// Counts one permanently retained source; the pending-handle drop path remains lock-free.
pub(crate) fn quarantine_write_source(state: &AtomicU8) -> bool {
    if state.fetch_or(WRITE_QUARANTINED, Ordering::AcqRel) & WRITE_QUARANTINED == 0 {
        QUARANTINED_WRITE_SOURCES.fetch_add(1, Ordering::Relaxed);
        true
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn successful_invalidation_releases_qp_ownership_before_publishing_retired() {
        let scope = Arc::new(WindowQpScope::default());
        scope.bindings.store(1, Ordering::Relaxed);
        let state = Arc::new(AtomicU8::new(INVALIDATING));
        Marker {
            state: state.clone(),
            ready: RETIRED,
            retire_qp: Some(scope.clone()),
            source: None,
        }
        .finish(true);
        assert_eq!(state.load(Ordering::Acquire), RETIRED);
        assert_eq!(scope.bindings.load(Ordering::Acquire), 0);
    }

    #[test]
    fn failed_invalidation_retains_qp_ownership() {
        let scope = Arc::new(WindowQpScope::default());
        scope.bindings.store(1, Ordering::Relaxed);
        let state = Arc::new(AtomicU8::new(INVALIDATING));
        Marker {
            state: state.clone(),
            ready: RETIRED,
            retire_qp: Some(scope.clone()),
            source: None,
        }
        .finish(false);
        assert_eq!(state.load(Ordering::Acquire), FAILED);
        assert_eq!(scope.bindings.load(Ordering::Acquire), 1);
    }

    #[test]
    fn failed_write_marker_keeps_source_even_after_handle_drop() {
        let source = Arc::new(7u8);
        let weak = Arc::downgrade(&source);
        let state = Arc::new(AtomicU8::new(WRITE_PENDING));
        let before = QUARANTINED_WRITE_SOURCES.load(Ordering::Relaxed);
        Marker {
            state: state.clone(),
            ready: WRITE_DONE,
            retire_qp: None,
            source: Some(source.clone()),
        }
        .finish(false);
        drop(source);
        assert_eq!(state.load(Ordering::Acquire), FAILED | WRITE_QUARANTINED);
        assert!(
            weak.upgrade().is_some(),
            "uncertain NIC source stays mapped"
        );
        assert!(QUARANTINED_WRITE_SOURCES.load(Ordering::Relaxed) > before);
    }

    #[test]
    fn abandoned_write_and_failed_cqe_share_one_quarantine_mark() {
        let source = Arc::new(7u8);
        let weak = Arc::downgrade(&source);
        let state = Arc::new(AtomicU8::new(WRITE_PENDING));
        assert!(quarantine_write_source(&state));
        assert!(!quarantine_write_source(&state));
        Marker {
            state: state.clone(),
            ready: WRITE_DONE,
            retire_qp: None,
            source: Some(source.clone()),
        }
        .finish(false);
        drop(source);
        assert_eq!(state.load(Ordering::Acquire), FAILED | WRITE_QUARANTINED);
        assert!(
            weak.upgrade().is_some(),
            "failed WRITE source remains registered"
        );
    }

    #[test]
    fn abandoned_write_completion_preserves_quarantine_mark() {
        let state = Arc::new(AtomicU8::new(WRITE_PENDING));
        assert!(quarantine_write_source(&state));
        Marker {
            state: state.clone(),
            ready: WRITE_DONE,
            retire_qp: None,
            source: Some(Arc::new(7u8)),
        }
        .finish(true);
        assert_eq!(
            state.load(Ordering::Acquire),
            WRITE_DONE | WRITE_QUARANTINED
        );
    }
}
