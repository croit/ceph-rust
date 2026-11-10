// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! TEST ONLY (feature `fault-inject`, adr 0024: not compiled in production): faults armed from outside (the OSD's
//! `rdma fault` tell command) and consumed by the next [`crate::verbs::Core::poll_flow`] of any core that has
//! connections. Used by the RDMA fault campaign (`lab/rdma-spike/fault-cells.sh`, doc/perf/rdma-fault-20261022.md).
use std::sync::atomic::{AtomicU32, Ordering};

static QP_ERR: AtomicU32 = AtomicU32::new(0);
static WRITE_QP_ERR: AtomicU32 = AtomicU32::new(0);
static WRITE_QP_ERR_TRIGGERED: AtomicU32 = AtomicU32::new(0);
static WRITE_QP_ERR_FAILED: AtomicU32 = AtomicU32::new(0);

/// Arm QP errors consumed only after the provider accepts a host WRITE. SEND,
/// preflight rejection and SQ backpressure cannot consume this fault.
pub fn arm_write_qp_err(n: u32) {
    WRITE_QP_ERR.fetch_add(n, Ordering::AcqRel);
}

/// Process-wide `(pending, successful ERR transitions, refused ERR transitions)`.
/// Successful transitions prove an accepted WRITE, not remote delivery or an
/// outstanding NIC transaction at the instant the transition took effect.
pub fn write_qp_err_state() -> (u32, u32, u32) {
    (
        WRITE_QP_ERR.load(Ordering::Acquire),
        WRITE_QP_ERR_TRIGGERED.load(Ordering::Acquire),
        WRITE_QP_ERR_FAILED.load(Ordering::Acquire),
    )
}

#[cfg(feature = "memory-windows")]
pub(crate) fn take_write_qp_err() -> bool {
    WRITE_QP_ERR
        .try_update(Ordering::AcqRel, Ordering::Acquire, |v| v.checked_sub(1))
        .is_ok()
}

#[cfg(feature = "memory-windows")]
pub(crate) fn record_write_qp_err(success: bool) {
    if success {
        &WRITE_QP_ERR_TRIGGERED
    } else {
        &WRITE_QP_ERR_FAILED
    }
    .fetch_add(1, Ordering::AcqRel);
}

/// Arm `n` forced QP errors: each is taken by one core poll that holds a live connection and moves that connection's
/// QP to ERR (every outstanding WR flushes, the session faults as after a real QP error).
pub fn arm_qp_err(n: u32) {
    QP_ERR.fetch_add(n, Ordering::AcqRel);
}

/// Armed forced QP errors not consumed yet.
pub fn pending_qp_err() -> u32 {
    QP_ERR.load(Ordering::Acquire)
}

/// Consume one armed QP error (false: none armed).
pub(crate) fn take_qp_err() -> bool {
    QP_ERR
        .try_update(Ordering::AcqRel, Ordering::Acquire, |v| v.checked_sub(1))
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Armed errors are consumed one per call and never underflow (one test: the counter is process-wide).
    #[test]
    fn armed_qp_errors_are_consumed_one_by_one() {
        assert!(!take_qp_err());
        arm_qp_err(2);
        assert_eq!(pending_qp_err(), 2);
        assert!(take_qp_err());
        assert!(take_qp_err());
        assert!(!take_qp_err());
        assert_eq!(pending_qp_err(), 0);
    }

    #[test]
    #[cfg(feature = "memory-windows")]
    fn write_fault_has_independent_admission_and_transition_counts() {
        assert_eq!(write_qp_err_state(), (0, 0, 0));
        assert!(!take_write_qp_err());
        arm_write_qp_err(2);
        assert_eq!(write_qp_err_state(), (2, 0, 0));
        assert!(take_write_qp_err());
        record_write_qp_err(true);
        assert_eq!(write_qp_err_state(), (1, 1, 0));
        assert!(take_write_qp_err());
        record_write_qp_err(false);
        assert!(!take_write_qp_err());
        assert_eq!(write_qp_err_state(), (0, 1, 1));
    }
}
