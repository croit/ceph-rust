// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Shared crash model for the in-memory testkit stores (journal, migration).
//!
//! `FaultPlan::crash_after(k)` makes the first `k` durable mutations succeed
//! and every later mutation fail with [`CRASH_ERRNO`] without changing
//! anything, modeling a process crash at every mutation boundary. Reads stay
//! available so the durable state can be inspected after the crash.
//! `k = 0` crashes before the first mutation.
//!
//! `FaultPlan::fail_at(k)` refuses only the `k`-th mutation with
//! [`CRASH_ERRNO`] and lets every other one proceed: a stage that fails on a
//! live cluster, so the caller's error path (prepare compensation) runs
//! against the durable state the failed stage left.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::journal_backend::EIO;

/// The errno a fault-plan crash returns for every later mutation (EIO).
pub const CRASH_ERRNO: i32 = EIO;

/// Crash model shared by one in-memory store and its process instances.
#[derive(Debug)]
pub struct FaultPlan {
    crash_after: u64,
    fail_at: Option<u64>,
    mutations: AtomicU64,
}

impl FaultPlan {
    /// Never crash.
    pub const fn none() -> Self {
        Self {
            crash_after: u64::MAX,
            fail_at: None,
            mutations: AtomicU64::new(0),
        }
    }

    /// Crash after the k-th durable mutation.
    pub const fn crash_after(k: u64) -> Self {
        Self {
            crash_after: k,
            fail_at: None,
            mutations: AtomicU64::new(0),
        }
    }

    /// Refuse only the k-th durable mutation; later mutations proceed.
    pub const fn fail_at(k: u64) -> Self {
        Self {
            crash_after: u64::MAX,
            fail_at: Some(k),
            mutations: AtomicU64::new(0),
        }
    }

    /// Durable mutations attempted so far (successful and refused).
    pub fn mutations(&self) -> u64 {
        self.mutations.load(Ordering::Relaxed)
    }

    /// Count one durable mutation; fails past the crash point or at the
    /// configured failure.
    pub(crate) fn record(&self) -> Result<(), i32> {
        let before = self.mutations.fetch_add(1, Ordering::Relaxed);
        if before >= self.crash_after || self.fail_at == Some(before) {
            return Err(CRASH_ERRNO);
        }
        Ok(())
    }
}
