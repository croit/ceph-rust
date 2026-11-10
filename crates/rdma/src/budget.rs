// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Sizing of the registered arenas of one core on one device from a byte budget (`flashstore_rdma_memory`: the arenas are
//! pinned, so they have their own budget on top of `osd_memory_target`; the daemon gives each (core, device) an equal part).
//! Memory is per core (shared SRQ), never per connection or per peer: the sessions of a core share the receive slots
//! through the dynamic credit grants ([`crate::grant`]); a core holds `srq_depth / MIN_WINDOW` sessions at the least.
//!
//! A budget of `b` bytes buys `b / slot` slots. Two thirds go to the receive arena (the SRQ); the rest is the send arena
//! (copy targets of outgoing bytes). The budget must hold at least [`MIN_CONNECTIONS`] line-rate windows
//! ([`crate::LINE_RATE_WINDOW`]) of receive slots and [`MIN_TX_WINDOWS`] of send slots; [`min_bytes`] is exactly that, and
//! a smaller budget is an error the daemon turns into a refusal to start (never into a silently tiny transport). The
//! window ceiling of a session follows the budget: up to [`crate::DEFAULT_MAX_WINDOW`], at most a [`MIN_CONNECTIONS`]th
//! of the receive slots (a small budget gives smaller windows, it does not refuse).

/// Connections a core must be able to hold at their largest window at the least.
pub const MIN_CONNECTIONS: u32 = 4;
/// Windows of send slots a core must have at the least (a connection may have a whole window of SENDs in flight).
pub const MIN_TX_WINDOWS: u32 = 2;

/// The budget cannot hold the minimum arenas.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TooSmall {
    pub have: u64,
    pub need: u64,
}

impl std::fmt::Display for TooSmall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} MiB per core and device, at least {} MiB needed",
            self.have >> 20,
            self.need.div_ceil(1 << 20)
        )
    }
}

/// Smallest budget of one (core, device) that [`size`] accepts.
pub fn min_bytes(slot: u32) -> u64 {
    u64::from(MIN_CONNECTIONS + MIN_TX_WINDOWS)
        * u64::from(crate::LINE_RATE_WINDOW)
        * u64::from(slot)
}

/// The equal part of `total` bytes for each of `cores` x `devices` arenas sets.
pub fn per_core(total: u64, cores: usize, devices: usize) -> u64 {
    total / (cores.max(1) * devices.max(1)) as u64
}

/// Arenas of one (core, device) part.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sizing {
    /// Receive slots (the SRQ depth).
    pub rx: u32,
    /// Send slots.
    pub tx: u32,
    /// Largest window one session may hold: `ceiling`, at most `rx / MIN_CONNECTIONS`.
    pub window: u32,
}

/// Receive slots, send slots and the session window ceiling for a budget of `bytes`; `ceiling` = the largest window one
/// session may hold when the budget allows it.
pub fn size(bytes: u64, slot: u32, ceiling: u32) -> Result<Sizing, TooSmall> {
    let slots = bytes / u64::from(slot);
    let rx = slots * 2 / 3;
    let tx = slots - rx;
    let line = u64::from(crate::LINE_RATE_WINDOW);
    if rx < u64::from(MIN_CONNECTIONS) * line || tx < u64::from(MIN_TX_WINDOWS) * line {
        return Err(TooSmall {
            have: bytes,
            need: min_bytes(slot),
        });
    }
    let fit = |n: u64| u32::try_from(n).unwrap_or(u32::MAX);
    Ok(Sizing {
        rx: fit(rx),
        tx: fit(tx),
        window: fit(rx / u64::from(MIN_CONNECTIONS)).min(ceiling),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DEFAULT_SLOT;

    const MIB: u64 = 1 << 20;

    fn s(rx: u32, tx: u32, window: u32) -> Result<Sizing, TooSmall> {
        Ok(Sizing { rx, tx, window })
    }

    #[test]
    fn splits_two_thirds_receive_one_third_send() {
        // 64 MiB = 1024 slots of 64 KiB: 682 receive slots, the rest is send
        assert_eq!(size(64 * MIB, DEFAULT_SLOT, 64), s(682, 342, 64));
        // 32 MiB = 512 slots: 341 receive slots = 113 sessions at the minimum window
        assert_eq!(size(32 * MIB, DEFAULT_SLOT, 64), s(341, 171, 64));
    }

    #[test]
    fn minimum_is_exact() {
        let m = min_bytes(DEFAULT_SLOT);
        assert_eq!(m, 6 * MIB);
        assert_eq!(size(m, DEFAULT_SLOT, 64), s(64, 32, 16));
        let e = size(m - u64::from(DEFAULT_SLOT), DEFAULT_SLOT, 64).unwrap_err();
        assert_eq!((e.have, e.need), (m - u64::from(DEFAULT_SLOT), m));
        assert_eq!(size(0, DEFAULT_SLOT, 64).unwrap_err().need, m);
    }

    #[test]
    fn the_window_ceiling_follows_the_budget() {
        // default 256 MiB: 8 cores x 1 device = 32 MiB parts get the full ceiling, 8 x 2 = 16 MiB parts a smaller one
        let c = crate::DEFAULT_MAX_WINDOW;
        assert_eq!(
            size(per_core(256 * MIB, 8, 1), DEFAULT_SLOT, c),
            s(341, 171, 64)
        );
        assert_eq!(
            size(per_core(256 * MIB, 8, 2), DEFAULT_SLOT, c),
            s(170, 86, 42)
        );
        // never above the ceiling, never below the line-rate window
        assert_eq!(size(512 * MIB, DEFAULT_SLOT, c).unwrap().window, c);
        assert_eq!(
            size(min_bytes(DEFAULT_SLOT), DEFAULT_SLOT, c)
                .unwrap()
                .window,
            crate::LINE_RATE_WINDOW
        );
    }

    #[test]
    fn registered_bytes_stay_within_the_budget() {
        for mib in [6u64, 7, 24, 25, 31, 32, 63, 64, 100, 512] {
            let z = size(mib * MIB, DEFAULT_SLOT, 64).unwrap();
            assert!((u64::from(z.rx) + u64::from(z.tx)) * u64::from(DEFAULT_SLOT) <= mib * MIB);
        }
    }

    #[test]
    fn equal_parts_per_core_and_device() {
        assert_eq!(per_core(512 * MIB, 8, 1), 64 * MIB);
        assert_eq!(per_core(512 * MIB, 8, 2), 32 * MIB);
        assert_eq!(per_core(512 * MIB, 0, 0), 512 * MIB);
    }
}
