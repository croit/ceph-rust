// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Values the device reports are not ours: the async event channel's return codes and a completion's byte count enter
//! the data path here, decided once and testable without a device.
use std::ffi::c_int;
use std::io;

/// Drain the device's async event channel: `wait` returns `1` when an event is pending, `0` when `stop` was signalled and
/// `< 0` (`-errno`) when the channel itself is broken. Report every `IBV_EVENT_QP_LAST_WQE_REACHED` to `last_wqe` (its QP
/// number) and every other event to `other` (type, QP number, fatal: a CQ/SRQ/device-fatal event, shim code 3), acknowledge
/// each one after its report, and return once `stop` is signalled. An event is reported before it is acknowledged, so a QP destroy of an acknowledged event returns
/// only after its report.
///
/// `Err` = the channel is broken (wait or read failed): no event arrives any more, so every later QP teardown of that
/// device runs into its drain limit. Callers report it once instead of treating it as a stop.
pub(crate) fn async_events(
    mut wait: impl FnMut() -> c_int,
    mut next: impl FnMut(&mut c_int, &mut u32) -> c_int,
    mut ack: impl FnMut(),
    mut last_wqe: impl FnMut(u32),
    mut other: impl FnMut(c_int, u32, bool),
) -> io::Result<()> {
    loop {
        match wait() {
            1 => {}
            0 => return Ok(()),
            rc => return Err(io::Error::from_raw_os_error(-rc)),
        }
        loop {
            let (mut ty, mut qpn) = (0, 0);
            match next(&mut ty, &mut qpn) {
                1 => last_wqe(qpn),
                rc @ (2 | 3) => other(ty, qpn, rc == 3),
                0 => break,
                e => return Err(io::Error::from_raw_os_error(-e)),
            }
            ack();
        }
    }
}

/// Bytes of the receive slot a completion reports, `None` when the provider reports more than the posted slot holds. A
/// longer SEND is a local length error (completion status != 0), so a clean completion with a longer count is a provider
/// defect; slicing the slot with it would run into the neighbouring slot or past the arena.
pub(crate) fn recv_len(byte_len: u32, slot: u32) -> Option<usize> {
    (byte_len <= slot).then_some(byte_len as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fatal_resource_event_is_delivered_before_acknowledgement() {
        let mut waits = [1, 0].into_iter();
        let mut reads = [3, 0].into_iter();
        let failed = std::cell::Cell::new(false);
        let wakes = std::cell::Cell::new(0);
        async_events(
            || waits.next().unwrap(),
            |ty, _| {
                *ty = 0;
                reads.next().unwrap()
            },
            || {
                assert!(
                    failed.get(),
                    "resource ownership must fail before event acknowledgement"
                )
            },
            |_| panic!("not a last-WQE event"),
            |_, _, fatal| {
                assert!(fatal);
                failed.set(true);
                wakes.set(wakes.get() + 1);
            },
        )
        .unwrap();
        assert!(failed.get());
        assert_eq!(wakes.get(), 1);
    }

    /// A channel error (`poll`/`fcntl` refused) must not read as the stop signal: the loop has to end with the errno, so
    /// the caller logs the broken channel instead of leaving every later QP teardown without its last-WQE event.
    #[test]
    fn a_broken_async_channel_is_an_error_and_not_a_stop() {
        let mut wakes = [-9].into_iter();
        let err = async_events(
            || wakes.next().expect("the loop must end on the failure"),
            |_, _| panic!("no event can be read from a broken channel"),
            || panic!("nothing to acknowledge"),
            |_| panic!("no last-WQE event from a broken channel"),
            |_, _, _| panic!("no other event from a broken channel"),
        )
        .unwrap_err();
        assert_eq!(err.raw_os_error(), Some(9));
    }

    #[test]
    fn a_failed_event_read_ends_the_channel_with_its_errno() {
        let mut wakes = [1].into_iter();
        let mut reads = [-5].into_iter();
        let mut acks = 0;
        let err = async_events(
            || wakes.next().unwrap_or(0),
            |_, _| {
                reads
                    .next()
                    .expect("a failed read ends the loop: it is not retried")
            },
            || acks += 1,
            |_| panic!("no event was reported"),
            |_, _, _| panic!("no event was reported"),
        )
        .unwrap_err();
        assert_eq!(err.raw_os_error(), Some(5));
        assert_eq!(acks, 0, "an unread event cannot be acknowledged");
    }

    /// Every wake drains the channel completely, and each event is reported before its acknowledgement (a QP destroy
    /// waits for the acknowledgement, so its report must already be recorded).
    #[test]
    fn every_event_is_reported_before_it_is_acknowledged() {
        let mut wakes = [1, 1, 0].into_iter();
        // (return code, event type, QP number): one wake with two events, one wake with one, then the stop signal
        let mut reads = [(1, 0, 7), (2, 8, 0), (0, 0, 0), (2, 4, 3), (0, 0, 0)].into_iter();
        let seen = std::cell::RefCell::new(Vec::new());
        async_events(
            || wakes.next().expect("the loop ends on the stop signal"),
            |ty, qpn| {
                let (rc, event, number) = reads.next().expect("drained in the recorded order");
                (*ty, *qpn) = (event, number);
                rc
            },
            || seen.borrow_mut().push("ack"),
            |qpn| {
                seen.borrow_mut()
                    .push(if qpn == 7 { "last wqe 7" } else { "last wqe" })
            },
            |ty, qpn, _| {
                seen.borrow_mut().push(match (ty, qpn) {
                    (8, 0) => "comm est",
                    (4, 3) => "other 3",
                    _ => "event",
                })
            },
        )
        .unwrap();
        assert_eq!(
            seen.into_inner(),
            ["last wqe 7", "ack", "comm est", "ack", "other 3", "ack"]
        );
    }

    /// The completion's byte count comes from the provider: a count beyond the posted slot must not slice the arena (it
    /// would run into the next slot or past the arena allocation).
    #[test]
    fn a_completion_longer_than_its_slot_is_refused() {
        assert_eq!(recv_len(0, 1024), Some(0));
        assert_eq!(recv_len(1, 1024), Some(1));
        assert_eq!(recv_len(1024, 1024), Some(1024));
        for byte_len in [1025, 4096, u32::MAX] {
            assert_eq!(recv_len(byte_len, 1024), None, "{byte_len} bytes");
        }
    }
}
