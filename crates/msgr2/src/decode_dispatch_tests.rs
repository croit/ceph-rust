// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
use super::*;
use crate::{DispatchBudget, DispatchError, Encoder, Seg, Tag};

fn secret() -> ConnSecret {
    ConnSecret::new(&(0..64u8).collect::<Vec<_>>()).unwrap()
}

#[test]
#[cfg(target_pointer_width = "64")]
fn wire_shape_metadata_reaches_dispatch_before_large_body_all_modes() {
    for rev in [Revision::V20, Revision::V21] {
        for secure in [false, true] {
            for len in [
                [41, 0, 0, (256 << 20) + 1],
                [41, 256 << 20, 0, 256 << 20],
                [41, u32::MAX, u32::MAX, u32::MAX],
            ] {
                let mut bytes = Vec::new();
                Preamble {
                    tag: Tag::Message as u8,
                    n: crate::MAX_SEGMENTS,
                    len,
                    align: crate::ALIGN_MESSAGE,
                    flags: 0,
                }
                .write(&mut bytes);
                if secure {
                    if rev == Revision::V21 {
                        bytes.resize(PREAMBLE_LEN + INLINE_LEN, 0);
                    }
                    let mut g = secret().tx(Role::Client, rev).unwrap();
                    let tag = g.seal(&mut bytes).unwrap();
                    if rev == Revision::V21 {
                        bytes.extend_from_slice(&tag);
                    }
                }
                let owner = budget(1, 1);
                let _held = owner.borrow_mut().try_acquire(1).unwrap();
                let (_, mut decoder) = pair(rev, secure);
                decoder.set_limits(crate::Limits::wire_shape());
                decoder.attach_dispatch(owner).unwrap();
                let rx = decoder.feed_admitted(&bytes).unwrap();
                assert_eq!(rx.consumed, prefix(rev, secure));
                assert!(matches!(rx.state, RxFeedState::DispatchBlocked { .. }));
                assert!(decoder.asm.segs.iter().all(|s| s.capacity() == 0));
                assert!(decoder.buf.capacity() <= 4096);
                assert_eq!(decoder.direct_want(), 0);
                assert_eq!(decoder.secure_want(), 0);
            }
        }
    }
}
fn pair(rev: Revision, secure: bool) -> (Encoder, Decoder) {
    let mut e = Encoder::new(rev);
    let mut d = Decoder::new(rev);
    if secure {
        e.set_secure(&secret(), Role::Client).unwrap();
        d.set_secure(&secret(), Role::Server).unwrap();
    }
    (e, d)
}
fn budget(target: u64, count: usize) -> Rc<RefCell<DispatchBudget>> {
    Rc::new(RefCell::new(DispatchBudget::new(target, count).unwrap()))
}
fn wire(e: &mut Encoder, front: &[u8], data: &[u8]) -> Vec<u8> {
    let mut w = Vec::new();
    e.encode_message(&[7; 41], front, &[], data, &mut w)
        .unwrap();
    w
}
fn prefix(rev: Revision, secure: bool) -> usize {
    if secure && rev == Revision::V21 {
        96
    } else {
        32
    }
}
fn feed_fragments(d: &mut Decoder, w: &[u8], quantum: usize) -> OwnedFrame {
    let mut at = 0;
    loop {
        let end = (at + quantum).min(w.len());
        let rx = d.feed_admitted(&w[at..end]).unwrap();
        at += rx.consumed;
        match rx.state {
            RxFeedState::FrameReady => {
                assert_eq!(at, w.len());
                return d.poll_owned().unwrap().unwrap();
            }
            RxFeedState::NeedInput => assert!(rx.consumed > 0 || at == w.len()),
            other => panic!("unexpected pause {other:?}"),
        }
        assert!(at < w.len(), "complete wire did not produce a frame");
    }
}

#[test]
fn shared_budget_blocks_before_body_then_empty_resume_and_exact_suffix_all_modes() {
    for rev in [Revision::V20, Revision::V21] {
        for secure in [false, true] {
            let owner = budget(8, 4);
            let (mut a, mut first) = pair(rev, secure);
            first.attach_dispatch(owner.clone()).unwrap();
            let frame = feed_fragments(&mut first, &wire(&mut a, &[8; 8], &[]), 1);
            assert_eq!(frame.dispatch.charge(), Some(8));
            let retained_bytes = frame.segs[1].clone();
            let (mut b, mut second) = pair(rev, secure);
            second.attach_dispatch(owner.clone()).unwrap();
            let data = vec![0x5c; 128 * 1024];
            let w = wire(&mut b, &[1, 2], &data);
            let later = wire(&mut b, &[3], &[]);
            let joined = [w.as_slice(), later.as_slice()].concat();
            let rx = second.feed_admitted(&joined).unwrap();
            assert_eq!(rx.consumed, prefix(rev, secure));
            let RxFeedState::DispatchBlocked { generation } = rx.state else {
                panic!("{rx:?}");
            };
            assert_eq!(owner.borrow_mut().arm(generation), Ok(false));
            assert_eq!(second.secure_want(), 0);
            assert_eq!(second.direct_want(), 0);
            assert!(second.asm.segs.iter().all(|b| b.capacity() == 0));
            assert!(second.buf.capacity() <= 4096);
            assert!(second.want <= 96);
            for _ in 0..3 {
                let again = second.feed_admitted(&[]).unwrap();
                assert_eq!(again.consumed, 0);
                assert!(matches!(again.state, RxFeedState::DispatchBlocked { .. }));
            }
            drop(frame);
            assert_eq!(&retained_bytes[..], &[8; 8]);
            let resumed = second.feed_admitted(&[]).unwrap();
            assert_eq!(
                resumed,
                RxFeed {
                    consumed: 0,
                    state: RxFeedState::NeedInput
                }
            );
            let next = second.feed_admitted(&joined[rx.consumed..]).unwrap();
            assert_eq!(next.state, RxFeedState::FrameReady);
            assert_eq!(next.consumed, w.len() - rx.consumed);
            let frame = second.poll_owned().unwrap().unwrap();
            assert_eq!(frame.dispatch.charge(), Some(data.len() as u64 + 2));
            assert_eq!(&frame.segs[3][..], data);
            assert_eq!(
                owner.borrow_mut().try_acquire(0),
                Err(DispatchError::NoCredit)
            );
            drop(frame);
            let frame = feed_fragments(&mut second, &later, 3);
            assert_eq!(frame.dispatch.charge(), Some(1));
            assert_eq!(&frame.segs[1][..], &[3]);
        }
    }
}

#[test]
fn corrupt_and_aborted_frames_retire_receiving_credit_all_modes() {
    for rev in [Revision::V20, Revision::V21] {
        for secure in [false, true] {
            let owner = budget(8, 3);
            let (mut e, mut d) = pair(rev, secure);
            d.attach_dispatch(owner.clone()).unwrap();
            let mut w = wire(&mut e, &[1, 2], &[3; 100]);
            let trailer = if secure {
                TAG_LEN
            } else if rev == Revision::V21 {
                13
            } else {
                17
            };
            let bad = w.len() - trailer - 1;
            w[bad] ^= 1;
            assert!(d.feed_admitted(&w).is_err());
            assert!(d.poll_owned().is_err());
            let release_proof = owner.borrow_mut().try_acquire(9).unwrap();
            drop(release_proof);

            let (mut e, mut d) = pair(rev, secure);
            d.attach_dispatch(owner.clone()).unwrap();
            let mut aborted = Vec::new();
            e.encode_ex(
                Tag::Message as u8,
                0,
                true,
                &[
                    Seg {
                        data: &[7; 41],
                        align: 8,
                    },
                    Seg {
                        data: &[3; 20],
                        align: 8,
                    },
                ],
                &mut aborted,
            )
            .unwrap();
            let valid = wire(&mut e, &[4], &[]);
            let joined = [aborted.as_slice(), valid.as_slice()].concat();
            let rx = d.feed_admitted(&joined).unwrap();
            assert_eq!(rx.state, RxFeedState::NeedInput);
            assert_eq!(rx.consumed, aborted.len());
            assert_eq!(d.aborted_frames(), 1);
            let release_proof = owner.borrow_mut().try_acquire(9).unwrap();
            drop(release_proof);
            let frame = feed_fragments(&mut d, &valid, 1);
            assert_eq!(&frame.segs[1][..], &[4]);
        }
    }
}

#[test]
fn admitted_secure_loan_preserves_nonce_and_guard_all_revisions() {
    for rev in [Revision::V20, Revision::V21] {
        let owner = budget(8, 2);
        let (mut e, mut d) = pair(rev, true);
        d.attach_dispatch(owner.clone()).unwrap();
        let payload = vec![11; 32768];
        for _ in 0..2 {
            let w = wire(&mut e, &[], &payload);
            let rx = d.feed_admitted(&w[..prefix(rev, true)]).unwrap();
            assert_eq!(rx.state, RxFeedState::NeedInput);
            let mut loan = d.secure_take().unwrap();
            let count = loan.remaining();
            assert_eq!(count, w.len() - rx.consumed);
            for (slot, value) in loan.spare_capacity_mut().iter_mut().zip(&w[rx.consumed..]) {
                slot.write(*value);
            }
            // SAFETY: exactly the entire remaining frame was initialized above; no pointer escaped.
            unsafe { loan.commit_initialized(count) };
            d.secure_put(loan).unwrap();
            let frame = d.poll_owned().unwrap().unwrap();
            assert_eq!(frame.dispatch.charge(), Some(payload.len() as u64));
            assert_eq!(&frame.segs[3][..], payload);
            drop(frame);
            assert!(d.poll_owned().unwrap().is_none());
        }
    }
}

#[test]
fn gated_crc_direct_loans_cannot_bypass_preamble_admission() {
    let owner = budget(8, 2);
    let held = owner.borrow_mut().try_acquire(8).unwrap();
    let (mut e, mut d) = pair(Revision::V21, false);
    d.attach_dispatch(owner.clone()).unwrap();
    let payload = vec![9; 32 * 1024];
    let w = wire(&mut e, &[], &payload);
    let rx = d.feed_admitted(&w).unwrap();
    assert!(matches!(rx.state, RxFeedState::DispatchBlocked { .. }));
    assert!(d.direct_take().is_none());
    drop(held);
    d.feed_admitted(&[]).unwrap();
    let mut at = rx.consumed;
    while d.direct_want() > 0 {
        let n = d.direct_want();
        let (mut v, mut crc) = d.direct_take().unwrap();
        v.extend_from_slice(&w[at..at + n]);
        crc.update(&v);
        d.direct_put(v, crc);
        at += n;
        if d.direct_want() == 0 && at < w.len() {
            let result = d.feed_admitted(&w[at..at + 4]).unwrap();
            at += result.consumed;
        }
    }
    let rx = d.feed_admitted(&w[at..]).unwrap();
    assert_eq!(rx.state, RxFeedState::FrameReady);
    let frame = d.poll_owned().unwrap().unwrap();
    assert_eq!(&frame.segs[3][..], payload);
    assert_eq!(frame.dispatch.charge(), Some(payload.len() as u64));
}

#[test]
fn unsupported_configuration_and_legacy_paths_refuse_without_body_allocation() {
    let owner = budget(8, 4);
    let mut d = Decoder::new(Revision::V21);
    d.attach_dispatch(owner.clone()).unwrap();
    assert!(d.feed_admitted(&[]).is_ok());
    for legacy in [0, 1, 2] {
        let mut d = Decoder::new(Revision::V21);
        d.attach_dispatch(owner.clone()).unwrap();
        match legacy {
            0 => d.feed(&[1; 64]),
            1 => d.commit(0),
            _ => assert_eq!(d.poll().unwrap_err(), Error::Busy),
        }
        assert_eq!(d.poll_owned().unwrap_err(), Error::Busy);
        assert_eq!(d.buffered(), 0);
    }
    let mut d = Decoder::new(Revision::V21);
    d.attach_dispatch(owner).unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        d.recv_buf(1024);
    }));
    assert!(result.is_err());
    assert_eq!(d.buf.capacity(), 0);
}

#[test]
fn malformed_or_hard_oversize_preamble_fails_before_body_allocation_all_modes() {
    for rev in [Revision::V20, Revision::V21] {
        for secure in [false, true] {
            let owner = budget(8, 2);
            let (mut e, mut d) = pair(rev, secure);
            d.attach_dispatch(owner.clone()).unwrap();
            let mut w = Vec::new();
            e.encode_message(&[1; 4096], &[], &[], &[2; 16], &mut w)
                .unwrap();
            assert_eq!(
                d.feed_admitted(&w),
                Err(Error::BadMessageHeaderLength(4096))
            );
            assert!(d.asm.segs.iter().all(|b| b.capacity() == 0));
            assert!(d.buf.capacity() <= 4096);
            let release_proof = owner.borrow_mut().try_acquire(9).unwrap();
            drop(release_proof);
            let (mut e, mut d) = pair(rev, secure);
            d.set_limits(Limits {
                max_segment: 1024,
                max_frame: 4096,
                ..Limits::default()
            });
            d.attach_dispatch(owner.clone()).unwrap();
            assert_eq!(
                d.feed_admitted(&wire(&mut e, &[], &[3; 2048])),
                Err(Error::SegmentTooLarge(2048))
            );
            assert!(d.asm.segs.iter().all(|b| b.capacity() == 0));
            assert!(d.buf.capacity() <= 4096);
        }
    }
}

#[test]
fn closing_decoder_retires_logical_credit_but_keeps_owned_loan_valid() {
    for rev in [Revision::V20, Revision::V21] {
        let owner = budget(8, 2);
        let (mut e, mut d) = pair(rev, true);
        d.attach_dispatch(owner.clone()).unwrap();
        let w = wire(&mut e, &[], &[2; 32768]);
        d.feed_admitted(&w[..prefix(rev, true)]).unwrap();
        let mut loan = d.secure_take().unwrap();
        drop(d);
        let proof = owner.borrow_mut().try_acquire(9).unwrap();
        assert!(loan.remaining() > 0);
        loan.spare_capacity_mut()[0].write(0x55);
        // SAFETY: exactly the next byte was initialized; socket pointer never escaped.
        unsafe { loan.commit_initialized(1) };
        drop((proof, loan));
    }
}

#[test]
fn pending_direct_failure_is_sticky_and_retires_guard_before_accepting_more() {
    let owner = budget(8, 2);
    let (mut e, mut d) = pair(Revision::V21, false);
    d.attach_dispatch(owner.clone()).unwrap();
    let w = wire(&mut e, &[], &[3; 32768]);
    let rx = d.feed_admitted(&w[..32]).unwrap();
    assert_eq!(rx.state, RxFeedState::NeedInput);
    assert_eq!(
        owner.borrow_mut().try_acquire(1),
        Err(DispatchError::NoCredit)
    );
    // Own deterministic injection of the pending error an allocation failure reports;
    // no giant allocation or allocator fault dependency is required.
    d.err = Some(Error::SegmentTooLarge(32768));
    assert_eq!(
        d.feed_admitted(&w[32..]),
        Err(Error::SegmentTooLarge(32768))
    );
    assert_eq!(d.asm.wire, 32);
    assert!(d.asm.segs.iter().all(|v| v.is_empty()));
    assert_eq!(d.feed_admitted(&[]), Err(Error::SegmentTooLarge(32768)));
    assert_eq!(d.poll_owned().unwrap_err(), Error::SegmentTooLarge(32768));
    assert!(d.direct_take().is_none());
    let proof = owner.borrow_mut().try_acquire(9).unwrap();
    drop(proof);
}

#[test]
fn invalid_secure_return_faults_guard_but_loan_storage_stays_owned() {
    for rev in [Revision::V20, Revision::V21] {
        let owner = budget(8, 2);
        let (mut e, mut d) = pair(rev, true);
        d.attach_dispatch(owner.clone()).unwrap();
        let w = wire(&mut e, &[], &[3; 32768]);
        d.feed_admitted(&w[..prefix(rev, true)]).unwrap();
        let loan = d.secure_take().unwrap();
        assert!(loan.remaining() > 1);
        // A partial return is an owned-loan contract violation, not dispatch pressure.
        assert_eq!(d.secure_put(loan), Err(Error::Busy));
        assert_eq!(d.feed_admitted(&[]), Err(Error::Busy));
        let proof = owner.borrow_mut().try_acquire(9).unwrap();
        drop(proof);
        let (_, mut foreign) = pair(rev, true);
        foreign.feed(&w[..prefix(rev, true)]);
        foreign.poll_owned().unwrap();
        let loan = foreign.secure_take().unwrap();
        let (_, mut receiver) = pair(rev, true);
        receiver.attach_dispatch(owner.clone()).unwrap();
        assert_eq!(receiver.secure_put(loan), Err(Error::Busy));
        assert_eq!(receiver.feed_admitted(&[]), Err(Error::Busy));
    }
}

#[test]
fn secure_partial_fallback_does_not_zero_whole_frame_before_spare_loan() {
    for rev in [Revision::V20, Revision::V21] {
        let owner = budget(8, 2);
        let (mut e, mut d) = pair(rev, true);
        d.attach_dispatch(owner.clone()).unwrap();
        let payload = vec![0x6b; 1024 * 1024];
        for _ in 0..2 {
            let w = wire(&mut e, &[], &payload);
            let accepted = prefix(rev, true) + 4096;
            let rx = d.feed_admitted(&w[..accepted]).unwrap();
            assert_eq!(rx.consumed, accepted);
            assert_eq!(rx.state, RxFeedState::NeedInput);
            assert_eq!(d.filled - d.start, accepted);
            assert_eq!(
                d.buf.len(),
                accepted,
                "fallback initialized bytes must follow actual received prefix"
            );
            assert!(d.want > 1024 * 1024);
            let mut loan = d.secure_take().unwrap();
            assert_eq!(loan.buf.len(), accepted);
            let count = loan.remaining();
            for (slot, value) in loan.spare_capacity_mut().iter_mut().zip(&w[accepted..]) {
                slot.write(*value);
            }
            // SAFETY: exactly the remaining wire prefix was initialized; no writer escaped.
            unsafe { loan.commit_initialized(count) };
            d.secure_put(loan).unwrap();
            let frame = d.poll_owned().unwrap().unwrap();
            assert_eq!(&frame.segs[3][..], payload);
            assert_eq!(frame.dispatch.charge(), Some(payload.len() as u64));
            drop(frame);
            assert!(d.poll_owned().unwrap().is_none());
        }
    }
}

#[test]
fn large_data_segments_are_recycled_only_after_every_reference_is_dropped() {
    const LEN: usize = 4 << 20;
    const CAP: usize = LEN + crate::rxpool::PAD_ROOM;
    // credit for two messages in flight; the shelf parks at most that much
    let owner = budget(2 * CAP as u64, 4);
    let (mut e, mut d) = pair(Revision::V21, false);
    d.set_rx_block_crcs(false);
    d.attach_dispatch(owner.clone()).unwrap();
    let payload = vec![5; LEN];
    let w = wire(&mut e, &[], &payload);
    let first = feed_fragments(&mut d, &w, 1 << 20);
    assert_eq!(&first.segs[3][..], payload);
    let ptr = first.segs[3].as_ptr();
    let tail = first.segs[3].slice(10..);
    drop(first);
    // a live slice keeps the buffer out of the shelf: the next message gets another one
    let second = feed_fragments(&mut d, &w, 1 << 20);
    let second_ptr = second.segs[3].as_ptr();
    assert_ne!(second_ptr, ptr);
    assert_eq!(&tail[..], &payload[10..]);
    drop(tail);
    drop(second);
    assert_eq!(owner.borrow().shelf().parked(), 2 * CAP);
    let third = feed_fragments(&mut d, &w, 1 << 20);
    assert_eq!(&third.segs[3][..], payload);
    assert!([ptr, second_ptr].contains(&third.segs[3].as_ptr()));
    assert_eq!(owner.borrow().shelf().parked(), CAP);
}

#[test]
fn attached_shelf_recycles_without_a_dispatch_domain() {
    const LEN: usize = 4 << 20;
    const CAP: usize = LEN + crate::rxpool::PAD_ROOM;
    let shelf = Arc::new(crate::RxShelf::new(2 * CAP as u64));
    let (mut e, mut d) = pair(Revision::V21, false);
    d.set_rx_block_crcs(false);
    d.attach_shelf(shelf.clone()).unwrap();
    let payload = vec![9; LEN];
    let w = wire(&mut e, &[], &payload);
    let round = |d: &mut Decoder| {
        for piece in w.chunks(1 << 20) {
            d.feed(piece);
        }
        d.poll_owned().unwrap().unwrap()
    };
    let first = round(&mut d);
    assert_eq!(&first.segs[3][..], payload);
    let ptr = first.segs[3].as_ptr();
    let kept = first.segs[3].slice(1..);
    drop(first);
    assert_eq!(shelf.parked(), 0, "a live slice owns the buffer");
    drop(kept);
    assert_eq!(shelf.parked(), CAP);
    let second = round(&mut d);
    assert_eq!(&second.segs[3][..], payload);
    assert_eq!(second.segs[3].as_ptr(), ptr, "the parked buffer is reused");
    assert_eq!(shelf.parked(), 0);
    drop(second);
    // a decoder with a dispatch domain keeps its domain's shelf and refuses a second one
    let (_, mut gated) = pair(Revision::V21, false);
    gated.attach_dispatch(budget(8, 1)).unwrap();
    gated.attach_shelf(shelf).unwrap();
}

#[test]
fn admitted_frames_keep_ingress_credit_until_delivery_is_dropped_all_modes() {
    let mut failures = Vec::new();
    for rev in [Revision::V20, Revision::V21] {
        for secure in [false, true] {
            for admitted in [false, true] {
                let credits = ingress::IngressCredits::with_frames(&[(1, 1 << 20)], 8);
                let (mut encoder, mut decoder) = pair(rev, secure);
                decoder.set_gate(Some(credits.frame_gate(0)));
                if admitted {
                    decoder.attach_dispatch(budget(1 << 20, 8)).unwrap();
                }
                let payload = [0x5c; 8192];
                let w = wire(&mut encoder, &[1, 2], &payload);
                let frame = if admitted {
                    let rx = decoder.feed_admitted(&w).unwrap();
                    assert_eq!(rx.consumed, w.len());
                    assert_eq!(rx.state, RxFeedState::FrameReady);
                    decoder.poll_owned().unwrap().unwrap()
                } else {
                    decoder.feed(&w);
                    decoder.poll_owned().unwrap().unwrap()
                };
                assert_eq!(&frame.segs[3][..], payload);
                if frame.credit.0.is_none() || credits.pool_stats()[0].used < w.len() as u64 {
                    failures.push((rev, secure, admitted));
                }
                drop(frame);
                assert!(
                    credits.idle(),
                    "{rev:?} secure={secure} admitted={admitted}"
                );
            }
        }
    }
    assert!(
        failures.is_empty(),
        "ingress credit released early: {failures:?}"
    );
}
