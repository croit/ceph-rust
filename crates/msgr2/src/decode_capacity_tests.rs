// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Full-backing capacity checks: a BytesMut view's capacity can hide its retained allocation.
use super::*;
use crate::{DispatchBudget, Encoder, MAX_SEGMENTS};

#[test]
fn empty_data_loan_avoids_body_capacity_and_retains_verified_crc() {
    for blocks in [false, true] {
        for fallback in [false, true] {
            let payload = vec![0x6d; 1_048_579];
            let mut encoder = Encoder::new(Revision::V21);
            let mut wire = Vec::new();
            encoder
                .encode_message(&[7; 41], b"front", b"middle", &payload, &mut wire)
                .unwrap();
            let mut decoder = Decoder::new(Revision::V21);
            decoder.set_rx_block_crcs(blocks);
            let mut at = 0;
            while decoder.asm.st != AsmSt::Seg || decoder.asm.seg != 3 {
                decoder.feed(&wire[at..at + 1]);
                at += 1;
                assert!(decoder.poll_owned().unwrap().is_none());
            }
            assert_eq!(decoder.direct_want(), payload.len());
            assert_eq!(decoder.asm.segs[3].capacity(), 0);
            let empty = decoder.direct_take_empty_data();
            let (mut segment, mut crcs) = if blocks {
                assert!(empty.is_none());
                assert_eq!(decoder.asm.segs[3].capacity(), 0);
                decoder.direct_take().unwrap()
            } else {
                let (segment, crcs) = empty.unwrap();
                assert_eq!(segment.capacity(), 0);
                (segment, crcs)
            };
            if fallback || blocks {
                // Ordinary socket/cancel fallback reserves once, before any data.
                segment.try_reserve_exact(payload.len()).unwrap();
                assert!(segment.capacity() >= payload.len());
                segment.extend_from_slice(&payload);
            } else {
                // Represents completed caller storage, not decoder allocation.
                segment = payload.clone();
            }
            crcs.update(&segment);
            decoder.direct_put(segment, crcs);
            decoder.feed(&wire[at + payload.len()..]);
            let frame = decoder.poll_owned().unwrap().unwrap();
            assert_eq!(frame.segs[3].as_ref(), payload);
            assert_eq!(frame.data_crc, Some(crc32c(!0, &payload)));
        }
    }
}

#[test]
fn empty_data_loan_refuses_partial_payload_without_changing_ordinary_loan() {
    let payload = vec![0x4a; 65_539];
    let mut encoder = Encoder::new(Revision::V21);
    let mut wire = Vec::new();
    encoder
        .encode_message(&[7; 41], b"front", b"middle", &payload, &mut wire)
        .unwrap();
    let mut decoder = Decoder::new(Revision::V21);
    decoder.set_rx_block_crcs(false);
    let prefix = wire.len() - payload.len() - 13 + 37;
    decoder.feed(&wire[..prefix]);
    assert!(decoder.poll_owned().unwrap().is_none());
    assert_eq!(decoder.asm.have(3), 37);
    assert!(decoder.direct_take_empty_data().is_none());
    let remaining = decoder.direct_want();
    let (mut segment, mut crcs) = decoder.direct_take().unwrap();
    assert_eq!(segment.len(), 37);
    assert!(segment.capacity() >= payload.len());
    segment.extend_from_slice(&wire[prefix..prefix + remaining]);
    crcs.update(&wire[prefix..prefix + remaining]);
    decoder.direct_put(segment, crcs);
    decoder.feed(&wire[prefix + remaining..]);
    assert_eq!(
        decoder.poll_owned().unwrap().unwrap().segs[3].as_ref(),
        payload
    );
}

fn wire_bound(rev: Revision, limits: Limits) -> usize {
    let padded = limits.max_frame as usize + MAX_SEGMENTS * (crate::CRYPTO_BLOCK - 1);
    match rev {
        Revision::V20 => PREAMBLE_LEN + padded + crate::CRYPTO_BLOCK + TAG_LEN,
        Revision::V21 => {
            PREAMBLE_LEN + INLINE_LEN + TAG_LEN + padded + TAG_LEN + crate::CRYPTO_BLOCK + TAG_LEN
        }
    }
}
fn bound(rev: Revision, limits: Limits) -> usize {
    wire_bound(rev, limits).max(64 * 1024)
}

#[test]
fn zero_capacity_tail_retains_full_original_vec_capacity() {
    let mut storage = bytes::BytesMut::with_capacity(64 * 1024);
    let original = storage.capacity();
    storage.resize(original, 0x5a);
    let head = storage.split_to(original).freeze();
    assert!(storage.is_empty());
    assert_eq!(storage.capacity(), 0);
    assert_eq!(head[original - 1], 0x5a);
    drop(head);
    let recovered: Vec<u8> = storage.into();
    assert!(recovered.is_empty());
    assert_eq!(
        recovered.capacity(),
        original,
        "zero view capacity did not free the backing"
    );
}

#[test]
fn unique_and_shared_high_offset_growth_preserves_four_r_induction_bound() {
    let r = 64 * 1024;
    for requested_capacity in [r / 4, r, 2 * r, 4 * r] {
        for fraction in [0, 1, 3, 4] {
            for shared in [false, true] {
                for requested in [r / 2, r] {
                    let mut storage = bytes::BytesMut::with_capacity(requested_capacity);
                    let original = storage.capacity();
                    assert!(original <= 4 * r);
                    storage.resize(original, 0x5a);
                    let offset = original * fraction / 4;
                    let prefix = storage.split_to(offset).freeze();
                    let len = storage.len().min(r / 4);
                    storage.truncate(len);
                    let alias = if shared {
                        Some(prefix)
                    } else {
                        drop(prefix);
                        None
                    };
                    storage.reserve(requested - len);
                    assert!(storage.capacity() >= requested);
                    assert!(storage.iter().all(|v| *v == 0x5a));
                    if let Some(alias) = &alias {
                        assert!(alias.iter().all(|v| *v == 0x5a));
                    }
                    drop(alias);
                    // No aliases remain: public conversion recovers the entire original Vec,
                    // including any hidden offset. Do not normalize until this endpoint.
                    let recovered: Vec<u8> = storage.into();
                    assert!(
                        recovered.capacity() <= 4 * r,
                        "C={} offset={offset} len={len} requested={requested} shared={shared}",
                        recovered.capacity()
                    );
                    assert_eq!(recovered.len(), len);
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Seed {
    Fresh,
    UniqueOffset,
    SharedOffset,
    UniqueZeroTail,
    SharedZeroTail,
}
#[derive(Clone, Copy, Debug)]
enum Receive {
    Fallback,
    Loan,
}

fn seed(decoder: &mut Decoder, variant: Seed, r: usize) -> Option<bytes::Bytes> {
    if matches!(variant, Seed::Fresh) {
        return None;
    }
    let mut storage = bytes::BytesMut::with_capacity(2 * r);
    let capacity = storage.capacity();
    assert!(capacity <= 4 * r);
    storage.resize(capacity, 0xa5);
    let offset = if matches!(variant, Seed::UniqueZeroTail | Seed::SharedZeroTail) {
        capacity
    } else {
        r + r / 2
    };
    assert!(
        offset > r,
        "fixture must exercise offsets larger than the frame bound"
    );
    let prefix = storage.split_to(offset).freeze();
    storage.truncate(0);
    decoder.buf = storage;
    if matches!(variant, Seed::SharedOffset | Seed::SharedZeroTail) {
        Some(prefix)
    } else {
        drop(prefix);
        None
    }
}

fn check_aliases(aliases: &[(bytes::Bytes, u8)], original: &Option<bytes::Bytes>) {
    for (alias, expected) in aliases {
        assert!(alias.iter().all(|v| *v == *expected));
    }
    if let Some(original) = original {
        assert!(original.iter().all(|v| *v == 0xa5));
    }
}

fn history(
    rev: Revision,
    seed_kind: Seed,
    receive: Receive,
    retain_results: bool,
    stop: usize,
    stop_at_loan: bool,
) {
    let limits = Limits {
        max_segment: 32 * 1024,
        max_frame: 64 * 1024,
        ..Limits::default()
    };
    let r = bound(rev, limits);
    let secret = ConnSecret::new(&(0..64u8).collect::<Vec<_>>()).unwrap();
    let mut encoder = Encoder::new(rev);
    encoder.set_secure(&secret, Role::Client).unwrap();
    let mut decoder = Decoder::new(rev);
    decoder.set_limits(limits);
    decoder.set_secure(&secret, Role::Server).unwrap();
    let owner = Rc::new(RefCell::new(DispatchBudget::new(0, 1).unwrap()));
    decoder.attach_dispatch(owner.clone()).unwrap();
    let original = seed(&mut decoder, seed_kind, r);
    let mut aliases = Vec::new();
    for index in 0..stop {
        check_aliases(&aliases, &original);
        let len = [512, 16 * 1024, 32 * 1024, 17, 24 * 1024, 8192][index % 6];
        let value = index as u8 + 1;
        let payload = vec![value; len];
        let mut wire = Vec::new();
        encoder
            .encode_message(&[7; 41], &[0x3c; 17], &[0x4d; 7], &payload, &mut wire)
            .unwrap();
        assert!(wire.len() <= r);
        let frame = match receive {
            Receive::Fallback => {
                let mut at = 0;
                loop {
                    let end = (at + [1, 97, 4096, 8191][index % 4]).min(wire.len());
                    let rx = decoder.feed_admitted(&wire[at..end]).unwrap();
                    at += rx.consumed;
                    if rx.state == RxFeedState::FrameReady {
                        assert_eq!(at, wire.len());
                        break decoder.poll_owned().unwrap().unwrap();
                    }
                    assert_eq!(rx.state, RxFeedState::NeedInput);
                    assert!(rx.consumed > 0 && at < wire.len());
                }
            }
            Receive::Loan => {
                let prefix = if rev == Revision::V21 {
                    96
                } else {
                    PREAMBLE_LEN
                };
                let received = prefix + 73;
                let rx = decoder.feed_admitted(&wire[..received]).unwrap();
                assert_eq!(rx.consumed, received);
                assert_eq!(rx.state, RxFeedState::NeedInput);
                let mut loan = decoder.secure_take().unwrap();
                if stop_at_loan && index + 1 == stop {
                    check_aliases(&aliases, &original);
                    drop(decoder); // logical credit ends; this owned loan still has real storage.
                    drop(aliases);
                    drop(original);
                    let recovered: Vec<u8> = loan.buf.into();
                    assert!(
                        recovered.capacity() <= 4 * r,
                        "loan C={} R={r} rev={rev:?} seed={seed_kind:?} stop={stop}",
                        recovered.capacity()
                    );
                    let proof = owner.borrow_mut().try_acquire(0).unwrap();
                    drop(proof);
                    return;
                }
                let mut at = received;
                while loan.remaining() > 0 {
                    let n = loan.remaining().min(4093);
                    for (slot, value) in loan.spare_capacity_mut()[..n]
                        .iter_mut()
                        .zip(&wire[at..at + n])
                    {
                        slot.write(*value);
                    }
                    // SAFETY: exact positive prefix initialized above; no socket/pointer retained.
                    unsafe { loan.commit_initialized(n) };
                    at += n;
                }
                assert_eq!(at, wire.len());
                decoder.secure_put(loan).unwrap();
                decoder.poll_owned().unwrap().unwrap()
            }
        };
        assert_eq!(&frame.segs[3][..], payload);
        assert_eq!(frame.dispatch.charge(), Some((len + 24) as u64));
        if retain_results {
            aliases.push((frame.segs[3].clone(), value));
            if aliases.len() > 2 {
                aliases.remove(0);
            }
        }
        drop(frame);
        // Caller data aliases are physical owners but must not hold logical dispatch credit.
        let proof = owner.borrow_mut().try_acquire(0).unwrap();
        drop(proof);
        assert!(decoder.poll_owned().unwrap().is_none());
    }
    check_aliases(&aliases, &original);
    drop(aliases);
    drop(original);
    let retained = core::mem::take(&mut decoder.buf);
    drop(decoder);
    let recovered: Vec<u8> = retained.into();
    assert!(
        recovered.capacity() <= 4 * r,
        "cache C={} R={r} rev={rev:?} seed={seed_kind:?} receive={receive:?} stop={stop}",
        recovered.capacity()
    );
}

#[test]
fn secure_decoder_cache_histories_bound_full_backing_and_preserve_aliases() {
    for rev in [Revision::V20, Revision::V21] {
        for seed in [
            Seed::Fresh,
            Seed::UniqueOffset,
            Seed::SharedOffset,
            Seed::UniqueZeroTail,
            Seed::SharedZeroTail,
        ] {
            for receive in [Receive::Fallback, Receive::Loan] {
                for retain in [false, true] {
                    for stop in [1, 2, 3, 5, 9, 17] {
                        history(rev, seed, receive, retain, stop, false);
                    }
                }
            }
        }
    }
}

#[test]
fn secure_reserved_loan_histories_bound_full_backing_after_decoder_retirement() {
    for rev in [Revision::V20, Revision::V21] {
        for seed in [
            Seed::Fresh,
            Seed::UniqueOffset,
            Seed::SharedOffset,
            Seed::UniqueZeroTail,
            Seed::SharedZeroTail,
        ] {
            for retain in [false, true] {
                for stop in [1, 3, 9] {
                    history(rev, seed, Receive::Loan, retain, stop, true);
                }
            }
        }
    }
}
