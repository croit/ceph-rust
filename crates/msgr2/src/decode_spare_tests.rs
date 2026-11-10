// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
use super::*;

fn write_spare(loan: &mut SecureRxBuffer, data: &[u8]) {
    let spare = loan.spare_capacity_mut();
    for (slot, byte) in spare.iter_mut().zip(data) {
        slot.write(*byte);
    }
    // SAFETY: every byte of the exact prefix was initialized above.
    unsafe { loan.commit_initialized(data.len()) };
}

#[test]
fn spare_prefix_safe_fallback_and_zero_commit_preserve_initialized_bounds() {
    let mut buf = bytes::BytesMut::with_capacity(128);
    buf.extend_from_slice(b"head");
    let mut loan = SecureRxBuffer {
        buf,
        filled: 4,
        end: 100,
    };
    let pointer = loan.buf.as_ptr();
    assert_eq!(loan.spare_capacity_mut().len(), 96);
    assert_eq!(loan.buf.len(), 4);
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| loan.commit(1))).is_err());
    assert_eq!(loan.filled, 4);
    // Zero completion is valid without initialization and cannot expose spare bytes.
    unsafe { loan.commit_initialized(0) };
    assert_eq!(loan.buf.len(), 4);
    write_spare(&mut loan, b"next");
    assert_eq!(&loan.buf[..], b"headnext");
    assert_eq!(loan.buf.len(), loan.filled);
    assert!(loan.recv_buf().iter().all(|&b| b == 0));
    assert_eq!(loan.buf.as_ptr(), pointer);
    loan.recv_buf()[..3].copy_from_slice(b"saf");
    loan.commit(3);
    write_spare(&mut loan, b"tail");
    assert_eq!(&loan.buf[..], b"headnextsaftail");
    assert_eq!(loan.buf.len(), loan.filled);
    assert_eq!(loan.buf.as_ptr(), pointer);
}

#[test]
fn overlarge_commits_reject_before_mutating_initialized_prefix() {
    let mut buf = bytes::BytesMut::with_capacity(128);
    buf.resize(128, 0x5a);
    let mut loan = SecureRxBuffer {
        buf,
        filled: 4,
        end: 100,
    };
    let before = loan.buf.clone();
    // All 97 bytes exist and are initialized. Only the logical frame boundary
    // is violated, so this tests validation without violating initialization.
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
            loan.commit_initialized(97)
        }))
        .is_err()
    );
    assert_eq!(loan.filled, 4);
    assert_eq!(loan.buf, before);
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| loan.commit(97))).is_err());
    assert_eq!(loan.filled, 4);
    assert_eq!(loan.buf, before);
}

#[test]
fn decoder_spare_growth_retained_frames_and_following_safe_input_authenticate() {
    for rev in [Revision::V20, Revision::V21] {
        let secret = crate::ConnSecret::new(&(0..64u8).collect::<Vec<_>>()).unwrap();
        let mut encoder = crate::Encoder::new(rev);
        encoder.set_secure(&secret, crate::Role::Client).unwrap();
        let mut decoder = Decoder::new(rev);
        decoder.set_secure(&secret, crate::Role::Server).unwrap();
        let mut held = Vec::new();
        for (index, size) in [32_771, 1_048_579, 4999, 65_539].into_iter().enumerate() {
            let expected = vec![index as u8 + 1; size];
            let mut wire = Vec::new();
            encoder
                .encode_message(&[9; 41], &[8; 19], &[], &expected, &mut wire)
                .unwrap();
            let prefix = 199;
            decoder.feed(&wire[..prefix]);
            assert!(decoder.poll_owned().unwrap().is_none());
            let mut loan = decoder.secure_take().unwrap();
            assert_eq!(loan.buf.len(), prefix);
            assert_eq!(loan.filled, prefix);
            assert!(loan.buf.capacity() >= loan.end);
            assert_eq!(
                decoder.initialized.unwrap().1 - decoder.initialized.unwrap().0,
                prefix
            );
            let identity = loan.buf.as_ptr();
            for (i, chunk) in wire[prefix..].chunks(4001).enumerate() {
                if i % 2 == 0 {
                    write_spare(&mut loan, chunk);
                } else {
                    loan.recv_buf()[..chunk.len()].copy_from_slice(chunk);
                    loan.commit(chunk.len());
                }
                assert_eq!(loan.buf.as_ptr(), identity);
            }
            decoder.secure_put(loan).unwrap();
            let frame = decoder.poll_owned().unwrap().unwrap();
            assert_eq!(frame.segs[3].as_ref(), expected);
            held.push((frame, expected));
            // Safe fallback after an owned split must not trust fresh spare as initialized.
            let mut control = Vec::new();
            encoder
                .encode_message(&[7; 41], &[], &[], &[6; 127], &mut control)
                .unwrap();
            decoder.feed(&control);
            let control = decoder.poll_owned().unwrap().unwrap();
            assert_eq!(control.segs[3].as_ref(), &[6; 127]);
            for (frame, expected) in &held {
                assert_eq!(frame.segs[3].as_ref(), expected);
            }
        }
    }
}
