// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
use bytes::Bytes;
use msgr2::{ConnSecret, Decoder, Encoder, Revision, Role};
use std::time::Instant;

fn secret() -> ConnSecret {
    ConnSecret::new(&[7; 64]).unwrap()
}

#[test]
fn shared_secure_subviews_preserve_exact_wire_and_existing_output_for_both_revisions() {
    for revision in [Revision::V20, Revision::V21] {
        for header_len in [0, 48, 49, 65] {
            for data_len in [8192, 8193, 8207, 8208] {
                let header = vec![1; header_len];
                let front = vec![2; 17];
                let middle = vec![3; 7];
                let source: Vec<_> = (0..data_len + 9).map(|n| (n * 31) as u8).collect();
                let owner = Bytes::from(source.clone());
                let data = owner.slice(3..data_len + 3);
                let mut reference = Encoder::new(revision);
                reference.set_secure(&secret(), Role::Client).unwrap();
                let mut expected = b"existing\x04\x05".to_vec();
                reference
                    .encode_message(&header, &front, &middle, &data, &mut expected)
                    .unwrap();
                let mut encoder = Encoder::new(revision);
                encoder.set_secure(&secret(), Role::Client).unwrap();
                let mut out = vec![4, 5];
                let mut chunks = vec![Bytes::from_static(b"existing")];
                encoder
                    .encode_message_owned(&header, front, middle, data, &mut out, &mut chunks)
                    .unwrap();
                let mut actual: Vec<_> = chunks
                    .iter()
                    .flat_map(|part| part.iter().copied())
                    .collect();
                actual.extend_from_slice(&out);
                assert_eq!(actual, expected);
                assert_eq!(owner.as_ref(), source);
            }
        }
    }
}

#[test]
fn authenticated_rx_keeps_the_received_payload_allocation() {
    let mut enc = Encoder::new(Revision::V21);
    enc.set_secure(&secret(), Role::Client).unwrap();
    let data = vec![0x6a; 1 << 20];
    let mut wire = Vec::new();
    enc.encode_message(&[1; 41], &[2; 17], &[3; 7], &data, &mut wire)
        .unwrap();
    let mut dec = Decoder::new(Revision::V21);
    dec.set_secure(&secret(), Role::Server).unwrap();
    let dst = dec.recv_buf(wire.len());
    let low = dst.as_ptr() as usize;
    let high = low + dst.len();
    dst[..wire.len()].copy_from_slice(&wire);
    dec.commit(wire.len());
    let frame = dec.poll_owned().unwrap().unwrap();
    assert_eq!(frame.segs[3].as_ref(), data);
    let p = frame.segs[3].as_ptr() as usize;
    assert!(
        p >= low && p + data.len() <= high,
        "authenticated RX copied the full payload"
    );
}

#[test]
fn owned_tx_is_byte_exact_and_does_not_mutate_shared_payloads() {
    for header_len in [0, 1, 48, 49, 64, 65, 130] {
        for front_len in [0, 1, 15, 16, 17] {
            for middle_len in [0, 7, 16, 17] {
                for extra in [0, 1, 15, 16] {
                    let header = vec![1; header_len];
                    let front = vec![2; front_len];
                    let middle = vec![3; middle_len];
                    let plaintext = vec![0x6a; 8192 + extra];
                    let mut reference = Encoder::new(Revision::V21);
                    reference.set_secure(&secret(), Role::Client).unwrap();
                    let mut expected = Vec::new();
                    reference
                        .encode_message(&header, &front, &middle, &plaintext, &mut expected)
                        .unwrap();
                    for shared in [false, true] {
                        let data = Bytes::from(plaintext.clone());
                        let ptr = data.as_ptr();
                        let held = shared.then(|| data.clone());
                        let mut enc = Encoder::new(Revision::V21);
                        enc.set_secure(&secret(), Role::Client).unwrap();
                        let mut out = Vec::new();
                        let mut chunks = Vec::new();
                        enc.encode_message_owned(
                            &header,
                            front.clone(),
                            middle.clone(),
                            data,
                            &mut out,
                            &mut chunks,
                        )
                        .unwrap();
                        if !shared {
                            assert!(
                                chunks
                                    .iter()
                                    .any(|b| b.len() == plaintext.len() && b.as_ptr() == ptr)
                            );
                        }
                        if let Some(held) = held {
                            assert_eq!(held.as_ref(), plaintext);
                        }
                        let mut actual: Vec<u8> =
                            chunks.iter().flat_map(|b| b.iter().copied()).collect();
                        actual.extend_from_slice(&out);
                        assert_eq!(actual, expected);
                    }
                }
            }
        }
    }
}

#[test]
fn authenticated_owned_frames_survive_growth_and_later_auth_failure() {
    for rev in [Revision::V20, Revision::V21] {
        let mut enc = Encoder::new(rev);
        enc.set_secure(&secret(), Role::Client).unwrap();
        let mut wire = Vec::new();
        for value in [7, 8] {
            enc.encode_message(
                &[1; 41],
                &[2; 17],
                &[3; 7],
                &vec![value; 1 << 20],
                &mut wire,
            )
            .unwrap();
        }
        let mut bad = Vec::new();
        enc.encode_message(&[1; 41], &[2; 17], &[3; 7], &vec![9; 1 << 20], &mut bad)
            .unwrap();
        *bad.last_mut().unwrap() ^= 1;
        let mut dec = Decoder::new(rev);
        dec.set_secure(&secret(), Role::Server).unwrap();
        dec.feed(&wire);
        let first = dec.poll_owned().unwrap().unwrap();
        dec.feed(&bad); // force receive growth while the first allocation is retained
        let second = dec.poll_owned().unwrap().unwrap();
        assert!(dec.poll_owned().is_err());
        assert!(first.segs[3].iter().all(|&b| b == 7));
        assert!(second.segs[3].iter().all(|&b| b == 8));
        assert!(dec.poll_owned().is_err());
    }
}

#[test]
fn a_small_secure_frame_does_not_pin_a_large_split_receive_allocation() {
    let mut enc = Encoder::new(Revision::V21);
    enc.set_secure(&secret(), Role::Client).unwrap();
    let mut wire = Vec::new();
    enc.encode_message(&[1; 41], &[2; 17], &[3; 7], &vec![7; 128 << 10], &mut wire)
        .unwrap();
    enc.encode_message(&[1; 41], &[2; 17], &[3; 7], &vec![8; 8192], &mut wire)
        .unwrap();
    let mut dec = Decoder::new(Revision::V21);
    dec.set_secure(&secret(), Role::Server).unwrap();
    let dst = dec.recv_buf(wire.len());
    let low = dst.as_ptr() as usize;
    let high = low + dst.len();
    dst[..wire.len()].copy_from_slice(&wire);
    dec.commit(wire.len());
    let first = dec.poll_owned().unwrap().unwrap();
    let second = dec.poll_owned().unwrap().unwrap();
    let ptr = second.segs[3].as_ptr() as usize;
    assert!(
        !(low..high).contains(&ptr),
        "small frame retained the original large backing after a split"
    );
    assert!(first.segs[3].iter().all(|&b| b == 7));
    assert!(second.segs[3].iter().all(|&b| b == 8));
}

#[test]
fn owned_front_and_middle_only_frames_preserve_legacy_wire_bytes() {
    for rev in [Revision::V20, Revision::V21] {
        for middle_only in [false, true] {
            let payload = vec![7; 8193];
            let (front, middle) = if middle_only {
                (Vec::new(), payload)
            } else {
                (payload, Vec::new())
            };
            let ptr = if middle_only {
                middle.as_ptr()
            } else {
                front.as_ptr()
            };
            let mut old = Encoder::new(rev);
            old.set_secure(&secret(), Role::Client).unwrap();
            let mut expected = Vec::new();
            old.encode_message(&[1; 41], &front, &middle, &[], &mut expected)
                .unwrap();
            let mut owned = Encoder::new(rev);
            owned.set_secure(&secret(), Role::Client).unwrap();
            let mut out = Vec::new();
            let mut chunks = Vec::new();
            owned
                .encode_message_owned(&[1; 41], front, middle, Bytes::new(), &mut out, &mut chunks)
                .unwrap();
            assert!(chunks.iter().any(|b| b.as_ptr() == ptr && b.len() == 8193));
            let mut actual: Vec<u8> = chunks.iter().flat_map(|b| b.iter().copied()).collect();
            actual.extend_from_slice(&out);
            assert_eq!(actual, expected);
        }
    }
}

#[test]
fn owned_frames_mix_with_borrowed_frames_without_changing_nonces_or_legacy_modes() {
    for rev in [Revision::V20, Revision::V21] {
        for secure in [false, true] {
            let mut old = Encoder::new(rev);
            let mut owned = Encoder::new(rev);
            if secure {
                old.set_secure(&secret(), Role::Client).unwrap();
                owned.set_secure(&secret(), Role::Client).unwrap();
            }
            let mut expected = Vec::new();
            let mut out = Vec::new();
            let mut chunks = Vec::new();
            for i in 0..5u8 {
                let bytes = vec![i; 8193];
                old.encode_message(&[1; 41], &[2; 17], &[3; 7], &bytes, &mut expected)
                    .unwrap();
                if i & 1 == 0 {
                    owned
                        .encode_message_owned(
                            &[1; 41],
                            vec![2; 17],
                            vec![3; 7],
                            Bytes::from(bytes),
                            &mut out,
                            &mut chunks,
                        )
                        .unwrap();
                } else {
                    owned
                        .encode_message(&[1; 41], &[2; 17], &[3; 7], &bytes, &mut out)
                        .unwrap();
                }
            }
            let mut actual: Vec<u8> = chunks.iter().flat_map(|b| b.iter().copied()).collect();
            actual.extend_from_slice(&out);
            assert_eq!(actual, expected);
        }
    }
}

#[test]
fn released_receive_storage_is_reclaimed_without_zeroing_its_initialized_payload() {
    let mut enc = Encoder::new(Revision::V21);
    enc.set_secure(&secret(), Role::Client).unwrap();
    let mut wire = Vec::new();
    enc.encode_message(&[1; 41], &[2; 17], &[3; 7], &vec![7; 1 << 20], &mut wire)
        .unwrap();
    let mut dec = Decoder::new(Revision::V21);
    dec.set_secure(&secret(), Role::Server).unwrap();
    let dst = dec.recv_buf(wire.len());
    let base = dst.as_ptr() as usize;
    dst[..wire.len()].copy_from_slice(&wire);
    dec.commit(wire.len());
    let frame = dec.poll_owned().unwrap().unwrap();
    let offset = frame.segs[3].as_ptr() as usize - base;
    drop(frame);
    let dst = dec.recv_buf(wire.len());
    assert_eq!(dst.as_ptr() as usize, base);
    assert_eq!(
        dst[offset], 7,
        "reclaimed initialized payload was needlessly zeroed"
    );
    dec.commit(0);
    assert!(dec.poll_owned().unwrap().is_none());
}

#[test]
#[ignore = "local secure frame copy benchmark"]
fn perf_secure_payload() {
    for len in [1 << 20, 4 << 20] {
        let mut tx_ns = 0;
        let mut rx_ns = 0;
        let iterations = 16;
        for _ in 0..iterations {
            let data = Bytes::from(vec![0x6a; len]);
            let mut enc = Encoder::new(Revision::V21);
            enc.set_secure(&secret(), Role::Client).unwrap();
            let mut out = Vec::with_capacity(len + 256);
            let mut chunks = Vec::with_capacity(4);
            let start = Instant::now();
            enc.encode_message_owned(
                &[1; 41],
                vec![2; 17],
                vec![3; 7],
                data,
                &mut out,
                &mut chunks,
            )
            .unwrap();
            tx_ns += start.elapsed().as_nanos();
            let mut wire: Vec<u8> = chunks.iter().flat_map(|b| b.iter().copied()).collect();
            wire.extend_from_slice(&out);
            let mut dec = Decoder::new(Revision::V21);
            dec.set_secure(&secret(), Role::Server).unwrap();
            dec.feed(&wire);
            let start = Instant::now();
            let frame = dec.poll_owned().unwrap().unwrap();
            rx_ns += start.elapsed().as_nanos();
            assert_eq!(frame.segs[3].len(), len);
            assert!(frame.segs[3].iter().all(|&b| b == 0x6a));
        }
        println!(
            "secure len={len} tx_ns={} rx_ns={}",
            tx_ns / iterations,
            rx_ns / iterations
        );
    }
}
