// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
mod common;
use common::*;
use denc::types::EntityName;
use msgr2::{auth::*, *};

#[test]
fn finalized_listing_crc_secure_partial_output_retains_owned_backing() {
    // A fully finalized count/body/trailer, compacted from a rounded builder.
    // Keep a separate expectation, not a Bytes alias in the unique-owner cases.
    let mut expected = Vec::with_capacity(512 << 10);
    expected.extend_from_slice(&1024u32.to_le_bytes());
    for i in 0..1024u32 {
        expected.extend_from_slice(&64u32.to_le_bytes());
        expected.extend_from_slice(&i.to_be_bytes());
        expected.extend_from_slice(&[b'k'; 60]);
        expected.extend_from_slice(&256u32.to_le_bytes());
        expected.extend_from_slice(&[0x5a; 256]);
    }
    expected.push(1);
    for mode in [MODE_CRC, MODE_SECURE] {
        for v20 in [false, true] {
            for retained_memo in [false, true] {
                let mut a = Node::new(
                    EntityName::CLIENT,
                    1,
                    1,
                    PolicyTable::uniform(Policy::lossy_client(0)),
                );
                let mut b = Node::new(
                    EntityName::OSD,
                    2,
                    2,
                    PolicyTable::uniform(Policy::stateless_registered_server(0)),
                );
                a.cfg.v20_only = v20;
                let secret: Vec<u8> = (0..64).collect();
                let mut c = a.dial_with(
                    &b,
                    Box::new(KeyedClient {
                        key: vec![9; 16],
                        secret: secret.clone(),
                        modes: vec![mode],
                        method: AUTH_METHOD_CEPHX,
                    }),
                    t(0),
                );
                let mut s = b.accept_with(
                    1,
                    Box::new(KeyedServer {
                        peer_name: Some(a.cfg.name),
                        key: vec![9; 16],
                        secret,
                        rounds: 0,
                        done: 0,
                        methods: vec![AUTH_METHOD_CEPHX],
                        modes: vec![mode],
                    }),
                    t(0),
                );
                exchange(&mut c, &mut s, t(1), &mut Rng(81), 4096);
                assert!(connected(&events(&mut c)).is_some());
                assert!(connected(&events(&mut s)).is_some());
                let mut rounded = Vec::with_capacity(512 << 10);
                rounded.extend_from_slice(&expected);
                let data = bytes::Bytes::from(rounded.into_boxed_slice());
                let start = data.as_ptr() as usize;
                let mut memo = retained_memo.then(|| data.clone());
                s.send_message(Message {
                    msg_type: 42,
                    tid: 73,
                    version: 1,
                    data,
                    ..Default::default()
                });
                let mut shared = 0;
                let mut turns = 0;
                while s.has_output() {
                    turns += 1;
                    assert!(turns < 1024, "bounded listing output must make progress");
                    let chunks = s.poll_output_chunks_bounded(4093);
                    assert!(!chunks.is_empty());
                    assert!(chunks.iter().map(|b| b.len()).sum::<usize>() <= 4093);
                    if let Some(memo) = memo.take() {
                        assert_eq!(
                            memo.as_ref(),
                            expected,
                            "Secure must not mutate retry plaintext"
                        );
                        drop(memo); // Transport must retain later partial chunks by itself.
                    }
                    for chunk in chunks {
                        if mode == MODE_CRC
                            && !v20
                            && (start..start + expected.len()).contains(&(chunk.as_ptr() as usize))
                        {
                            assert_eq!(chunk.as_ptr() as usize, start + shared);
                            shared += chunk.len();
                        }
                        c.on_bytes(&chunk, t(2));
                    }
                }
                if mode == MODE_CRC && !v20 {
                    assert_eq!(shared, expected.len());
                }
                let got = events(&mut c);
                let messages = msgs(&got);
                assert_eq!(messages.len(), 1);
                assert_eq!(messages[0].header.tid, 73);
                assert_eq!(messages[0].data.as_ref(), expected);
            }
        }
    }
}

#[test]
fn bounded_handshake_and_mixed_consumers_preserve_crc_secure_messages_and_sequences() {
    for mode in [MODE_CRC, MODE_SECURE] {
        for v20 in [false, true] {
            let mut a = Node::new(EntityName::OSD, 1, 1, PolicyTable::osd_cluster());
            let mut b = Node::new(EntityName::OSD, 2, 2, PolicyTable::osd_cluster());
            a.cfg.v20_only = v20;
            let key = vec![3; 16];
            let secret = (0..64u8).collect::<Vec<_>>();
            let mut c = a.dial_with(
                &b,
                Box::new(KeyedClient {
                    key: key.clone(),
                    secret: secret.clone(),
                    modes: vec![mode],
                    method: 2,
                }),
                t(0),
            );
            let mut s = b.accept_with(
                1,
                Box::new(KeyedServer {
                    peer_name: Some(a.cfg.name),
                    key,
                    secret,
                    rounds: 1,
                    done: 0,
                    methods: vec![2],
                    modes: vec![mode],
                }),
                t(0),
            );
            // Byte-size handoff includes banner/auth/secure transition.
            for _ in 0..100_000 {
                assert!(c.poll_output_bounded(0).is_empty());
                let out = c.poll_output_bounded(1);
                assert!(out.len() <= 1);
                s.on_bytes(&out, t(1));
                let back = s.poll_output_bounded(1);
                assert!(back.len() <= 1);
                c.on_bytes(&back, t(1));
                if out.is_empty() && back.is_empty() {
                    break;
                }
            }
            assert!(
                connected(&events(&mut c)).is_some(),
                "mode={mode} v20={v20}"
            );
            assert!(connected(&events(&mut s)).is_some());
            for collector in 0..4 {
                for tid in (collector * 4 + 1)..=(collector * 4 + 4) {
                    c.send_message(msg(tid, 42, 8000));
                }
                let mut iteration = 0;
                while c.has_output() {
                    iteration += 1;
                    assert!(iteration < 100_000);
                    assert!(c.poll_output_bounded(0).is_empty());
                    assert!(c.poll_output_chunks_bounded(0).is_empty());
                    let out = if iteration == 5 && collector == 0 {
                        c.poll_output_chunks().concat()
                    } else if iteration == 5 && collector == 1 {
                        c.poll_output()
                    } else if collector == 3 || iteration % 2 == 0 {
                        let limit = [1, 7, 4093][iteration % 3];
                        let chunks = c.poll_output_chunks_bounded(limit);
                        assert!(chunks.iter().map(|chunk| chunk.len()).sum::<usize>() <= limit);
                        chunks.concat()
                    } else {
                        let limit = [1, 7, 4093][iteration % 3];
                        let out = c.poll_output_bounded(limit);
                        assert!(out.len() <= limit);
                        out
                    };
                    assert!(!out.is_empty());
                    s.on_bytes(&out, t(2));
                }
            }
            let received = events(&mut s);
            assert_eq!(msgs(&received).len(), 16);
            for (index, got) in msgs(&received).into_iter().enumerate() {
                assert_eq!(got.header.tid, index as u64 + 1);
                assert_eq!(got.front.as_ref(), vec![(index + 1) as u8; 8000]);
                assert_eq!(got.data.as_ref(), vec![7; 24000]);
            }
            // ACK and a later message exercise following CRC/AEAD sequence state.
            exchange(&mut c, &mut s, t(3), &mut Rng(17), 113);
            c.send_message(msg(17, 42, 3));
            exchange(&mut c, &mut s, t(4), &mut Rng(19), 11);
            assert_eq!(msgs(&events(&mut s))[0].front.as_ref(), &[17; 3]);
        }
    }
}

#[test]
fn bounded_shared_crc_payload_slices_retain_the_original_allocation() {
    let mut a = Node::new(EntityName::OSD, 1, 1, PolicyTable::osd_cluster());
    let mut b = Node::new(EntityName::OSD, 2, 2, PolicyTable::osd_cluster());
    let mut c = a.dial(&b, t(0));
    let mut s = b.accept(1, t(0));
    exchange(&mut c, &mut s, t(1), &mut Rng(13), 4096);
    assert!(connected(&events(&mut c)).is_some());
    events(&mut s);
    let data = bytes::Bytes::from(vec![0x63; 1 << 20]);
    let start = data.as_ptr() as usize;
    c.send_message(Message {
        msg_type: 42,
        tid: 1,
        version: 1,
        data: data.clone(),
        ..Default::default()
    });
    let mut shared = 0;
    while c.has_output() {
        assert!(c.poll_output_chunks_bounded(0).is_empty());
        let chunks = c.poll_output_chunks_bounded(4093);
        assert!(chunks.iter().map(|chunk| chunk.len()).sum::<usize>() <= 4093);
        for chunk in chunks {
            let pointer = chunk.as_ptr() as usize;
            if (start..start + data.len()).contains(&pointer) {
                assert_eq!(pointer, start + shared);
                shared += chunk.len();
            }
            s.on_bytes(&chunk, t(2));
        }
    }
    assert_eq!(shared, data.len());
    assert_eq!(msgs(&events(&mut s))[0].data.as_ref(), data.as_ref());
}
