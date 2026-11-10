// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! One output poll hands a transport every frame queued on the link (and an owed ACK), in wire order, in crc and
//! secure mode: the driver's single vectored write per link and turn rests on it.
mod common;
use common::*;
use denc::types::EntityName;
use msgr2::{auth::*, *};

fn linked(mode: u32) -> (Connection, Connection) {
    let mut a = Node::new(EntityName::OSD, 1, 1, PolicyTable::osd_cluster());
    let mut b = Node::new(EntityName::OSD, 2, 2, PolicyTable::osd_cluster());
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
    exchange(&mut c, &mut s, t(1), &mut Rng(5), 1 << 16);
    assert!(connected(&events(&mut c)).is_some(), "mode={mode}");
    assert!(connected(&events(&mut s)).is_some());
    (c, s)
}

#[test]
fn every_queued_frame_and_the_owed_ack_leave_in_one_output_poll() {
    for mode in [MODE_CRC, MODE_SECURE] {
        for size in [64, 8000] {
            let (mut c, mut s) = linked(mode);
            // The server owes an ACK for the first batch and answers in the same turn: the reply carries it.
            for tid in 1..=12 {
                c.send_message(msg(tid, 42, size));
            }
            let wire = c.poll_output_chunks_bounded(usize::MAX);
            assert!(!wire.is_empty());
            assert!(!c.has_output(), "one poll drained all 12 frames");
            assert!(c.poll_output_chunks_bounded(usize::MAX).is_empty());
            for chunk in &wire {
                s.on_bytes(chunk, t(2));
            }
            let got = events(&mut s);
            assert_eq!(msgs(&got).len(), 12, "mode={mode} size={size}");
            for (i, m) in msgs(&got).into_iter().enumerate() {
                assert_eq!(m.header.tid, i as u64 + 1, "wire order");
            }
            s.send_message(msg(100, 43, size));
            let back = s.poll_output_chunks_bounded(usize::MAX);
            assert!(!back.is_empty());
            assert!(!s.has_output(), "reply and ACK left together");
            for chunk in &back {
                c.on_bytes(chunk, t(3));
            }
            assert_eq!(msgs(&events(&mut c)).len(), 1);
            // The reply acknowledged the whole batch in its header: the server owes nothing more.
            assert!(!s.has_output());
        }
    }
}
