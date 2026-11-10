// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
use super::*;

fn ready(rev: Revision, secure: bool, lossy: bool) -> Connection {
    let policy = if lossy {
        Policy::lossy_client(0)
    } else {
        Policy::lossless_client(0)
    };
    let cfg = Config::new(
        EntityName::new(EntityName::CLIENT, 1),
        EntityAddrVec::single(EntityAddr::blank()),
        PolicyTable::uniform(policy),
    );
    let table = SessionTable::new(1);
    let mut session = Session::new(
        SessionKey::Anon(1),
        policy,
        EntityAddrVec::single(EntityAddr::blank()),
    );
    session.active = Some(1);
    session.state = SessState::Ready;
    let sid = table.insert(session);
    let mut c = Connection::base(
        1,
        Role::Client,
        cfg,
        table,
        EntityAddr::blank(),
        EntityName::OSD,
        policy,
    );
    c.sid = Some(sid);
    c.st = St::Ready;
    c.enc = Encoder::new(rev);
    c.enter_mode(if secure { MODE_SECURE } else { MODE_CRC }, &[7; 64])
        .unwrap();
    c
}
fn message(tid: u64) -> Message {
    Message {
        tid,
        msg_type: 42,
        data: Bytes::from(vec![tid as u8; 8193]),
        ..Default::default()
    }
}
fn take(c: &mut Connection, maximum: usize, shared: bool) -> Vec<u8> {
    if shared {
        c.poll_output_chunks_bounded(maximum).concat()
    } else {
        c.poll_output_bounded(maximum)
    }
}
fn decoder(rev: Revision, secure: bool) -> Decoder {
    let mut d = Decoder::new(rev);
    if secure {
        d.set_secure(&ConnSecret::new(&[7; 64]).unwrap(), Role::Server)
            .unwrap();
    }
    d
}

#[test]
fn bounded_preparation_and_mixed_drains_are_byte_exact_with_one_frame_overshoot() {
    for rev in [Revision::V20, Revision::V21] {
        for secure in [false, true] {
            for shared in [false, true] {
                for lossy in [false, true] {
                    let mut c = ready(rev, secure, lossy);
                    let mut reference = ready(rev, secure, lossy);
                    for tid in 1..=4 {
                        c.send_message(message(tid));
                        reference.send_message(message(tid));
                    }
                    let expected = reference.poll_output();
                    assert!(take(&mut c, 0, shared).is_empty());
                    assert_eq!(c.sess(|s| s.out_seq), Some(0));
                    let mut wire = take(&mut c, 1, shared);
                    assert_eq!(wire.len(), 1);
                    assert_eq!(c.sess(|s| s.unsent()), Some(3));
                    assert_eq!(c.sess(|s| s.out_seq), Some(1));
                    wire.extend(take(&mut c, usize::MAX, shared)); // Drain only existing frame.
                    assert_eq!(c.sess(|s| s.unsent()), Some(3));
                    let frame_len = wire.len();
                    let next = take(&mut c, frame_len + 1, shared);
                    assert_eq!(next.len(), frame_len + 1);
                    assert_eq!(c.sess(|s| s.unsent()), Some(1)); // Whole second frame overshoots.
                    wire.extend(next);
                    wire.extend(c.poll_output_chunks().concat()); // Unbounded still eager.
                    assert_eq!(
                        wire, expected,
                        "rev={rev:?} secure={secure} shared={shared} lossy={lossy}"
                    );
                    assert_eq!(c.sess(|s| s.unsent()), Some(0));
                }
            }
        }
    }
}

#[test]
fn bounded_selection_preserves_priority_fifo_and_lossless_replay_sequences() {
    let mut c = ready(Revision::V21, false, false);
    for (tid, priority) in [(1, 5), (2, 20), (3, 10)] {
        let mut m = message(tid);
        m.priority = priority;
        c.send_message(m);
    }
    let mut wire = take(&mut c, 1, true);
    assert_eq!(c.sess(|s| s.unacked()), Some(1));
    let mut high = message(4);
    high.priority = 30;
    c.send_message(high);
    wire.extend(take(&mut c, usize::MAX, false));
    assert_eq!(c.sess(|s| s.unsent()), Some(3));
    wire.extend(c.poll_output());
    let mut d = decoder(Revision::V21, false);
    d.feed(&wire);
    let mut received = Vec::new();
    while let Some(frame) = d.poll_owned().unwrap() {
        let header = MsgHeader2::from_bytes(&frame.segs[0]).unwrap();
        received.push((header.tid, header.seq));
    }
    assert_eq!(received, [(2, 1), (4, 2), (3, 3), (1, 4)]);
    c.sess(|s| s.requeue_for_replay());
    let mut replay = take(&mut c, 1, true);
    assert_eq!(c.sess(|s| s.out_seq), Some(4));
    replay.extend(c.poll_output());
    assert_eq!(replay, wire);
}

#[test]
fn queued_messages_piggyback_ack_before_standalone_ack_and_keep_gcm_sequence() {
    for secure in [false, true] {
        let mut c = ready(Revision::V21, secure, false);
        c.sess(|s| s.in_seq = 1);
        c.send_message(message(1));
        c.send_message(message(2));
        let mut wire = take(&mut c, 1, true);
        wire.extend(take(&mut c, usize::MAX, true));
        c.sess(|s| s.in_seq = 2);
        wire.extend(take(&mut c, 1, false));
        wire.extend(take(&mut c, usize::MAX, false));
        c.sess(|s| s.in_seq = 3);
        wire.extend(take(&mut c, 1, true));
        wire.extend(take(&mut c, usize::MAX, true));
        let mut d = decoder(Revision::V21, secure);
        d.feed(&wire);
        for ack in [1, 2] {
            let frame = d.poll_owned().unwrap().unwrap();
            assert_eq!(frame.tag, Tag::Message as u8);
            assert_eq!(MsgHeader2::from_bytes(&frame.segs[0]).unwrap().ack_seq, ack);
        }
        assert_eq!(d.poll_owned().unwrap().unwrap().tag, Tag::Ack as u8);
        assert!(d.poll_owned().unwrap().is_none());
    }
}

#[test]
fn superseded_owner_drops_already_encoded_wire_before_either_bounded_drain() {
    for shared in [false, true] {
        let mut c = ready(Revision::V21, false, false);
        c.send_keepalive(Duration::ZERO);
        assert!(!c.out.is_empty());
        c.sess(|s| s.active = Some(99));
        assert!(take(&mut c, 128, shared).is_empty());
        assert_eq!(c.st, St::Closed);
        assert!(c.out.is_empty() && c.out_chunks.is_empty());
    }
}

#[test]
fn bounded_notification_consumers_drain_controls_and_deferred_messages_without_rx() {
    for shared in [false, true] {
        let mut c = ready(Revision::V21, false, true);
        let queue = crate::OutputQueue::default();
        c.set_output_queue(&queue, 1);
        c.send_keepalive(Duration::ZERO);
        c.send_message(message(1));
        c.send_message(message(2));
        let mut wire = Vec::new();
        let mut visits = 0;
        while let Some(id) = queue.pop() {
            assert_eq!(id, 1);
            visits += 1;
            assert!(visits < 1000);
            wire.extend(take(&mut c, 113, shared));
        }
        assert!(!c.has_output());
        let mut d = decoder(Revision::V21, false);
        d.feed(&wire);
        let mut tids = Vec::new();
        while let Some(frame) = d.poll_owned().unwrap() {
            if frame.tag == Tag::Message as u8 {
                tids.push(MsgHeader2::from_bytes(&frame.segs[0]).unwrap().tid);
            }
        }
        assert_eq!(tids, [1, 2]);
    }
}

#[test]
fn queue_admission_counts_unsent_and_unacknowledged_without_retiring_replacement_carriers() {
    let mut c = ready(Revision::V21, false, false);
    c.retirement_receipt = c.retirement();
    assert_eq!(c.queued_messages(), 0);
    c.send_message(message(1));
    assert_eq!(c.queued_messages(), 1);
    assert!(!c.poll_output_chunks().is_empty());
    assert_eq!(c.queued_messages(), 1);
    c.send_message(message(2));
    assert_eq!(c.queued_messages(), 2);
    c.sess(|s| s.trim_sent(1));
    assert_eq!(c.queued_messages(), 1);
    c.sess(|s| s.dialer = Some(99));
    assert!(!c.dispose_session());
    assert_eq!(c.queued_messages(), 1);
    assert_eq!(c.table.len(), 1);
    c.sess(|s| {
        s.dialer = None;
        s.active = Some(99)
    });
    assert!(!c.dispose_session());
    assert_eq!(c.table.len(), 1);
    c.sess(|s| {
        s.active = None;
        s.state = SessState::Standby
    });
    c.st = St::Closed;
    assert!(c.dispose_session());
    assert!(c.table.is_empty());
    assert_eq!(c.queued_messages(), 0);
    assert_eq!(c.state(), ConnState::Closed);
    assert!(!c.dispose_session());
}

#[test]
fn retirement_receipt_rejects_a_newer_incarnation_even_after_its_socket_closes() {
    let c = ready(Revision::V21, false, false);
    let receipt = c.retirement().unwrap();
    c.sess(|s| {
        s.connect_seq += 1;
        s.active = None;
        s.dialer = None;
    });
    assert!(!receipt.is_current());
    assert!(!receipt.dispose());
    assert_eq!(c.table.len(), 1);
}

#[test]
fn write_receipts_follow_exact_final_wire_byte_in_crc_secure_and_partial_drains() {
    for revision in [Revision::V20, Revision::V21] {
        for secure in [false, true] {
            for lossy in [false, true] {
                for shared in [false, true] {
                    let mut c = ready(revision, secure, lossy);
                    assert!(c.configure_write_receipts(2));
                    let mut low = message(1);
                    low.priority = 1;
                    let low = c.send_message_tracked(low).unwrap();
                    let mut high = message(2);
                    high.priority = 20;
                    let high = c.send_message_tracked(high).unwrap();
                    let retained = c.send_message_tracked(message(3)).unwrap_err();
                    assert!(matches!(retained, crate::SendError::Temporary(_)));
                    let retained = retained.into_message();
                    assert_eq!(retained.tid, 3);
                    assert_eq!(high.status(), crate::WriteStatus::Pending);
                    assert_eq!(take(&mut c, 1, shared).len(), 1);
                    assert!(c.acknowledge_output(1));
                    assert_eq!(high.status(), crate::WriteStatus::Pending);
                    let rest = take(&mut c, usize::MAX, shared);
                    assert_eq!(high.status(), crate::WriteStatus::Pending);
                    assert!(c.acknowledge_output(rest.len() - 1));
                    assert_eq!(high.status(), crate::WriteStatus::Pending);
                    assert_eq!(low.status(), crate::WriteStatus::Pending);
                    assert!(c.acknowledge_output(1));
                    assert_eq!(high.status(), crate::WriteStatus::Written);
                    assert_eq!(low.status(), crate::WriteStatus::Pending);
                    assert!(!c.acknowledge_output(1));
                    let wire = c.poll_output_chunks();
                    assert_eq!(low.status(), crate::WriteStatus::Pending);
                    assert!(c.acknowledge_output(wire.iter().map(Bytes::len).sum()));
                    assert_eq!(low.status(), crate::WriteStatus::Written);
                    if !lossy {
                        assert_eq!(c.queued_messages(), 2);
                    }
                    // Peer ACK is independent of socket acceptance.
                    drop(high);
                    let next = c.send_message_tracked(retained).unwrap();
                    assert_eq!(next.status(), crate::WriteStatus::Pending);
                    let wire = c.poll_output();
                    assert!(c.acknowledge_output(wire.len()));
                    assert_eq!(next.status(), crate::WriteStatus::Written);
                }
            }
        }
    }
}

/// A message beyond the frame limits is refused at admission like `send_message` (the pump never meets it): the
/// caller gets it back and the receipt slot stays free.
#[test]
fn tracked_message_beyond_the_frame_limits_is_refused_and_keeps_its_slot() {
    let mut c = ready(Revision::V21, false, false);
    assert!(c.configure_write_receipts(1));
    c.cfg.limits.max_segment = 4096;
    let refused = c.send_message_tracked(message(1)).unwrap_err();
    assert!(matches!(refused, crate::SendError::FrameLimit(_)));
    let refused = refused.into_message();
    assert_eq!(refused.tid, 1);
    assert_eq!(c.queued_messages(), 0);
    let mut small = message(2);
    small.data = Bytes::from(vec![2; 64]);
    let receipt = c.send_message_tracked(small).unwrap();
    let wire = c.poll_output();
    assert!(c.acknowledge_output(wire.len()));
    assert_eq!(receipt.status(), crate::WriteStatus::Written);
}

/// An encode failure in the pump fails that message alone on lossless and lossy sessions (it is never resent, its
/// seq is skipped): its receipt is discarded and nothing stays queued for it.
#[test]
fn encode_failure_discards_the_receipt_on_lossless_and_lossy_sessions() {
    for lossy in [false, true] {
        let mut c = ready(Revision::V21, false, lossy);
        assert!(c.configure_write_receipts(1));
        let receipt = c.send_message_tracked(message(1)).unwrap();
        // limits shrink after admission (encoder only): the pump's encode fails and faults the connection
        c.enc.set_limits(Limits {
            max_segment: 4096,
            ..c.cfg.limits
        });
        assert!(c.poll_output().is_empty(), "lossy={lossy}");
        assert_eq!(
            receipt.status(),
            crate::WriteStatus::Discarded,
            "lossy={lossy}"
        );
        assert_eq!(c.queued_messages(), 0, "lossy={lossy}: not kept for resend");
    }
}

#[test]
fn write_receipt_replay_cannot_complete_a_reused_slot_and_reset_discards_pending() {
    let mut c = ready(Revision::V21, false, false);
    assert!(c.configure_write_receipts(1));
    let first = c.send_message_tracked(message(1)).unwrap();
    let wire = c.poll_output();
    assert!(c.acknowledge_output(wire.len()));
    assert_eq!(first.status(), crate::WriteStatus::Written);
    drop(first);
    let second = c.send_message_tracked(message(2)).unwrap();
    c.sess(|s| s.requeue_for_replay());
    let prefix = c.poll_output_chunks_bounded(1);
    let suffix = c.poll_output_chunks_bounded(usize::MAX);
    assert!(c.acknowledge_output(prefix.iter().chain(&suffix).map(Bytes::len).sum()));
    assert_eq!(second.status(), crate::WriteStatus::Pending);
    let wire = c.poll_output();
    assert!(c.acknowledge_output(wire.len()));
    assert_eq!(second.status(), crate::WriteStatus::Written);
    drop(second);
    let discarded = c.send_message_tracked(message(3)).unwrap();
    c.sess(|s| s.reset_all(false));
    assert_eq!(discarded.status(), crate::WriteStatus::Discarded);
}

#[test]
fn unwritten_receipt_survives_a_lossless_replacement_carrier() {
    for secure in [false, true] {
        let mut old = ready(Revision::V21, secure, false);
        assert!(old.configure_write_receipts(1));
        let receipt = old.send_message_tracked(message(1)).unwrap();
        assert_eq!(old.poll_output_bounded(1).len(), 1);
        assert!(old.acknowledge_output(1));
        old.reset_transport();
        old.sess(|s| {
            s.requeue_for_replay();
            s.active = Some(2);
        });
        let mut next = ready(Revision::V21, secure, false);
        next.table = old.table.clone();
        next.sid = old.sid;
        next.id = 2;
        assert!(next.configure_write_receipts(1));
        assert_eq!(receipt.status(), crate::WriteStatus::Pending);
        let wire = next.poll_output_chunks();
        assert!(next.acknowledge_output(wire.iter().map(Bytes::len).sum()));
        assert_eq!(receipt.status(), crate::WriteStatus::Written);
        drop(receipt);
        let discarded = next.send_message_tracked(message(2)).unwrap();
        drop(next.table.remove(next.sid.unwrap()));
        assert_eq!(discarded.status(), crate::WriteStatus::Discarded);
    }
}

#[test]
fn never_sent_carried_message_keeps_its_receipt_when_the_old_session_is_removed() {
    let mut old = ready(Revision::V21, false, false);
    assert!(old.configure_write_receipts(1));
    let receipt = old.send_message_tracked(message(1)).unwrap();
    let (queued, pool) = old
        .sess(|s| (s.take_unsent_tracked(), s.carry_writes()))
        .unwrap();
    drop(old.table.remove(old.sid.unwrap()));
    assert_eq!(receipt.status(), crate::WriteStatus::Pending);
    let mut next = ready(Revision::V21, false, false);
    next.sess(|s| {
        s.writes = pool;
        for q in queued {
            s.queue_carried(q);
        }
    });
    assert!(next.configure_write_receipts(1));
    let wire = next.poll_output();
    assert!(next.acknowledge_output(wire.len()));
    assert_eq!(receipt.status(), crate::WriteStatus::Written);
}

#[test]
fn peer_ack_completes_receipt_after_transport_reset_and_replay_queue() {
    for replay in [false, true] {
        let mut c = ready(Revision::V21, false, false);
        assert!(c.configure_write_receipts(1));
        let receipt = c.send_message_tracked(message(1)).unwrap();
        let _wire = c.poll_output();
        c.reset_transport();
        c.sess(|s| {
            if replay {
                s.requeue_for_replay();
            }
            s.trim_sent(1);
        });
        assert_eq!(receipt.status(), crate::WriteStatus::Written);
        assert_eq!(c.queued_messages(), 0);
    }
}

#[test]
fn unconfigured_connection_never_accounts_exported_output() {
    for revision in [Revision::V20, Revision::V21] {
        for secure in [false, true] {
            let mut plain = ready(revision, secure, false);
            let mut tracked = ready(revision, secure, false);
            assert!(tracked.configure_write_receipts(1));
            assert!(plain.send_message(message(1)));
            let receipt = tracked.send_message_tracked(message(1)).unwrap();
            let wire = plain.poll_output();
            assert!(!wire.is_empty());
            assert_eq!(wire, tracked.poll_output());
            assert_eq!(plain.output_exported, 0);
            assert_eq!(plain.write_ends.capacity(), 0);
            assert!(tracked.acknowledge_output(wire.len()));
            assert_eq!(receipt.status(), crate::WriteStatus::Written);
        }
    }
}

#[test]
fn unwritten_bound_falls_on_write_while_unacked_waits_for_the_peer_ack() {
    let mut c = ready(Revision::V21, false, false);
    c.send_message(message(1));
    c.send_message(message(2));
    assert_eq!((c.unwritten_messages(), c.unacked_messages()), (2, 0));
    while !c.poll_output_chunks().is_empty() {}
    // Written but unacknowledged: a paused reader never sees the ACK, so an
    // admission bound on unwritten messages must not count these.
    assert_eq!((c.unwritten_messages(), c.unacked_messages()), (0, 2));
    assert_eq!(c.queued_messages(), 2);
    c.sess(|s| s.trim_sent(2));
    assert_eq!((c.unwritten_messages(), c.unacked_messages()), (0, 0));
}
