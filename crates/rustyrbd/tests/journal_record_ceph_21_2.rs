// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Golden journal records emitted by the Ceph 21.2.0 reference dencoder, and
//! the streaming player rules of `doc/spec/rustyrbd/ffi-journal-io.md`
//! (journaling S3) over hand-built stock-format records.

use rustyrbd::{decode_journal_record, encode_journal_record};

#[test]
fn reference_records_match_encoded_bytes_and_crc() {
    let vectors: &[(u64, u64, &[u8], &[u8])] = &[
        (
            123,
            1,
            b"",
            include_bytes!("../../../testdata/rustyrbd/journal-entry-21.2.0/1.bin"),
        ),
        (
            123,
            2,
            b"data",
            include_bytes!("../../../testdata/rustyrbd/journal-entry-21.2.0/2.bin"),
        ),
    ];
    let mut output = Vec::new();
    for (entry, tag, data, expected) in vectors {
        encode_journal_record(*entry, *tag, data, &mut output).unwrap();
        assert_eq!(&output, expected);
    }
}

#[test]
fn reference_records_decode_and_reject_corruption() {
    let records: &[(u64, &[u8], &[u8])] = &[
        (
            1,
            b"",
            include_bytes!("../../../testdata/rustyrbd/journal-entry-21.2.0/1.bin"),
        ),
        (
            2,
            b"data",
            include_bytes!("../../../testdata/rustyrbd/journal-entry-21.2.0/2.bin"),
        ),
    ];
    for (tag, data, wire) in records {
        let decoded = decode_journal_record(wire).unwrap();
        assert_eq!(
            (
                decoded.entry_tid,
                decoded.tag_tid,
                decoded.data,
                decoded.consumed
            ),
            (123, *tag, *data, wire.len())
        );
        for end in 0..wire.len() {
            assert!(
                decode_journal_record(&wire[..end]).is_err(),
                "accepted truncated prefix {end}"
            );
        }
        for offset in 0..wire.len() {
            let mut corrupt = wire.to_vec();
            corrupt[offset] ^= 0x80;
            assert!(
                decode_journal_record(&corrupt).is_err(),
                "accepted corruption at {offset}"
            );
        }
        let mut followed = wire.to_vec();
        followed.extend_from_slice(wire);
        let first = decode_journal_record(&followed).unwrap();
        let second = decode_journal_record(&followed[first.consumed..]).unwrap();
        assert_eq!(second.data, *data);
        assert_eq!(second.consumed, wire.len());
    }
}

#[cfg(feature = "journal-testkit")]
mod player {
    use rustyrbd::journal_mem::MemJournalBackend;
    use rustyrbd::{
        EBADMSG, ENOMSG, JournalBackend, JournalEvent, JournalGeometry, JournalObjectPosition,
        JournalPlayer, OBJECT_READ_CHUNK, encode_journal_event_entry,
    };

    fn geometry(order: u8, width: u8, active_set: u64) -> JournalGeometry {
        JournalGeometry {
            order,
            splay_width: width,
            pool_id: -1,
            minimum_set: 0,
            active_set,
        }
    }

    fn position(object: u64, tag: u64, entry: u64) -> JournalObjectPosition {
        JournalObjectPosition {
            object_number: object,
            tag_tid: tag,
            entry_tid: entry,
        }
    }

    /// Hand-built stock-format record: preamble `0x3141592653589793`,
    /// version 1, entry TID, tag TID, payload length, event entry bytes and
    /// the raw CRC32C of the preceding bytes.
    fn stock_record(entry_tid: u64, tag_tid: u64, event: &JournalEvent) -> Vec<u8> {
        let mut entry = Vec::new();
        encode_journal_event_entry(event, 0, 0, &mut entry).unwrap();
        let mut record = Vec::with_capacity(33 + entry.len());
        record.extend_from_slice(&0x3141592653589793u64.to_le_bytes());
        record.push(1);
        record.extend_from_slice(&entry_tid.to_le_bytes());
        record.extend_from_slice(&tag_tid.to_le_bytes());
        record.extend_from_slice(&(entry.len() as u32).to_le_bytes());
        record.extend_from_slice(&entry);
        record.extend_from_slice(&crc::crc32c(0, &record).to_le_bytes());
        record
    }

    fn write_event<'a>(offset: u64, data: &'a [u8]) -> JournalEvent<'a> {
        JournalEvent::Write {
            offset,
            length: data.len() as u64,
            data,
        }
    }

    /// The seal result: positions and next append TID.
    type Seal = (Vec<JournalObjectPosition>, u64);

    /// Replay the whole prefix and seal; returns the (tag, tid) sequence and
    /// the seal result.
    fn replay_all(
        mut player: JournalPlayer,
        backend: &mut MemJournalBackend,
    ) -> Result<(Vec<(u64, u64)>, Seal), i32> {
        let mut sequence = Vec::new();
        while let Some(record) = player.next(backend)? {
            sequence.push((record.tag_tid, record.entry_tid));
        }
        Ok((sequence, player.seal()))
    }

    #[test]
    fn reference_vectors_replay_the_stock_record_stream() {
        let mut backend = MemJournalBackend::new().with_min_alloc_size(8);
        backend.create(12, 2, -1).unwrap();
        let mut splay_zero = stock_record(0, 1, &write_event(0, b"aaa"));
        splay_zero.extend(stock_record(2, 1, &JournalEvent::Flush));
        let splay_one = stock_record(1, 1, &write_event(512, b"bbb"));
        backend.append(0, 1 << 12, &splay_zero).unwrap();
        backend.append(1, 1 << 12, &splay_one).unwrap();

        let player = JournalPlayer::new(&geometry(12, 2, 0), &[], &[1]).unwrap();
        let (sequence, (positions, next_tid)) = replay_all(player, &mut backend).unwrap();
        assert_eq!(sequence, [(1, 0), (1, 1), (1, 2)]);
        assert_eq!(positions, [position(0, 1, 2), position(1, 1, 1)]);
        assert_eq!(next_tid, 3);
    }

    #[test]
    fn no_position_starts_at_the_first_records_tag() {
        // Two tags with records and no commit position (fresh
        // registration): the first record's tag is the current one, the
        // newer tag follows at its TID 0; nothing is skipped.
        let mut backend = MemJournalBackend::new().with_min_alloc_size(8);
        backend.create(12, 2, -1).unwrap();
        let mut splay_zero = stock_record(0, 1, &write_event(0, b"aaa"));
        splay_zero.extend(stock_record(0, 2, &write_event(0, b"ccc")));
        let mut splay_one = stock_record(1, 1, &write_event(512, b"bbb"));
        splay_one.extend(stock_record(1, 2, &JournalEvent::Flush));
        backend.append(0, 1 << 12, &splay_zero).unwrap();
        backend.append(1, 1 << 12, &splay_one).unwrap();

        let mut player = JournalPlayer::new(&geometry(12, 2, 0), &[], &[1, 2]).unwrap();
        assert_eq!(player.active_tag(), None);
        let mut sequence = Vec::new();
        while let Some(record) = player.next(&mut backend).unwrap() {
            sequence.push((record.tag_tid, record.entry_tid));
        }
        assert_eq!(sequence, [(1, 0), (1, 1), (2, 0), (2, 1)]);
        assert_eq!(player.active_tag(), Some(2));
        let (positions, next_tid) = player.seal();
        assert_eq!(positions, [position(1, 2, 1), position(0, 2, 0)]);
        assert_eq!(next_tid, 2);
    }

    #[test]
    fn no_position_and_no_record_leaves_the_tag_unset() {
        let mut backend = MemJournalBackend::new().with_min_alloc_size(8);
        backend.create(12, 2, -1).unwrap();
        let mut player = JournalPlayer::new(&geometry(12, 2, 0), &[], &[1, 2]).unwrap();
        assert_eq!(player.next(&mut backend).unwrap(), None);
        assert_eq!(player.active_tag(), None);
        assert_eq!(player.seal(), (Vec::new(), 0));
    }

    #[test]
    fn oracle_positions_replay_and_seal() {
        // The C writer oracle committed [(1,1,1),(0,1,0)], newest first, for
        // a Write at (object 0, tag 1, entry 0) and a Flush at
        // (object 1, tag 1, entry 1) with splay width 2.
        let mut backend = MemJournalBackend::new().with_min_alloc_size(8);
        backend.create(12, 2, -1).unwrap();
        backend
            .append(0, 1 << 12, &stock_record(0, 1, &write_event(0, b"aaa")))
            .unwrap();
        backend
            .append(1, 1 << 12, &stock_record(1, 1, &JournalEvent::Flush))
            .unwrap();

        let player = JournalPlayer::new(
            &geometry(12, 2, 0),
            &[position(1, 1, 1), position(0, 1, 0)],
            &[1],
        )
        .unwrap();
        let (sequence, (positions, next_tid)) = replay_all(player, &mut backend).unwrap();
        assert!(sequence.is_empty(), "the committed prefix is skipped");
        assert_eq!(positions, [position(1, 1, 1), position(0, 1, 0)]);
        assert_eq!(next_tid, 2);
    }

    #[test]
    fn absent_objects_below_active_set_are_empty() {
        let mut backend = MemJournalBackend::new().with_min_alloc_size(8);
        backend.create(12, 2, -1).unwrap();
        let mut splay_zero = stock_record(0, 1, &write_event(0, b"aaa"));
        splay_zero.extend(stock_record(2, 1, &JournalEvent::Flush));
        backend.append(2, 1 << 12, &splay_zero).unwrap();
        backend
            .append(1, 1 << 12, &stock_record(1, 1, &write_event(512, b"bbb")))
            .unwrap();
        // Objects 0 and 3 are absent.

        let player = JournalPlayer::new(&geometry(12, 2, 1), &[], &[1]).unwrap();
        let (sequence, (positions, next_tid)) = replay_all(player, &mut backend).unwrap();
        assert_eq!(sequence, [(1, 0), (1, 1), (1, 2)]);
        assert_eq!(positions, [position(2, 1, 2), position(1, 1, 1)]);
        assert_eq!(next_tid, 3);
    }

    #[test]
    fn empty_active_set_object_is_the_tail() {
        let mut backend = MemJournalBackend::new().with_min_alloc_size(8);
        backend.create(12, 2, -1).unwrap();
        backend
            .append(0, 1 << 12, &stock_record(0, 1, &write_event(0, b"aaa")))
            .unwrap();
        backend
            .append(1, 1 << 12, &stock_record(1, 1, &write_event(512, b"bbb")))
            .unwrap();
        backend.touch_object(2).unwrap();
        backend.touch_object(3).unwrap();

        let player = JournalPlayer::new(&geometry(12, 2, 1), &[], &[1]).unwrap();
        let (sequence, (positions, next_tid)) = replay_all(player, &mut backend).unwrap();
        assert_eq!(sequence, [(1, 0), (1, 1)]);
        assert_eq!(positions, [position(1, 1, 1), position(0, 1, 0)]);
        assert_eq!(next_tid, 2);
    }

    #[test]
    fn mid_stream_tid_gap_fails_enomsg() {
        let mut backend = MemJournalBackend::new().with_min_alloc_size(8);
        backend.create(12, 1, -1).unwrap();
        let mut object = stock_record(0, 1, &write_event(0, b"aaa"));
        object.extend(stock_record(2, 1, &write_event(1024, b"ccc")));
        backend.append(0, 1 << 12, &object).unwrap();

        let mut player = JournalPlayer::new(&geometry(12, 1, 0), &[], &[1]).unwrap();
        let first = player.next(&mut backend).unwrap().unwrap();
        assert_eq!((first.tag_tid, first.entry_tid), (1, 0));
        assert_eq!(player.next(&mut backend), Err(ENOMSG));
    }

    #[test]
    fn tail_gap_stops_and_seals_over_orphans() {
        // Splay 0 holds tids 0 and 2; splay 1 is empty at the active set,
        // so tid 1's missing stream is a tail: the prefix stops after tid 0
        // and the seal covers the orphan tid 2.
        let mut backend = MemJournalBackend::new().with_min_alloc_size(8);
        backend.create(12, 2, -1).unwrap();
        let mut object = stock_record(0, 1, &write_event(0, b"aaa"));
        object.extend(stock_record(2, 1, &write_event(1024, b"ccc")));
        backend.append(0, 1 << 12, &object).unwrap();

        let player = JournalPlayer::new(&geometry(12, 2, 0), &[], &[1]).unwrap();
        let (sequence, (positions, next_tid)) = replay_all(player, &mut backend).unwrap();
        assert_eq!(sequence, [(1, 0)]);
        assert_eq!(positions, [position(0, 1, 2)]);
        assert_eq!(next_tid, 3);
    }

    #[test]
    fn older_tag_records_are_stale_and_skipped() {
        let mut backend = MemJournalBackend::new().with_min_alloc_size(8);
        backend.create(12, 1, -1).unwrap();
        let mut object = stock_record(5, 1, &write_event(0, b"old"));
        object.extend(stock_record(0, 2, &write_event(0, b"aaa")));
        object.extend(stock_record(1, 2, &write_event(512, b"bbb")));
        object.extend(stock_record(2, 2, &JournalEvent::Flush));
        backend.append(0, 1 << 12, &object).unwrap();

        let player =
            JournalPlayer::new(&geometry(12, 1, 0), &[position(0, 2, 0)], &[1, 2]).unwrap();
        let (sequence, (positions, next_tid)) = replay_all(player, &mut backend).unwrap();
        assert_eq!(sequence, [(2, 1), (2, 2)]);
        assert_eq!(positions, [position(0, 2, 2)]);
        assert_eq!(next_tid, 3);
    }

    #[test]
    fn newer_tag_nonzero_tid_is_retained_and_reseeked() {
        // The retained (tag 2, tid 1) record in splay 1 is seen before the
        // new tag's tid-0 record in splay 0; the player re-seeks from splay
        // 0, promotes at tid 0, and replays the retained record in
        // sequence (J1).
        let mut backend = MemJournalBackend::new().with_min_alloc_size(8);
        backend.create(12, 2, -1).unwrap();
        let mut splay_zero = stock_record(0, 1, &write_event(0, b"aaa"));
        splay_zero.extend(stock_record(0, 2, &write_event(0, b"new")));
        backend.append(0, 1 << 12, &splay_zero).unwrap();
        backend
            .append(
                1,
                1 << 12,
                &stock_record(1, 2, &write_event(512, b"retained")),
            )
            .unwrap();

        let player =
            JournalPlayer::new(&geometry(12, 2, 0), &[position(0, 1, 0)], &[1, 2]).unwrap();
        let (sequence, (positions, next_tid)) = replay_all(player, &mut backend).unwrap();
        assert_eq!(sequence, [(2, 0), (2, 1)]);
        assert_eq!(positions, [position(1, 2, 1), position(0, 2, 0)]);
        assert_eq!(next_tid, 2);
    }

    #[test]
    fn wrong_splay_record_fails_ebadmsg() {
        let mut backend = MemJournalBackend::new().with_min_alloc_size(8);
        backend.create(12, 2, -1).unwrap();
        // TID 1 belongs to splay 1, not splay 0's object.
        backend
            .append(0, 1 << 12, &stock_record(1, 1, &write_event(0, b"aaa")))
            .unwrap();

        let mut player = JournalPlayer::new(&geometry(12, 2, 0), &[], &[1]).unwrap();
        assert_eq!(player.next(&mut backend), Err(EBADMSG));
    }

    #[test]
    fn malformed_positions_fail_ebadmsg() {
        // More positions than splays.
        assert!(matches!(
            JournalPlayer::new(
                &geometry(12, 2, 0),
                &[position(0, 1, 0), position(1, 1, 1), position(2, 1, 2)],
                &[1]
            ),
            Err(EBADMSG)
        ));
        // A position beyond the last object of the active set.
        assert!(matches!(
            JournalPlayer::new(&geometry(12, 2, 0), &[position(4, 1, 0)], &[1]),
            Err(EBADMSG)
        ));
        // Two positions of the same splay stream.
        assert!(matches!(
            JournalPlayer::new(
                &geometry(12, 2, 0),
                &[position(0, 1, 0), position(2, 1, 1)],
                &[1]
            ),
            Err(EBADMSG)
        ));
        // An empty tag list.
        assert!(matches!(
            JournalPlayer::new(&geometry(12, 2, 0), &[], &[]),
            Err(EBADMSG)
        ));
        // A persisted record that is not present in its object.
        let mut backend = MemJournalBackend::new().with_min_alloc_size(8);
        backend.create(12, 1, -1).unwrap();
        backend
            .append(0, 1 << 12, &stock_record(1, 1, &write_event(0, b"aaa")))
            .unwrap();
        let mut player =
            JournalPlayer::new(&geometry(12, 1, 0), &[position(0, 1, 0)], &[1]).unwrap();
        assert_eq!(player.next(&mut backend), Err(EBADMSG));
    }

    #[test]
    fn unaligned_zero_tail_fails_ebadmsg() {
        let mut backend = MemJournalBackend::new();
        backend.create(12, 1, -1).unwrap();
        let mut object = stock_record(0, 1, &write_event(0, b"aa"));
        object.extend([0, 0, 0]);
        backend.write_raw_object(0, &object).unwrap();

        let mut player = JournalPlayer::new(&geometry(12, 1, 0), &[], &[1]).unwrap();
        assert_eq!(player.next(&mut backend), Err(EBADMSG));
    }

    #[test]
    fn allocation_unit_padding_is_skipped() {
        // The default 4096-byte allocation pad between the two records is
        // skipped, not a zero gap.
        let mut backend = MemJournalBackend::new();
        backend.create(14, 1, -1).unwrap();
        backend
            .append(0, 1 << 14, &stock_record(0, 1, &write_event(0, b"aaa")))
            .unwrap();
        backend
            .append(0, 1 << 14, &stock_record(1, 1, &write_event(512, b"bbb")))
            .unwrap();

        let player = JournalPlayer::new(&geometry(14, 1, 0), &[], &[1]).unwrap();
        let (sequence, (positions, next_tid)) = replay_all(player, &mut backend).unwrap();
        assert_eq!(sequence, [(1, 0), (1, 1)]);
        assert_eq!(positions, [position(0, 1, 1)]);
        assert_eq!(next_tid, 2);
    }

    #[test]
    fn padded_record_crossing_the_soft_maximum_replays() {
        // Order 13 (8 KiB), 4096-byte pad: the class accepts the second
        // append at padded size 4096 < 8192, and the 5000-byte record ends
        // past the soft maximum. Records and zero pad past it are ordinary.
        let mut backend = MemJournalBackend::new().with_min_alloc_size(4096);
        backend.create(13, 1, -1).unwrap();
        let big = vec![7u8; 5000];
        backend
            .append(0, 1 << 13, &stock_record(0, 1, &write_event(0, b"a")))
            .unwrap();
        let crossing = stock_record(1, 1, &write_event(4096, &big));
        assert!(4096 + crossing.len() > 1 << 13);
        backend.append(0, 1 << 13, &crossing).unwrap();

        let player = JournalPlayer::new(&geometry(13, 1, 0), &[], &[1]).unwrap();
        let (sequence, (positions, next_tid)) = replay_all(player, &mut backend).unwrap();
        assert_eq!(sequence, [(1, 0), (1, 1)]);
        assert_eq!(positions, [position(0, 1, 1)]);
        assert_eq!(next_tid, 2);
    }

    #[test]
    fn object_past_the_size_bound_fails_ebadmsg() {
        // More than 2 << order bytes in one object is malformed.
        let mut backend = MemJournalBackend::new().with_min_alloc_size(8);
        backend.create(12, 1, -1).unwrap();
        let mut object = Vec::new();
        for entry in 0..8 {
            object.extend(stock_record(entry, 1, &write_event(0, &[1u8; 2500])));
        }
        assert!(object.len() > 2 << 12);
        backend.write_raw_object(0, &object).unwrap();

        let player = JournalPlayer::new(&geometry(12, 1, 0), &[], &[1]).unwrap();
        assert_eq!(replay_all(player, &mut backend).err(), Some(EBADMSG));
    }

    #[test]
    fn a_single_record_past_the_size_bound_fails_ebadmsg() {
        // One hand-made record larger than the whole 2 << order window is
        // corruption, exactly like any other partial record.
        let mut backend = MemJournalBackend::new().with_min_alloc_size(8);
        backend.create(12, 1, -1).unwrap();
        let big = vec![9u8; 9000];
        let record = stock_record(0, 1, &write_event(0, &big));
        assert!(record.len() > 2 << 12);
        backend.write_raw_object(0, &record).unwrap();

        let player = JournalPlayer::new(&geometry(12, 1, 0), &[], &[1]).unwrap();
        assert_eq!(replay_all(player, &mut backend).err(), Some(EBADMSG));
    }

    #[test]
    fn streaming_memory_bound_is_one_object_per_splay() {
        // 256 KiB objects force every stream to read in several 64 KiB
        // chunks; the player must retain at most one chunk per splay.
        let mut backend = MemJournalBackend::new();
        backend.create(18, 2, -1).unwrap();
        for splay in 0..2u64 {
            for entry in (splay..60u64).step_by(2) {
                backend
                    .append(
                        splay,
                        1 << 18,
                        &stock_record(entry, 1, &write_event(entry, b"aaa")),
                    )
                    .unwrap();
            }
        }

        let mut player = JournalPlayer::new(&geometry(18, 2, 0), &[], &[1]).unwrap();
        let mut sequence = Vec::new();
        loop {
            let bound = 2 * OBJECT_READ_CHUNK;
            assert!(
                player.retained_bytes() <= bound,
                "retained {} bytes exceed the one-chunk-per-splay bound {bound}",
                player.retained_bytes()
            );
            match player.next(&mut backend).unwrap() {
                Some(record) => sequence.push((record.tag_tid, record.entry_tid)),
                None => break,
            }
        }
        assert!(player.retained_bytes() <= 2 * OBJECT_READ_CHUNK);
        let expected: Vec<(u64, u64)> = (0..60).map(|entry| (1, entry)).collect();
        assert_eq!(sequence, expected);
        let (positions, next_tid) = player.seal();
        assert_eq!(positions, [position(1, 1, 59), position(0, 1, 58)]);
        assert_eq!(next_tid, 60);
    }
}
