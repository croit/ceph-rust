// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Golden EventEntry instances emitted by the Ceph 21.2.0 reference dencoder.

use rustyrbd::{
    JournalEvent, JournalEventKind, decode_journal_event_entry, encode_journal_event_entry,
};

macro_rules! vector {
    ($n:literal) => {
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../testdata/rustyrbd/journal-event-21.2.0/",
            stringify!($n),
            ".bin"
        )) as &[u8]
    };
}

#[test]
fn reference_event_instances_decode_and_reencode() {
    let vectors = [
        vector!(1),
        vector!(2),
        vector!(3),
        vector!(4),
        vector!(5),
        vector!(6),
        vector!(7),
        vector!(8),
        vector!(9),
        vector!(10),
        vector!(11),
        vector!(12),
        vector!(13),
        vector!(14),
        vector!(15),
        vector!(16),
        vector!(17),
        vector!(18),
        vector!(19),
        vector!(20),
        vector!(21),
        vector!(22),
        vector!(23),
        vector!(24),
        vector!(25),
        vector!(26),
        vector!(27),
        vector!(28),
        vector!(29),
        vector!(30),
    ];
    let kinds = [
        0, 0, 1, 1, 2, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 13, 15, 15, 16,
        16, 17, 17,
    ];
    for (index, (bytes, expected_kind)) in vectors.iter().zip(kinds).enumerate() {
        let decoded = decode_journal_event_entry(bytes)
            .unwrap_or_else(|error| panic!("vector {}: {error:?}", index + 1));
        assert_eq!(decoded.version, 5, "vector {}", index + 1);
        assert_eq!(decoded.consumed, bytes.len(), "vector {}", index + 1);
        let event = decoded.event.expect("known reference event");
        let kind = match &event {
            JournalEvent::Discard { .. } => 0,
            JournalEvent::Write { .. } => 1,
            JournalEvent::Flush => 2,
            JournalEvent::OpFinish { .. } => 3,
            JournalEvent::Snapshot { kind, .. } => match kind {
                JournalEventKind::Create => 4,
                JournalEventKind::Remove => 5,
                JournalEventKind::Protect => 7,
                JournalEventKind::Unprotect => 8,
                JournalEventKind::Rollback => 9,
            },
            JournalEvent::SnapshotRename { .. } => 6,
            JournalEvent::ImageRename { .. } => 10,
            JournalEvent::Resize { .. } => 11,
            JournalEvent::Flatten { .. } => 12,
            JournalEvent::MirrorPromoteDemote => 13,
            JournalEvent::SnapshotLimit { .. } => 14,
            JournalEvent::FeatureUpdate { .. } => 15,
            JournalEvent::MetadataSet { .. } => 16,
            JournalEvent::MetadataRemove { .. } => 17,
            JournalEvent::WriteSame { .. } => 18,
            JournalEvent::CompareAndWrite { .. } => 19,
        };
        assert_eq!(kind, expected_kind, "vector {}", index + 1);
        let mut encoded = Vec::new();
        encode_journal_event_entry(
            &event,
            decoded.timestamp_seconds,
            decoded.timestamp_nanoseconds,
            &mut encoded,
        )
        .unwrap();
        assert_eq!(&encoded, bytes, "vector {}", index + 1);
    }
    let write = decode_journal_event_entry(vectors[3]).unwrap();
    assert_eq!(
        write.event,
        Some(JournalEvent::Write {
            offset: 123,
            length: 456,
            data: &[b'1'; 32]
        })
    );
    assert_eq!(
        (write.timestamp_seconds, write.timestamp_nanoseconds),
        (1, 1)
    );
    let finish = decode_journal_event_entry(vectors[5]).unwrap();
    assert_eq!(
        finish.event,
        Some(JournalEvent::OpFinish {
            operation_id: 123,
            repeated_operation_id: 123,
            result: -1
        })
    );
}
