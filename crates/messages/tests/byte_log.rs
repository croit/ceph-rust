// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
use denc::{
    Decode, Decoder,
    types::{EntityAddrVec, EntityName, UTime, Uuid},
};
use messages::{
    ByteCephEntityName, ByteLogEntry, ByteMLog, CephEntityName, LogEntry, MLog, Message,
};

fn string(bytes: &[u8], output: &mut Vec<u8>) {
    output.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    output.extend_from_slice(bytes);
}

fn entry_wire(id: &[u8], msg: &[u8], channel: &[u8]) -> Vec<u8> {
    let mut body = 16u32.to_le_bytes().to_vec(); // Configured MGR principal, CLIENT messenger rank.
    string(id, &mut body);
    body.push(8);
    body.extend_from_slice(&77i64.to_le_bytes());
    body.extend_from_slice(&[2, 0, 0, 0, 0]); // Empty addrvec, MSG_ADDR2.
    body.extend_from_slice(&123u32.to_le_bytes());
    body.extend_from_slice(&456u32.to_le_bytes());
    body.extend_from_slice(&9u64.to_le_bytes());
    body.extend_from_slice(&1u16.to_le_bytes());
    string(msg, &mut body);
    string(channel, &mut body);
    let mut wire = vec![5, 5];
    wire.extend_from_slice(&(body.len() as u32).to_le_bytes());
    wire.extend_from_slice(&body);
    wire
}

fn log_wire(id: &[u8], msg: &[u8], channel: &[u8]) -> Vec<u8> {
    let mut wire = 42u64.to_le_bytes().to_vec();
    wire.extend_from_slice(&(-1i16).to_le_bytes());
    wire.extend_from_slice(&0u64.to_le_bytes());
    wire.extend_from_slice(&[7; 16]);
    wire.extend_from_slice(&1u32.to_le_bytes());
    wire.extend_from_slice(&entry_wire(id, msg, channel));
    wire
}

fn entry(id: &[u8]) -> ByteLogEntry {
    ByteLogEntry {
        name: ByteCephEntityName {
            ty: 16,
            id: id.to_vec(),
        },
        rank: EntityName::client(77),
        addrs: EntityAddrVec::default(),
        stamp: UTime::new(123, 456),
        seq: 9,
        prio: 1,
        msg: "message".into(),
        channel: "cluster".into(),
    }
}

#[test]
fn byte_log_principal_has_exact_name_entry_and_message_wire() {
    for id in [b"".as_slice(), b" spaces.more ", b"\xff\x80.$id.more"] {
        let e = entry(id);
        let mut name = 16u32.to_le_bytes().to_vec();
        string(id, &mut name);
        assert_eq!(denc::to_vec(&e.name).unwrap(), name);
        assert_eq!(
            ByteCephEntityName::decode(&mut Decoder::new(&name)).unwrap(),
            e.name
        );
        let log = ByteMLog {
            version: 42,
            fsid: Uuid([7; 16]),
            entries: vec![e.clone()],
        };
        let wire = log_wire(id, b"message", b"cluster");
        let encoded = log.encode(u64::MAX).unwrap();
        assert_eq!(encoded.front, wire);
        assert!(encoded.middle.is_empty() && encoded.data.is_empty());
        assert_eq!(
            ByteLogEntry::decode(&mut Decoder::new(&wire[38..])).unwrap(),
            e
        );
        assert_eq!(ByteMLog::decode(1, &wire, &[], &[]).unwrap(), log);
    }
}

#[test]
fn native_string_log_api_and_byte_log_share_identical_ascii_wire() {
    let e = entry(b"native.name with spaces");
    let native = MLog {
        version: 42,
        fsid: Uuid([7; 16]),
        entries: vec![LogEntry {
            name: CephEntityName {
                ty: 16,
                id: "native.name with spaces".into(),
            },
            rank: e.rank,
            addrs: e.addrs.clone(),
            stamp: e.stamp,
            seq: e.seq,
            prio: e.prio,
            msg: e.msg.clone(),
            channel: e.channel.clone(),
        }],
    };
    let byte = ByteMLog {
        version: 42,
        fsid: native.fsid,
        entries: vec![e],
    };
    for features in [0, u64::MAX] {
        let text_wire = native.encode(features).unwrap();
        assert_eq!(text_wire, byte.encode(features).unwrap());
        let decoded = MLog::decode(1, &text_wire.front, &[], &[]).unwrap();
        assert_eq!(decoded.entries[0].name, native.entries[0].name);
        assert_eq!(decoded.entries[0].msg, native.entries[0].msg);
        assert_eq!(decoded.entries[0].channel, native.entries[0].channel);
        assert_eq!(decoded.encode(features).unwrap(), text_wire);
        let (ty, version, compat, wire) = messages::AnyMessage::from(native.clone())
            .encode(features)
            .unwrap();
        assert_eq!(
            (ty, version, compat),
            (
                ByteMLog::MSG_TYPE,
                ByteMLog::HEAD_VERSION,
                ByteMLog::COMPAT_VERSION
            )
        );
        assert_eq!(wire, text_wire);
    }
}

#[test]
fn byte_log_does_not_relax_text_principal_message_or_channel_decoders() {
    let wire = log_wire(b"\xff", b"message", b"cluster");
    assert!(MLog::decode(1, &wire, &[], &[]).is_err());
    assert!(LogEntry::decode(&mut Decoder::new(&wire[38..])).is_err());
    assert!(CephEntityName::decode(&mut Decoder::new(&wire[44..])).is_err());
    for (msg, channel) in [
        (b"\xff".as_slice(), b"cluster".as_slice()),
        (b"message", b"\xff"),
    ] {
        let invalid = log_wire(b"native", msg, channel);
        assert!(ByteMLog::decode(1, &invalid, &[], &[]).is_err());
    }
}
