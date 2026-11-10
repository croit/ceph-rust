// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Own literal RC-MONONCE61 fronts, independent of codec-generated expectations.
use denc::types::Uuid;
use messages::{MMonCommand, MMonCommandAck, Message};
#[test]
fn literal_command_fsid_psm_and_binary_data() {
    let front = [
        0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        7, 7, 7, 7, 7, 1, 0, 0, 0, 2, 0, 0, 0, b'{', b'}',
    ];
    let data = [255, 0, 254];
    let command = MMonCommand::decode(1, &front, &[], &data).unwrap();
    assert_eq!(command.version, 0);
    assert_eq!(command.fsid, Uuid([7; 16]));
    assert_eq!(command.cmd, ["{}"]);
    assert_eq!(command.data, data);
    let encoded = command.encode(u64::MAX).unwrap();
    assert_eq!(encoded.front, front);
    assert_eq!(&encoded.data[..], &data);
    assert_eq!(MMonCommand::MSG_TYPE, 50);
    for end in 0..front.len() {
        assert!(MMonCommand::decode(1, &front[..end], &[], &data).is_err());
    }
}
#[test]
fn literal_ack_service_version_negative_status_and_echo() {
    let front = [
        7, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 243, 255, 255, 255, 2, 0, 0, 0,
        b'n', b'o', 1, 0, 0, 0, 2, 0, 0, 0, b'{', b'}',
    ];
    let data = [0, 255];
    let ack = MMonCommandAck::decode(1, &front, &[], &data).unwrap();
    assert_eq!((ack.version, ack.r), (7, -13));
    assert_eq!(ack.rs, "no");
    assert_eq!(ack.cmd, ["{}"]);
    assert_eq!(ack.data, data);
    let encoded = ack.encode(u64::MAX).unwrap();
    assert_eq!(encoded.front, front);
    assert_eq!(&encoded.data[..], &data);
    assert_eq!(MMonCommandAck::MSG_TYPE, 51);
    for end in 0..front.len() {
        assert!(MMonCommandAck::decode(1, &front[..end], &[], &data).is_err());
    }
}
