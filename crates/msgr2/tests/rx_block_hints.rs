// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Optional store metadata never changes wire integrity or delivered bytes.
mod common;
use common::*;
use denc::types::EntityName;
use msgr2::*;

fn frame(rev: Revision, secure: bool) -> (Vec<u8>, Vec<u8>, Option<ConnSecret>) {
    let data: Vec<u8> = (0..BLOCKS_MIN + 123).map(|n| (n * 131) as u8).collect();
    let mut encoder = Encoder::new(rev);
    let secret = secure.then(|| ConnSecret::new(&[11; 64]).unwrap());
    if let Some(secret) = &secret {
        encoder.set_secure(secret, Role::Client).unwrap();
    }
    let mut wire = Vec::new();
    encoder
        .encode_message(&[7; 40], b"front", b"middle", &data, &mut wire)
        .unwrap();
    (wire, data, secret)
}

#[test]
fn fragmented_crc_frames_keep_whole_crc_without_block_hints() {
    let (wire, data, _) = frame(Revision::V21, false);
    for enabled in [false, true] {
        for piece in [7, 1448, 32768, wire.len()] {
            let mut decoder = Decoder::new(Revision::V21);
            decoder.set_rx_block_crcs(enabled);
            for chunk in wire.chunks(piece) {
                decoder.feed(chunk);
            }
            let frame = decoder.poll_owned().unwrap().unwrap();
            assert_eq!(frame.segs[3].as_ref(), data);
            assert_eq!(frame.data_crc, Some(crc::crc32c(!0, &data)));
            assert_eq!(frame.data_blocks.is_some(), enabled);
            assert_eq!(frame.data_head, 0);
            if let Some(blocks) = frame.data_blocks {
                let expected: Vec<_> = data
                    .as_chunks::<4096>()
                    .0
                    .iter()
                    .map(|b| crc::crc32c(0, b))
                    .collect();
                assert_eq!(blocks.as_ref(), expected);
            }
            assert!(decoder.poll_owned().unwrap().is_none());
            let mut corrupt = wire.clone();
            // A byte in the data segment; leave both CRC fields untouched.
            let index = corrupt.len() - 13 - 300;
            corrupt[index] ^= 0x80;
            let mut decoder = Decoder::new(Revision::V21);
            decoder.set_rx_block_crcs(enabled);
            for chunk in corrupt.chunks(piece) {
                decoder.feed(chunk);
            }
            assert!(matches!(decoder.poll_owned(), Err(Error::BadSegmentCrc(3))));
        }
    }
}

#[test]
fn direct_receive_without_hints_uses_whole_segment_crc_and_rejects_corruption() {
    let (wire, data, _) = frame(Revision::V21, false);
    for corrupt in [false, true] {
        let mut input = wire.clone();
        if corrupt {
            let i = input.len() - 13 - 300;
            input[i] ^= 1;
        }
        let mut decoder = Decoder::new(Revision::V21);
        decoder.set_rx_block_crcs(false);
        decoder.set_rx_place(true);
        let mut position = 0;
        let mut loans = 0;
        while position < input.len() {
            let want = decoder.direct_want();
            if want == 0 {
                let end = (position + 43).min(input.len());
                decoder.feed(&input[position..end]);
                position = end;
            } else {
                let (mut buffer, mut crc) = decoder.direct_take().unwrap();
                let end = position + want;
                for chunk in input[position..end].chunks(1448) {
                    buffer.extend_from_slice(chunk);
                    crc.update(chunk);
                    assert!(
                        crc.blocks().is_empty(),
                        "no block table for a byte-only owner"
                    );
                }
                position = end;
                decoder.direct_put(buffer, crc);
                loans += 1;
            }
        }
        assert!(loans > 0);
        if corrupt {
            assert!(matches!(decoder.poll_owned(), Err(Error::BadSegmentCrc(3))));
        } else {
            let frame = decoder.poll_owned().unwrap().unwrap();
            assert_eq!(frame.segs[3].as_ref(), data);
            assert_eq!(frame.data_crc, Some(crc::crc32c(!0, &data)));
            assert!(frame.data_blocks.is_none());
            assert_eq!(frame.data_head, 0);
        }
    }
}

#[test]
fn secure_and_v20_frames_ignore_optional_block_hints() {
    for (rev, secure) in [
        (Revision::V20, false),
        (Revision::V20, true),
        (Revision::V21, true),
    ] {
        for enabled in [false, true] {
            let (wire, data, secret) = frame(rev, secure);
            let mut decoder = Decoder::new(rev);
            decoder.set_rx_block_crcs(enabled);
            if let Some(secret) = secret {
                decoder.set_secure(&secret, Role::Server).unwrap();
            }
            for chunk in wire.chunks(1448) {
                decoder.feed(chunk);
            }
            let frame = decoder.poll_owned().unwrap().unwrap();
            assert_eq!(frame.segs[3].as_ref(), data);
            assert!(frame.data_blocks.is_none());
        }
    }
}

#[test]
fn connection_preserves_hint_choice_across_banner_and_reconnect() {
    let mut client = Node::new(EntityName::OSD, 1, 1, PolicyTable::osd_cluster());
    let mut server = Node::new(EntityName::OSD, 2, 2, PolicyTable::osd_cluster());
    assert!(client.cfg.rx_block_crcs);
    client.cfg.rx_block_crcs = false;
    let mut rng = Rng(77);
    let mut c = client.dial(&server, t(0));
    let mut s = server.accept(1, t(0));
    c.send_message(msg(1, 42, 10));
    exchange(&mut c, &mut s, t(1), &mut rng, 4096);
    events(&mut c);
    events(&mut s);
    for phase in 0..2 {
        s.send_message(msg(phase + 2, 42, 40_000));
        exchange(&mut c, &mut s, t(2 + phase * 6), &mut rng, 1448);
        let received = events(&mut c);
        let messages = msgs(&received);
        assert_eq!(messages.len(), 1);
        let message = &messages[0];
        assert_eq!(
            message.data_crc.of(&message.data),
            Some(crc::crc32c(!0, &message.data))
        );
        assert!(message.data_crc.payload().unwrap().blocks.is_none());
        if phase == 0 {
            c.on_closed(t(5));
            s.on_closed(t(5));
            c.send_message(msg(7, 42, 10));
            events(&mut c);
            events(&mut s);
            s = server.accept(1, t(6));
            c.on_connected(t(6));
            exchange(&mut c, &mut s, t(7), &mut rng, 4096);
            events(&mut c);
            events(&mut s);
        }
    }
}
