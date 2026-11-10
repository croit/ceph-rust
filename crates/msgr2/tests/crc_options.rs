// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! `ms_crc_data` interop matrix (spec msgr2.md 4.3): sender true/false x receiver true/false, v2.0 and v2.1, CRC mode and
//! secure mode. A false sender writes 0 into every segment crc slot; a false receiver reads and discards the values
//! without comparing. Secure mode has GCM tags instead of crc fields and ignores the switch.
mod common;
use common::*;
use denc::types::EntityName;
use msgr2::auth::*;
use msgr2::*;

const HELLO: u8 = Tag::Hello as u8;

fn secret() -> ConnSecret {
    let s: Vec<u8> = (0..64u8)
        .map(|i| i.wrapping_mul(7).wrapping_add(3))
        .collect();
    ConnSecret::new(&s).unwrap()
}

fn mk(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

/// One frame of the matrix: `(segment page, segment lengths)` at alignment 8, the last one non-empty.
fn frames() -> [([usize; 4], Vec<Vec<u8>>); 2] {
    [[18, 0, 0, 0], [60, 140, 24, 3000]].map(|lens| {
        let segs = (0..4).map(|i| mk(lens[i], i as u8 + 1)).collect();
        (lens, segs)
    })
}

fn is_control(lens: &[usize; 4]) -> bool {
    lens[1..].iter().all(|&l| l == 0)
}

/// Segment crc slots of a CRC-mode frame: `(wire offset, value the sender computes)`.
fn crc_slots(rev: Revision, lens: [usize; 4], segs: &[Vec<u8>]) -> Vec<(usize, u32)> {
    let n = lens.iter().rposition(|&l| l != 0).unwrap() + 1;
    let mut off = PREAMBLE_LEN;
    let mut slots = Vec::new();
    match rev {
        Revision::V21 => {
            if lens[0] > 0 {
                off += lens[0];
                slots.push((off, crc::crc32c(!0, &segs[0])));
                off += 4;
            }
            for &l in &lens[1..n] {
                off += l;
            }
            if n > 1 {
                off += 1; // late_status
                for (i, seg) in segs.iter().enumerate().skip(1) {
                    slots.push((off, if i < n { crc::crc32c(!0, seg) } else { 0 }));
                    off += 4;
                }
            }
        }
        Revision::V20 => {
            for &l in &lens[..n] {
                off += l;
            }
            off += 1; // late_flags
            for (i, seg) in segs.iter().enumerate() {
                slots.push((off, if i < n { crc::crc32c(!0, seg) } else { 0 }));
                off += 4;
            }
        }
    }
    slots
}

fn slot(wire: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(wire[at..at + 4].try_into().unwrap())
}

fn encode(e: &mut Encoder, segs: &[Vec<u8>], lens: &[usize; 4]) -> Vec<u8> {
    let mut out = Vec::new();
    if is_control(lens) {
        e.encode_control(HELLO, &segs[0], &mut out).unwrap();
    } else {
        e.encode_message(&segs[0], &segs[1], &segs[2], &segs[3], &mut out)
            .unwrap();
    }
    out
}

fn decode(d: &mut Decoder, wire: &[u8]) -> Result<Option<OwnedFrame>, Error> {
    d.feed(wire);
    d.poll_owned()
}

/// Sender: the crc slots keep their positions (frame length unchanged); a false sender writes 0 into every one of them,
/// including the seg0 trailer (v2.1) and the empty-segment slots.
#[test]
fn sender_crc_data_writes_the_crc_or_zero() {
    for rev in [Revision::V20, Revision::V21] {
        for (lens, segs) in frames() {
            let mut on = Encoder::new(rev);
            let wire_on = encode(&mut on, &segs, &lens);
            let mut off = Encoder::new(rev);
            off.set_crc_data(false);
            let wire_off = encode(&mut off, &segs, &lens);
            assert_eq!(wire_on.len(), wire_off.len(), "{rev:?} {lens:?}: length");
            assert_eq!(
                &wire_on[..PREAMBLE_LEN],
                &wire_off[..PREAMBLE_LEN],
                "{rev:?} {lens:?}: preamble (its own crc is always computed)"
            );
            let slots = crc_slots(rev, lens, &segs);
            assert!(!slots.is_empty());
            for (at, expected) in slots {
                assert_eq!(
                    slot(&wire_on, at),
                    expected,
                    "{rev:?} {lens:?}: slot at {at}"
                );
                assert_eq!(slot(&wire_off, at), 0, "{rev:?} {lens:?}: slot at {at}");
            }
        }
    }
}

/// Full codec matrix: v2.0/v2.1 x CRC/secure x sender x receiver, control frame and MESSAGE.
#[test]
fn crc_data_codec_matrix() {
    for rev in [Revision::V20, Revision::V21] {
        for secure in [false, true] {
            for tx in [false, true] {
                for rx in [false, true] {
                    for (lens, segs) in frames() {
                        let cell = format!("{rev:?} secure={secure} tx={tx} rx={rx} {lens:?}");
                        let mut e = Encoder::new(rev);
                        e.set_crc_data(tx);
                        let mut d = Decoder::new(rev);
                        d.set_crc_data(rx);
                        if secure {
                            e.set_secure(&secret(), Role::Client).unwrap();
                            d.set_secure(&secret(), Role::Server).unwrap();
                        }
                        let wire = encode(&mut e, &segs, &lens);
                        let got = decode(&mut d, &wire);
                        if !secure && !tx && rx {
                            assert_eq!(got.err(), Some(Error::BadSegmentCrc(0)), "{cell}");
                            continue;
                        }
                        let f = got.unwrap_or_else(|e| panic!("{cell}: {e:?}")).unwrap();
                        assert_eq!(
                            f.tag,
                            if is_control(&lens) {
                                HELLO
                            } else {
                                Tag::Message as u8
                            },
                            "{cell}"
                        );
                        let n = lens.iter().rposition(|&l| l != 0).unwrap() + 1;
                        for (i, seg) in segs.iter().enumerate().take(n) {
                            assert_eq!(&f.segs[i][..], &seg[..], "{cell}: segment {i}");
                        }
                    }
                }
            }
        }
    }
}

/// Secure mode ignores the switch: identical bytes either way (GCM tags, no crc fields), every combination decodes.
#[test]
fn crc_data_is_ignored_in_secure_mode() {
    for rev in [Revision::V20, Revision::V21] {
        for (lens, segs) in frames() {
            let bytes = |crc_data: bool| {
                let mut e = Encoder::new(rev);
                e.set_crc_data(crc_data);
                e.set_secure(&secret(), Role::Client).unwrap();
                let mut out = Vec::new();
                e.encode_message(&segs[0], &segs[1], &segs[2], &segs[3], &mut out)
                    .unwrap();
                out
            };
            assert_eq!(bytes(true), bytes(false), "{rev:?} {lens:?}");
        }
    }
}

/// A receiver with `ms_crc_data=false` accepts frames whose crc slots are wrong (read and discarded); with true the same
/// frame faults. Covers the seg0 trailer and the epilogue of v2.1 and all four v2.0 slots, control and MESSAGE.
#[test]
fn crc_data_off_skips_the_segment_comparison() {
    for rev in [Revision::V20, Revision::V21] {
        for (lens, segs) in frames() {
            let mut e = Encoder::new(rev);
            let mut wire = encode(&mut e, &segs, &lens);
            for (at, _) in crc_slots(rev, lens, &segs) {
                wire[at..at + 4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
            }
            let mut skip = Decoder::new(rev);
            skip.set_crc_data(false);
            assert!(
                decode(&mut skip, &wire).is_ok(),
                "{rev:?} {lens:?}: a wrong crc is not compared"
            );
            let mut verify = Decoder::new(rev);
            verify.set_crc_data(true);
            assert!(
                matches!(
                    decode(&mut verify, &wire),
                    Err(Error::BadSegmentCrc(_) | Error::BadLateStatus(_))
                ),
                "{rev:?} {lens:?}: a wrong crc faults with verification on"
            );
        }
    }
}

/// The switch does not weaken the checks outside the segment crcs: the preamble crc and v2.1 `late_status` still fault.
#[test]
fn crc_data_off_keeps_preamble_and_late_status_checks() {
    for rev in [Revision::V20, Revision::V21] {
        for (lens, segs) in frames() {
            let mut e = Encoder::new(rev);
            e.set_crc_data(false);
            let wire = encode(&mut e, &segs, &lens);

            let mut bad_preamble = wire.clone();
            bad_preamble[4] ^= 0xFF;
            let mut d = Decoder::new(rev);
            d.set_crc_data(false);
            assert_eq!(
                decode(&mut d, &bad_preamble).err(),
                Some(Error::BadPreambleCrc),
                "{rev:?} {lens:?}: preamble crc"
            );

            if rev == Revision::V21 && !is_control(&lens) {
                let late = PREAMBLE_LEN
                    + segs[0].len()
                    + 4
                    + segs[1..4].iter().map(Vec::len).sum::<usize>();
                let mut bad_late = wire.clone();
                bad_late[late] = 0x07; // neither COMPLETE (0x0E) nor ABORTED (0x01)
                let mut d = Decoder::new(rev);
                d.set_crc_data(false);
                assert_eq!(
                    decode(&mut d, &bad_late).err(),
                    Some(Error::BadLateStatus(0x07)),
                    "{rev:?} {lens:?}: late_status"
                );
            }
        }
    }
}

/// End-to-end: the option is read when a connection is created, per daemon (it covers both directions of a connection).
/// Verifying peers (`ms_crc_data=true`) interoperate; two non-verifying peers interoperate; a mixed pair faults on the
/// verifying side at the first frame of the non-verifying peer (its HELLO carries crc 0), so it never becomes ready.
#[test]
fn crc_data_connection_matrix_crc_mode() {
    for rev in [Revision::V20, Revision::V21] {
        for a_crc in [false, true] {
            for b_crc in [false, true] {
                let cell = format!("{rev:?} a_crc={a_crc} b_crc={b_crc}");
                let mut a = Node::new(EntityName::OSD, 1, 1, PolicyTable::osd_cluster());
                let mut b = Node::new(EntityName::OSD, 2, 2, PolicyTable::osd_cluster());
                a.cfg.v20_only = rev == Revision::V20;
                b.cfg.v20_only = rev == Revision::V20;
                a.cfg.crc_data = a_crc;
                b.cfg.crc_data = b_crc;
                let mut c = a.dial(&b, t(0));
                let mut s = b.accept(1, t(0));
                let mut rng = Rng(5);
                exchange(&mut c, &mut s, t(1), &mut rng, 4096);
                let ce = events(&mut c);
                let se = events(&mut s);
                if a_crc != b_crc {
                    let (faulted, other, who) = if a_crc {
                        (&ce, &se, "verifying client")
                    } else {
                        (&se, &ce, "verifying server")
                    };
                    assert!(
                        faulted.iter().any(|e| matches!(
                            e,
                            Event::Fault(FaultReason::Frame(Error::BadSegmentCrc(0)))
                        )),
                        "{cell}: the {who} must fault on the peer's zero crc: {faulted:?}"
                    );
                    assert!(connected(faulted).is_none(), "{cell}: {who} not ready");
                    assert!(
                        !other.iter().any(|e| matches!(e, Event::Fault(_))),
                        "{cell}: the non-verifying side does not check the received crcs"
                    );
                    assert!(connected(other).is_none(), "{cell}: not ready");
                    continue;
                }
                assert!(connected(&ce).is_some(), "{cell}: client ready: {ce:?}");
                assert!(connected(&se).is_some(), "{cell}: server ready: {se:?}");
                assert!(c.send_message(msg(1, 42, 8000)), "{cell}: queued");
                exchange(&mut c, &mut s, t(2), &mut rng, 4096);
                let se = events(&mut s);
                let delivered = msgs(&se);
                assert_eq!(delivered.len(), 1, "{cell}: one message");
                assert_eq!(delivered[0].header.tid, 1, "{cell}");
                assert_eq!(delivered[0].data.len(), 24000, "{cell}: data segment");
                // COMPLETE | NOCRC: no message-level crc, whatever ms_crc_data says (spec 4.3)
                assert_eq!(delivered[0].header.flags, 0x03, "{cell}: header2.flags");
            }
        }
    }
}

/// End-to-end secure mode: the pre-auth frames are CRC mode, so a mixed pair still faults on the verifying side; after
/// AUTH_DONE the connection is GCM-framed and the option no longer matters (every equal pair delivers a message).
#[test]
fn crc_data_connection_matrix_secure_mode() {
    let key = vec![3u8; 16];
    let sec: Vec<u8> = (0..64u8).collect();
    for rev in [Revision::V20, Revision::V21] {
        for a_crc in [false, true] {
            for b_crc in [false, true] {
                let cell = format!("{rev:?} secure a_crc={a_crc} b_crc={b_crc}");
                let mut a = Node::new(EntityName::OSD, 1, 1, PolicyTable::osd_cluster());
                let mut b = Node::new(EntityName::OSD, 2, 2, PolicyTable::osd_cluster());
                a.cfg.v20_only = rev == Revision::V20;
                b.cfg.v20_only = rev == Revision::V20;
                a.cfg.crc_data = a_crc;
                b.cfg.crc_data = b_crc;
                let mut c = a.dial_with(
                    &b,
                    Box::new(KeyedClient {
                        key: key.clone(),
                        secret: sec.clone(),
                        modes: vec![MODE_SECURE],
                        method: AUTH_METHOD_CEPHX,
                    }),
                    t(0),
                );
                let mut s = b.accept_with(
                    1,
                    Box::new(KeyedServer {
                        peer_name: Some(a.cfg.name),
                        key: key.clone(),
                        secret: sec.clone(),
                        rounds: 1,
                        done: 0,
                        methods: vec![AUTH_METHOD_CEPHX],
                        modes: vec![MODE_SECURE],
                    }),
                    t(0),
                );
                let mut rng = Rng(9);
                exchange(&mut c, &mut s, t(1), &mut rng, 4096);
                let ce = events(&mut c);
                let se = events(&mut s);
                if a_crc != b_crc {
                    let faulted = if a_crc { &ce } else { &se };
                    assert!(
                        faulted.iter().any(|e| matches!(
                            e,
                            Event::Fault(FaultReason::Frame(Error::BadSegmentCrc(0)))
                        )),
                        "{cell}: the verifying side faults on the pre-auth zero crc: {faulted:?}"
                    );
                    continue;
                }
                assert!(
                    connected(&ce).is_some(),
                    "{cell}: client {ce:?} / server {se:?}"
                );
                assert!(
                    connected(&se).is_some(),
                    "{cell}: server {se:?} / client {ce:?}"
                );
                assert!(c.send_message(msg(1, 42, 8000)), "{cell}: queued");
                exchange(&mut c, &mut s, t(2), &mut rng, 4096);
                assert_eq!(msgs(&events(&mut s)).len(), 1, "{cell}: one message");
            }
        }
    }
}
