// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Replay of real osd0<->mon crc-mode captures (testdata/msgr2/, v21.1.1 reference cluster)
//! through our state machines. The cephx payloads are opaque to us: scripted auth handlers
//! replay the captured payloads and signature verification is switched off (we do not hold the
//! cephx keys that would make the captured HMACs verifiable).
mod common;
use common::*;
use denc::types::{EntityAddr, EntityAddrVec, EntityName};
use msgr2::auth::*;
use msgr2::payload::*;
use msgr2::*;
use std::path::PathBuf;

fn load(name: &str) -> Vec<u8> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/msgr2")
        .join(name);
    std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

/// Frames of a captured one-direction stream: (tag, segments).
fn frames(s: &[u8]) -> Vec<(u8, Vec<Vec<u8>>)> {
    let (b, n) = Banner::parse(s).unwrap().unwrap();
    let mut d = Decoder::new(b.revision());
    d.feed(&s[n..]);
    let mut v = vec![];
    while let Some(f) = d.poll().unwrap() {
        v.push((f.tag, f.segments().iter().map(|x| x.to_vec()).collect()));
    }
    v
}

#[derive(Debug)]
struct Replay {
    req: AuthRequest,
    more: Vec<u8>,
}
impl AuthClientHandler for Replay {
    fn get_auth_request(&mut self, _: u8) -> Result<AuthRequestOut, AuthError> {
        Ok(AuthRequestOut {
            method: self.req.method,
            preferred_modes: self.req.preferred_modes.clone(),
            payload: self.req.auth_payload.clone(),
        })
    }
    fn handle_auth_reply_more(&mut self, _: &[u8]) -> Result<Vec<u8>, AuthError> {
        Ok(self.more.clone())
    }
    fn handle_auth_done(&mut self, _: u64, _: u32, _: &[u8]) -> Result<AuthSecrets, AuthError> {
        Ok(AuthSecrets::default())
    }
    fn handle_auth_bad_method(
        &mut self,
        _: u32,
        _: i32,
        _: &[u32],
        _: &[u32],
    ) -> Result<(), AuthError> {
        Err(AuthError("unexpected".into()))
    }
}

#[derive(Debug)]
struct ReplayServer {
    method: u32,
    modes: Vec<u32>,
    reply: Vec<u8>,
}
impl AuthServerHandler for ReplayServer {
    fn supported_methods(&self, _: u8) -> Vec<u32> {
        vec![self.method]
    }
    fn supported_modes(&self, _: u8, _: u32) -> Vec<u32> {
        self.modes.clone()
    }
    fn handle_auth_request(
        &mut self,
        _: u8,
        more: bool,
        _: u32,
        _: u32,
        _: &[u8],
    ) -> AuthServerStep {
        if !more {
            return AuthServerStep::More(vec![1, 2, 3]);
        }
        AuthServerStep::Done {
            reply: self.reply.clone(),
            global_id: 4242,
            peer_name: None,
            secrets: AuthSecrets::default(),
        }
    }
}

fn mon_addr() -> EntityAddr {
    EntityAddr::v4(2, 0, [172, 28, 0, 10], 3300)
}

fn osd_cfg(ty: u8, num: i64, ip: [u8; 4], pol: PolicyTable) -> Config {
    let mut c = Config::new(
        EntityName::new(ty, num),
        EntityAddrVec::single(EntityAddr::v4(2, 1234, ip, 6801)),
        pol,
    );
    c.verify_signature = false;
    c
}

fn client_inputs(name: &str) -> (AuthRequest, Vec<u8>) {
    let fr = frames(&load(name));
    let req =
        AuthRequest::from_bytes(&fr.iter().find(|f| f.0 == Tag::AuthRequest as u8).unwrap().1[0])
            .unwrap();
    let more = AuthRequestMore::from_bytes(
        &fr.iter()
            .find(|f| f.0 == Tag::AuthRequestMore as u8)
            .unwrap()
            .1[0],
    )
    .unwrap()
    .auth_payload;
    (req, more)
}

#[test]
fn captured_mon_to_osd_stream_drives_client_to_ready() {
    for name in ["osd0-mon-36940", "osd0-mon-36936"] {
        let s2c = load(&format!("{name}-s2c.bin"));
        let fr = frames(&s2c);
        let n_msgs = fr.iter().filter(|f| f.0 == Tag::Message as u8).count();
        let (req, more) = client_inputs(&format!("{name}-c2s.bin"));
        for (chunk, compression) in [(usize::MAX, true), (4096, false), (7, true), (1, false)] {
            if chunk == 1 && s2c.len() > 50_000 {
                continue;
            }
            let table = SessionTable::new(1);
            let mut cfg = osd_cfg(
                EntityName::OSD,
                0,
                [172, 28, 0, 20],
                PolicyTable::osd_public(),
            );
            cfg.compression = compression;
            let mut c = Connection::client(
                1,
                cfg,
                table.clone(),
                Box::new(Replay {
                    req: req.clone(),
                    more: more.clone(),
                }),
                EntityName::MON,
                EntityAddrVec::single(mon_addr()),
                mon_addr(),
            );
            assert!(matches!(c.poll_event(), Some(Event::Dial { .. })));
            c.on_connected(t(0));
            let mut rng = Rng(5);
            let mut o = Vec::new();
            let n = chunk.min(s2c.len());
            let mut p = 0;
            while p < s2c.len() {
                let e = (p + 1 + (rng.next() as usize % n)).min(s2c.len());
                c.on_bytes(&s2c[p..e], t(1));
                o.extend(c.poll_output());
                p = e;
            }
            let ev = events(&mut c);
            let faults: Vec<_> = ev.iter().filter(|e| matches!(e, Event::Fault(_))).collect();
            assert!(faults.is_empty(), "{name}: {faults:?}");
            let pi = connected(&ev).expect("connected");
            assert_eq!(pi.name.ty, EntityName::MON);
            assert!(!pi.resumed);
            assert_eq!(c.state(), ConnState::Ready);
            let got = msgs(&ev);
            assert_eq!(got.len(), n_msgs, "{name} chunk {chunk}");
            // seqs are 1..=n in order
            for (i, m) in got.iter().enumerate() {
                assert_eq!(m.header.seq, i as u64 + 1);
            }
            // our output decodes: banner + frames, starting with HELLO, AUTH_REQUEST ...
            let (_, bn) = Banner::parse(&o).unwrap().unwrap();
            let mut d = Decoder::new(Revision::V21);
            d.feed(&o[bn..]);
            let mut tags = vec![];
            while let Ok(Some(f)) = d.poll() {
                tags.push(f.tag);
            }
            assert_eq!(&tags[..4], &[1, 2, 5, 7], "{tags:?}");
            // with compression advertised on both sides the (no-op) handshake runs first
            let next = if compression {
                Tag::CompressionRequest
            } else {
                Tag::ClientIdent
            };
            assert_eq!(tags[4], next as u8, "{tags:?}");
        }
    }
}

#[test]
fn captured_osd_to_mon_stream_drives_server_to_ready() {
    // We play the mon: feed the osd0 -> mon stream into a server-role connection.
    let c2s = load("osd0-mon-36940-c2s.bin");
    let fr = frames(&c2s);
    let n_msgs = fr.iter().filter(|f| f.0 == Tag::Message as u8).count();
    let ci =
        ClientIdent::from_bytes(&fr.iter().find(|f| f.0 == Tag::ClientIdent as u8).unwrap().1[0])
            .unwrap();
    assert!(n_msgs > 0);
    let req =
        AuthRequest::from_bytes(&fr.iter().find(|f| f.0 == Tag::AuthRequest as u8).unwrap().1[0])
            .unwrap();
    let mut cfg = osd_cfg(
        EntityName::MON,
        0,
        [172, 28, 0, 10],
        PolicyTable::uniform(Policy::stateless_server(0)),
    );
    cfg.addrs = EntityAddrVec::single(mon_addr()); // the captured target_addr
    cfg.compression = true; // both captured banners advertised COMPRESSION: the osd sent COMPRESSION_REQUEST
    let mut s = Connection::server(
        1,
        cfg,
        SessionTable::new(1),
        Box::new(ReplayServer {
            method: req.method,
            modes: vec![MODE_CRC],
            reply: vec![9],
        }),
        EntityAddr::v4(2, 0, [172, 28, 0, 20], 36940),
        t(0),
    );
    let mut rng = Rng(6);
    feed(&mut s, &c2s, t(1), &mut rng, 300);
    let ev = events(&mut s);
    let faults: Vec<_> = ev.iter().filter(|e| matches!(e, Event::Fault(_))).collect();
    assert!(faults.is_empty(), "{faults:?}");
    let pi = connected(&ev).expect("connected");
    assert_eq!(pi.name, EntityName::osd(ci.gid));
    assert_eq!(pi.addrs, ci.addrs);
    assert_eq!(pi.global_id, 4242);
    assert_eq!(s.mode(), MODE_CRC);
    assert_eq!(msgs(&ev).len(), n_msgs);
}
