// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! In-memory end-to-end: a minimal fake mon (written from spec sec 4-6, 9, 10) issues tickets;
//! MonAuthClient <-> fake mon, Authorizer <-> AuthorizerVerifier.

use std::collections::BTreeMap;

use cephx::challenge::{compute_key, random_u64};
use cephx::envelope::*;
use cephx::none::*;
use cephx::ticket::*;
use cephx::types::*;
use cephx::{
    Authorizer, AuthorizerVerifier, CryptoKey, Error, KeyType, MonAuthClient, MonAuthConfig,
    MonReply, UTime, Usage, Verdict,
};
use denc::{Decode, Decoder, Encode, Encoder};

const T0: u64 = 1_700_000_000;
const AUTH_TTL: u32 = 72 * 3600;
const SVC_TTL: u32 = 3600;

fn ut(s: u64) -> UTime {
    UTime::new(s as u32, 0)
}

/// Client wall time (the fake mon counts whole seconds).
fn w(s: u64) -> std::time::Duration {
    std::time::Duration::from_secs(s)
}

struct FakeMon {
    keys: BTreeMap<String, CryptoKey>,
    rotating: BTreeMap<u32, RotatingSecrets>,
    session_ty: KeyType,
    next_gid: u64,
    server_challenge: u64,
    secure: bool,
    // per-session (single connection fake)
    entity: Option<EntityName>,
    gid: u64,
    auth_sk: Option<CryptoKey>,
    got_challenge: bool,
    enc_flag_replies: u32,
}

impl FakeMon {
    fn new(session_ty: KeyType) -> Self {
        let mut rotating = BTreeMap::new();
        for (i, svc) in [ENTITY_AUTH, ENTITY_MON, ENTITY_OSD, ENTITY_MGR]
            .into_iter()
            .enumerate()
        {
            let mut m = BTreeMap::new();
            for j in 0..3u64 {
                let id = 100 * (i as u64 + 1) + j;
                m.insert(
                    id,
                    ExpiringCryptoKey {
                        key: CryptoKey::generate(session_ty, ut(T0)).unwrap(),
                        // prev expired, current +1h, next +2h (relative to T0)
                        expiration: ut(T0 + 3600 * j),
                    },
                );
            }
            rotating.insert(
                svc,
                RotatingSecrets {
                    secrets: m,
                    max_ver: 3,
                },
            );
        }
        Self {
            keys: BTreeMap::new(),
            rotating,
            session_ty,
            next_gid: 0x1000,
            server_challenge: 0,
            secure: false,
            entity: None,
            gid: 0,
            auth_sk: None,
            got_challenge: false,
            enc_flag_replies: 0,
        }
    }

    fn rot_current(&self, svc: u32) -> (u64, &CryptoKey) {
        let (id, k) = self.rotating[&svc].current().unwrap();
        (*id, &k.key)
    }

    fn issue(&self, svc: u32, now: u64, ttl: u32, sk: &CryptoKey) -> TicketEntry {
        let (id, rk) = self.rot_current(svc);
        let info = ServiceTicketInfo {
            ticket: AuthTicket {
                name: self.entity.clone().unwrap().into(),
                global_id: self.gid,
                auid: AUTH_UID_DEFAULT,
                created: ut(now),
                expires: ut(now + u64::from(ttl)),
                caps: CapsInfo::from_text("allow profile osd"),
                flags: 0,
            },
            session_key: sk.clone(),
        };
        TicketEntry {
            service_id: svc,
            session_key: sk.clone(),
            validity: UTime::new(ttl, 0),
            blob: seal_ticket_info(rk, id, &info).unwrap(),
        }
    }

    fn start(&mut self, payload: &[u8]) -> Vec<u8> {
        let (mode, name, gid) = parse_none_payload(payload).unwrap();
        assert_eq!(mode, AUTH_MODE_MON);
        self.entity = Some(name);
        self.gid = gid;
        self.server_challenge = random_u64().unwrap() | 1;
        self.got_challenge = true;
        ServerChallenge {
            server_challenge: self.server_challenge,
        }
        .encode_to_vec()
        .unwrap()
    }

    /// GET_AUTH_SESSION_KEY body (after challenge). Returns AUTH_DONE / MAuthReply result_bl.
    fn authenticate(&mut self, body: &[u8], now: u64, initial: bool) -> Result<Vec<u8>, i32> {
        let mut d = Decoder::new(body);
        let h = RequestHeader::decode(&mut d).unwrap();
        assert_eq!(h.request_type, CEPHX_GET_AUTH_SESSION_KEY);
        let a = Authenticate::decode(&mut d).unwrap();
        let name = self.entity.clone().unwrap();
        let ekey = self.keys.get(&name.to_string()).ok_or(-13)?.clone();
        if !self.got_challenge
            || compute_key(&ekey, self.server_challenge, a.client_challenge).unwrap() != a.key
        {
            return Err(-13);
        }
        // old-ticket policy (sec 10.3, v3 client)
        let mut old_sk = None;
        if self.gid == 0 {
            if !a.old_ticket.blob.is_empty() {
                return Err(-22);
            }
            self.gid = self.next_gid;
            self.next_gid += 1;
        } else {
            let rk = self.rotating[&ENTITY_AUTH]
                .get(a.old_ticket.secret_id)
                .ok_or(-13)?;
            let info = open_ticket_info(rk, &a.old_ticket.blob).map_err(|_| -13)?;
            if info.ticket.global_id != self.gid {
                return Err(-13);
            }
            old_sk = Some(info.session_key);
            self.enc_flag_replies += 1;
        }
        let sk = CryptoKey::generate(self.session_ty, ut(now)).unwrap();
        let auth_entry = self.issue(ENTITY_AUTH, now, AUTH_TTL, &sk);
        let mut e = Encoder::new();
        ResponseHeader {
            request_type: CEPHX_GET_AUTH_SESSION_KEY,
            status: 0,
        }
        .encode(&mut e)
        .unwrap();
        e.raw(&encode_ticket_reply(&[auth_entry], &ekey, old_sk.as_ref()).unwrap())
            .unwrap();
        if a.other_keys != 0 {
            let secret = if initial && self.secure {
                vec![0x5a; 64]
            } else {
                vec![]
            };
            e.bytes(&seal_string_wrapped(&sk, Usage::AuthConnectionSecret, &secret).unwrap())
                .unwrap();
            let extra: Vec<TicketEntry> = [ENTITY_MON, ENTITY_OSD, ENTITY_MGR]
                .into_iter()
                .filter(|b| a.other_keys & b != 0)
                .map(|b| {
                    let ssk = CryptoKey::generate(self.session_ty, ut(now)).unwrap();
                    self.issue(b, now, SVC_TTL, &ssk)
                })
                .collect();
            if extra.is_empty() {
                e.bytes(&[]).unwrap();
            } else {
                e.bytes(&encode_ticket_reply(&extra, &sk, None).unwrap())
                    .unwrap();
            }
        }
        self.auth_sk = Some(sk);
        Ok(e.into_vec())
    }

    fn request(&mut self, body: &[u8], now: u64) -> Result<Vec<u8>, i32> {
        let mut d = Decoder::new(body);
        let h = RequestHeader::decode(&mut d).unwrap();
        match h.request_type {
            CEPHX_GET_AUTH_SESSION_KEY => self.authenticate(body, now, false),
            CEPHX_GET_PRINCIPAL_SESSION_KEY => {
                // authorizer for AUTH service, no challenge
                d.u8().unwrap();
                let gid = d.u64().unwrap();
                assert_eq!(d.u32().unwrap(), ENTITY_AUTH);
                let tb = TicketBlob::decode(&mut d).unwrap();
                let rk = self.rotating[&ENTITY_AUTH].get(tb.secret_id).ok_or(-13)?;
                let info = open_ticket_info(rk, &tb.blob).map_err(|_| -13)?;
                assert_eq!(gid, info.ticket.global_id);
                let _az: Authorize =
                    open_wrapped_t(&info.session_key, Usage::Authorize, &mut d).map_err(|_| -13)?;
                let req = ServiceTicketRequest::decode(&mut d).unwrap();
                let entries: Vec<TicketEntry> = [ENTITY_MON, ENTITY_OSD, ENTITY_MGR]
                    .into_iter()
                    .filter(|b| req.keys & b != 0)
                    .map(|b| {
                        let ssk = CryptoKey::generate(self.session_ty, ut(now)).unwrap();
                        self.issue(b, now, SVC_TTL, &ssk)
                    })
                    .collect();
                let mut e = Encoder::new();
                ResponseHeader {
                    request_type: h.request_type,
                    status: 0,
                }
                .encode(&mut e)
                .unwrap();
                e.raw(&encode_ticket_reply(&entries, &info.session_key, None).unwrap())
                    .unwrap();
                Ok(e.into_vec())
            }
            CEPHX_GET_ROTATING_KEY => {
                let ekey = self.keys[&self.entity.clone().unwrap().to_string()].clone();
                let mut e = Encoder::new();
                ResponseHeader {
                    request_type: h.request_type,
                    status: 0,
                }
                .encode(&mut e)
                .unwrap();
                // caller is an OSD: OSD set; renew the window to be current at `now`
                let mut r = self.rotating[&ENTITY_OSD].clone();
                r.max_ver += 0;
                e.raw(&seal_wrapped_t(&ekey, Usage::RotatingSecret, &r).unwrap())
                    .unwrap();
                Ok(e.into_vec())
            }
            _ => Err(-22),
        }
    }
}

fn osd_cfg(id: &str, key: &CryptoKey) -> MonAuthConfig {
    MonAuthConfig::osd(EntityName::parse(id).unwrap(), key.clone())
}

/// Run the initial handshake; returns the AUTH_DONE global_id.
fn handshake(
    c: &mut MonAuthClient,
    mon: &mut FakeMon,
    now: u64,
    secure: bool,
) -> Result<(), Error> {
    mon.secure = secure;
    let p = c.start();
    let sc = mon.start(&p);
    let more = c.on_reply_more(&sc, w(now))?;
    let done = mon.authenticate(&more, now, true).map_err(Error::Status)?;
    let gid = mon.gid;
    c.on_done(gid, if secure { 2 } else { 1 }, &done, w(now))
}

/// Drive poll/response until nothing more is requested.
fn pump(c: &mut MonAuthClient, mon: &mut FakeMon, now: u64) -> Vec<u16> {
    let mut seen = vec![];
    while let Some(r) = c.poll(w(now)).unwrap() {
        seen.push(r.request_type);
        let res = mon.request(&r.payload, now);
        match res {
            Ok(bl) => assert_eq!(
                c.on_response(0, mon.gid, &bl, w(now)).unwrap(),
                MonReply::Installed
            ),
            Err(e) => {
                c.on_response(e, mon.gid, &[], w(now)).unwrap_err();
                break;
            }
        }
        assert!(seen.len() < 10, "request loop");
    }
    seen
}

fn setup(ty: KeyType) -> (FakeMon, CryptoKey, CryptoKey) {
    let mut mon = FakeMon::new(ty);
    let k1 = CryptoKey::generate(ty, ut(T0)).unwrap();
    let k2 = CryptoKey::generate(ty, ut(T0)).unwrap();
    mon.keys.insert("osd.1".into(), k1.clone());
    mon.keys.insert("osd.2".into(), k2.clone());
    (mon, k1, k2)
}

#[test]
fn mon_session_and_peer_authorizer_all_modes() {
    for ty in [KeyType::Aes, KeyType::Aes256Krb5] {
        for secure in [false, true] {
            let (mut mon, k1, k2) = setup(ty);
            // osd.1 and osd.2 authenticate separately (separate "connections")
            let mut c1 = MonAuthClient::new(osd_cfg("osd.1", &k1));
            handshake(&mut c1, &mut mon, T0, secure).unwrap();
            let gid1 = c1.global_id();
            assert!(gid1 >= 0x1000);
            assert_eq!(c1.connection_secret().is_some(), secure);
            if secure {
                assert_eq!(c1.connection_secret().unwrap().as_bytes(), &[0x5a; 64]);
            }
            assert!(c1.session_key().is_some());
            for svc in [ENTITY_AUTH, ENTITY_MON, ENTITY_OSD, ENTITY_MGR] {
                assert!(c1.ticket(svc).unwrap().have_key(w(T0)), "svc {svc:#x}");
            }
            assert_eq!(c1.need_mask(w(T0)), 0);
            // rotating keys: first poll fetches, then nothing
            assert_eq!(pump(&mut c1, &mut mon, T0), vec![CEPHX_GET_ROTATING_KEY]);
            assert_eq!(c1.rotating().secrets.len(), 3);

            let mut c2 = MonAuthClient::new(osd_cfg("osd.2", &k2));
            handshake(&mut c2, &mut mon, T0, secure).unwrap();
            pump(&mut c2, &mut mon, T0);
            assert_ne!(c1.global_id(), c2.global_id());

            // osd.1 -> osd.2: authorizer with challenge round
            let mut az = c1.authorizer(ENTITY_OSD).unwrap();
            let mut v = AuthorizerVerifier::new(ENTITY_OSD, secure);
            let rot = c2.rotating().clone();
            let more = match v.verify(az.payload(), &rot).unwrap() {
                Verdict::More(m) => m,
                Verdict::Done(_) => panic!("must challenge first"),
            };
            let p2 = az.on_reply_more(&more).unwrap().to_vec();
            let peer = match v.verify(&p2, &rot).unwrap() {
                Verdict::Done(p) => p,
                Verdict::More(_) => panic!("challenge twice"),
            };
            az.on_done(&peer.reply).unwrap();
            assert_eq!(peer.name.to_string(), "osd.1");
            assert_eq!(peer.global_id, gid1);
            assert_eq!(peer.caps_text.as_deref(), Some("allow profile osd"));
            assert_eq!(peer.session_key, *az.session_key());
            assert_eq!(peer.connection_secret.is_some(), secure);
            assert_eq!(
                peer.connection_secret
                    .as_ref()
                    .map(|c| c.as_bytes().to_vec()),
                az.connection_secret().map(|c| c.as_bytes().to_vec())
            );
        }
    }
}

#[test]
fn renewal_and_reclaim() {
    for ty in [KeyType::Aes, KeyType::Aes256Krb5] {
        let (mut mon, k1, _) = setup(ty);
        let mut c = MonAuthClient::new(osd_cfg("osd.1", &k1));
        handshake(&mut c, &mut mon, T0, false).unwrap();
        pump(&mut c, &mut mon, T0);
        let gid = c.global_id();
        // before renewal point: nothing (rotating current expires T0+3600, cutoff 30s)
        assert!(pump(&mut c, &mut mon, T0 + 2699).is_empty());
        // 45 min: service tickets renew, AUTH not yet
        let r = pump(&mut c, &mut mon, T0 + 2700);
        assert_eq!(r, vec![CEPHX_GET_PRINCIPAL_SESSION_KEY]);
        assert!(c.ticket(ENTITY_OSD).unwrap().have_key(w(T0 + 2700)));
        assert_eq!(c.need_mask(w(T0 + 2700)), 0);
        // rotating "current" expired at T0+3600+30 -> refresh is due after that
        let t = T0 + 3631;
        let r = pump(&mut c, &mut mon, t);
        assert!(r.contains(&CEPHX_GET_ROTATING_KEY), "{r:?}");
        // at most one rotating request per second
        assert!(c.poll(w(t)).unwrap().is_none());
        // AUTH at 54h: GET_AUTH (reclaim with old ticket -> enc_flag=1), extras installed
        let t = T0 + 54 * 3600;
        let r = pump(&mut c, &mut mon, t);
        assert_eq!(r[0], CEPHX_GET_AUTH_SESSION_KEY);
        assert_eq!(c.global_id(), gid);
        assert!(c.ticket(ENTITY_AUTH).unwrap().have_key(w(t)));
        assert!(c.ticket(ENTITY_OSD).unwrap().have_key(w(t)));
        // reconnect to "another mon": reclaim with old ticket and enc_flag reply
        handshake(&mut c, &mut mon, t + 5, false).unwrap();
        assert_eq!(c.global_id(), gid);
        assert!(c.ticket(ENTITY_AUTH).unwrap().have_key(w(t + 5)));
        assert!(mon.enc_flag_replies >= 2, "reclaim must use enc_flag=1");
    }
}

#[test]
fn mon_rejections() {
    let (mut mon, k1, _) = setup(KeyType::Aes);
    // wrong key
    let bad = CryptoKey::generate(KeyType::Aes, ut(T0)).unwrap();
    let mut c = MonAuthClient::new(osd_cfg("osd.1", &bad));
    assert_eq!(
        handshake(&mut c, &mut mon, T0, false),
        Err(Error::Status(-13))
    );
    // unknown entity
    let mut c = MonAuthClient::new(osd_cfg("osd.9", &k1));
    assert_eq!(
        handshake(&mut c, &mut mon, T0, false),
        Err(Error::Status(-13))
    );
    // state machine ordering
    let mut c = MonAuthClient::new(osd_cfg("osd.1", &k1));
    assert!(c.on_reply_more(&[], w(T0)).is_err());
    assert!(c.on_done(1, 1, &[], w(T0)).is_err());
    assert!(c.poll(w(T0)).unwrap().is_none());
    // secure mode without secret
    let mut mon = FakeMon::new(KeyType::Aes);
    mon.keys.insert("osd.1".into(), k1.clone());
    let mut c = MonAuthClient::new(osd_cfg("osd.1", &k1));
    mon.secure = false;
    let p = c.start();
    let sc = mon.start(&p);
    let more = c.on_reply_more(&sc, w(T0)).unwrap();
    let done = mon.authenticate(&more, T0, true).unwrap();
    assert!(c.on_done(mon.gid, 2, &done, w(T0)).is_err());
}

struct Peer {
    rot: RotatingSecrets,
    az: Authorizer,
    gid: u64,
}

/// Build a verifier-side set + a ticket for osd.1 -> OSD service via fake mon.
fn peer(ty: KeyType) -> Peer {
    let (mut mon, k1, _) = setup(ty);
    let mut c = MonAuthClient::new(osd_cfg("osd.1", &k1));
    handshake(&mut c, &mut mon, T0, false).unwrap();
    Peer {
        rot: mon.rotating[&ENTITY_OSD].clone(),
        az: c.authorizer(ENTITY_OSD).unwrap(),
        gid: c.global_id(),
    }
}

fn complete(
    v: &mut AuthorizerVerifier,
    az: &mut Authorizer,
    rot: &RotatingSecrets,
) -> Result<Verdict, Error> {
    match v.verify(az.payload(), rot)? {
        Verdict::More(m) => {
            let p = az.on_reply_more(&m)?.to_vec();
            v.verify(&p, rot)
        }
        d => Ok(d),
    }
}

#[test]
fn verifier_rejects() {
    for ty in [KeyType::Aes, KeyType::Aes256Krb5] {
        let p = peer(ty);
        // good
        let mut az = p.az;
        let mut v = AuthorizerVerifier::new(ENTITY_OSD, false);
        assert!(matches!(
            complete(&mut v, &mut az, &p.rot),
            Ok(Verdict::Done(_))
        ));
        let payload = az.payload().to_vec();

        // wrong service type
        let mut v = AuthorizerVerifier::new(ENTITY_MGR, false);
        assert!(v.verify(&payload, &p.rot).is_err());
        // unknown / aged-out secret id
        let mut v = AuthorizerVerifier::new(ENTITY_OSD, false);
        let mut rot = p.rot.clone();
        rot.secrets.clear();
        assert!(v.verify(&payload, &rot).is_err());
        // wrong first byte
        let mut bad = payload.clone();
        bad[0] = 0;
        assert!(v.verify(&bad, &p.rot).is_err());
        bad[0] = 10;
        assert!(v.verify(&bad, &p.rot).is_err());
        // truncation, at every cut
        for n in 0..payload.len() {
            let mut v = AuthorizerVerifier::new(ENTITY_OSD, false);
            assert!(v.verify(&payload[..n], &p.rot).is_err(), "cut {n}");
        }
        // global_id mismatch
        let mut bad = payload.clone();
        bad[1] ^= 1;
        let mut v = AuthorizerVerifier::new(ENTITY_OSD, false);
        assert!(v.verify(&bad, &p.rot).is_err());
        assert_ne!(p.gid, 0);
        // Flipped byte in the encrypted authorize. AES-CBC has no MAC (classic Ceph neither):
        // a flip in the last ciphertext block garbles that whole plaintext block, i.e. the
        // unauthenticated nonce tail, have_challenge and server_challenge. have_challenge==0
        // (prob 1/256) legitimately yields a fresh challenge (More, nothing granted); a
        // nonzero one fails the challenge check (2^-64). So: never Done, and with krb5 (HMAC)
        // always an error. Loop over every position.
        for i in 0..payload.len() {
            let mut bad = payload.clone();
            bad[i] ^= 0x40;
            let mut v = AuthorizerVerifier::new(ENTITY_OSD, false);
            match v.verify(&bad, &p.rot) {
                Ok(Verdict::Done(_)) => panic!("flip at {i} accepted"),
                Ok(Verdict::More(_)) | Err(_) => {}
            }
        }
        // wrong challenge response: replay first-round payload twice (have_challenge=0 again
        // re-issues a challenge, never succeeds)
        let mut az2 = peer(ty);
        let mut v2 = AuthorizerVerifier::new(ENTITY_OSD, false);
        assert!(matches!(
            v2.verify(az2.az.payload(), &az2.rot),
            Ok(Verdict::More(_))
        ));
        assert!(matches!(
            v2.verify(az2.az.payload(), &az2.rot),
            Ok(Verdict::More(_))
        ));
        // answer from another connection's challenge is wrong
        let mut v3 = AuthorizerVerifier::new(ENTITY_OSD, false);
        let Ok(Verdict::More(m)) = v3.verify(az2.az.payload(), &az2.rot) else {
            panic!()
        };
        let p_ok = az2.az.on_reply_more(&m).unwrap().to_vec();
        let mut v4 = AuthorizerVerifier::new(ENTITY_OSD, false);
        let _ = v4.verify(az2.az.payload(), &az2.rot); // different challenge
        assert!(v4.verify(&p_ok, &az2.rot).is_err());
        assert!(matches!(v3.verify(&p_ok, &az2.rot), Ok(Verdict::Done(_))));
    }
}

#[test]
fn cached_ticket_reconnects_after_expiry_until_its_rotating_key_is_removed() {
    for ty in [KeyType::Aes, KeyType::Aes256Krb5] {
        for secure in [false, true] {
            let (mut mon, key, _) = setup(ty);
            let mut c = MonAuthClient::new(osd_cfg("osd.1", &key));
            handshake(&mut c, &mut mon, T0, secure).unwrap();
            let now = w(T0 + u64::from(SVC_TTL) + 1);
            assert!(c.ticket(ENTITY_OSD).unwrap().need_key(now));
            for invalidate in [false, true] {
                if invalidate {
                    c.wipe_secrets_and_tickets();
                }
                let mut az = c.authorizer(ENTITY_OSD).unwrap();
                let mut verifier = AuthorizerVerifier::new(ENTITY_OSD, secure);
                let Verdict::Done(peer) =
                    complete(&mut verifier, &mut az, &mon.rotating[&ENTITY_OSD]).unwrap()
                else {
                    panic!("authentication did not finish")
                };
                az.on_done(&peer.reply).unwrap();
                assert_eq!(az.connection_secret().is_some(), secure);
                let mut missing = mon.rotating[&ENTITY_OSD].clone();
                missing
                    .secrets
                    .remove(&c.ticket(ENTITY_OSD).unwrap().blob().secret_id);
                assert!(
                    AuthorizerVerifier::new(ENTITY_OSD, secure)
                        .verify(az.payload(), &missing)
                        .is_err()
                );
            }
        }
    }
}

#[test]
fn ticket_hardening_checks() {
    // Forge tickets with a key we hold (acting as a mon) and check each hardening rule.
    let ty = KeyType::Aes;
    let rk = CryptoKey::generate(ty, ut(T0)).unwrap();
    let mut rot = RotatingSecrets::default();
    rot.secrets.insert(
        7,
        ExpiringCryptoKey {
            key: rk.clone(),
            expiration: ut(T0 + 3600),
        },
    );
    let mk = |f: &dyn Fn(&mut ServiceTicketInfo)| -> Result<Verdict, Error> {
        let sk = CryptoKey::generate(ty, ut(T0)).unwrap();
        let mut info = ServiceTicketInfo {
            ticket: AuthTicket {
                name: EntityName::parse("osd.1").unwrap().into(),
                global_id: 5000,
                auid: AUTH_UID_DEFAULT,
                created: ut(T0),
                expires: ut(T0 + 100),
                caps: CapsInfo::from_text("allow *"),
                flags: 0,
            },
            session_key: sk,
        };
        f(&mut info);
        let blob = seal_ticket_info(&rk, 7, &info).unwrap();
        let mut az = Authorizer::from_ticket(5000, ENTITY_OSD, &blob, &info.session_key)?;
        let mut v = AuthorizerVerifier::new(ENTITY_OSD, false);
        complete(&mut v, &mut az, &rot)
    };
    assert!(matches!(mk(&|_| {}), Ok(Verdict::Done(_))));
    assert!(mk(&|i| i.ticket.global_id = 1).is_err());
    assert!(mk(&|i| i.ticket.auid = 5).is_err());
    assert!(mk(&|i| i.ticket.caps.allow_all = true).is_err());
    assert!(mk(&|i| i.ticket.expires = ut(T0 - 1)).is_err());
    assert!(mk(&|i| i.ticket.created.nsec = 1_000_000_001).is_err());
    assert!(mk(&|i| i.ticket.caps.caps = vec![9, 9]).is_err());
    assert!(mk(&|i| i.ticket.caps.caps.push(0)).is_err());
    assert!(mk(&|i| i.ticket.created = ut(T0 + 301)).is_err());
    assert!(
        mk(&|i| {
            i.ticket.created = ut(T0 + 300);
            i.ticket.expires = ut(T0 + 400);
        })
        .is_ok()
    );
    assert!(mk(&|i| i.ticket.caps = CapsInfo::default()).is_ok());
    assert!(
        mk(&|i| i.session_key = CryptoKey::new(KeyType::Aes, ut(T0), b"")).is_err(),
        "empty session key"
    );
}

#[test]
fn none_variants() {
    let name = EntityName::parse("osd.4").unwrap();
    let mut c = NoneMonClient::new(name.clone(), 0);
    let p = c.start();
    let (m, n, g) = parse_none_payload(&p).unwrap();
    assert_eq!((m, n.to_string(), g), (AUTH_MODE_MON, "osd.4".into(), 0));
    c.on_done(0x1234, &[]);
    assert!(c.is_done());
    assert_eq!(c.global_id(), 0x1234);
    let az = NoneAuthorizer::new(&name, 0x1234);
    let peer = verify_none(az.payload()).unwrap();
    assert_eq!(
        peer,
        NonePeer {
            name,
            global_id: 0x1234
        }
    );
    // mon-mode payload is not an authorizer
    assert!(verify_none(&mon_auth_payload(&peer.name, 1)).is_err());
    assert!(verify_none(&az.payload()[..5]).is_err());
}

#[test]
fn mode_list_parsing() {
    use cephx::modes::*;
    let p = parse_modes("secure crc, bogus");
    assert_eq!(p.modes, vec![CON_MODE_SECURE, CON_MODE_CRC]);
    assert_eq!(p.unknown, ["bogus"]);
    // every separator and surrounding whitespace; unknown words keep their order
    let p = parse_modes(" crc;secure\tnope,x, ");
    assert_eq!(p.modes, vec![CON_MODE_CRC, CON_MODE_SECURE]);
    assert_eq!(p.unknown, ["nope", "x"]);
    assert_eq!(parse_modes("").modes, vec![]);
    assert_eq!(parse_modes("").unknown, Vec::<String>::new());
}

#[test]
fn ticket_reply_roundtrip_and_errors() {
    let ty = KeyType::Aes256Krb5;
    let pk = CryptoKey::generate(ty, ut(T0)).unwrap();
    let old = CryptoKey::generate(ty, ut(T0)).unwrap();
    let e = TicketEntry {
        service_id: ENTITY_OSD,
        session_key: CryptoKey::generate(ty, ut(T0)).unwrap(),
        validity: UTime::new(3600, 0),
        blob: TicketBlob {
            secret_id: 3,
            blob: vec![1; 50],
        },
    };
    for enc in [None, Some(&old)] {
        let b = encode_ticket_reply(std::slice::from_ref(&e), &pk, enc).unwrap();
        let got = decode_ticket_reply(&mut Decoder::new(&b), &pk, Some(&old)).unwrap();
        assert_eq!(got, vec![e.clone()]);
        // wrong principal key
        assert!(decode_ticket_reply(&mut Decoder::new(&b), &old, Some(&old)).is_err());
        for n in 0..b.len() {
            assert!(decode_ticket_reply(&mut Decoder::new(&b[..n]), &pk, Some(&old)).is_err());
        }
    }
    // enc_flag without old key
    let b = encode_ticket_reply(std::slice::from_ref(&e), &pk, Some(&old)).unwrap();
    assert!(decode_ticket_reply(&mut Decoder::new(&b), &pk, None).is_err());
    // handler bookkeeping: renew at 3/4
    let mut h = TicketHandler::new(ENTITY_OSD);
    assert!(h.need_key(w(0)) && !h.have_key(w(0)));
    h.install(e.clone(), w(1000));
    assert_eq!((h.expires(), h.renew_after()), (w(4600), w(3700)));
    assert!(h.have_key(w(4599)) && !h.have_key(w(4600)));
    assert!(!h.need_key(w(3699)) && h.need_key(w(3700)));
    // validity zero = expired at once and requested again (sec 5.1, 16.1)
    let mut e0 = e;
    e0.validity = UTime::new(0, 0);
    h.install(e0, w(1000));
    for now in [0, 1000, u64::MAX - 1] {
        assert!(
            !h.have_key(w(now)) && h.need_key(w(now)),
            "validity 0 at now={now}"
        );
    }
    h.invalidate();
    assert!(h.need_key(w(0)) && h.session_key().is_some());
}

/// Sec 16.3: a ticket identity id is opaque bytes. The cephx verify path must carry it verbatim
/// instead of refusing it in the text decoder. The ticket is built byte for byte (u32 type + bytes id),
/// as a peer with a non-UTF-8 id would send it.
#[test]
fn non_utf8_ticket_identity_verifies() {
    for ty in [KeyType::Aes, KeyType::Aes256Krb5] {
        let rk = CryptoKey::generate(ty, ut(T0)).unwrap();
        let sk = CryptoKey::generate(ty, ut(T0)).unwrap();
        let mut rot = RotatingSecrets::default();
        rot.secrets.insert(
            7,
            ExpiringCryptoKey {
                key: rk.clone(),
                expiration: ut(T0 + 3600),
            },
        );
        let id = b"\xff\x80";
        let mut ticket = Encoder::new();
        ticket.u8(2).unwrap(); // AuthTicket v2
        ticket.u32(ENTITY_CLIENT).unwrap();
        ticket.bytes(id).unwrap();
        ticket.u64(5000).unwrap(); // global_id
        ticket.u64(AUTH_UID_DEFAULT).unwrap();
        ut(T0).encode(&mut ticket).unwrap();
        ut(T0 + 100).encode(&mut ticket).unwrap();
        CapsInfo::from_text("allow *").encode(&mut ticket).unwrap();
        ticket.u32(0).unwrap();
        let mut body = Encoder::new();
        body.u8(1).unwrap(); // ServiceTicketInfo v1
        body.raw(ticket.buf()).unwrap();
        sk.encode(&mut body).unwrap();
        let blob = TicketBlob {
            secret_id: 7,
            blob: seal_raw(&rk, Usage::TicketInfo, body.buf()).unwrap(),
        };
        // the ticket blob round trip keeps every id byte
        let back = open_ticket_info(&rk, &blob.blob).unwrap();
        assert_eq!(&denc::to_vec(&back.ticket.name).unwrap()[8..], id);
        // a peer verifies the authorizer built from that ticket, non-UTF-8 id included
        let mut az = Authorizer::from_ticket(5000, ENTITY_OSD, &blob, &sk).unwrap();
        let mut v = AuthorizerVerifier::new(ENTITY_OSD, false);
        let more = match v.verify(az.payload(), &rot).unwrap() {
            Verdict::More(m) => m,
            Verdict::Done(_) => panic!("must challenge first"),
        };
        az.on_reply_more(&more).unwrap();
        let Verdict::Done(peer) = v.verify(az.payload(), &rot).unwrap() else {
            panic!("second round must complete");
        };
        assert_eq!(peer.name.ty, ENTITY_CLIENT);
        assert_eq!(&denc::to_vec(&peer.name).unwrap()[8..], id);
    }
}

/// `rotate-key` / `wipe-rotating-secrets` (spec sec 2.2): after the mon switched to a new key, a wipe re-authenticates;
/// that fails with the old key and succeeds once the new one is set, then tickets and rotating secrets come back.
#[test]
fn live_key_rotation_and_wipe() {
    for ty in [KeyType::Aes, KeyType::Aes256Krb5] {
        let (mut mon, k1, _) = setup(ty);
        let mut c = MonAuthClient::new(osd_cfg("osd.1", &k1));
        handshake(&mut c, &mut mon, T0, false).unwrap();
        pump(&mut c, &mut mon, T0);
        assert_eq!(c.rotating().secrets.len(), 3);
        let kn = CryptoKey::generate(ty, ut(T0)).unwrap();
        mon.keys.insert("osd.1".into(), kn.clone());
        c.wipe_secrets_and_tickets();
        assert!(c.rotating().secrets.is_empty());
        assert_ne!(c.need_mask(w(T0 + 1)) & ENTITY_AUTH, 0);
        assert!(!c.ticket(ENTITY_OSD).unwrap().have_key(w(T0 + 1)));
        // still the old key: the mon refuses the re-authentication
        assert_eq!(
            pump(&mut c, &mut mon, T0 + 1),
            vec![CEPHX_GET_AUTH_SESSION_KEY]
        );
        assert!(!c.ticket(ENTITY_AUTH).unwrap().have_key(w(T0 + 1)));
        c.set_key(kn);
        let r = pump(&mut c, &mut mon, T0 + 2);
        assert_eq!(r[0], CEPHX_GET_AUTH_SESSION_KEY, "{r:?}");
        assert!(r.contains(&CEPHX_GET_ROTATING_KEY), "{r:?}");
        for svc in [ENTITY_AUTH, ENTITY_MON, ENTITY_OSD, ENTITY_MGR] {
            assert!(c.ticket(svc).unwrap().have_key(w(T0 + 2)), "svc {svc:#x}");
        }
        assert_eq!(c.rotating().secrets.len(), 3);
    }
}

/// Clock-skew suspicion (spec sec 13): `current` (expires T0+3600) expired more than `auth_service_ticket_ttl` ago.
#[test]
fn rotating_clock_skew_bound_follows_the_ttl() {
    let (mut mon, k1, _) = setup(KeyType::Aes);
    let mut c = MonAuthClient::new(osd_cfg("osd.1", &k1));
    assert!(!c.rotating_clock_skew(w(T0 + 100_000)), "no set yet");
    handshake(&mut c, &mut mon, T0, false).unwrap();
    pump(&mut c, &mut mon, T0);
    assert!(!c.rotating_clock_skew(w(T0)));
    assert!(!c.rotating_clock_skew(w(T0 + 7199)));
    assert!(c.rotating_clock_skew(w(T0 + 7200)));
    c.set_service_ticket_ttl(7200);
    assert!(!c.rotating_clock_skew(w(T0 + 7200)));
    assert!(c.rotating_clock_skew(w(T0 + 10_800)));
}

/// AUTH_DONE must carry a GET_AUTH_SESSION_KEY reply. Any other cephx reply sealed with the entity key (a replayed
/// rotating or principal reply) is refused before it changes state: accepting it left the session without an AUTH
/// session key, i.e. an empty msgr2 signature key whose all-zero AUTH_SIGNATURE anyone can forge.
#[test]
fn auth_done_needs_an_auth_session_key_reply() {
    for ty in [KeyType::Aes, KeyType::Aes256Krb5] {
        let (mut mon, k1, _) = setup(ty);
        // a genuine session yields replies an attacker can record
        let mut c = MonAuthClient::new(osd_cfg("osd.1", &k1));
        handshake(&mut c, &mut mon, T0, false).unwrap();
        let rot_req = RequestHeader {
            request_type: CEPHX_GET_ROTATING_KEY,
        }
        .encode_to_vec()
        .unwrap();
        let rotating_reply = mon.request(&rot_req, T0).unwrap();
        // fresh client, first connect: the fake mon answers the challenge round with the recorded reply
        let mut v = MonAuthClient::new(osd_cfg("osd.1", &k1));
        let sc = mon.start(&v.start());
        v.on_reply_more(&sc, w(T0)).unwrap();
        assert!(matches!(
            v.on_done(0x4242, 1, &rotating_reply, w(T0)),
            Err(Error::Protocol(_))
        ));
        assert!(v.session_key().is_none());
        assert!(v.rotating().secrets.is_empty(), "nothing installed");
        assert_eq!(
            v.global_id(),
            0,
            "global_id of a refused AUTH_DONE not adopted"
        );
        // the same client completes a genuine handshake afterwards
        handshake(&mut v, &mut mon, T0, false).unwrap();
        assert!(v.session_key().is_some());
    }
}

/// MAuthReply pairing (spec sec 9): a reply with no current request (unsolicited, late after the request timed out,
/// or still in flight across `wipe-rotating-secrets`) is ignored and never installed; the session stays up and the
/// reply to the resend is installed. Before the fix such a reply dropped the mon session.
#[test]
fn stale_mon_reply_is_ignored_and_the_resend_still_installs() {
    let (mut mon, k1, _) = setup(KeyType::Aes256Krb5);
    let mut c = MonAuthClient::new(osd_cfg("osd.1", &k1));
    handshake(&mut c, &mut mon, T0, false).unwrap();
    pump(&mut c, &mut mon, T0);
    let rot_req = RequestHeader {
        request_type: CEPHX_GET_ROTATING_KEY,
    }
    .encode_to_vec()
    .unwrap();
    let rotating_reply = mon.request(&rot_req, T0).unwrap();

    // unsolicited: no request at all
    let before = c.rotating().clone();
    assert_eq!(
        c.on_response(0, mon.gid, &rotating_reply, w(T0)).unwrap(),
        MonReply::Ignored
    );
    assert_eq!(c.ignored_replies(), 1);
    assert!(c.session_key().is_some(), "session kept");
    assert_eq!(c.rotating(), &before, "nothing installed");

    // in flight across a wipe: the pre-wipe reply is dropped, the resend's reply installed
    let now = T0 + 5600;
    let r = c.poll(w(now)).unwrap().unwrap();
    assert_eq!(r.request_type, CEPHX_GET_PRINCIPAL_SESSION_KEY);
    let pre_wipe = mon.request(&r.payload, now).unwrap();
    c.wipe_secrets_and_tickets();
    assert!(!c.ticket(ENTITY_AUTH).unwrap().have_key(w(now)));
    let resend_req = c.poll(w(now)).unwrap().unwrap();
    assert_eq!(resend_req.request_type, CEPHX_GET_AUTH_SESSION_KEY);
    let resend = mon.request(&resend_req.payload, now).unwrap();
    assert_eq!(
        c.on_response(0, mon.gid, &pre_wipe, w(now)).unwrap(),
        MonReply::Ignored
    );
    assert!(
        !c.ticket(ENTITY_AUTH).unwrap().have_key(w(now)),
        "pre-wipe tickets refused"
    );
    assert_eq!(
        c.on_response(0, mon.gid, &resend, w(now)).unwrap(),
        MonReply::Installed
    );
    assert!(c.ticket(ENTITY_AUTH).unwrap().have_key(w(now)));
}

/// Two wipes before any reply: both pre-wipe replies are dropped in order, only the last resend's reply installs.
#[test]
fn mon_replies_across_two_wipes_install_only_the_last_resend() {
    let (mut mon, k1, _) = setup(KeyType::Aes);
    let mut c = MonAuthClient::new(osd_cfg("osd.1", &k1));
    handshake(&mut c, &mut mon, T0, false).unwrap();
    pump(&mut c, &mut mon, T0);
    let now = T0 + 5600;
    let a = c.poll(w(now)).unwrap().unwrap();
    let ra = mon.request(&a.payload, now).unwrap();
    c.wipe_secrets_and_tickets();
    let b = c.poll(w(now)).unwrap().unwrap();
    let rb = mon.request(&b.payload, now).unwrap();
    c.wipe_secrets_and_tickets();
    let cr = c.poll(w(now)).unwrap().unwrap();
    assert_eq!(cr.request_type, CEPHX_GET_AUTH_SESSION_KEY);
    let rc = mon.request(&cr.payload, now).unwrap();
    for (r, what) in [
        (&ra, "before the first wipe"),
        (&rb, "before the second wipe"),
    ] {
        assert_eq!(
            c.on_response(0, mon.gid, r, w(now)).unwrap(),
            MonReply::Ignored,
            "{what}"
        );
        assert!(!c.ticket(ENTITY_AUTH).unwrap().have_key(w(now)), "{what}");
    }
    assert_eq!(
        c.on_response(0, mon.gid, &rc, w(now)).unwrap(),
        MonReply::Installed
    );
    assert!(c.ticket(ENTITY_AUTH).unwrap().have_key(w(now)));
}

/// Wrong reply type for the request in flight: ignored, nothing installed, the right reply still installs.
#[test]
fn mon_reply_of_another_type_is_ignored() {
    let (mut mon, k1, _) = setup(KeyType::Aes);
    let mut c = MonAuthClient::new(osd_cfg("osd.1", &k1));
    handshake(&mut c, &mut mon, T0, false).unwrap();
    pump(&mut c, &mut mon, T0);
    let rot_req = RequestHeader {
        request_type: CEPHX_GET_ROTATING_KEY,
    }
    .encode_to_vec()
    .unwrap();
    let rotating_reply = mon.request(&rot_req, T0).unwrap();
    c.wipe_secrets_and_tickets();
    let req = c.poll(w(T0 + 1)).unwrap().unwrap();
    assert_eq!(req.request_type, CEPHX_GET_AUTH_SESSION_KEY);
    assert_eq!(
        c.on_response(0, mon.gid, &rotating_reply, w(T0 + 1))
            .unwrap(),
        MonReply::Ignored
    );
    assert!(c.rotating().secrets.is_empty());
    let answer = mon.request(&req.payload, T0 + 1).unwrap();
    assert_eq!(
        c.on_response(0, mon.gid, &answer, w(T0 + 1)).unwrap(),
        MonReply::Installed
    );
    assert!(c.ticket(ENTITY_AUTH).unwrap().have_key(w(T0 + 1)));
}

/// The rotating refresh throttle (one request per second) does not latch after a backward clock step.
#[test]
fn rotating_refresh_survives_a_backward_clock_step() {
    let (mut mon, k1, _) = setup(KeyType::Aes);
    let mut c = MonAuthClient::new(osd_cfg("osd.1", &k1));
    handshake(&mut c, &mut mon, T0, false).unwrap();
    let r = c.poll(w(T0 + 50)).unwrap().unwrap();
    assert_eq!(r.request_type, CEPHX_GET_ROTATING_KEY);
    // the mon fails it: no request in flight any more
    assert!(c.on_response(-11, mon.gid, &[], w(T0 + 50)).is_err());
    // same second: throttled
    assert!(c.poll(w(T0 + 50)).unwrap().is_none());
    // clock stepped back: refreshes again
    let r = c.poll(w(T0 + 10)).unwrap().unwrap();
    assert_eq!(r.request_type, CEPHX_GET_ROTATING_KEY);
}
