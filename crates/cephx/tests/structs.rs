// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Struct encodings: golden vectors from ceph-dencoder (testdata/cephx/dencoder) and round trips.

use cephx::none::EntityName;
use cephx::types::*;
use cephx::{CryptoKey, KeyType, UTime};
use denc::{Decode, Encode, from_slice};
use std::collections::BTreeMap;

fn golden<T>(name: &str, n: usize)
where
    T: for<'a> Decode<'a> + Encode + core::fmt::Debug + PartialEq,
{
    for i in 1..=n {
        let p = format!(
            "{}/../../testdata/cephx/dencoder/{name}.{i}.bin",
            env!("CARGO_MANIFEST_DIR")
        );
        let raw = std::fs::read(&p).unwrap_or_else(|e| panic!("{p}: {e}"));
        let v: T = from_slice(&raw).unwrap_or_else(|e| panic!("{name}.{i}: {e}"));
        assert_eq!(v.encode_to_vec().unwrap(), raw, "{name}.{i} re-encode");
    }
}

#[test]
fn dencoder_goldens() {
    golden::<CapsInfo>("AuthCapsInfo", 3);
    golden::<AuthTicket>("AuthTicket", 2);
    golden::<Authenticate>("CephXAuthenticate", 2);
    golden::<Authorize>("CephXAuthorize", 2);
    golden::<AuthorizeChallenge>("CephXAuthorizeChallenge", 1);
    golden::<AuthorizeReply>("CephXAuthorizeReply", 2);
    golden::<ChallengeBlob>("CephXChallengeBlob", 1);
    golden::<RequestHeader>("CephXRequestHeader", 1);
    golden::<ResponseHeader>("CephXResponseHeader", 1);
    golden::<ServerChallenge>("CephXServerChallenge", 1);
    golden::<ServiceTicket>("CephXServiceTicket", 2);
    golden::<ServiceTicketInfo>("CephXServiceTicketInfo", 2);
    golden::<ServiceTicketRequest>("CephXServiceTicketRequest", 1);
    golden::<TicketBlob>("CephXTicketBlob", 1);
    golden::<ExpiringCryptoKey>("ExpiringCryptoKey", 2);
    golden::<RotatingSecrets>("RotatingSecrets", 2);
    golden::<EntityName>("EntityName", 3);
}

fn key(ty: KeyType, c: u32) -> CryptoKey {
    CryptoKey::generate(ty, UTime::new(c, 5)).unwrap()
}

fn rt<T>(v: &T)
where
    T: for<'a> Decode<'a> + Encode + core::fmt::Debug + PartialEq,
{
    let b = v.encode_to_vec().unwrap();
    assert_eq!(&from_slice::<T>(&b).unwrap(), v);
}

#[test]
fn roundtrips() {
    rt(&RequestHeader {
        request_type: 0x0400,
    });
    rt(&ResponseHeader {
        request_type: 0x0200,
        status: -13,
    });
    rt(&ServerChallenge {
        server_challenge: 9,
    });
    rt(&ChallengeBlob {
        server_challenge: 1,
        client_challenge: 2,
    });
    let tb = TicketBlob {
        secret_id: u64::MAX,
        blob: vec![1, 2, 3],
    };
    rt(&tb);
    rt(&Authenticate {
        client_challenge: 1,
        key: 2,
        old_ticket: tb.clone(),
        other_keys: 0x35,
    });
    rt(&ServiceTicketRequest { keys: 0x14 });
    for ty in [KeyType::Aes, KeyType::Aes256Krb5] {
        let sk = key(ty, 100);
        rt(&ServiceTicket {
            session_key: sk.clone(),
            validity: UTime::new(3600, 0),
        });
        let t = AuthTicket {
            name: EntityName::parse("osd.3").unwrap().into(),
            global_id: 4242,
            auid: AUTH_UID_DEFAULT,
            created: UTime::new(10, 1),
            expires: UTime::new(20, 2),
            caps: CapsInfo::from_text("allow *"),
            flags: 0,
        };
        rt(&t);
        rt(&ServiceTicketInfo {
            ticket: t,
            session_key: sk.clone(),
        });
        let mut m = BTreeMap::new();
        for i in 1..=3u64 {
            m.insert(
                i,
                ExpiringCryptoKey {
                    key: key(ty, i as u32),
                    expiration: UTime::new(1000 + i as u32, 0),
                },
            );
        }
        let rs = RotatingSecrets {
            secrets: m,
            max_ver: 7,
        };
        rt(&rs);
        assert_eq!(rs.current().unwrap().0, &2);
        assert!(rs.get(3).is_some() && rs.get(4).is_none());
    }
    rt(&Authorize {
        nonce: 5,
        have_challenge: true,
        server_challenge_plus_one: 6,
    });
    rt(&AuthorizeChallenge {
        server_challenge: 77,
    });
    rt(&AuthorizeReply {
        nonce_plus_one: 3,
        connection_secret: vec![].into(),
    });
    rt(&AuthorizeReply {
        nonce_plus_one: 3,
        connection_secret: vec![9; 64].into(),
    });
}

#[test]
fn version_tolerance() {
    // Authorize v1: only nonce.
    let a: Authorize = from_slice(&[1, 5, 0, 0, 0, 0, 0, 0, 0]).unwrap();
    assert_eq!(a.nonce, 5);
    assert!(!a.have_challenge);
    // AuthorizeReply v1 has no secret, v2 has.
    let mut v1 = vec![1u8];
    v1.extend(8u64.to_le_bytes());
    assert!(
        from_slice::<AuthorizeReply>(&v1)
            .unwrap()
            .connection_secret
            .is_empty()
    );
    // the connection secret never reaches a Debug rendering
    let r = AuthorizeReply {
        nonce_plus_one: 1,
        connection_secret: vec![0xab; 64].into(),
    };
    let dbg = format!("{r:?}");
    assert!(
        dbg.contains("connection_secret_len: 64") && !dbg.contains("171"),
        "{dbg}"
    );
    // Authenticate v1 (no other_keys), ticket omitted.
    let mut a1 = vec![1u8];
    a1.extend(1u64.to_le_bytes());
    a1.extend(2u64.to_le_bytes());
    let a: Authenticate = from_slice(&a1).unwrap();
    assert_eq!((a.client_challenge, a.key, a.other_keys), (1, 2, 0));
    assert_eq!(a.old_ticket, TicketBlob::default());
    // Truncations never panic.
    let full = Authenticate::default().encode_to_vec().unwrap();
    for n in 0..full.len() {
        assert!(from_slice::<Authenticate>(&full[..n]).is_err() || n >= 17);
    }
}

#[test]
fn caps_text() {
    let c = CapsInfo::from_text("allow rwx");
    assert_eq!(c.text().unwrap().as_deref(), Some("allow rwx"));
    assert_eq!(CapsInfo::default().text().unwrap(), None);
    let mut bad = c.clone();
    bad.caps.push(0);
    assert!(bad.text().is_err());
}
