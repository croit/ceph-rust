// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
use cephx::{
    CryptoKey, KeyType, Usage,
    envelope::{open_wrapped_t, seal_raw_t, seal_wrapped_t},
    none::ENTITY_OSD,
    ticket::{TicketEntry, TicketHandler},
    types::{Authorize, AuthorizeChallenge, AuthorizeReply, TicketBlob},
};
use denc::{Decode, Decoder};
use msgr2::auth::{AuthClientHandler, MODE_CRC, MODE_SECURE};
use rustyrados::{MessengerMode, OsdAuth, OsdAuthError};
use std::time::Duration;

fn key() -> CryptoKey {
    CryptoKey::new(KeyType::Aes, Default::default(), b"0123456789abcdef")
}
fn ticket() -> TicketHandler {
    service_ticket(ENTITY_OSD)
}
fn service_ticket(service: u32) -> TicketHandler {
    let mut ticket = TicketHandler::new(service);
    ticket.install(
        TicketEntry {
            service_id: service,
            session_key: key(),
            validity: denc::types::UTime::new(60, 0),
            blob: TicketBlob {
                secret_id: 9,
                blob: b"opaque ticket".to_vec(),
            },
        },
        Duration::from_secs(1000),
    );
    ticket
}
fn auth(mode: MessengerMode) -> OsdAuth {
    OsdAuth::new(77, ticket(), mode).unwrap()
}
fn decode(payload: &[u8]) -> Authorize {
    let mut d = Decoder::new(payload);
    assert_eq!(d.u8().unwrap(), 1);
    assert_eq!(d.u64().unwrap(), 77);
    assert_eq!(d.u32().unwrap(), ENTITY_OSD);
    let blob = TicketBlob::decode(&mut d).unwrap();
    assert_eq!(blob.secret_id, 9);
    assert_eq!(blob.blob, b"opaque ticket");
    open_wrapped_t(&key(), Usage::Authorize, &mut d).unwrap()
}
fn reply(nonce: u64, secret: &[u8]) -> Vec<u8> {
    seal_wrapped_t(
        &key(),
        Usage::AuthorizeReply,
        &AuthorizeReply {
            nonce_plus_one: nonce.wrapping_add(1),
            connection_secret: secret.to_vec().into(),
        },
    )
    .unwrap()
}

#[test]
fn crc_and_secure_publish_only_verified_secrets_and_keep_fixed_service_identity() {
    for (policy, mode, secret) in [
        (MessengerMode::Crc, MODE_CRC, vec![]),
        (MessengerMode::Secure, MODE_SECURE, vec![0x42; 64]),
    ] {
        let mut a = auth(policy);
        let req = a.get_auth_request(ENTITY_OSD as u8).unwrap();
        assert_eq!(req.method, 2);
        assert_eq!(req.preferred_modes, vec![mode]);
        let first = decode(&req.payload);
        assert!(!first.have_challenge);
        let out = a
            .handle_auth_done(999, mode, &reply(first.nonce, &secret))
            .unwrap();
        assert_eq!(out.session_key, b"0123456789abcdef");
        assert_eq!(out.connection_secret, secret);
        assert!(
            a.handle_auth_done(77, mode, &reply(first.nonce, &[]))
                .is_err()
        );
    }
}
#[test]
fn challenge_and_restart_use_fresh_nonce_and_preserve_ticket_identity() {
    let mut a = auth(MessengerMode::PreferSecure);
    let first = a.get_auth_request(4).unwrap();
    assert_eq!(first.preferred_modes, vec![2, 1]);
    let old = decode(&first.payload);
    let more = seal_raw_t(
        &key(),
        Usage::AuthorizeChallenge,
        &AuthorizeChallenge {
            server_challenge: 123,
        },
    )
    .unwrap();
    let challenged = decode(&a.handle_auth_reply_more(&more).unwrap());
    assert_eq!(challenged.nonce, old.nonce);
    assert!(challenged.have_challenge);
    assert_eq!(challenged.server_challenge_plus_one, 124);
    a.handle_auth_done(0, MODE_CRC, &reply(old.nonce, &[]))
        .unwrap();
    let next = decode(&a.get_auth_request(4).unwrap().payload);
    assert_ne!(next.nonce, old.nonce);
    assert!(!next.have_challenge);
    assert!(
        a.handle_auth_done(0, MODE_CRC, &reply(old.nonce, &[]))
            .is_err()
    );
}

#[test]
fn crc_first_policy_retains_secure_fallback_and_rejects_unoffered_modes() {
    for mode in [MODE_CRC, MODE_SECURE] {
        let mut a = auth(MessengerMode::PreferCrc);
        let request = a.get_auth_request(4).unwrap();
        assert_eq!(request.preferred_modes, vec![1, 2]);
        let nonce = decode(&request.payload).nonce;
        let secret = if mode == MODE_SECURE {
            vec![0x42; 64]
        } else {
            vec![]
        };
        let verified = a
            .handle_auth_done(77, mode, &reply(nonce, &secret))
            .unwrap();
        assert_eq!(verified.connection_secret, secret);
    }
    for mode in [0, 3, u32::MAX] {
        let mut a = auth(MessengerMode::PreferCrc);
        let request = a.get_auth_request(4).unwrap();
        let nonce = decode(&request.payload).nonce;
        assert!(a.handle_auth_done(77, mode, &reply(nonce, &[])).is_err());
        assert!(a.get_auth_request(4).is_err());
    }
}
#[test]
fn role_identity_and_service_rejections_are_local() {
    assert_eq!(
        OsdAuth::new(0, ticket(), MessengerMode::Crc).unwrap_err(),
        OsdAuthError::Identity
    );
    let mut t = ticket();
    t.service_id = 1;
    assert_eq!(
        OsdAuth::new(77, t, MessengerMode::Crc).unwrap_err(),
        OsdAuthError::Service
    );
    // Local expiry (60 s ticket installed at 1000 s) and invalidation schedule renewal only: the cached
    // authorizer stays usable at the peer's discretion (classic cephx; NT-authrotate-02).
    let mut t = ticket();
    assert!(!t.have_key(Duration::from_secs(1060)));
    t.invalidate();
    let mut a = OsdAuth::new(77, t, MessengerMode::Crc).unwrap();
    assert!(!decode(&a.get_auth_request(4).unwrap().payload).have_challenge);
    let mut a = auth(MessengerMode::Crc);
    assert!(a.get_auth_request(1).unwrap_err().0.ends_with("Peer"));
    assert!(a.get_auth_request(4).is_err());
}
#[test]
fn malformed_done_wrong_mode_missing_secure_secret_and_bad_method_never_fall_back() {
    let mut a = auth(MessengerMode::Secure);
    let nonce = decode(&a.get_auth_request(4).unwrap().payload).nonce;
    assert!(
        a.handle_auth_done(77, MODE_CRC, &reply(nonce, &[]))
            .unwrap_err()
            .0
            .ends_with("Mode")
    );
    let mut a = auth(MessengerMode::Secure);
    let nonce = decode(&a.get_auth_request(4).unwrap().payload).nonce;
    assert!(
        a.handle_auth_done(77, MODE_SECURE, &reply(nonce, &[]))
            .unwrap_err()
            .0
            .ends_with("Secret")
    );
    let mut a = auth(MessengerMode::Crc);
    a.get_auth_request(4).unwrap();
    let error = a
        .handle_auth_done(77, MODE_CRC, b"SECRET-MARKER")
        .unwrap_err();
    assert!(!error.0.contains("SECRET-MARKER"));
    let mut a = auth(MessengerMode::Crc);
    assert!(a.handle_auth_bad_method(2, -95, &[1], &[1]).is_err());
    assert!(a.get_auth_request(4).is_err());
    assert!(!format!("{a:?}").contains("opaque ticket"));
}
#[test]
fn callbacks_before_request_are_rejected() {
    let mut a = auth(MessengerMode::Crc);
    assert!(a.handle_auth_reply_more(&[]).is_err());
    assert!(a.handle_auth_done(77, MODE_CRC, &reply(1, &[])).is_err());
}

#[test]
fn manager_authorizers_bind_ticket_and_peer_service_before_releasing_secrets() {
    use cephx::none::ENTITY_MGR;
    assert!(matches!(
        OsdAuth::new_manager(77, ticket(), MessengerMode::Crc),
        Err(OsdAuthError::Service)
    ));
    assert!(matches!(
        OsdAuth::new(77, service_ticket(ENTITY_MGR), MessengerMode::Crc),
        Err(OsdAuthError::Service)
    ));
    let mut wrong_peer =
        OsdAuth::new_manager(77, service_ticket(ENTITY_MGR), MessengerMode::Crc).unwrap();
    assert!(wrong_peer.get_auth_request(ENTITY_OSD as u8).is_err());
    for (policy, mode, secret) in [
        (MessengerMode::Crc, MODE_CRC, vec![]),
        (MessengerMode::Secure, MODE_SECURE, vec![0x42; 64]),
    ] {
        let mut auth = OsdAuth::new_manager(77, service_ticket(ENTITY_MGR), policy).unwrap();
        let req = auth.get_auth_request(ENTITY_MGR as u8).unwrap();
        let mut d = Decoder::new(&req.payload);
        assert_eq!(d.u8().unwrap(), 1);
        assert_eq!(d.u64().unwrap(), 77);
        assert_eq!(d.u32().unwrap(), ENTITY_MGR);
        TicketBlob::decode(&mut d).unwrap();
        let nonce = open_wrapped_t::<Authorize>(&key(), Usage::Authorize, &mut d)
            .unwrap()
            .nonce;
        let verified = auth
            .handle_auth_done(999, mode, &reply(nonce, &secret))
            .unwrap();
        assert_eq!(verified.connection_secret, secret);
    }
}
