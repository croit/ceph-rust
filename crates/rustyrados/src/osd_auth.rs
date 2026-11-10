// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
use crate::MessengerMode;
use cephx::{
    Authorizer,
    modes::{AUTH_CEPHX, CON_MODE_SECURE},
    none::ENTITY_OSD,
    ticket::TicketHandler,
};
use msgr2::auth::{AuthClientHandler, AuthError, AuthRequestOut, AuthSecrets};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OsdAuthError {
    Identity,
    Service,
    Ticket,
    Phase,
    Peer,
    Authorizer,
    Challenge,
    Reply,
    Mode,
    Secret,
    Rejected,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    New,
    Requested,
    Done,
    Failed,
}
/// Cold, single-owner OSD service authentication with a fixed client identity. Takes no clock: a cached
/// ticket stays usable after local expiry until the peer drops its sealing key (classic cephx).
pub struct OsdAuth {
    gid: u64,
    service: u32,
    ticket: TicketHandler,
    mode: MessengerMode,
    authorizer: Option<Authorizer>,
    phase: Phase,
}
impl std::fmt::Debug for OsdAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OsdAuth")
            .field("phase", &self.phase)
            .finish_non_exhaustive()
    }
}
impl OsdAuth {
    /// Capture a cached OSD ticket. Recreate after rejection;
    /// a renewed monitor ticket does not mutate this snapshot.
    pub fn new(gid: u64, ticket: TicketHandler, mode: MessengerMode) -> Result<Self, OsdAuthError> {
        Self::for_service(gid, ticket, mode, ENTITY_OSD)
    }
    /// Independent service authorizer for an authenticated manager connection.
    pub fn new_manager(
        gid: u64,
        ticket: TicketHandler,
        mode: MessengerMode,
    ) -> Result<Self, OsdAuthError> {
        Self::for_service(gid, ticket, mode, cephx::none::ENTITY_MGR)
    }
    /// Independent service authorizer for an authenticated metadata connection.
    pub fn new_mds(
        gid: u64,
        ticket: TicketHandler,
        mode: MessengerMode,
    ) -> Result<Self, OsdAuthError> {
        Self::for_service(gid, ticket, mode, cephx::none::ENTITY_MDS)
    }
    fn for_service(
        gid: u64,
        ticket: TicketHandler,
        mode: MessengerMode,
        service: u32,
    ) -> Result<Self, OsdAuthError> {
        if gid == 0 {
            return Err(OsdAuthError::Identity);
        }
        if ticket.service_id != service {
            return Err(OsdAuthError::Service);
        }
        if ticket.session_key().is_none() {
            return Err(OsdAuthError::Ticket);
        }
        Ok(Self {
            gid,
            service,
            ticket,
            mode,
            authorizer: None,
            phase: Phase::New,
        })
    }
    fn fail<T>(&mut self, error: OsdAuthError) -> Result<T, AuthError> {
        self.phase = Phase::Failed;
        self.authorizer = None;
        Err(AuthError(format!("native OSD auth: {error:?}")))
    }
    fn current(&mut self) -> Result<(), AuthError> {
        if self.phase == Phase::Failed {
            return self.fail(OsdAuthError::Phase);
        }
        Ok(())
    }
}
impl AuthClientHandler for OsdAuth {
    fn get_auth_request(&mut self, peer_type: u8) -> Result<AuthRequestOut, AuthError> {
        self.current()?;
        if u32::from(peer_type) != self.service {
            return self.fail(OsdAuthError::Peer);
        }
        let authorizer = match Authorizer::new(self.gid, self.service, &self.ticket) {
            Ok(authorizer) => authorizer,
            Err(_) => return self.fail(OsdAuthError::Authorizer),
        };
        let payload = authorizer.payload().to_vec();
        self.authorizer = Some(authorizer);
        self.phase = Phase::Requested;
        Ok(AuthRequestOut {
            method: AUTH_CEPHX,
            preferred_modes: self.mode.modes(),
            payload,
        })
    }
    fn handle_auth_reply_more(&mut self, payload: &[u8]) -> Result<Vec<u8>, AuthError> {
        self.current()?;
        if self.phase != Phase::Requested {
            return self.fail(OsdAuthError::Phase);
        }
        match self.authorizer.as_mut().unwrap().on_reply_more(payload) {
            Ok(payload) => Ok(payload.to_vec()),
            Err(_) => self.fail(OsdAuthError::Challenge),
        }
    }
    fn handle_auth_done(
        &mut self,
        _global_id: u64,
        mode: u32,
        payload: &[u8],
    ) -> Result<AuthSecrets, AuthError> {
        self.current()?;
        if self.phase != Phase::Requested {
            return self.fail(OsdAuthError::Phase);
        }
        if !self.mode.accepts(mode) {
            return self.fail(OsdAuthError::Mode);
        }
        let authorizer = self.authorizer.as_mut().unwrap();
        if authorizer.on_done(payload).is_err() {
            return self.fail(OsdAuthError::Reply);
        }
        let connection_secret = authorizer
            .connection_secret()
            .map(|s| s.as_bytes())
            .unwrap_or_default();
        if mode == CON_MODE_SECURE && connection_secret.len() < 40 {
            return self.fail(OsdAuthError::Secret);
        }
        let secrets = AuthSecrets {
            session_key: authorizer.session_key().secret().to_vec(),
            connection_secret: connection_secret.to_vec(),
        };
        self.phase = Phase::Done;
        Ok(secrets)
    }
    fn handle_auth_bad_method(
        &mut self,
        _: u32,
        _: i32,
        _: &[u32],
        _: &[u32],
    ) -> Result<(), AuthError> {
        self.fail(OsdAuthError::Rejected)
    }
}

/// Ticketless client service auth. The service role is local policy, not wire identity.
pub struct NoneServiceAuth {
    authorizer: cephx::none::NoneAuthorizer,
    service: u32,
    mode: MessengerMode,
    phase: Phase,
}
impl std::fmt::Debug for NoneServiceAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoneServiceAuth")
            .field("phase", &self.phase)
            .finish_non_exhaustive()
    }
}
impl NoneServiceAuth {
    pub fn new(
        name: cephx::none::EntityName,
        gid: u64,
        service: u32,
        mode: MessengerMode,
    ) -> Result<Self, OsdAuthError> {
        Self::new_bytes(name.into(), gid, service, mode)
    }
    pub fn new_bytes(
        name: cephx::none::ByteEntityName,
        gid: u64,
        service: u32,
        mode: MessengerMode,
    ) -> Result<Self, OsdAuthError> {
        if gid == 0 || cephx::none::type_name(name.ty).is_none() || name.id.contains(&0) {
            return Err(OsdAuthError::Identity);
        }
        if !matches!(
            service,
            ENTITY_OSD | cephx::none::ENTITY_MDS | cephx::none::ENTITY_MGR
        ) {
            return Err(OsdAuthError::Service);
        }
        if !mode.accepts(cephx::modes::CON_MODE_CRC) {
            return Err(OsdAuthError::Mode);
        }
        Ok(Self {
            authorizer: cephx::none::NoneAuthorizer::new(&name, gid),
            service,
            mode,
            phase: Phase::New,
        })
    }
    fn fail<T>(&mut self, error: OsdAuthError) -> Result<T, AuthError> {
        self.phase = Phase::Failed;
        Err(AuthError(format!("native NONE service auth: {error:?}")))
    }
}
impl AuthClientHandler for NoneServiceAuth {
    fn get_auth_request(&mut self, peer_type: u8) -> Result<AuthRequestOut, AuthError> {
        // The messenger may restart a new stream with the same fixed identity.
        if self.phase == Phase::Failed {
            return self.fail(OsdAuthError::Phase);
        }
        if u32::from(peer_type) != self.service {
            return self.fail(OsdAuthError::Peer);
        }
        let preferred_modes: Vec<_> = self
            .mode
            .modes()
            .into_iter()
            .filter(|&m| m == cephx::modes::CON_MODE_CRC)
            .collect();
        if preferred_modes.is_empty() {
            return self.fail(OsdAuthError::Mode);
        }
        self.phase = Phase::Requested;
        Ok(AuthRequestOut {
            method: cephx::modes::AUTH_NONE,
            preferred_modes,
            payload: self.authorizer.payload().to_vec(),
        })
    }
    fn handle_auth_reply_more(&mut self, _: &[u8]) -> Result<Vec<u8>, AuthError> {
        self.fail(OsdAuthError::Challenge)
    }
    fn handle_auth_done(
        &mut self,
        _global_id: u64,
        mode: u32,
        _payload: &[u8],
    ) -> Result<AuthSecrets, AuthError> {
        if self.phase != Phase::Requested {
            return self.fail(OsdAuthError::Phase);
        }
        if mode != cephx::modes::CON_MODE_CRC || !self.mode.accepts(mode) {
            return self.fail(OsdAuthError::Mode);
        }
        // Service AUTH_DONE never reassigns the monitor-owned identity.
        self.phase = Phase::Done;
        Ok(AuthSecrets::default())
    }
    fn handle_auth_bad_method(
        &mut self,
        _: u32,
        _: i32,
        _: &[u32],
        _: &[u32],
    ) -> Result<(), AuthError> {
        self.fail(OsdAuthError::Rejected)
    }
}

#[cfg(test)]
mod none_tests {
    use super::*;
    use cephx::{
        modes::{AUTH_NONE, CON_MODE_CRC},
        none::{ENTITY_MDS, ENTITY_MGR, ENTITY_MON, EntityName},
    };
    #[test]
    fn byte_none_service_auth_owns_exact_wire_and_keeps_identity_validation() {
        for service in [ENTITY_OSD, ENTITY_MDS, ENTITY_MGR] {
            let mut name =
                cephx::none::ByteEntityName::parse_bytes(b"auth.\xff spaces.more").unwrap();
            let mut auth =
                NoneServiceAuth::new_bytes(name.clone(), 77, service, MessengerMode::Crc).unwrap();
            name.id.fill(b'x');
            drop(name);
            let request = auth.get_auth_request(service as u8).unwrap();
            let mut wanted = vec![1, 32, 0, 0, 0, 13, 0, 0, 0];
            wanted.extend_from_slice(b"\xff spaces.more");
            wanted.extend_from_slice(&77u64.to_le_bytes());
            assert_eq!(request.payload, wanted);
            let bad = cephx::none::ByteEntityName::parse_bytes(b"client.a\0b").unwrap();
            assert!(matches!(
                NoneServiceAuth::new_bytes(bad, 77, service, MessengerMode::Crc),
                Err(OsdAuthError::Identity)
            ));
        }
    }

    fn handler(service: u32, mode: MessengerMode) -> NoneServiceAuth {
        NoneServiceAuth::new(
            EntityName::parse("client.none-test").unwrap(),
            0x1234,
            service,
            mode,
        )
        .unwrap()
    }
    #[test]
    fn none_osd_and_manager_requests_have_exact_identity_bytes_and_no_secrets() {
        for service in [ENTITY_OSD, ENTITY_MDS, ENTITY_MGR] {
            for mode in [
                MessengerMode::Crc,
                MessengerMode::PreferSecure,
                MessengerMode::PreferCrc,
            ] {
                let mut auth = handler(service, mode);
                let request = auth.get_auth_request(service as u8).unwrap();
                assert_eq!(request.method, AUTH_NONE);
                assert_eq!(request.preferred_modes, vec![CON_MODE_CRC]);
                let mut expected = vec![1, 8, 0, 0, 0, 9, 0, 0, 0];
                expected.extend_from_slice(b"none-test");
                expected.extend_from_slice(&0x1234_u64.to_le_bytes());
                assert_eq!(request.payload, expected);
                // Both the service's id and opaque payload are ignored, not adopted.
                let secrets = auth
                    .handle_auth_done(999, CON_MODE_CRC, b"ignored")
                    .unwrap();
                assert!(secrets.session_key.is_empty());
                assert!(secrets.connection_secret.is_empty());
                let restarted = auth.get_auth_request(service as u8).unwrap();
                assert_eq!(restarted.payload, expected);
                auth.handle_auth_done(999, CON_MODE_CRC, &[]).unwrap();
                assert!(auth.handle_auth_done(0x1234, CON_MODE_CRC, &[]).is_err());
                assert!(auth.get_auth_request(service as u8).is_err());
            }
        }
    }
    #[test]
    fn none_authorizer_preserves_generic_role_empty_and_whitespace_ids() {
        for role in ["auth", "mon", "osd", "mds", "mgr", "client"] {
            for id in ["", "name with spaces", "nested.id"] {
                let name = EntityName::parse(&format!("{role}.{id}")).unwrap();
                for service in [ENTITY_OSD, ENTITY_MDS, ENTITY_MGR] {
                    let mut auth =
                        NoneServiceAuth::new(name.clone(), 77, service, MessengerMode::Crc)
                            .unwrap();
                    let request = auth.get_auth_request(service as u8).unwrap();
                    let mut expected = vec![1];
                    expected.extend_from_slice(&name.ty.to_le_bytes());
                    expected.extend_from_slice(&(id.len() as u32).to_le_bytes());
                    expected.extend_from_slice(id.as_bytes());
                    expected.extend_from_slice(&77_u64.to_le_bytes());
                    assert_eq!(request.payload, expected);
                }
            }
        }
        assert!(matches!(
            NoneServiceAuth::new(
                EntityName {
                    ty: 255,
                    id: "test".into()
                },
                77,
                ENTITY_OSD,
                MessengerMode::Crc
            ),
            Err(OsdAuthError::Identity)
        ));
    }
    #[test]
    fn none_service_identity_role_and_secure_only_are_rejected() {
        for (name, gid) in [("client.none-test", 0), ("client.bad\0name", 77)] {
            assert!(matches!(
                NoneServiceAuth::new(
                    EntityName::parse(name).unwrap(),
                    gid,
                    ENTITY_OSD,
                    MessengerMode::Crc
                ),
                Err(OsdAuthError::Identity)
            ));
        }
        assert!(matches!(
            NoneServiceAuth::new(
                EntityName::parse("client.test").unwrap(),
                77,
                ENTITY_MON,
                MessengerMode::Crc
            ),
            Err(OsdAuthError::Service)
        ));
        assert!(matches!(
            NoneServiceAuth::new(
                EntityName::parse("client.test").unwrap(),
                77,
                ENTITY_OSD,
                MessengerMode::Secure
            ),
            Err(OsdAuthError::Mode)
        ));
        for (service, wrong) in [(ENTITY_OSD, ENTITY_MGR), (ENTITY_MGR, ENTITY_OSD)] {
            let mut auth = handler(service, MessengerMode::Crc);
            assert!(auth.get_auth_request(wrong as u8).is_err());
            assert!(auth.get_auth_request(service as u8).is_err());
            assert!(auth.handle_auth_done(77, CON_MODE_CRC, &[]).is_err());
        }
    }
    #[test]
    fn none_service_phase_challenge_mode_and_rejection_fail_closed() {
        for service in [ENTITY_OSD, ENTITY_MDS, ENTITY_MGR] {
            let mut auth = handler(service, MessengerMode::Crc);
            assert!(auth.handle_auth_done(77, CON_MODE_CRC, &[]).is_err());
            let mut auth = handler(service, MessengerMode::Crc);
            auth.get_auth_request(service as u8).unwrap();
            assert!(auth.handle_auth_reply_more(&[]).is_err());
            assert!(auth.handle_auth_done(77, CON_MODE_CRC, &[]).is_err());
            let mut auth = handler(service, MessengerMode::PreferSecure);
            auth.get_auth_request(service as u8).unwrap();
            assert!(auth.handle_auth_done(77, CON_MODE_SECURE, &[]).is_err());
            assert!(auth.handle_auth_done(77, CON_MODE_CRC, &[]).is_err());
            let mut auth = handler(service, MessengerMode::Crc);
            auth.get_auth_request(service as u8).unwrap();
            assert!(
                auth.handle_auth_bad_method(AUTH_NONE, -95, &[AUTH_CEPHX], &[CON_MODE_CRC])
                    .is_err()
            );
            assert!(auth.handle_auth_done(77, CON_MODE_CRC, &[]).is_err());
        }
    }
}

#[cfg(test)]
mod cephx_tests {
    use super::*;
    use cephx::{CryptoKey, key::KeyType, modes::AUTH_CEPHX, none::ENTITY_MDS};
    use std::time::Duration;

    fn ticket(service: u32, validity: u32) -> TicketHandler {
        let mut t = TicketHandler::new(service);
        t.install(
            cephx::ticket::TicketEntry {
                service_id: service,
                session_key: CryptoKey::new(KeyType::Aes, Default::default(), &[7; 16]),
                validity: denc::types::UTime {
                    sec: validity,
                    nsec: 0,
                },
                blob: cephx::types::TicketBlob {
                    secret_id: 11,
                    blob: vec![1, 2, 3],
                },
            },
            Duration::from_secs(100),
        );
        t
    }

    #[test]
    fn mds_authorizer_carries_mds_identity_and_rejects_foreign_tickets() {
        let mut auth = OsdAuth::new_mds(77, ticket(ENTITY_MDS, 3600), MessengerMode::Crc).unwrap();
        let request = auth.get_auth_request(ENTITY_MDS as u8).unwrap();
        assert_eq!(request.method, AUTH_CEPHX);
        // base_bl: mode 1, global id, service id, ticket blob.
        assert_eq!(request.payload[0], cephx::none::AUTH_MODE_AUTHORIZER);
        assert_eq!(&request.payload[1..9], &77_u64.to_le_bytes());
        assert_eq!(&request.payload[9..13], &ENTITY_MDS.to_le_bytes());
        // A peer other than MDS is refused before anything reaches the wire.
        assert!(auth.get_auth_request(ENTITY_OSD as u8).is_err());

        for foreign in [ENTITY_OSD, cephx::none::ENTITY_MGR] {
            assert!(matches!(
                OsdAuth::new_mds(77, ticket(foreign, 3600), MessengerMode::Crc),
                Err(OsdAuthError::Service)
            ));
        }
        assert!(matches!(
            OsdAuth::new_mds(0, ticket(ENTITY_MDS, 3600), MessengerMode::Crc),
            Err(OsdAuthError::Identity)
        ));
        assert!(matches!(
            OsdAuth::new_mds(77, TicketHandler::new(ENTITY_MDS), MessengerMode::Crc),
            Err(OsdAuthError::Ticket)
        ));
    }
}
