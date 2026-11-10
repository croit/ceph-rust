// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
use cephx::monclient::{MonAuthClient, MonAuthConfig};
use cephx::none::{
    ByteEntityName, EntityName, NoneAuthorizer, NoneMonClient, mon_auth_payload, none_authorizer,
    verify_none,
};
use cephx::{CryptoKey, KeyType};
use denc::{Decode, Decoder};

fn expected(mode: u8, ty: u32, id: &[u8], gid: u64) -> Vec<u8> {
    let mut bytes = vec![mode];
    bytes.extend_from_slice(&ty.to_le_bytes());
    bytes.extend_from_slice(&(id.len() as u32).to_le_bytes());
    bytes.extend_from_slice(id);
    bytes.extend_from_slice(&gid.to_le_bytes());
    bytes
}

#[test]
fn byte_entity_roles_and_suffixes_have_exact_shared_wire_vectors() {
    for (role, ty) in [
        (b"auth".as_slice(), 32u32),
        (b"mon", 1),
        (b"osd", 4),
        (b"mds", 2),
        (b"mgr", 16),
        (b"client", 8),
    ] {
        for id in [
            b"".as_slice(),
            b" ",
            b" leading and trailing ",
            b"name with spaces",
            b"nested.id.more",
            b"\xc3\xa4",
            b"\xff\x80.$id name",
        ] {
            let mut full = role.to_vec();
            full.push(b'.');
            full.extend_from_slice(id);
            let name = ByteEntityName::parse_bytes(&full).unwrap();
            assert_eq!(name.ty, ty);
            assert_eq!(name.id, id);
            let mon = expected(10, ty, id, 77);
            let service = expected(1, ty, id, 77);
            assert_eq!(mon_auth_payload(&name, 77), mon);
            assert_eq!(none_authorizer(&name, 77), service);
            assert_eq!(denc::to_vec(&name).unwrap(), mon[1..mon.len() - 8]);
            assert_eq!(
                ByteEntityName::decode(&mut Decoder::new(&mon[1..])).unwrap(),
                name
            );
            if let Ok(text) = std::str::from_utf8(&full) {
                let native: EntityName = EntityName::parse(text).unwrap();
                assert_eq!(native, name);
                assert_eq!(mon_auth_payload(&native, 77), mon);
                assert_eq!(none_authorizer(&native, 77), service);
                assert_eq!(denc::to_vec(&native).unwrap(), denc::to_vec(&name).unwrap());
            }
        }
    }
    for full in [
        b"".as_slice(),
        b"client",
        b"unknown.x",
        b"CLIENT.x",
        b"cl\xffient.x",
    ] {
        assert!(ByteEntityName::parse_bytes(full).is_none());
    }
}

#[test]
fn byte_clients_and_authorizers_own_identity_after_input_and_config_drop() {
    let mut input = b"mgr.\xff name.more".to_vec();
    let name = ByteEntityName::parse_bytes(&input).unwrap();
    input.fill(b'x');
    let wanted = expected(10, 16, b"\xff name.more", 77);
    let mut none = NoneMonClient::new_bytes(name.clone(), 77);
    let config = MonAuthConfig {
        name: name.clone(),
        key: CryptoKey::new(KeyType::Aes, Default::default(), &[7; 16]),
        want: 1 | 4 | 16 | 32,
        want_rotating: false,
        service_ticket_ttl: 3600,
    };
    let mut cephx = MonAuthClient::with_global_id_bytes(config, 77);
    let authorizer = NoneAuthorizer::new(&name, 77);
    drop(name);
    assert_eq!(none.start(), wanted);
    assert_eq!(cephx.start(), wanted);
    let mut cloned = cephx.clone();
    drop(cephx);
    assert_eq!(cloned.start(), wanted);
    assert_eq!(authorizer.payload(), expected(1, 16, b"\xff name.more", 77));
    none.on_done(99, &[]);
    assert_eq!(none.start(), expected(10, 16, b"\xff name.more", 99));
}

#[test]
fn byte_decoder_does_not_relax_native_text_or_service_verifiers() {
    let wire = expected(1, 8, b"\xff", 77);
    assert!(<EntityName as Decode>::decode(&mut Decoder::new(&wire[1..])).is_err());
    assert!(verify_none(&wire).is_err());
    let name = ByteEntityName::decode(&mut Decoder::new(&wire[1..])).unwrap();
    assert_eq!(name.id, [255]);
    let native = EntityName::parse("client.native").unwrap();
    assert_eq!(
        verify_none(&none_authorizer(&native, 77)).unwrap().name,
        native
    );
}
