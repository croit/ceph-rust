// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Control-frame payloads (spec 7, 8.1). Each type knows its [`Tag`]; [`Payload::to_bytes`] /
//! [`Payload::from_bytes`] convert to/from the single control segment. Addresses are always
//! encoded in the addr2 form (spec 0). Trailing bytes after the known fields are ignored on decode.
use crate::Tag;
use denc::types::{EntityAddr, EntityAddrVec};
use denc::{BufMut, Decode, Decoder, Encode, Encoder, Error, Result};

/// A control-frame payload.
pub trait Payload: Sized {
    /// Frame tag carrying this payload.
    const TAG: Tag;
    /// Append the encoded fields.
    fn enc<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()>;
    /// Decode the fields (trailing bytes are left unread).
    fn dec(d: &mut Decoder<'_>) -> Result<Self>;

    /// Encode to a fresh Vec. A field that cannot be represented (>4 GiB) is an error: a partially encoded payload
    /// must never be framed.
    fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut e = Encoder::new();
        self.enc(&mut e)?;
        Ok(e.into_vec())
    }
    /// Decode from a control segment.
    fn from_bytes(b: &[u8]) -> Result<Self> {
        Self::dec(&mut Decoder::new(b))
    }
}

fn enc_vec32<B: BufMut>(e: &mut Encoder<B>, v: &[u32]) -> Result<()> {
    e.count(v.len())?;
    v.iter().try_for_each(|x| e.u32(*x))
}
fn dec_vec32(d: &mut Decoder<'_>) -> Result<Vec<u32>> {
    let n = d.count()?;
    (0..n).map(|_| d.u32()).collect()
}

macro_rules! payload {
    ($(#[$m:meta])* $name:ident, $tag:ident { $($(#[$fm:meta])* $f:ident : $t:ty),* $(,)? },
     |$e:ident, $s:ident| $enc:block, |$d:ident| $dec:block) => {
        $(#[$m])*
        #[derive(Clone, Debug, PartialEq, Eq, Default)]
        pub struct $name { $($(#[$fm])* pub $f: $t),* }
        impl Payload for $name {
            const TAG: Tag = Tag::$tag;
            fn enc<B: BufMut>(&$s, $e: &mut Encoder<B>) -> Result<()> $enc
            fn dec($d: &mut Decoder<'_>) -> Result<Self> $dec
        }
    };
}

payload!(
    /// HELLO (7.1).
    Hello, Hello {
        /// Sender's entity type.
        entity_type: u8,
        /// Receiver's address as seen by the sender.
        peer_addr: EntityAddr,
    },
    |e, self| { e.u8(self.entity_type)?; self.peer_addr.encode(e) },
    |d| { Ok(Self { entity_type: d.u8()?, peer_addr: EntityAddr::decode(d)? }) }
);

payload!(
    /// AUTH_REQUEST (7.2).
    AuthRequest, AuthRequest {
        /// Auth method id.
        method: u32,
        /// Connection modes in preference order.
        preferred_modes: Vec<u32>,
        /// Method-specific payload.
        auth_payload: Vec<u8>,
    },
    |e, self| { e.u32(self.method)?; enc_vec32(e, &self.preferred_modes)?; e.bytes(&self.auth_payload) },
    |d| { Ok(Self { method: d.u32()?, preferred_modes: dec_vec32(d)?, auth_payload: d.bytes()?.to_vec() }) }
);

payload!(
    /// AUTH_BAD_METHOD (7.3).
    AuthBadMethod, AuthBadMethod {
        /// Rejected method.
        method: u32,
        /// Negative errno.
        result: i32,
        /// Methods the server allows.
        allowed_methods: Vec<u32>,
        /// Modes the server allows.
        allowed_modes: Vec<u32>,
    },
    |e, self| {
        e.u32(self.method)?; e.i32(self.result)?;
        enc_vec32(e, &self.allowed_methods)?; enc_vec32(e, &self.allowed_modes)
    },
    |d| { Ok(Self { method: d.u32()?, result: d.i32()?, allowed_methods: dec_vec32(d)?, allowed_modes: dec_vec32(d)? }) }
);

payload!(
    /// AUTH_REPLY_MORE (7.4).
    AuthReplyMore, AuthReplyMore { /** Opaque auth payload. */ auth_payload: Vec<u8> },
    |e, self| { e.bytes(&self.auth_payload) },
    |d| { Ok(Self { auth_payload: d.bytes()?.to_vec() }) }
);

payload!(
    /// AUTH_REQUEST_MORE (7.5).
    AuthRequestMore, AuthRequestMore { /** Opaque auth payload. */ auth_payload: Vec<u8> },
    |e, self| { e.bytes(&self.auth_payload) },
    |d| { Ok(Self { auth_payload: d.bytes()?.to_vec() }) }
);

payload!(
    /// AUTH_DONE (7.6).
    AuthDone, AuthDone {
        /// Global id assigned to the peer.
        global_id: u64,
        /// Final connection mode.
        connection_mode: u32,
        /// Method-specific final data.
        auth_payload: Vec<u8>,
    },
    |e, self| { e.u64(self.global_id)?; e.u32(self.connection_mode)?; e.bytes(&self.auth_payload) },
    |d| { Ok(Self { global_id: d.u64()?, connection_mode: d.u32()?, auth_payload: d.bytes()?.to_vec() }) }
);

/// AUTH_SIGNATURE (7.7): HMAC-SHA256, 32 raw bytes.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct AuthSignature {
    /// The signature.
    pub signature: [u8; 32],
}
impl Payload for AuthSignature {
    const TAG: Tag = Tag::AuthSignature;
    fn enc<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.raw(&self.signature)
    }
    fn dec(d: &mut Decoder<'_>) -> Result<Self> {
        Ok(Self {
            signature: d.array::<32>()?,
        })
    }
}

payload!(
    /// CLIENT_IDENT (7.8).
    ClientIdent, ClientIdent {
        /// Client's advertised addresses.
        addrs: EntityAddrVec,
        /// Exact address dialled.
        target_addr: EntityAddr,
        /// Numeric part of the entity name.
        gid: i64,
        /// Messenger-wide connection counter.
        global_seq: u64,
        /// CEPH_FEATURE_* supported.
        supported_features: u64,
        /// CEPH_FEATURE_* required of the server.
        required_features: u64,
        /// bit0 = client is lossy.
        flags: u64,
        /// Client cookie.
        cookie: u64,
    },
    |e, self| {
        self.addrs.encode(e)?; self.target_addr.encode(e)?; e.i64(self.gid)?; e.u64(self.global_seq)?;
        e.u64(self.supported_features)?; e.u64(self.required_features)?; e.u64(self.flags)?; e.u64(self.cookie)
    },
    |d| { Ok(Self {
        addrs: EntityAddrVec::decode(d)?, target_addr: EntityAddr::decode(d)?, gid: d.i64()?, global_seq: d.u64()?,
        supported_features: d.u64()?, required_features: d.u64()?, flags: d.u64()?, cookie: d.u64()?,
    }) }
);

payload!(
    /// SERVER_IDENT (7.9).
    ServerIdent, ServerIdent {
        /// Server's advertised addresses.
        addrs: EntityAddrVec,
        /// Server's entity number.
        gid: i64,
        /// Fresh global_seq of the server.
        global_seq: u64,
        /// CEPH_FEATURE_* supported.
        supported_features: u64,
        /// CEPH_FEATURE_* required.
        required_features: u64,
        /// bit0 = LOSSY.
        flags: u64,
        /// Server cookie.
        cookie: u64,
    },
    |e, self| {
        self.addrs.encode(e)?; e.i64(self.gid)?; e.u64(self.global_seq)?; e.u64(self.supported_features)?;
        e.u64(self.required_features)?; e.u64(self.flags)?; e.u64(self.cookie)
    },
    |d| { Ok(Self {
        addrs: EntityAddrVec::decode(d)?, gid: d.i64()?, global_seq: d.u64()?, supported_features: d.u64()?,
        required_features: d.u64()?, flags: d.u64()?, cookie: d.u64()?,
    }) }
);

payload!(
    /// IDENT_MISSING_FEATURES (7.10).
    IdentMissingFeatures, IdentMissingFeatures { /** Missing feature bits. */ features: u64 },
    |e, self| { e.u64(self.features) },
    |d| { Ok(Self { features: d.u64()? }) }
);

payload!(
    /// SESSION_RECONNECT (7.11).
    SessionReconnect, SessionReconnect {
        /// Client addresses.
        addrs: EntityAddrVec,
        /// Client cookie.
        client_cookie: u64,
        /// Server cookie.
        server_cookie: u64,
        /// Client global_seq.
        global_seq: u64,
        /// Reconnect attempt counter.
        connect_seq: u64,
        /// Client's in_seq.
        msg_seq: u64,
    },
    |e, self| {
        self.addrs.encode(e)?; e.u64(self.client_cookie)?; e.u64(self.server_cookie)?;
        e.u64(self.global_seq)?; e.u64(self.connect_seq)?; e.u64(self.msg_seq)
    },
    |d| { Ok(Self {
        addrs: EntityAddrVec::decode(d)?, client_cookie: d.u64()?, server_cookie: d.u64()?,
        global_seq: d.u64()?, connect_seq: d.u64()?, msg_seq: d.u64()?,
    }) }
);

payload!(
    /// SESSION_RESET (7.12).
    SessionReset, SessionReset { /** True = drop everything. */ full: bool },
    |e, self| { e.bool(self.full) },
    |d| { Ok(Self { full: d.bool()? }) }
);

payload!(
    /// SESSION_RETRY (7.13).
    SessionRetry, SessionRetry { /** Server's connect_seq. */ connect_seq: u64 },
    |e, self| { e.u64(self.connect_seq) },
    |d| { Ok(Self { connect_seq: d.u64()? }) }
);

payload!(
    /// SESSION_RETRY_GLOBAL (7.14).
    SessionRetryGlobal, SessionRetryGlobal { /** Server's recorded peer global_seq. */ global_seq: u64 },
    |e, self| { e.u64(self.global_seq) },
    |d| { Ok(Self { global_seq: d.u64()? }) }
);

payload!(
    /// SESSION_RECONNECT_OK (7.15).
    SessionReconnectOk, SessionReconnectOk { /** Server's in_seq. */ msg_seq: u64 },
    |e, self| { e.u64(self.msg_seq) },
    |d| { Ok(Self { msg_seq: d.u64()? }) }
);

payload!(
    /// WAIT (7.16): empty payload.
    Wait, Wait { },
    |_e, self| { Ok(()) },
    |_d| { Ok(Self {}) }
);

payload!(
    /// KEEPALIVE2 (7.17).
    Keepalive2, Keepalive2 { /** Sender's stamp, seconds. */ sec: u32, /** nanoseconds. */ nsec: u32 },
    |e, self| { e.u32(self.sec)?; e.u32(self.nsec) },
    |d| { Ok(Self { sec: d.u32()?, nsec: d.u32()? }) }
);

payload!(
    /// KEEPALIVE2_ACK (7.18).
    Keepalive2Ack, Keepalive2Ack { /** Echoed stamp, seconds. */ sec: u32, /** nanoseconds. */ nsec: u32 },
    |e, self| { e.u32(self.sec)?; e.u32(self.nsec) },
    |d| { Ok(Self { sec: d.u32()?, nsec: d.u32()? }) }
);

payload!(
    /// ACK (7.19).
    Ack, Ack { /** Highest received message seq. */ seq: u64 },
    |e, self| { e.u64(self.seq) },
    |d| { Ok(Self { seq: d.u64()? }) }
);

payload!(
    /// COMPRESSION_REQUEST (7.20).
    CompressionRequest, CompressionRequest {
        /// Client wants compression.
        is_compress: bool,
        /// Preferred method ids.
        preferred_methods: Vec<u32>,
    },
    |e, self| { e.bool(self.is_compress)?; enc_vec32(e, &self.preferred_methods) },
    |d| { Ok(Self { is_compress: d.bool()?, preferred_methods: dec_vec32(d)? }) }
);

payload!(
    /// COMPRESSION_DONE (7.21).
    CompressionDone, CompressionDone {
        /// Compression negotiated.
        is_compress: bool,
        /// Chosen method id.
        method: u32,
    },
    |e, self| { e.bool(self.is_compress)?; e.u32(self.method) },
    |d| { Ok(Self { is_compress: d.bool()?, method: d.u32()? }) }
);

/// RDMA_UPGRADE op: client offers its endpoint.
pub const RDMA_OFFER: u8 = 1;
/// RDMA_UPGRADE op: server accepts with its endpoint.
pub const RDMA_ACCEPT: u8 = 2;
/// RDMA_UPGRADE op: server declines, the connection stays on TCP.
pub const RDMA_DECLINE: u8 = 3;

payload!(
    /// RDMA_UPGRADE (spec 18): op + the transport's endpoint record (opaque here, empty on decline).
    RdmaUpgrade, RdmaUpgrade {
        /// [`RDMA_OFFER`] / [`RDMA_ACCEPT`] / [`RDMA_DECLINE`].
        op: u8,
        /// Endpoint record of the sender.
        endpoint: Vec<u8>,
    },
    |e, self| { e.raw(&[self.op])?; e.bytes(&self.endpoint) },
    |d| { Ok(Self { op: d.array::<1>()?[0], endpoint: d.bytes()?.to_vec() }) }
);

/// Size of `ceph_msg_header2`.
pub const HEADER2_LEN: usize = 41;
/// header2 flags: footer COMPLETE | NOCRC as sent by Ceph.
pub const HDR_FLAGS_DEFAULT: u8 = 0x03;

/// `ceph_msg_header2` (8.1), MESSAGE segment 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct MsgHeader2 {
    /// Message sequence number (starts at 1).
    pub seq: u64,
    /// Transaction id.
    pub tid: u64,
    /// Message type.
    pub msg_type: u16,
    /// Priority.
    pub priority: u16,
    /// Payload encoding version.
    pub version: u16,
    /// Always 0.
    pub data_pre_padding_len: u32,
    /// Sender-side data offset hint.
    pub data_off: u16,
    /// Piggybacked ack (sender's in_seq).
    pub ack_seq: u64,
    /// Footer flags.
    pub flags: u8,
    /// Oldest decoder version able to read `version`.
    pub compat_version: u16,
    /// Reserved.
    pub reserved: u16,
}

impl MsgHeader2 {
    /// Encode to the fixed 41 bytes.
    pub fn to_bytes(&self) -> [u8; HEADER2_LEN] {
        let mut b = [0u8; HEADER2_LEN];
        b[0..8].copy_from_slice(&self.seq.to_le_bytes());
        b[8..16].copy_from_slice(&self.tid.to_le_bytes());
        b[16..18].copy_from_slice(&self.msg_type.to_le_bytes());
        b[18..20].copy_from_slice(&self.priority.to_le_bytes());
        b[20..22].copy_from_slice(&self.version.to_le_bytes());
        b[22..26].copy_from_slice(&self.data_pre_padding_len.to_le_bytes());
        b[26..28].copy_from_slice(&self.data_off.to_le_bytes());
        b[28..36].copy_from_slice(&self.ack_seq.to_le_bytes());
        b[36] = self.flags;
        b[37..39].copy_from_slice(&self.compat_version.to_le_bytes());
        b[39..41].copy_from_slice(&self.reserved.to_le_bytes());
        b
    }

    /// Decode (at least 41 bytes; extra ignored).
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < HEADER2_LEN {
            return Err(Error::Eof {
                needed: HEADER2_LEN,
                remaining: b.len(),
            });
        }
        let u16_ = |o: usize| denc::le::rd_u16(b, o);
        let u64_ = |o: usize| denc::le::rd_u64(b, o);
        Ok(Self {
            seq: u64_(0),
            tid: u64_(8),
            msg_type: u16_(16),
            priority: u16_(18),
            version: u16_(20),
            data_pre_padding_len: denc::le::rd_u32(b, 22),
            data_off: u16_(26),
            ack_seq: u64_(28),
            flags: b[36],
            compat_version: u16_(37),
            reserved: u16_(39),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt<T: Payload + PartialEq + core::fmt::Debug>(v: T) {
        let b = v.to_bytes().unwrap();
        assert_eq!(T::from_bytes(&b).unwrap(), v);
        // truncation never panics
        for i in 0..b.len() {
            let _ = T::from_bytes(&b[..i]);
        }
    }

    /// A payload whose fields do not fit their wire lengths: framing a truncated encoding must be impossible.
    struct TooLongPayload;

    impl Payload for TooLongPayload {
        const TAG: Tag = Tag::Ack;
        fn enc<B: BufMut>(&self, _e: &mut Encoder<B>) -> denc::Result<()> {
            Err(denc::Error::TooLong)
        }
        fn dec(_d: &mut Decoder<'_>) -> denc::Result<Self> {
            Ok(Self)
        }
    }

    #[test]
    fn unrepresentable_payloads_are_reported_not_framed() {
        assert_eq!(TooLongPayload.to_bytes(), Err(denc::Error::TooLong));
    }

    fn addr(p: u16) -> EntityAddr {
        EntityAddr::v4(2, 77, [10, 0, 0, 1], p)
    }

    #[test]
    fn all_roundtrip() {
        rt(Hello {
            entity_type: 4,
            peer_addr: addr(1),
        });
        rt(AuthRequest {
            method: 2,
            preferred_modes: vec![1, 2],
            auth_payload: vec![1, 2, 3],
        });
        rt(AuthBadMethod {
            method: 2,
            result: -95,
            allowed_methods: vec![1],
            allowed_modes: vec![1, 2],
        });
        rt(AuthReplyMore {
            auth_payload: vec![9; 5],
        });
        rt(AuthRequestMore {
            auth_payload: vec![],
        });
        rt(AuthDone {
            global_id: 5,
            connection_mode: 2,
            auth_payload: vec![7; 100],
        });
        rt(AuthSignature { signature: [3; 32] });
        rt(ClientIdent {
            addrs: EntityAddrVec::single(addr(2)),
            target_addr: addr(3),
            gid: 4,
            global_seq: 5,
            supported_features: 6,
            required_features: 7,
            flags: 1,
            cookie: 9,
        });
        rt(ServerIdent {
            addrs: EntityAddrVec::single(addr(2)),
            gid: -1,
            global_seq: 5,
            supported_features: 6,
            required_features: 7,
            flags: 0,
            cookie: 9,
        });
        rt(IdentMissingFeatures { features: 1 << 40 });
        rt(SessionReconnect {
            addrs: EntityAddrVec::single(addr(2)),
            client_cookie: 1,
            server_cookie: 2,
            global_seq: 3,
            connect_seq: 4,
            msg_seq: 5,
        });
        rt(SessionReset { full: true });
        rt(SessionRetry { connect_seq: 8 });
        rt(SessionRetryGlobal { global_seq: 8 });
        rt(SessionReconnectOk { msg_seq: 8 });
        rt(Wait {});
        rt(Keepalive2 { sec: 1, nsec: 2 });
        rt(Keepalive2Ack { sec: 1, nsec: 2 });
        rt(Ack { seq: 99 });
        rt(CompressionRequest {
            is_compress: true,
            preferred_methods: vec![3, 4],
        });
        rt(CompressionDone {
            is_compress: false,
            method: 0,
        });
        rt(RdmaUpgrade {
            op: RDMA_ACCEPT,
            endpoint: vec![9; 32],
        });
        assert_eq!(
            RdmaUpgrade {
                op: RDMA_DECLINE,
                endpoint: Vec::new()
            }
            .to_bytes()
            .unwrap(),
            [3, 0, 0, 0, 0]
        );
    }

    #[test]
    fn header2_layout() {
        let h = MsgHeader2 {
            seq: 1,
            tid: 2,
            msg_type: 3,
            priority: 4,
            version: 5,
            data_pre_padding_len: 0,
            data_off: 6,
            ack_seq: 7,
            flags: 3,
            compat_version: 8,
            reserved: 0,
        };
        let b = h.to_bytes();
        assert_eq!(b.len(), 41);
        assert_eq!(MsgHeader2::from_bytes(&b).unwrap(), h);
        assert!(MsgHeader2::from_bytes(&b[..40]).is_err());
        assert_eq!(b[36], 3);
    }

    #[test]
    fn wire_shapes() {
        assert_eq!(Wait {}.to_bytes().unwrap(), Vec::<u8>::new());
        assert_eq!(Ack { seq: 1 }.to_bytes().unwrap(), 1u64.to_le_bytes());
        assert_eq!(SessionReset { full: true }.to_bytes().unwrap(), [1]);
        let a = AuthRequest {
            method: 1,
            preferred_modes: vec![1],
            auth_payload: vec![0xaa],
        }
        .to_bytes()
        .unwrap();
        assert_eq!(a, [1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0xaa]);
    }
}
