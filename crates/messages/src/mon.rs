// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Mon-facing session messages (spec osd-lifecycle.md section 2, cephx.md section 9).

use crate::meta;
use crate::msg::{Message, Segments, front_with, get_psm, put_psm};
use crate::types::{CephEntityName, LogEntryPayload};
use denc::types::Uuid;
use denc::{Decode, Decoder, Encode, Result};
use std::collections::BTreeMap;

/// MAuth (17): cephx request on an established mon session.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct MAuth {
    /// PSM `version` (0).
    pub version: u64,
    /// Auth protocol (2 = cephx).
    pub protocol: u32,
    pub auth_payload: Vec<u8>,
    pub monmap_epoch: u32,
}
/// `auth_payload` is the cephx request (ticket/authenticator): print its length only.
impl std::fmt::Debug for MAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MAuth")
            .field("version", &self.version)
            .field("protocol", &self.protocol)
            .field("auth_payload_len", &self.auth_payload.len())
            .field("monmap_epoch", &self.monmap_epoch)
            .finish()
    }
}
impl Message for MAuth {
    meta!(17, 1, 1);
    fn encode(&self, f: u64) -> Result<Segments> {
        Ok(Segments::front(front_with(f, |e| {
            put_psm(e, self.version)?;
            e.u32(self.protocol)?;
            e.bytes(&self.auth_payload)?;
            e.u32(self.monmap_epoch)
        })?))
    }
    fn decode(_v: u16, front: &[u8], _m: &[u8], _d: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(front);
        Ok(MAuth {
            version: get_psm(&mut d)?,
            protocol: d.u32()?,
            auth_payload: d.bytes()?.to_vec(),
            monmap_epoch: d.u32()?,
        })
    }
}

/// MAuthReply (18).
#[derive(Clone, PartialEq, Eq, Default)]
pub struct MAuthReply {
    pub protocol: u32,
    pub result: i32,
    pub global_id: u64,
    pub result_bl: Vec<u8>,
    pub result_msg: String,
}
/// `result_bl` carries the service ticket: print its length only.
impl std::fmt::Debug for MAuthReply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MAuthReply")
            .field("protocol", &self.protocol)
            .field("result", &self.result)
            .field("global_id", &self.global_id)
            .field("result_bl_len", &self.result_bl.len())
            .field("result_msg", &self.result_msg)
            .finish()
    }
}
impl Message for MAuthReply {
    meta!(18, 1, 1);
    fn encode(&self, f: u64) -> Result<Segments> {
        Ok(Segments::front(front_with(f, |e| {
            e.u32(self.protocol)?;
            e.i32(self.result)?;
            e.u64(self.global_id)?;
            e.bytes(&self.result_bl)?;
            self.result_msg.encode(e)
        })?))
    }
    fn decode(_v: u16, front: &[u8], _m: &[u8], _d: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(front);
        Ok(MAuthReply {
            protocol: d.u32()?,
            result: d.i32()?,
            global_id: d.u64()?,
            result_bl: d.bytes()?.to_vec(),
            result_msg: String::decode(&mut d)?,
        })
    }
}

/// MMonGetMap (5): empty request for the monmap.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MMonGetMap;
impl Message for MMonGetMap {
    meta!(5, 1, 1);
    fn encode(&self, _f: u64) -> Result<Segments> {
        Ok(Segments::default())
    }
    fn decode(_v: u16, _f: &[u8], _m: &[u8], _d: &[u8]) -> Result<Self> {
        Ok(MMonGetMap)
    }
}

/// One MMonSubscribe item: `start` epoch + flags (`1` = ONETIME).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SubItem {
    pub start: u64,
    pub flags: u8,
}
impl SubItem {
    pub const ONETIME: u8 = 1;
}

/// MMonSubscribe (15, hv=3).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MMonSubscribe {
    pub what: BTreeMap<String, SubItem>,
    /// Short hostname; the mon uses it for `host:` config masks. Always send.
    pub hostname: String,
}
impl Message for MMonSubscribe {
    meta!(15, 3, 1);
    fn encode(&self, f: u64) -> Result<Segments> {
        Ok(Segments::front(front_with(f, |e| {
            e.count(self.what.len())?;
            for (k, v) in &self.what {
                k.encode(e)?;
                e.u64(v.start)?;
                e.u8(v.flags)?;
            }
            self.hostname.encode(e)
        })?))
    }
    fn decode(v: u16, front: &[u8], _m: &[u8], _d: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(front);
        let n = d.count()?;
        let mut what = BTreeMap::new();
        for _ in 0..n {
            let k = String::decode(&mut d)?;
            what.insert(
                k,
                SubItem {
                    start: d.u64()?,
                    flags: d.u8()?,
                },
            );
        }
        let hostname = if v >= 2 {
            String::decode(&mut d)?
        } else {
            String::new()
        };
        Ok(MMonSubscribe { what, hostname })
    }
}

/// MMonSubscribeAck (16). Ignored by stateful-sub mons.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MMonSubscribeAck {
    pub interval: u32,
    pub fsid: Uuid,
}
impl Message for MMonSubscribeAck {
    meta!(16, 1, 1);
    fn encode(&self, f: u64) -> Result<Segments> {
        Ok(Segments::front(front_with(f, |e| {
            e.u32(self.interval)?;
            self.fsid.encode(e)
        })?))
    }
    fn decode(_v: u16, front: &[u8], _m: &[u8], _d: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(front);
        Ok(MMonSubscribeAck {
            interval: d.u32()?,
            fsid: Uuid::decode(&mut d)?,
        })
    }
}

/// MMonGetVersion (19): `what` = "osdmap" | "monmap" | "mdsmap" | "fsmap".
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MMonGetVersion {
    pub handle: u64,
    pub what: String,
}
impl Message for MMonGetVersion {
    meta!(19, 1, 1);
    fn encode(&self, f: u64) -> Result<Segments> {
        Ok(Segments::front(front_with(f, |e| {
            e.u64(self.handle)?;
            self.what.encode(e)
        })?))
    }
    fn decode(_v: u16, front: &[u8], _m: &[u8], _d: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(front);
        Ok(MMonGetVersion {
            handle: d.u64()?,
            what: String::decode(&mut d)?,
        })
    }
}

/// MMonGetVersionReply (20, hv=2 hc=2).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MMonGetVersionReply {
    pub handle: u64,
    /// last_committed (newest epoch).
    pub version: u64,
    /// first_committed (oldest epoch the mon still has); 0 for hv<2.
    pub oldest_version: u64,
}
impl Message for MMonGetVersionReply {
    meta!(20, 2, 2);
    fn encode(&self, f: u64) -> Result<Segments> {
        Ok(Segments::front(front_with(f, |e| {
            e.u64(self.handle)?;
            e.u64(self.version)?;
            e.u64(self.oldest_version)
        })?))
    }
    fn decode(v: u16, front: &[u8], _m: &[u8], _d: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(front);
        Ok(MMonGetVersionReply {
            handle: d.u64()?,
            version: d.u64()?,
            oldest_version: if v >= 2 { d.u64()? } else { 0 },
        })
    }
}

/// Arguments of a command whose values may be secrets, by command prefix (`config set` values, `config-key`
/// values, the `key` of any `auth` command, injected args). Everything else of a command prints verbatim.
fn secret_args(prefix: &str) -> &'static [&'static str] {
    match prefix {
        "config set" => &["val", "value"],
        "config-key set" | "config-key put" => &["val"],
        "injectargs" => &["injected_args"],
        p if p.starts_with("auth ") => &["key"],
        _ => &[],
    }
}

/// Debug text of a command's JSON strings with the secret arguments dropped. A string that is not a JSON object
/// cannot be classified and prints as its length only.
fn redacted_cmd(cmd: &[String]) -> Vec<String> {
    cmd.iter()
        .map(|c| match serde_json::from_str::<serde_json::Value>(c) {
            Ok(serde_json::Value::Object(mut o)) => {
                let secret =
                    secret_args(o.get("prefix").and_then(|p| p.as_str()).unwrap_or_default());
                for k in secret {
                    if let Some(v) = o.get_mut(*k) {
                        *v = serde_json::Value::String("<redacted>".into());
                    }
                }
                serde_json::Value::Object(o).to_string()
            }
            _ => format!("<unparsed command, {} bytes>", c.len()),
        })
        .collect()
}

/// MMonCommand (50): PSM, fsid, `cmd` (JSON strings); `data` segment = optional input blob.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct MMonCommand {
    pub version: u64,
    pub fsid: Uuid,
    pub cmd: Vec<String>,
    pub data: Vec<u8>,
}
/// `data` carries command input such as the `osd new` keyring JSON: print its length only; secret arguments of
/// `cmd` are dropped.
impl std::fmt::Debug for MMonCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MMonCommand")
            .field("version", &self.version)
            .field("fsid", &self.fsid)
            .field("cmd", &redacted_cmd(&self.cmd))
            .field("data_len", &self.data.len())
            .finish()
    }
}
impl Message for MMonCommand {
    meta!(50, 1, 1);
    fn encode(&self, f: u64) -> Result<Segments> {
        Ok(Segments::with_data(
            front_with(f, |e| {
                put_psm(e, self.version)?;
                self.fsid.encode(e)?;
                self.cmd.encode(e)
            })?,
            self.data.clone(),
        ))
    }
    fn decode(_v: u16, front: &[u8], _m: &[u8], data: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(front);
        Ok(MMonCommand {
            version: get_psm(&mut d)?,
            fsid: Uuid::decode(&mut d)?,
            cmd: Vec::decode(&mut d)?,
            data: data.to_vec(),
        })
    }
}

/// MMonCommandAck (51): PSM (version = last_committed), r, rs, echo of cmd; output in `data`.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct MMonCommandAck {
    pub version: u64,
    pub r: i32,
    pub rs: String,
    pub cmd: Vec<String>,
    pub data: Vec<u8>,
}
/// `rs` can echo a refused value and `data` is command output (keys): print lengths only; the `cmd` echo drops
/// secret arguments.
impl std::fmt::Debug for MMonCommandAck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MMonCommandAck")
            .field("version", &self.version)
            .field("r", &self.r)
            .field("rs_len", &self.rs.len())
            .field("cmd", &redacted_cmd(&self.cmd))
            .field("data_len", &self.data.len())
            .finish()
    }
}
impl Message for MMonCommandAck {
    meta!(51, 1, 1);
    fn encode(&self, f: u64) -> Result<Segments> {
        Ok(Segments::with_data(
            front_with(f, |e| {
                put_psm(e, self.version)?;
                e.i32(self.r)?;
                self.rs.encode(e)?;
                self.cmd.encode(e)
            })?,
            self.data.clone(),
        ))
    }
    fn decode(_v: u16, front: &[u8], _m: &[u8], data: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(front);
        Ok(MMonCommandAck {
            version: get_psm(&mut d)?,
            r: d.i32()?,
            rs: String::decode(&mut d)?,
            cmd: Vec::decode(&mut d)?,
            data: data.to_vec(),
        })
    }
}

/// MMonMap (4): front = `bl` holding an encoded MonMap (opaque here).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MMonMap {
    pub monmap: Vec<u8>,
}
impl Message for MMonMap {
    meta!(4, 1, 1);
    fn encode(&self, f: u64) -> Result<Segments> {
        Ok(Segments::front(front_with(f, |e| e.bytes(&self.monmap))?))
    }
    fn decode(_v: u16, front: &[u8], _m: &[u8], _d: &[u8]) -> Result<Self> {
        Ok(MMonMap {
            monmap: Decoder::new(front).bytes()?.to_vec(),
        })
    }
}

/// MConfig (62): complete resolved mon-level option set for this entity.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MConfig {
    pub config: BTreeMap<String, String>,
}
impl Message for MConfig {
    meta!(62, 1, 1);
    fn encode(&self, f: u64) -> Result<Segments> {
        Ok(Segments::front(front_with(f, |e| self.config.encode(e))?))
    }
    fn decode(_v: u16, front: &[u8], _m: &[u8], _d: &[u8]) -> Result<Self> {
        Ok(MConfig {
            config: BTreeMap::decode(&mut Decoder::new(front))?,
        })
    }
}

/// MGetConfig (63): pre-daemon bootstrap config request.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MGetConfig {
    pub name: CephEntityName,
    pub host: String,
    pub device_class: String,
}
impl Message for MGetConfig {
    meta!(63, 1, 1);
    fn encode(&self, f: u64) -> Result<Segments> {
        Ok(Segments::front(front_with(f, |e| {
            self.name.encode(e)?;
            self.host.encode(e)?;
            self.device_class.encode(e)
        })?))
    }
    fn decode(_v: u16, front: &[u8], _m: &[u8], _d: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(front);
        Ok(MGetConfig {
            name: CephEntityName::decode(&mut d)?,
            host: String::decode(&mut d)?,
            device_class: String::decode(&mut d)?,
        })
    }
}

/// MLog (52): PSM, fsid, entries.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MLogPayload<I> {
    pub version: u64,
    pub fsid: Uuid,
    pub entries: Vec<LogEntryPayload<I>>,
}
/// Native text principal API and strict decoder.
pub type MLog = MLogPayload<String>;
/// Byte principal only; message and channel remain native text.
pub type ByteMLog = MLogPayload<Vec<u8>>;
impl<I: AsRef<[u8]> + for<'a> Decode<'a>> Message for MLogPayload<I> {
    meta!(52, 1, 1);
    fn encode(&self, f: u64) -> Result<Segments> {
        Ok(Segments::front(front_with(f, |e| {
            put_psm(e, self.version)?;
            self.fsid.encode(e)?;
            self.entries.encode(e)
        })?))
    }
    fn decode(_v: u16, front: &[u8], _m: &[u8], _d: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(front);
        Ok(Self {
            version: get_psm(&mut d)?,
            fsid: Uuid::decode(&mut d)?,
            entries: Vec::decode(&mut d)?,
        })
    }
}

/// MLogAck (53): `channel` absent in old senders (empty then).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MLogAck {
    pub fsid: Uuid,
    pub last: u64,
    pub channel: String,
}
impl Message for MLogAck {
    meta!(53, 1, 1);
    fn encode(&self, f: u64) -> Result<Segments> {
        Ok(Segments::front(front_with(f, |e| {
            self.fsid.encode(e)?;
            e.u64(self.last)?;
            self.channel.encode(e)
        })?))
    }
    fn decode(_v: u16, front: &[u8], _m: &[u8], _d: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(front);
        let fsid = Uuid::decode(&mut d)?;
        let last = d.u64()?;
        let channel = if d.is_empty() {
            String::new()
        } else {
            String::decode(&mut d)?
        };
        Ok(MLogAck {
            fsid,
            last,
            channel,
        })
    }
}

/// MCommand (97): tell-style command to a daemon (not a PSM). Input blob in `data`.
/// Header version is not given in the spec; 1/1 assumed.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct MCommand {
    pub fsid: Uuid,
    pub cmd: Vec<String>,
    pub data: Vec<u8>,
}
/// `data` may carry a keyring or other credentials: print its length only.
impl std::fmt::Debug for MCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MCommand")
            .field("fsid", &self.fsid)
            .field("cmd", &redacted_cmd(&self.cmd))
            .field("data_len", &self.data.len())
            .finish()
    }
}
impl Message for MCommand {
    meta!(97, 1, 1);
    fn encode(&self, f: u64) -> Result<Segments> {
        Ok(Segments::with_data(
            front_with(f, |e| {
                self.fsid.encode(e)?;
                self.cmd.encode(e)
            })?,
            self.data.clone(),
        ))
    }
    fn decode(_v: u16, front: &[u8], _m: &[u8], data: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(front);
        Ok(MCommand {
            fsid: Uuid::decode(&mut d)?,
            cmd: Vec::decode(&mut d)?,
            data: data.to_vec(),
        })
    }
}

/// MCommandReply (98): r, rs; output in `data`; header tid echoes the request.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct MCommandReply {
    pub r: i32,
    pub rs: String,
    pub data: Vec<u8>,
}
/// `rs` can echo a refused value (the request is not part of the reply, so it cannot be classified) and `data` is
/// command output: print lengths only.
impl std::fmt::Debug for MCommandReply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MCommandReply")
            .field("r", &self.r)
            .field("rs_len", &self.rs.len())
            .field("data_len", &self.data.len())
            .finish()
    }
}
impl Message for MCommandReply {
    meta!(98, 1, 1);
    fn encode(&self, f: u64) -> Result<Segments> {
        Ok(Segments::with_data(
            front_with(f, |e| {
                e.i32(self.r)?;
                self.rs.encode(e)
            })?,
            self.data.clone(),
        ))
    }
    fn decode(_v: u16, front: &[u8], _m: &[u8], data: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(front);
        Ok(MCommandReply {
            r: d.i32()?,
            rs: String::decode(&mut d)?,
            data: data.to_vec(),
        })
    }
}

/// Monitor MPing (2). Requests have no front; responses contain a byte string.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct MPing {
    pub reply: Option<Vec<u8>>,
}
/// The reply blob is opaque peer data: print its length only.
impl std::fmt::Debug for MPing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MPing")
            .field("reply_len", &self.reply.as_ref().map(Vec::len))
            .finish()
    }
}
impl Message for MPing {
    meta!(2, 1, 0);
    fn encode(&self, f: u64) -> Result<Segments> {
        match &self.reply {
            None => Ok(Segments::default()),
            Some(reply) => Ok(Segments::front(front_with(f, |e| e.bytes(reply))?)),
        }
    }
    fn decode(_v: u16, front: &[u8], middle: &[u8], data: &[u8]) -> Result<Self> {
        if !middle.is_empty() || !data.is_empty() {
            return Err(denc::Error::BadValue("ping segments"));
        }
        if front.is_empty() {
            return Ok(Self::default());
        }
        let mut d = Decoder::new(front);
        let reply = d.bytes()?.to_vec();
        if !d.is_empty() {
            return Err(denc::Error::TrailingBytes(d.remaining()));
        }
        Ok(Self { reply: Some(reply) })
    }
}

#[cfg(test)]
mod ping_tests {
    use super::*;
    #[test]
    fn ping_empty_request_and_exact_binary_reply_envelope() {
        assert!(MPing::default().encode(0).unwrap().front.is_empty());
        let reply = MPing {
            reply: Some(vec![0, 255, 7]),
        };
        assert_eq!(reply.encode(0).unwrap().front, [3, 0, 0, 0, 0, 255, 7]);
        assert_eq!(
            MPing::decode(1, &[3, 0, 0, 0, 0, 255, 7], &[], &[]).unwrap(),
            reply
        );
        for bytes in [&[3, 0, 0, 0, 7][..], &[0, 0, 0, 0, 7][..]] {
            assert!(MPing::decode(1, bytes, &[], &[]).is_err());
        }
        assert!(MPing::decode(1, &[], &[1], &[]).is_err());
        assert!(MPing::decode(1, &[], &[], &[1]).is_err());
    }
}

#[cfg(test)]
mod debug_redaction_tests {
    use super::*;

    fn cmd(json: &str) -> Vec<String> {
        vec![json.to_string()]
    }

    #[test]
    fn secret_arguments_are_dropped_from_command_debug() {
        let cases = [
            r#"{"prefix":"config set","who":"osd.1","name":"key","value":"S3CRET"}"#,
            r#"{"prefix":"config set","var":"key","val":"S3CRET"}"#,
            r#"{"prefix":"config-key set","key":"mgr/x","val":"S3CRET"}"#,
            r#"{"prefix":"config-key put","key":"mgr/x","val":"S3CRET"}"#,
            r#"{"prefix":"auth add","entity":"client.a","key":"S3CRET"}"#,
            r#"{"prefix":"injectargs","injected_args":["--key=S3CRET"]}"#,
        ];
        for c in cases {
            let m = MMonCommand {
                cmd: cmd(c),
                data: b"S3CRET".to_vec(),
                ..Default::default()
            };
            let t = MCommand {
                cmd: cmd(c),
                data: b"S3CRET".to_vec(),
                ..Default::default()
            };
            let a = MMonCommandAck {
                cmd: cmd(c),
                rs: "bad value S3CRET".into(),
                data: b"S3CRET".to_vec(),
                ..Default::default()
            };
            let r = MCommandReply {
                rs: "bad value S3CRET".into(),
                data: b"S3CRET".to_vec(),
                ..Default::default()
            };
            for text in [
                format!("{m:?}"),
                format!("{t:?}"),
                format!("{a:?}"),
                format!("{r:?}"),
            ] {
                assert!(!text.contains("S3CRET"), "{c}: {text}");
            }
        }
    }

    #[test]
    fn non_secret_commands_and_names_stay_readable() {
        let m = MMonCommand {
            cmd: cmd(r#"{"prefix":"config set","name":"key","value":"v"}"#),
            ..Default::default()
        };
        let text = format!("{m:?}");
        assert!(
            text.contains("config set") && text.contains("<redacted>"),
            "{text}"
        );
        let m = MMonCommand {
            cmd: cmd(r#"{"prefix":"osd tree"}"#),
            ..Default::default()
        };
        assert!(format!("{m:?}").contains("osd tree"));
        let m = MMonCommand {
            cmd: cmd("not json S3CRET"),
            ..Default::default()
        };
        let text = format!("{m:?}");
        assert!(
            !text.contains("S3CRET") && text.contains("<unparsed command"),
            "{text}"
        );
    }
}
