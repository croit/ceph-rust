// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! PG export file container (doc/spec/objectstore-tool.md 3): fixed super header, then sections
//! `header | body | footer`; byte-compatible with the classic tool so a PG moves between classic and croit-flashstore-osd OSDs.
use denc::{Decode, Decoder, Encode, Encoder};
use messages::OsdSuperblock;
use pgwire::{PastIntervals, PgInfo, PgLog, PgMissing};
use std::collections::BTreeMap;
use std::io::{Read, Write};

pub const T_PG_BEGIN: u8 = 1;
pub const T_PG_END: u8 = 2;
pub const T_OBJECT_BEGIN: u8 = 3;
pub const T_OBJECT_END: u8 = 4;
pub const T_DATA: u8 = 5;
pub const T_ATTRS: u8 = 6;
pub const T_OMAP_HDR: u8 = 7;
pub const T_OMAP: u8 = 8;
pub const T_PG_METADATA: u8 = 9;
pub const T_POOL_BEGIN: u8 = 10;
pub const END_OF_TYPES: u8 = 12;

const SHORT_MAGIC: u32 = 0xffce;
pub const SUPER_MAGIC: u32 = (SHORT_MAGIC << 16) | SHORT_MAGIC;
pub const SUPER_VER: u32 = 2;
const END_MAGIC: u32 = (0xecff << 16) | SHORT_MAGIC;
/// header = envelope(6) + u32 type-magic + i64 size; footer = envelope(6) + u32 magic.
pub const HDR_LEN: u32 = 18;
pub const FTR_LEN: u32 = 10;
/// Objects are streamed in data sections of at most this many bytes.
pub const MAX_READ: u64 = 8 << 20;
/// A DATA body: envelope(6) + u64 off + u64 len + u32 buffer length, then the payload.
const DATA_ENV: u64 = 6 + 8 + 8 + 4;
/// Bound of a DATA body (spec 3: at most [`MAX_READ`] payload bytes per section).
pub const MAX_DATA_BODY: u64 = MAX_READ + DATA_ENV;
/// Bound of every other section body (one object's attributes/omap, the embedded OSDMap), read into memory whole:
/// [`crate::MAX_INPUT`]. A section header claiming more is refused.
pub const MAX_META_BODY: u64 = crate::MAX_INPUT;
/// Omap pairs per omap section.
pub const OMAP_BATCH: usize = 25;
/// On-disk PG info version recorded in the metadata section (classic `struct_v` of the pg info).
pub const PG_STRUCT_V: u8 = 10;

pub type Res<T> = Result<T, String>;

fn de(e: denc::Error) -> String {
    format!("decode: {e}")
}
fn en(e: denc::Error) -> String {
    format!("encode: {e}")
}
fn io(e: std::io::Error) -> String {
    format!("io: {e}")
}
/// A short read is the container's own "truncated file"; any other io error keeps its cause.
fn read_err(e: std::io::Error, what: &str) -> String {
    if e.kind() == std::io::ErrorKind::UnexpectedEof {
        format!("Unexpected EOF {what}")
    } else {
        format!("io: {what}: {e}")
    }
}

#[derive(Debug)]
pub struct SectionWriter<W: Write> {
    w: W,
}

impl<W: Write> SectionWriter<W> {
    pub fn new(w: W) -> Self {
        SectionWriter { w }
    }
    fn put(&mut self, b: &[u8]) -> Res<()> {
        self.w.write_all(b).map_err(io)
    }
    fn header(t: u8, size: i64) -> Vec<u8> {
        let mut h = Vec::with_capacity(HDR_LEN as usize);
        h.extend_from_slice(&[1, 1]);
        h.extend_from_slice(&12u32.to_le_bytes());
        let dbg = (u32::from(t) << 24) | (u32::from(t) << 16) | SHORT_MAGIC;
        h.extend_from_slice(&dbg.to_le_bytes());
        h.extend_from_slice(&size.to_le_bytes());
        h
    }
    pub fn write_super(&mut self) -> Res<()> {
        let mut b = Vec::with_capacity(16);
        for v in [SUPER_MAGIC, SUPER_VER, HDR_LEN, FTR_LEN] {
            b.extend_from_slice(&v.to_le_bytes());
        }
        self.put(&b)
    }
    pub fn section(&mut self, t: u8, body: &[u8]) -> Res<()> {
        self.put(&Self::header(t, body.len() as i64))?;
        self.put(body)?;
        self.footer()
    }
    /// DATA section: byte-identical to [`Self::section`] of [`enc_data`], but the payload is written from `data`
    /// instead of through an encoder buffer (a bulk export moves every byte once).
    pub fn data(&mut self, off: u64, data: &[u8]) -> Res<()> {
        let n = data.len() as u64;
        let len = u32::try_from(n).map_err(|_| "DATA section too long".to_string())?;
        self.put(&Self::header(T_DATA, (DATA_ENV + n) as i64))?;
        // ENV(1,1){ u64 off, u64 len, buffer }: the envelope length covers the buffer, whose payload follows
        let mut env = Vec::with_capacity(DATA_ENV as usize);
        env.extend_from_slice(&[1, 1]);
        env.extend_from_slice(&(4 + 16 + len).to_le_bytes());
        env.extend_from_slice(&off.to_le_bytes());
        env.extend_from_slice(&n.to_le_bytes());
        env.extend_from_slice(&len.to_le_bytes());
        self.put(&env)?;
        self.put(data)?;
        self.footer()
    }
    fn footer(&mut self) -> Res<()> {
        let mut f = vec![1, 1];
        f.extend_from_slice(&4u32.to_le_bytes());
        f.extend_from_slice(&END_MAGIC.to_le_bytes());
        self.put(&f)
    }
    /// Header-only section (PG_END, OBJECT_END).
    pub fn simple(&mut self, t: u8) -> Res<()> {
        self.put(&Self::header(t, 0))
    }
    pub fn finish(mut self) -> Res<W> {
        self.w.flush().map_err(io)?;
        Ok(self.w)
    }
}

#[derive(Debug)]
pub struct SectionReader<R: Read> {
    r: R,
    hdr: u32,
    ftr: u32,
}

impl<R: Read> SectionReader<R> {
    /// Reads and validates the 16 byte super header.
    pub fn open(mut r: R) -> Res<Self> {
        let mut b = [0u8; 16];
        r.read_exact(&mut b)
            .map_err(|e| read_err(e, "reading the export header"))?;
        let v = |i: usize| u32::from_le_bytes(b[i..i + 4].try_into().unwrap());
        if v(0) != SUPER_MAGIC {
            return Err("Invalid magic number (not a PG export file)".into());
        }
        if v(4) > SUPER_VER {
            return Err(format!("Can't handle export format version={}", v(4)));
        }
        let (hdr, ftr) = (v(8), v(12));
        if !(HDR_LEN..=4096).contains(&hdr) || ftr > 4096 {
            return Err("corrupt export super header".into());
        }
        Ok(SectionReader { r, hdr, ftr })
    }
    /// Next section type; `body` is replaced by the section body (reused across calls, so a bulk import does not
    /// allocate per section). The size is checked against the bound of the type before a byte is read, and the
    /// body is read incrementally: a corrupt size cannot drive an allocation the file does not back.
    pub fn read_next(&mut self, body: &mut Vec<u8>) -> Res<u8> {
        let mut h = vec![0u8; self.hdr as usize];
        self.r
            .read_exact(&mut h)
            .map_err(|e| read_err(e, "in a section header"))?;
        // envelope (v, compat, len) then u32 type-magic, i64 size
        if h.len() < 18 {
            return Err("short section header".into());
        }
        let dbg = u32::from_le_bytes(h[6..10].try_into().unwrap());
        let size = i64::from_le_bytes(h[10..18].try_into().unwrap());
        let t = (dbg >> 24) as u8;
        let max = if t == T_DATA {
            MAX_DATA_BODY
        } else {
            MAX_META_BODY
        };
        if !(0..=max as i64).contains(&size) {
            return Err(format!(
                "corrupt section size {size} (type {t}: at most {max} bytes)"
            ));
        }
        body.clear();
        let n = (&mut self.r)
            .take(size as u64)
            .read_to_end(body)
            .map_err(|e| read_err(e, "in a section body"))?;
        if n as u64 != size as u64 {
            return Err(format!(
                "Unexpected EOF in a section body ({n} of {size} bytes)"
            ));
        }
        if size > 0 {
            let mut f = vec![0u8; self.ftr as usize];
            self.r
                .read_exact(&mut f)
                .map_err(|e| read_err(e, "in a section footer"))?;
            if f.len() < 10 || u32::from_le_bytes(f[6..10].try_into().unwrap()) != END_MAGIC {
                return Err("Bad footer magic".into());
            }
        }
        Ok(t)
    }
}

// ------------------------------------------------------------------ section bodies

#[derive(Debug)]
pub struct PgBegin {
    pub pgid: denc::types::SpgT,
    pub sb: OsdSuperblock,
}

pub fn enc_pg_begin(b: &PgBegin) -> Res<Vec<u8>> {
    let mut e = Encoder::new();
    e.versioned(3, 2, |e| {
        b.pgid.pgid.encode(e)?;
        b.sb.encode(e)?;
        b.pgid.shard.encode(e)
    })
    .map_err(en)?;
    Ok(e.into_vec())
}

pub fn dec_pg_begin(body: &[u8]) -> Res<PgBegin> {
    let mut d = Decoder::new(body);
    d.versioned(3, |d, v| {
        let pg = denc::types::PgT::decode(d)?;
        let sb = if v > 1 {
            OsdSuperblock::decode(d)?
        } else {
            OsdSuperblock::default()
        };
        let shard = if v > 2 {
            denc::types::ShardId::decode(d)?
        } else {
            denc::types::ShardId::NO_SHARD
        };
        Ok(PgBegin {
            pgid: denc::types::SpgT { pgid: pg, shard },
            sb,
        })
    })
    .map_err(de)
}

#[derive(Debug)]
pub struct ObjectBegin {
    pub hoid: denc::types::Ghobject,
}

/// `oi_raw`: the object's `_` attribute verbatim (an encoded object_info_t) or `None` (default info).
pub fn enc_object_begin(g: &denc::types::Ghobject, oi_raw: Option<&[u8]>) -> Res<Vec<u8>> {
    let mut e = Encoder::new();
    e.versioned(3, 1, |e| {
        g.hobj.encode(e)?;
        e.u64(g.generation)?;
        g.shard.encode(e)?;
        match oi_raw {
            Some(b) => e.raw(b),
            None => replwire::ObjectInfo::new(g.hobj.clone()).encode(e),
        }
    })
    .map_err(en)?;
    Ok(e.into_vec())
}

pub fn dec_object_begin(body: &[u8]) -> Res<ObjectBegin> {
    let mut d = Decoder::new(body);
    d.versioned(3, |d, v| {
        let hobj = denc::types::Hobject::decode(d)?;
        let (generation, shard) = if v > 1 {
            (d.u64()?, denc::types::ShardId::decode(d)?)
        } else {
            (
                denc::types::Ghobject::NO_GEN,
                denc::types::ShardId::NO_SHARD,
            )
        };
        // object_info_t (v > 2) is not needed: the same bytes arrive in the `_` attribute
        Ok(ObjectBegin {
            hoid: denc::types::Ghobject::new(hobj, generation, shard),
        })
    })
    .map_err(de)
}

pub fn enc_data(off: u64, data: &[u8]) -> Res<Vec<u8>> {
    let mut e = Encoder::with_capacity(data.len() + 32);
    e.versioned(1, 1, |e| {
        e.u64(off)?;
        e.u64(data.len() as u64)?;
        e.bytes(data)
    })
    .map_err(en)?;
    Ok(e.into_vec())
}

pub fn dec_data(body: &[u8]) -> Res<(u64, Vec<u8>)> {
    let mut d = Decoder::new(body);
    d.versioned(1, |d, _| {
        let off = d.u64()?;
        let _len = d.u64()?;
        Ok((off, d.bytes()?.to_vec()))
    })
    .map_err(de)
}

pub fn enc_map(m: &BTreeMap<Vec<u8>, Vec<u8>>) -> Res<Vec<u8>> {
    let mut e = Encoder::new();
    e.versioned(1, 1, |e| {
        e.count(m.len())?;
        for (k, v) in m {
            e.bytes(k)?;
            e.bytes(v)?;
        }
        Ok(())
    })
    .map_err(en)?;
    Ok(e.into_vec())
}

pub fn dec_map(body: &[u8]) -> Res<BTreeMap<Vec<u8>, Vec<u8>>> {
    let mut d = Decoder::new(body);
    d.versioned(1, |d, _| {
        let n = d.count()?;
        let mut m = BTreeMap::new();
        for _ in 0..n {
            let k = d.bytes()?.to_vec();
            let v = d.bytes()?.to_vec();
            m.insert(k, v);
        }
        Ok(m)
    })
    .map_err(de)
}

pub fn enc_omap_hdr(h: &[u8]) -> Res<Vec<u8>> {
    let mut e = Encoder::new();
    e.versioned(1, 1, |e| e.bytes(h)).map_err(en)?;
    Ok(e.into_vec())
}

pub fn dec_omap_hdr(body: &[u8]) -> Res<Vec<u8>> {
    let mut d = Decoder::new(body);
    d.versioned(1, |d, _| Ok(d.bytes()?.to_vec())).map_err(de)
}

#[derive(Debug)]
pub struct Metadata {
    pub struct_ver: u8,
    pub map_epoch: u32,
    pub info: PgInfo,
    pub log: PgLog,
    pub past_intervals: PastIntervals,
    /// The OSDMap at `map_epoch`, verbatim.
    pub osdmap_raw: Vec<u8>,
    /// Pre-nautilus divergent priors; non-empty only in ancient exports.
    pub divergent_priors: usize,
    pub missing: PgMissing,
}

pub fn enc_metadata(m: &Metadata) -> Res<Vec<u8>> {
    let mut e = Encoder::new();
    e.versioned(6, 6, |e| {
        e.u8(m.struct_ver)?;
        e.u32(m.map_epoch)?;
        m.info.encode(e)?;
        m.log.encode(e)?;
        m.past_intervals.encode(e)?;
        e.raw(&m.osdmap_raw)?;
        e.count(0)?; // divergent_priors
        m.missing.encode(e)
    })
    .map_err(en)?;
    Ok(e.into_vec())
}

pub fn dec_metadata(body: &[u8]) -> Res<Metadata> {
    let mut d = Decoder::new(body);
    d.versioned(6, |d, v| {
        let struct_ver = d.u8()?;
        let map_epoch = d.u32()?;
        let info = PgInfo::decode(d)?;
        let log = PgLog::decode(d)?;
        let past_intervals = if v >= 6 {
            PastIntervals::decode(d)?
        } else {
            return Err(denc::Error::BadValue(
                "export without past_intervals (struct_v < 6) is not supported",
            ));
        };
        let osdmap_raw = if v > 2 {
            d.envelope_raw()?.to_vec()
        } else {
            Vec::new()
        };
        let divergent_priors = if v > 3 {
            let n = d.count()?;
            for _ in 0..n {
                denc::types::Eversion::decode(d)?;
                denc::types::Hobject::decode(d)?;
            }
            n
        } else {
            0
        };
        let missing = if v > 4 {
            PgMissing::decode(d)?
        } else {
            PgMissing::default()
        };
        Ok(Metadata {
            struct_ver,
            map_epoch,
            info,
            log,
            past_intervals,
            osdmap_raw,
            divergent_priors,
            missing,
        })
    })
    .map_err(de)
}
