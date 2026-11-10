// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Standard LUKS headers and AES-XTS; see the pinned encryption wire contract.
use aes::{Aes128, Aes256};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine, engine::general_purpose::STANDARD};
use cipher::{BlockCipherDecrypt, BlockCipherEncrypt, BlockSizeUser, KeyInit, consts::U16};
use pbkdf2::pbkdf2_hmac;
use rand::Rng;
use sha2::{Digest, Sha256, Sha512};
use xts_mode::{Array, Xts128};
use zeroize::Zeroizing;

pub const FORMAT_LUKS1: u8 = 0;
pub const FORMAT_LUKS2: u8 = 1;
pub const ALG_AES128: u8 = 0;
pub const ALG_AES256: u8 = 1;
pub const DATA_OFFSET: u64 = 8 * 1024 * 1024;
pub const SECTOR_SIZE: u64 = 4096;
/// Standard primary magic (offset 0).
pub const MAGIC: &[u8; 6] = b"LUKS\xba\xbe";
/// Standard LUKS2 secondary-header magic.
pub const SECONDARY: &[u8; 6] = b"SKUL\xba\xbe";
const CLONE_MAGIC: &[u8; 6] = b"RBDL\xba\xbe";
/// Secondary-header magic of a clone (a header with a parent).
pub const CLONE_SECONDARY: &[u8; 6] = b"LDBR\xba\xbe";
const STRIPES: usize = 4000;
const ITERATIONS: u32 = 200_000;
const HEADER_SIZE: usize = 16 * 1024;
/// KDF parameter bounds enforced on the unlock path before any derivation,
/// see doc/spec/rustyrbd/luks-kdf-limits.md. The memory and cpus maxima are
/// libcryptsetup's own hard limits (`crypt_pbkdf_get_limits`,
/// lib/crypto_backend/pbkdf_check.c); the argon2 work bound (passes x memory)
/// closes the unbounded-CPU gap without rejecting a low-memory, many-pass
/// header libcryptsetup creates. PBKDF2 iterations stay unbounded like stock
/// (u32, so derivation always ends).
const ARGON2_MAX_MEMORY_KIB: u32 = 4 * 1024 * 1024; // 4 GiB
const ARGON2_MAX_CPUS: u32 = 4;
const ARGON2_MAX_WORK_KIB: u64 = 1_000 * ARGON2_MAX_MEMORY_KIB as u64;

#[derive(Debug, PartialEq, Eq)]
pub enum LuksError {
    BadHeader,
    /// The image does not begin with a recognized LUKS or RBD clone magic.
    UnrecognizedMagic,
    /// A recognized RBD clone header has an incompatible magic value.
    WrongMagic,
    BadJson,
    BadKeySize,
    Kdf,
    WrongPassphrase,
}
/// An unlocked volume. The key buffer is wiped when dropped.
#[derive(Clone, PartialEq, Eq)]
pub struct LuksLoad {
    pub volume_key: Zeroizing<Vec<u8>>,
    pub data_offset: u64,
    pub sector_size: usize,
}
impl std::fmt::Debug for LuksLoad {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LuksLoad")
            .field("data_offset", &self.data_offset)
            .field("sector_size", &self.sector_size)
            .finish_non_exhaustive()
    }
}
fn key_size(alg: u8) -> Result<usize, LuksError> {
    match alg {
        ALG_AES128 => Ok(32),
        ALG_AES256 => Ok(64),
        _ => Err(LuksError::BadKeySize),
    }
}
fn random(len: usize) -> Zeroizing<Vec<u8>> {
    let mut value = Zeroizing::new(vec![0; len]);
    rand::rng().fill_bytes(&mut value);
    value
}
fn be32(data: &[u8], off: usize) -> Result<u32, LuksError> {
    Ok(u32::from_be_bytes(
        data.get(off..off + 4)
            .ok_or(LuksError::BadHeader)?
            .try_into()
            .unwrap(),
    ))
}
fn be64(data: &[u8], off: usize) -> Result<u64, LuksError> {
    Ok(u64::from_be_bytes(
        data.get(off..off + 8)
            .ok_or(LuksError::BadHeader)?
            .try_into()
            .unwrap(),
    ))
}
fn field(data: &[u8], off: usize, len: usize) -> Result<&str, LuksError> {
    let bytes = data.get(off..off + len).ok_or(LuksError::BadHeader)?;
    let end = bytes.iter().position(|v| *v == 0).unwrap_or(len);
    std::str::from_utf8(&bytes[..end]).map_err(|_| LuksError::BadHeader)
}
fn put_field(data: &mut [u8], off: usize, text: &str) {
    data[off..off + text.len()].copy_from_slice(text.as_bytes());
}
fn hash(name: &str, bytes: &[u8]) -> Result<Vec<u8>, LuksError> {
    match name {
        "sha256" => Ok(Sha256::digest(bytes).to_vec()),
        "sha512" => Ok(Sha512::digest(bytes).to_vec()),
        _ => Err(LuksError::Kdf),
    }
}
fn pbkdf(
    name: &str,
    key: &[u8],
    salt: &[u8],
    iterations: u32,
    len: usize,
) -> Result<Zeroizing<Vec<u8>>, LuksError> {
    if iterations == 0 {
        return Err(LuksError::BadHeader);
    }
    let mut out = Zeroizing::new(vec![0; len]);
    match name {
        "sha256" => pbkdf2_hmac::<Sha256>(key, salt, iterations, &mut out),
        "sha512" => pbkdf2_hmac::<Sha512>(key, salt, iterations, &mut out),
        _ => return Err(LuksError::Kdf),
    };
    Ok(out)
}
fn equal(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |diff, (a, b)| diff | (a ^ b)) == 0
}
fn diffuse(bytes: &mut [u8], name: &str) -> Result<(), LuksError> {
    match name {
        "sha256" => diffuse_with::<Sha256>(bytes),
        "sha512" => diffuse_with::<Sha512>(bytes),
        _ => return Err(LuksError::Kdf),
    }
    Ok(())
}
/// Hash each digest-wide chunk with its big-endian index prefix, without
/// copying key material into a heap buffer.
fn diffuse_with<D: Digest>(bytes: &mut [u8]) {
    for (index, chunk) in bytes.chunks_mut(<D as Digest>::output_size()).enumerate() {
        let digest = D::new()
            .chain_update((index as u32).to_be_bytes())
            .chain_update(&*chunk)
            .finalize();
        chunk.copy_from_slice(&digest[..chunk.len()]);
    }
}
fn af_merge(
    bytes: &[u8],
    key_len: usize,
    stripes: usize,
    name: &str,
) -> Result<Zeroizing<Vec<u8>>, LuksError> {
    if stripes == 0
        || !matches!(key_len, 32 | 64)
        || key_len.checked_mul(stripes) != Some(bytes.len())
    {
        return Err(LuksError::BadHeader);
    }
    let mut accumulator = Zeroizing::new(vec![0; key_len]);
    for (index, stripe) in bytes.chunks_exact(key_len).enumerate() {
        for (a, b) in accumulator.iter_mut().zip(stripe) {
            *a ^= b;
        }
        if index + 1 < stripes {
            diffuse(&mut accumulator, name)?;
        }
    }
    Ok(accumulator)
}
/// Split `key` into `STRIPES` anti-forensic stripes, zero-padded to a
/// multiple of `align` in the same allocation (no unwiped reallocation).
fn af_split(key: &[u8], align: usize) -> Result<Zeroizing<Vec<u8>>, LuksError> {
    let len = key.len() * STRIPES;
    let mut out = Zeroizing::new(vec![0; len.next_multiple_of(align)]);
    rand::rng().fill_bytes(&mut out[..len]);
    let mut acc = Zeroizing::new(vec![0; key.len()]);
    for stripe in out[..key.len() * (STRIPES - 1)].chunks_exact(key.len()) {
        for (a, b) in acc.iter_mut().zip(stripe) {
            *a ^= b;
        }
        diffuse(&mut acc, "sha256")?;
    }
    for (dst, (a, b)) in out[key.len() * (STRIPES - 1)..len]
        .iter_mut()
        .zip(acc.iter().zip(key))
    {
        *dst = a ^ b;
    }
    Ok(out)
}
fn uuid() -> String {
    let mut bytes = random(16);
    bytes[6] = (bytes[6] & 15) | 64;
    bytes[8] = (bytes[8] & 63) | 128;
    let text = hex::encode(bytes);
    format!(
        "{}-{}-{}-{}-{}",
        &text[..8],
        &text[8..12],
        &text[12..16],
        &text[16..20],
        &text[20..]
    )
}
fn slot_area(header: &[u8], offset: u64, size: u64, payload: u64) -> Result<&[u8], LuksError> {
    let end = offset.checked_add(size).ok_or(LuksError::BadHeader)?;
    if end > payload || !offset.is_multiple_of(512) || !size.is_multiple_of(512) {
        return Err(LuksError::BadHeader);
    }
    let start = usize::try_from(offset).map_err(|_| LuksError::BadHeader)?;
    let end = usize::try_from(end).map_err(|_| LuksError::BadHeader)?;
    header.get(start..end).ok_or(LuksError::BadHeader)
}

pub fn luks1_create(passphrase: &[u8], alg: u8) -> Result<(Vec<u8>, LuksLoad), LuksError> {
    luks1_create_at(passphrase, alg, DATA_OFFSET, DATA_OFFSET)
}

/// Allocate the reserved header prefix. The caller has validated `len`
/// against the raw image, so a refused reservation is a header error instead
/// of a process abort.
fn header_prefix(len: u64) -> Result<Vec<u8>, LuksError> {
    let len = usize::try_from(len).map_err(|_| LuksError::BadHeader)?;
    let mut header = Vec::new();
    header
        .try_reserve_exact(len)
        .map_err(|_| LuksError::BadHeader)?;
    header.resize(len, 0);
    Ok(header)
}

/// Create standard LUKS metadata with an explicitly aligned raw payload
/// offset inside a raw image of `raw_size` bytes. The returned buffer spans
/// the whole reserved prefix, so the offset is validated against the image
/// before anything is allocated.
pub fn luks1_create_at(
    passphrase: &[u8],
    alg: u8,
    data_offset: u64,
    raw_size: u64,
) -> Result<(Vec<u8>, LuksLoad), LuksError> {
    if data_offset < DATA_OFFSET
        || !data_offset.is_multiple_of(512)
        || data_offset > raw_size
        || u32::try_from(data_offset / 512).is_err()
    {
        return Err(LuksError::BadHeader);
    }

    let key = random(key_size(alg)?);
    let salt = random(32);
    let digest_salt = random(32);
    let mut header = header_prefix(data_offset)?;
    header[..6].copy_from_slice(MAGIC);
    header[6..8].copy_from_slice(&1u16.to_be_bytes());
    put_field(&mut header, 8, "aes");
    put_field(&mut header, 40, "xts-plain64");
    put_field(&mut header, 72, "sha256");
    header[104..108].copy_from_slice(
        &u32::try_from(data_offset / 512)
            .map_err(|_| LuksError::BadHeader)?
            .to_be_bytes(),
    );
    header[108..112].copy_from_slice(&(key.len() as u32).to_be_bytes());
    header[112..132].copy_from_slice(&pbkdf("sha256", &key, &digest_salt, ITERATIONS, 20)?);
    header[132..164].copy_from_slice(&digest_salt);
    header[164..168].copy_from_slice(&ITERATIONS.to_be_bytes());
    put_field(&mut header, 168, &uuid());
    let reservation = (key.len() * STRIPES).next_multiple_of(4096);
    for slot in 0..8 {
        header[208 + slot * 48..212 + slot * 48].copy_from_slice(&0x0000deadu32.to_be_bytes());
        let descriptor = 208 + slot * 48;
        let material_offset = 4096 + slot * reservation;
        header[descriptor + 40..descriptor + 44]
            .copy_from_slice(&((material_offset / 512) as u32).to_be_bytes());
        header[descriptor + 44..descriptor + 48].copy_from_slice(&(STRIPES as u32).to_be_bytes());
    }
    let slot = 208;
    let offset = 4096usize;
    header[slot..slot + 4].copy_from_slice(&0x00ac71f3u32.to_be_bytes());
    header[slot + 4..slot + 8].copy_from_slice(&ITERATIONS.to_be_bytes());
    header[slot + 8..slot + 40].copy_from_slice(&salt);
    header[slot + 40..slot + 44].copy_from_slice(&((offset / 512) as u32).to_be_bytes());
    header[slot + 44..slot + 48].copy_from_slice(&(STRIPES as u32).to_be_bytes());
    let mut area = af_split(&key, 512)?;
    let slot_key = pbkdf("sha256", passphrase, &salt, ITERATIONS, key.len())?;
    AesXts::new(&slot_key, 512)?.apply(&mut area, 0, false)?;
    header[offset..offset + area.len()].copy_from_slice(&area);
    Ok((
        header,
        LuksLoad {
            volume_key: key,
            data_offset,
            sector_size: 512,
        },
    ))
}
pub fn luks1_parse(header: &[u8], passphrase: &[u8]) -> Result<LuksLoad, LuksError> {
    if header.len() < 592
        || detect_format(header) != Some(FORMAT_LUKS1)
        || field(header, 8, 32)? != "aes"
        || field(header, 40, 32)? != "xts-plain64"
    {
        return Err(LuksError::BadHeader);
    }
    let name = field(header, 72, 32)?;
    let payload = be32(header, 104)? as u64 * 512;
    let key_len = be32(header, 108)? as usize;
    if !matches!(key_len, 32 | 64) {
        return Err(LuksError::BadKeySize);
    }
    for slot in 0..8 {
        let off = 208 + slot * 48;
        if be32(header, off)? != 0x00ac71f3 {
            continue;
        }
        let stripes = be32(header, off + 44)? as usize;
        let len = key_len.checked_mul(stripes).ok_or(LuksError::BadHeader)?;
        let size = len.checked_add(511).ok_or(LuksError::BadHeader)? / 512 * 512;
        let offset = be32(header, off + 40)? as u64 * 512;
        if offset < 592 {
            return Err(LuksError::BadHeader);
        }
        let mut area = Zeroizing::new(slot_area(header, offset, size as u64, payload)?.to_vec());
        let slot_key = pbkdf(
            name,
            passphrase,
            &header[off + 8..off + 40],
            be32(header, off + 4)?,
            key_len,
        )?;
        AesXts::new(&slot_key, 512)?.apply(&mut area, 0, true)?;
        let key = af_merge(&area[..len], key_len, stripes, name)?;
        let digest = pbkdf(name, &key, &header[132..164], be32(header, 164)?, 20)?;
        if equal(&digest, &header[112..132]) {
            return Ok(LuksLoad {
                volume_key: key,
                data_offset: payload,
                sector_size: 512,
            });
        }
    }
    Err(LuksError::WrongPassphrase)
}
fn checksum_copy(header: &mut [u8], offset: usize, size: usize) {
    header[offset + 448..offset + 512].fill(0);
    let checksum = Sha256::digest(&header[offset..offset + size]);
    header[offset + 448..offset + 480].copy_from_slice(&checksum);
}
pub fn luks2_create(passphrase: &[u8], alg: u8) -> Result<(Vec<u8>, LuksLoad), LuksError> {
    luks2_create_at(passphrase, alg, DATA_OFFSET, DATA_OFFSET)
}

/// Create standard LUKS metadata with an explicitly aligned raw payload
/// offset inside a raw image of `raw_size` bytes. The returned buffer spans
/// the whole reserved prefix, so the offset is validated against the image
/// before anything is allocated.
pub fn luks2_create_at(
    passphrase: &[u8],
    alg: u8,
    data_offset: u64,
    raw_size: u64,
) -> Result<(Vec<u8>, LuksLoad), LuksError> {
    if data_offset < DATA_OFFSET
        || !data_offset.is_multiple_of(512)
        || data_offset > raw_size
        || usize::try_from(data_offset).is_err()
    {
        return Err(LuksError::BadHeader);
    }

    let key = random(key_size(alg)?);
    let salt = random(32);
    let digest_salt = random(32);
    let slot_offset = 2 * HEADER_SIZE;
    let mut area = af_split(&key, 4096)?;
    let kdf = argon_key(
        passphrase,
        &salt,
        3,
        65536,
        4,
        Algorithm::Argon2id,
        key.len(),
    )?;
    AesXts::new(&kdf, 512)?.apply(&mut area, 0, false)?;
    let json=serde_json::json!({"keyslots":{"0":{"type":"luks2","key_size":key.len(),"af":{"type":"luks1","stripes":STRIPES,"hash":"sha256"},"area":{"type":"raw","offset":slot_offset.to_string(),"size":area.len().to_string(),"encryption":"aes-xts-plain64","key_size":key.len()},"kdf":{"type":"argon2id","time":3,"memory":65536,"cpus":4,"salt":STANDARD.encode(&salt)}}},"tokens":{},"segments":{"0":{"type":"crypt","offset":data_offset.to_string(),"size":"dynamic","encryption":"aes-xts-plain64","iv_tweak":"0","sector_size":4096}},"digests":{"0":{"type":"pbkdf2","keyslots":["0"],"segments":["0"],"hash":"sha256","iterations":ITERATIONS,"salt":STANDARD.encode(&digest_salt),"digest":STANDARD.encode(pbkdf("sha256",&key,&digest_salt,ITERATIONS,32)?) }},"config":{"json_size":(HEADER_SIZE-4096).to_string(),"keyslots_size":(data_offset as usize-2*HEADER_SIZE).to_string()}}).to_string();
    if json.len() + 4096 >= HEADER_SIZE {
        return Err(LuksError::BadJson);
    }
    let mut header = header_prefix(data_offset)?;
    let id = uuid();
    for (offset, magic) in [(0, MAGIC), (HEADER_SIZE, SECONDARY)] {
        header[offset..offset + 6].copy_from_slice(magic);
        header[offset + 6..offset + 8].copy_from_slice(&2u16.to_be_bytes());
        header[offset + 8..offset + 16].copy_from_slice(&(HEADER_SIZE as u64).to_be_bytes());
        header[offset + 16..offset + 24].copy_from_slice(&1u64.to_be_bytes());
        put_field(&mut header, offset + 72, "sha256");
        header[offset + 104..offset + 168].copy_from_slice(&random(64));
        put_field(&mut header, offset + 168, &id);
        header[offset + 256..offset + 264].copy_from_slice(&(offset as u64).to_be_bytes());
        header[offset + 4096..offset + 4096 + json.len()].copy_from_slice(json.as_bytes());
        checksum_copy(&mut header, offset, HEADER_SIZE);
    }
    header[slot_offset..slot_offset + area.len()].copy_from_slice(&area);
    Ok((
        header,
        LuksLoad {
            volume_key: key,
            data_offset,
            sector_size: 4096,
        },
    ))
}
fn argon_key(
    password: &[u8],
    salt: &[u8],
    time: u32,
    memory: u32,
    cpus: u32,
    algorithm: Algorithm,
    len: usize,
) -> Result<Zeroizing<Vec<u8>>, LuksError> {
    // Reject header KDF parameters above libcryptsetup's hard limits before
    // any allocation: a crafted header must not force a ~TiB allocation or
    // near-endless CPU (spec rustyrbd/luks-kdf-limits.md).
    if memory > ARGON2_MAX_MEMORY_KIB
        || cpus > ARGON2_MAX_CPUS
        || u64::from(time) * u64::from(memory) > ARGON2_MAX_WORK_KIB
    {
        return Err(LuksError::Kdf);
    }
    let params = Params::new(memory, time, cpus, None).map_err(|_| LuksError::Kdf)?;
    let mut output = Zeroizing::new(vec![0; len]);
    Argon2::new(algorithm, Version::V0x13, params)
        .hash_password_into(password, salt, &mut output)
        .map_err(|_| LuksError::Kdf)?;
    Ok(output)
}
fn text<'a>(v: &'a serde_json::Value, key: &str) -> Result<&'a str, LuksError> {
    v.get(key)
        .and_then(|v| v.as_str())
        .ok_or(LuksError::BadJson)
}
fn number(v: &serde_json::Value, key: &str) -> Result<u64, LuksError> {
    v.get(key)
        .and_then(|v| v.as_u64())
        .ok_or(LuksError::BadJson)
}
fn u32_json(v: &serde_json::Value, key: &str) -> Result<u32, LuksError> {
    u32::try_from(number(v, key)?).map_err(|_| LuksError::BadJson)
}
fn decimal(v: &serde_json::Value, key: &str) -> Result<u64, LuksError> {
    text(v, key)?.parse().map_err(|_| LuksError::BadJson)
}
fn b64(v: &serde_json::Value, key: &str) -> Result<Vec<u8>, LuksError> {
    STANDARD
        .decode(text(v, key)?)
        .map_err(|_| LuksError::BadJson)
}
fn metadata_copy(header: &[u8], off: usize) -> Result<(u64, usize, serde_json::Value), LuksError> {
    let prefix = header
        .get(off..off.checked_add(4096).ok_or(LuksError::BadHeader)?)
        .ok_or(LuksError::BadHeader)?;
    let expected = if off == 0 { MAGIC } else { SECONDARY };
    if &prefix[..6] != expected
        || prefix[6..8] != 2u16.to_be_bytes()
        || be64(prefix, 256)? != off as u64
    {
        return Err(LuksError::BadHeader);
    }
    let size = usize::try_from(be64(prefix, 8)?).map_err(|_| LuksError::BadHeader)?;
    if !(16384..=4 * 1024 * 1024).contains(&size)
        || !size.is_power_of_two()
        || (off != 0 && off != size)
    {
        return Err(LuksError::BadHeader);
    }
    let mut copy = header
        .get(off..off.checked_add(size).ok_or(LuksError::BadHeader)?)
        .ok_or(LuksError::BadHeader)?
        .to_vec();
    let stored = copy[448..512].to_vec();
    copy[448..512].fill(0);
    let calculated = hash(field(prefix, 72, 32)?, &copy)?;
    if !equal(&calculated, &stored[..calculated.len()])
        || stored[calculated.len()..].iter().any(|b| *b != 0)
    {
        return Err(LuksError::BadHeader);
    }
    let json = &copy[4096..];
    let end = json
        .iter()
        .position(|v| *v == 0)
        .ok_or(LuksError::BadJson)?;
    let value = serde_json::from_slice(&json[..end]).map_err(|_| LuksError::BadJson)?;
    Ok((be64(prefix, 16)?, size, value))
}
pub fn luks2_parse(header: &[u8], passphrase: &[u8]) -> Result<LuksLoad, LuksError> {
    let (_, metadata_size, value) = newest_metadata_copy(header)?;
    unlock_luks2(header, passphrase, metadata_size, value)
}

fn newest_metadata_copy(header: &[u8]) -> Result<(u64, usize, serde_json::Value), LuksError> {
    // Probe standard secondary offsets independently of a corrupt primary size.
    let mut copies = Vec::new();
    if let Ok(copy) = metadata_copy(header, 0) {
        copies.push(copy)
    }
    for shift in 14..=22 {
        let offset = 1usize << shift;
        if let Ok(copy) = metadata_copy(header, offset) {
            copies.push(copy)
        }
    }
    copies
        .into_iter()
        .max_by_key(|copy| copy.0)
        .ok_or(LuksError::BadHeader)
}

fn unlock_luks2(
    header: &[u8],
    passphrase: &[u8],
    metadata_size: usize,
    value: serde_json::Value,
) -> Result<LuksLoad, LuksError> {
    let segments = value
        .get("segments")
        .and_then(|v| v.as_object())
        .ok_or(LuksError::BadJson)?;
    let (segment_id, segment) = segments
        .iter()
        .find(|(_, v)| v.get("type").and_then(|v| v.as_str()) == Some("crypt"))
        .ok_or(LuksError::BadJson)?;
    if text(segment, "encryption")? != "aes-xts-plain64" || decimal(segment, "iv_tweak")? != 0 {
        return Err(LuksError::BadHeader);
    }
    let payload = decimal(segment, "offset")?;
    let sector_size =
        usize::try_from(number(segment, "sector_size")?).map_err(|_| LuksError::BadJson)?;
    if !matches!(sector_size, 512 | 4096) {
        return Err(LuksError::BadHeader);
    }
    let slots = value
        .get("keyslots")
        .and_then(|v| v.as_object())
        .ok_or(LuksError::BadJson)?;
    let digests = value
        .get("digests")
        .and_then(|v| v.as_object())
        .ok_or(LuksError::BadJson)?;
    for (slot_id, slot) in slots {
        if text(slot, "type")? != "luks2" {
            continue;
        }
        let key_len = usize::try_from(number(slot, "key_size")?).map_err(|_| LuksError::BadJson)?;
        if !matches!(key_len, 32 | 64) {
            return Err(LuksError::BadKeySize);
        }
        let area = slot.get("area").ok_or(LuksError::BadJson)?;
        if text(area, "encryption")? != "aes-xts-plain64" || text(area, "type")? != "raw" {
            return Err(LuksError::BadHeader);
        }
        let offset = decimal(area, "offset")?;
        let area_size = decimal(area, "size")?;
        let keyslots_size = decimal(
            value.get("config").ok_or(LuksError::BadJson)?,
            "keyslots_size",
        )?;
        let reserved_end = (metadata_size as u64)
            .checked_mul(2)
            .and_then(|start| start.checked_add(keyslots_size))
            .ok_or(LuksError::BadHeader)?;
        if offset < 2 * metadata_size as u64
            || offset
                .checked_add(area_size)
                .is_none_or(|end| end > reserved_end)
        {
            return Err(LuksError::BadHeader);
        }
        let slot_key_len =
            usize::try_from(number(area, "key_size")?).map_err(|_| LuksError::BadJson)?;
        if !matches!(slot_key_len, 32 | 64) {
            return Err(LuksError::BadKeySize);
        }
        let kdf = slot.get("kdf").ok_or(LuksError::BadJson)?;
        let salt = b64(kdf, "salt")?;
        let slot_key = match text(kdf, "type")? {
            "pbkdf2" => pbkdf(
                text(kdf, "hash")?,
                passphrase,
                &salt,
                u32_json(kdf, "iterations")?,
                slot_key_len,
            )?,
            kind @ ("argon2i" | "argon2id") => argon_key(
                passphrase,
                &salt,
                u32_json(kdf, "time")?,
                u32_json(kdf, "memory")?,
                u32_json(kdf, "cpus")?,
                if kind == "argon2i" {
                    Algorithm::Argon2i
                } else {
                    Algorithm::Argon2id
                },
                slot_key_len,
            )?,
            _ => return Err(LuksError::Kdf),
        };
        let mut material = Zeroizing::new(slot_area(header, offset, area_size, payload)?.to_vec());
        AesXts::new(&slot_key, 512)?.apply(&mut material, 0, true)?;
        let af = slot.get("af").ok_or(LuksError::BadJson)?;
        if text(af, "type")? != "luks1" {
            return Err(LuksError::BadHeader);
        }
        let stripes = usize::try_from(number(af, "stripes")?).map_err(|_| LuksError::BadJson)?;
        let len = key_len.checked_mul(stripes).ok_or(LuksError::BadHeader)?;
        let key = af_merge(
            material.get(..len).ok_or(LuksError::BadHeader)?,
            key_len,
            stripes,
            text(af, "hash")?,
        )?;
        for digest in digests.values() {
            let links = |key: &str, id: &str| {
                digest
                    .get(key)
                    .and_then(|v| v.as_array())
                    .is_some_and(|a| a.iter().any(|v| v.as_str() == Some(id)))
            };
            if !links("keyslots", slot_id) || !links("segments", segment_id) {
                continue;
            }
            if text(digest, "type")? != "pbkdf2" {
                return Err(LuksError::Kdf);
            }
            let expected = b64(digest, "digest")?;
            if expected.is_empty() {
                return Err(LuksError::BadHeader);
            }
            let check = pbkdf(
                text(digest, "hash")?,
                &key,
                &b64(digest, "salt")?,
                u32_json(digest, "iterations")?,
                expected.len(),
            )?;
            if equal(&check, &expected) {
                return Ok(LuksLoad {
                    volume_key: key,
                    data_offset: payload,
                    sector_size,
                });
            }
        }
    }
    Err(LuksError::WrongPassphrase)
}
pub fn detect_format(header: &[u8]) -> Option<u8> {
    if header.get(..6)? != MAGIC && header.get(..6)? != CLONE_MAGIC {
        return None;
    }
    match u16::from_be_bytes(header.get(6..8)?.try_into().ok()?) {
        1 => Some(FORMAT_LUKS1),
        2 => Some(FORMAT_LUKS2),
        _ => None,
    }
}

/// Restore the standard LUKS magic fields in a private copy of a clone
/// header. The on-disk bytes and LUKS checksums are left untouched.
pub fn restore_clone_magic(header: &mut [u8]) -> Result<bool, LuksError> {
    if header.get(..6) != Some(CLONE_MAGIC.as_slice()) {
        return Ok(false);
    }
    let format = detect_format(header).ok_or(LuksError::WrongMagic)?;
    match format {
        FORMAT_LUKS1 => header[..6].copy_from_slice(MAGIC),
        FORMAT_LUKS2 => {
            let size = usize::try_from(be64(header, 8)?).map_err(|_| LuksError::BadHeader)?;
            if size < 16 * 1024 || header.len() < size.checked_add(6).ok_or(LuksError::BadHeader)? {
                return Err(LuksError::BadHeader);
            }
            if header.get(size..size + 6) != Some(CLONE_SECONDARY.as_slice()) {
                return Err(LuksError::WrongMagic);
            }
            header[..6].copy_from_slice(MAGIC);
            header[size..size + 6].copy_from_slice(SECONDARY);
        }
        _ => return Err(LuksError::WrongMagic),
    }
    Ok(true)
}

/// Where the standard magic goes back when an encrypted clone is flattened
/// (the reference's luks FlattenRequest). `prefix` = the first 16 raw header
/// bytes. `Ok(None)`: the header already carries the standard magic. `Ok(Some(None))`:
/// rewrite the primary magic only (LUKS1). `Ok(Some(Some(offset)))`: also rewrite the
/// LUKS2 secondary-header magic at `offset`.
pub fn flatten_restore_plan(prefix: &[u8]) -> Result<Option<Option<u64>>, LuksError> {
    if prefix.get(..6) != Some(CLONE_MAGIC.as_slice()) {
        return Ok(None);
    }
    match detect_format(prefix).ok_or(LuksError::WrongMagic)? {
        FORMAT_LUKS1 => Ok(Some(None)),
        FORMAT_LUKS2 => {
            let size = be64(prefix, 8)?;
            if !(16384..=4 * 1024 * 1024).contains(&size) || !size.is_power_of_two() {
                return Err(LuksError::BadHeader);
            }
            Ok(Some(Some(size)))
        }
        _ => Err(LuksError::WrongMagic),
    }
}

/// Mark a newly created standard header as belonging to a cloned image.
/// Checksums remain those calculated with the standard LUKS magic values.
pub fn mark_clone_magic(header: &mut [u8]) -> Result<(), LuksError> {
    match detect_format(header).ok_or(LuksError::BadHeader)? {
        FORMAT_LUKS1 => header[..6].copy_from_slice(CLONE_MAGIC),
        FORMAT_LUKS2 => {
            let size = usize::try_from(be64(header, 8)?).map_err(|_| LuksError::BadHeader)?;
            if header.len() < size.checked_add(6).ok_or(LuksError::BadHeader)?
                || header.get(size..size + 6) != Some(SECONDARY.as_slice())
            {
                return Err(LuksError::BadHeader);
            }
            header[..6].copy_from_slice(CLONE_MAGIC);
            header[size..size + 6].copy_from_slice(CLONE_SECONDARY);
        }
        _ => return Err(LuksError::BadHeader),
    }
    Ok(())
}

/// Required prefix for metadata and keyslot loading. The caller must check it
/// against the raw image size before allocating or issuing another read.
/// Reevaluate after extending the prefix: newly discovered metadata can reveal
/// keyslots beyond it. A request larger than `header` always advances through
/// the format's finite metadata sizes or to the selected payload boundary.
pub fn required_header_size(header: &[u8]) -> Result<usize, LuksError> {
    match detect_format(header) {
        Some(FORMAT_LUKS1) => {
            usize::try_from(be32(header, 104)? as u64 * 512).map_err(|_| LuksError::BadHeader)
        }
        Some(FORMAT_LUKS2) => {
            let size = usize::try_from(be64(header, 8)?).map_err(|_| LuksError::BadHeader)?;
            if header.get(..6) == Some(CLONE_MAGIC.as_slice()) {
                if !(16384..=4 * 1024 * 1024).contains(&size) || !size.is_power_of_two() {
                    return Err(LuksError::BadHeader);
                }
                return size.checked_mul(2).ok_or(LuksError::BadHeader);
            }
            let (_, metadata_size, value) = match newest_metadata_copy(header) {
                Ok(copy) => copy,
                Err(_) => {
                    // Each format-defined secondary copy must be read in full
                    // before a damaged primary can make the header unloadable.
                    return (14..=22)
                        .map(|shift| 2usize << shift)
                        .find(|end| *end > header.len())
                        .ok_or(LuksError::BadHeader);
                }
            };
            let segments = value
                .get("segments")
                .and_then(|v| v.as_object())
                .ok_or(LuksError::BadJson)?;
            let segment = segments
                .values()
                .find(|v| v.get("type").and_then(|v| v.as_str()) == Some("crypt"))
                .ok_or(LuksError::BadJson)?;
            usize::try_from(decimal(segment, "offset")?)
                .map(|payload| payload.max(2 * metadata_size))
                .map_err(|_| LuksError::BadHeader)
        }
        _ => Err(LuksError::BadHeader),
    }
}

/// Expanded AES key schedules, built once per key. The `aes` crate wipes
/// each schedule on drop (feature `zeroize`).
/// Boxed: the schedules differ by kilobytes (AES-NI vs soft backends).
enum Schedule {
    Aes128(Box<Keys<Aes128>>),
    Aes256(Box<Keys<Aes256>>),
}

/// XTS area cipher plus the two block ciphers for partial-unit transforms.
struct Keys<C> {
    area: Xts128<C>,
    data: C,
    tweak: C,
}

impl Schedule {
    fn new(key: &[u8]) -> Result<Self, LuksError> {
        match key.len() {
            32 => {
                let (k1, k2) = key.split_at(16);
                Ok(Self::Aes128(Box::new(Keys {
                    area: Xts128::new(cipher_key(k1)?, cipher_key(k2)?),
                    data: cipher_key(k1)?,
                    tweak: cipher_key(k2)?,
                })))
            }
            64 => {
                let (k1, k2) = key.split_at(32);
                Ok(Self::Aes256(Box::new(Keys {
                    area: Xts128::new(cipher_key(k1)?, cipher_key(k2)?),
                    data: cipher_key(k1)?,
                    tweak: cipher_key(k2)?,
                })))
            }
            _ => Err(LuksError::BadKeySize),
        }
    }
}

pub struct AesXts {
    key: Zeroizing<Vec<u8>>,
    schedule: Schedule,
    sector_size: usize,
}

impl Clone for AesXts {
    fn clone(&self) -> Self {
        Self::new(&self.key, self.sector_size).expect("key and sector size were validated in new")
    }
}

impl std::fmt::Debug for AesXts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AesXts")
            .field("sector_size", &self.sector_size)
            .finish_non_exhaustive()
    }
}

impl AesXts {
    /// Build a cryptor from a 32- or 64-byte volume key and the LUKS sector
    /// size (512 for LUKS1, 4096 for LUKS2). The AES key schedules are
    /// expanded here once, not per operation.
    pub fn new(volume_key: &[u8], sector_size: usize) -> Result<Self, LuksError> {
        if !matches!(sector_size, 512 | 4096) {
            return Err(LuksError::BadHeader);
        }
        Ok(Self {
            schedule: Schedule::new(volume_key)?,
            key: Zeroizing::new(volume_key.to_vec()),
            sector_size,
        })
    }

    /// The XTS block size (16 bytes for AES).
    pub fn block_size(&self) -> usize {
        16
    }

    /// The LUKS sector size.
    pub fn sector_size(&self) -> usize {
        self.sector_size
    }

    /// Encrypt or decrypt one XTS-aligned extent in place. `sector` is the
    /// logical sector number (the byte offset relative to the data offset,
    /// divided by the sector size) and `decrypt` selects the direction.
    pub fn apply(&self, data: &mut [u8], sector: u64, decrypt: bool) -> Result<(), LuksError> {
        if data.is_empty() {
            return Ok(());
        }
        if !data.len().is_multiple_of(self.sector_size) {
            return Err(LuksError::BadKeySize);
        }
        // LUKS `xts-plain64` convention: the 64-bit sector number is stored
        // little-endian in the first 8 bytes of the 16-byte initial tweak, the
        // rest is zero (the reference `BlockCrypto` builds the IV exactly
        // this way).
        let get_tweak = |i: u128| {
            let mut b = [0u8; 16];
            let number = sector as u128 + (i - sector as u128) * (self.sector_size / 512) as u128;
            b[..8].copy_from_slice(&(number as u64).to_le_bytes());
            Array(b)
        };
        match &self.schedule {
            Schedule::Aes128(keys) => {
                let area = &keys.area;
                if decrypt {
                    area.decrypt_area(data, self.sector_size, sector as u128, get_tweak);
                } else {
                    area.encrypt_area(data, self.sector_size, sector as u128, get_tweak);
                }
            }
            Schedule::Aes256(keys) => {
                let area = &keys.area;
                if decrypt {
                    area.decrypt_area(data, self.sector_size, sector as u128, get_tweak);
                } else {
                    area.encrypt_area(data, self.sector_size, sector as u128, get_tweak);
                }
            }
        }
        Ok(())
    }

    /// Transform complete AES blocks at an arbitrary position in an XTS
    /// unit. The logical offset is relative to the encrypted payload.
    pub fn apply_blocks(
        &self,
        data: &mut [u8],
        offset: u64,
        decrypt: bool,
    ) -> Result<(), LuksError> {
        if !offset.is_multiple_of(16) || !data.len().is_multiple_of(16) {
            return Err(LuksError::BadKeySize);
        }
        offset
            .checked_add(data.len() as u64)
            .ok_or(LuksError::BadKeySize)?;
        if offset.is_multiple_of(self.sector_size as u64)
            && data.len().is_multiple_of(self.sector_size)
        {
            return self.apply(data, offset / 512, decrypt);
        }
        match &self.schedule {
            Schedule::Aes128(keys) => apply_xts_blocks(
                &keys.data,
                &keys.tweak,
                self.sector_size,
                data,
                offset,
                decrypt,
            ),
            Schedule::Aes256(keys) => apply_xts_blocks(
                &keys.data,
                &keys.tweak,
                self.sector_size,
                data,
                offset,
                decrypt,
            ),
        }
        Ok(())
    }
}

/// Expand an AES key in place from the wiped key buffer; the `aes` crate
/// wipes the expanded schedule on drop (feature `zeroize`).
fn cipher_key<C: KeyInit>(key: &[u8]) -> Result<C, LuksError> {
    C::new_from_slice(key).map_err(|_| LuksError::BadKeySize)
}

fn apply_xts_blocks<C: BlockSizeUser<BlockSize = U16> + BlockCipherEncrypt + BlockCipherDecrypt>(
    data_cipher: &C,
    tweak_cipher: &C,
    unit: usize,
    data: &mut [u8],
    offset: u64,
    decrypt: bool,
) {
    let mut at = offset;
    let mut cursor = 0;
    while cursor < data.len() {
        let within = (at % unit as u64) as usize;
        let span = (unit - within).min(data.len() - cursor);
        let mut tweak: Array<u8, U16> = Array([0u8; 16]);
        tweak.0[..8].copy_from_slice(&(at / unit as u64 * (unit as u64 / 512)).to_le_bytes());
        tweak_cipher.encrypt_block(&mut tweak);
        let advance = |tweak: &mut Array<u8, U16>| {
            let value = u128::from_le_bytes(tweak.0);
            tweak.0 = ((value << 1) ^ if value >> 127 != 0 { 0x87 } else { 0 }).to_le_bytes();
        };
        for _ in 0..within / 16 {
            advance(&mut tweak);
        }
        let mut block_start = cursor;
        while block_start < cursor + span {
            let block =
                Array::slice_as_mut_array(&mut data[block_start..block_start + 16]).unwrap();
            for i in 0..16 {
                block[i] ^= tweak[i];
            }
            if decrypt {
                data_cipher.decrypt_block(block);
            } else {
                data_cipher.encrypt_block(block);
            }
            for i in 0..16 {
                block[i] ^= tweak[i];
            }
            advance(&mut tweak);
            block_start += 16;
        }
        cursor += span;
        at += span as u64;
    }
}

/// An installed image cryptor: the AES-XTS data key plus the LUKS data-area
/// offset. Encrypted image data starts at raw byte `data_offset`; a logical
/// image offset `x` maps to raw `x + data_offset`, and the XTS sector number
/// is `x / 512` (the reference `BlockCrypto` convention).
#[derive(Debug, Clone)]
pub struct Cryptor {
    xts: AesXts,
    data_offset: u64,
}

impl Cryptor {
    /// Build a cryptor from a 32- or 64-byte volume key, the LUKS data-area
    /// offset, and the LUKS sector size (512 for LUKS1, 4096 for LUKS2).
    pub fn new(volume_key: &[u8], data_offset: u64, sector_size: usize) -> Result<Self, LuksError> {
        Ok(Self {
            xts: AesXts::new(volume_key, sector_size)?,
            data_offset,
        })
    }

    /// The LUKS data-area offset in raw bytes.
    pub fn data_offset(&self) -> u64 {
        self.data_offset
    }

    /// The LUKS sector size in bytes (the XTS sector boundary).
    pub fn sector_size(&self) -> usize {
        self.xts.sector_size()
    }

    /// Map a logical image offset to its raw (on-disk) offset. An offset that
    /// cannot be shifted by `data_offset` is rejected instead of wrapping.
    pub fn raw_offset(&self, logical: u64) -> Result<u64, LuksError> {
        logical
            .checked_add(self.data_offset)
            .ok_or(LuksError::BadHeader)
    }

    /// Encrypt `data` in place for a write at logical `offset`.
    pub fn encrypt(&self, data: &mut [u8], offset: u64) -> Result<(), LuksError> {
        self.xts.apply(data, offset / 512, false)
    }

    /// Decrypt `data` in place for a read at logical `offset`.
    pub fn decrypt(&self, data: &mut [u8], offset: u64) -> Result<(), LuksError> {
        self.xts.apply(data, offset / 512, true)
    }

    /// Decrypt allocated units using provider extent metadata. Extents are
    /// ordered, non-overlapping byte ranges within `data`; their bytes already
    /// occupy those positions. An entirely absent unit becomes plaintext zero.
    /// A partly allocated unit is decrypted with zero ciphertext in its gaps.
    pub fn decrypt_sparse_units(
        &self,
        data: &mut [u8],
        offset: u64,
        extents: &[(usize, usize)],
    ) -> Result<(), LuksError> {
        let unit = self.sector_size();
        if !offset.is_multiple_of(unit as u64) || !data.len().is_multiple_of(unit) {
            return Err(LuksError::BadHeader);
        }
        self.decrypt_sparse_fragment(data, offset, extents)
    }

    /// Decrypt an object-local, AES-block-aligned fragment using allocation
    /// extents relative to that fragment. Each touched crypto unit is either
    /// decrypted with zero ciphertext in its gaps or filled with plaintext
    /// zero when no extent intersects its fragment. The caller must include
    /// the complete intersection of each touched crypto unit with this object
    /// extent; a shorter query cannot establish whether the unit is absent.
    pub fn decrypt_sparse_fragment(
        &self,
        data: &mut [u8],
        offset: u64,
        extents: &[(usize, usize)],
    ) -> Result<(), LuksError> {
        let unit = self.sector_size();
        if !offset.is_multiple_of(16) || !data.len().is_multiple_of(16) {
            return Err(LuksError::BadHeader);
        }
        offset
            .checked_add(data.len() as u64)
            .ok_or(LuksError::BadHeader)?;
        let mut last = 0;
        for &(start, length) in extents {
            let end = start.checked_add(length).ok_or(LuksError::BadHeader)?;
            if length == 0 || start < last || end > data.len() {
                return Err(LuksError::BadHeader);
            }
            last = end;
        }
        let mut cursor = 0;
        for &(start, length) in extents {
            data[cursor..start].fill(0);
            cursor = start + length;
        }
        data[cursor..].fill(0);
        let mut index = 0;
        let mut start = 0;
        while start < data.len() {
            while index < extents.len() && extents[index].0 + extents[index].1 <= start {
                index += 1;
            }
            let in_unit = ((offset + start as u64) % unit as u64) as usize;
            let end = (start + unit - in_unit).min(data.len());
            if index < extents.len() && extents[index].0 < end {
                self.crypt_blocks(&mut data[start..end], offset + start as u64, true)?;
            }
            start = end;
        }
        Ok(())
    }

    /// Transform complete AES blocks, including a fragment of an XTS unit.
    pub fn crypt_blocks(
        &self,
        data: &mut [u8],
        offset: u64,
        decrypt: bool,
    ) -> Result<(), LuksError> {
        self.xts.apply_blocks(data, offset, decrypt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn luks2_round_trips_the_volume_key() {
        let (header, load) = luks2_create(b"passphrase", ALG_AES256).unwrap();
        let parsed = luks2_parse(&header, b"passphrase").unwrap();
        assert_eq!(parsed.volume_key, load.volume_key);
        assert_eq!(parsed.data_offset, DATA_OFFSET);
        assert_eq!(detect_format(&header), Some(FORMAT_LUKS2));
    }

    #[test]
    fn luks2_read_plan_uses_secondary_despite_corrupt_primary_size() {
        let mut header = vec![0; 2 * HEADER_SIZE];
        let off = HEADER_SIZE;
        header[off..off + 6].copy_from_slice(SECONDARY);
        header[off + 6..off + 8].copy_from_slice(&2u16.to_be_bytes());
        header[off + 8..off + 16].copy_from_slice(&(HEADER_SIZE as u64).to_be_bytes());
        header[off + 256..off + 264].copy_from_slice(&(off as u64).to_be_bytes());
        put_field(&mut header, off + 72, "sha256");
        let json = br#"{"segments":{"0":{"type":"crypt","offset":"8388608"}}}"#;
        header[off + 4096..off + 4096 + json.len()].copy_from_slice(json);
        checksum_copy(&mut header, off, HEADER_SIZE);
        header[..6].copy_from_slice(MAGIC);
        header[6..8].copy_from_slice(&2u16.to_be_bytes());
        for corrupt_size in [0, 32768, u64::MAX] {
            header[8..16].copy_from_slice(&corrupt_size.to_be_bytes());
            assert_eq!(required_header_size(&header), Ok(DATA_OFFSET as usize));
        }
        // A secondary outside the available prefix requires further reads.
        assert_eq!(required_header_size(&header[..4096]), Ok(32768));
        header.resize(8 * 1024 * 1024, 0);
        header[off..off + 6].fill(0);
        assert_eq!(required_header_size(&header), Err(LuksError::BadHeader));
    }

    #[test]
    fn key_material_is_wiped_on_drop() {
        fn wiped<T: zeroize::ZeroizeOnDrop>(_: &T) {}
        let (_, load) = luks2_create(b"wipe", ALG_AES128).unwrap();
        wiped(&load.volume_key);
        let xts = AesXts::new(&load.volume_key, 512).unwrap();
        wiped(&xts.key);
        wiped(&cipher_key::<Aes128>(&xts.key[..16]).unwrap());
        wiped(&cipher_key::<Aes256>(&[0; 32]).unwrap());
        wiped(&pbkdf("sha256", b"wipe", b"salt", 1, 32).unwrap());
        wiped(&af_split(&load.volume_key, 512).unwrap());
    }

    #[test]
    fn luks1_round_trips_the_volume_key() {
        let (header, load) = luks1_create(b"passphrase", ALG_AES128).unwrap();
        let parsed = luks1_parse(&header, b"passphrase").unwrap();
        assert_eq!(parsed.volume_key, load.volume_key);
        assert_eq!(parsed.data_offset, DATA_OFFSET);
        assert_eq!(detect_format(&header), Some(FORMAT_LUKS1));
        assert!(
            !header
                .windows(load.volume_key.len())
                .any(|bytes| bytes == *load.volume_key)
        );
    }

    #[test]
    fn clone_header_magic_restores_standard_luks_checksums() {
        let (mut header, load) = luks2_create(b"clone-key", ALG_AES128).unwrap();
        mark_clone_magic(&mut header).unwrap();
        assert_eq!(detect_format(&header), Some(FORMAT_LUKS2));
        assert_eq!(
            luks2_parse(&header, b"clone-key"),
            Err(LuksError::BadHeader)
        );
        assert_eq!(restore_clone_magic(&mut header), Ok(true));
        assert_eq!(
            luks2_parse(&header, b"clone-key").unwrap().volume_key,
            load.volume_key
        );

        let (mut header, _) = luks1_create(b"clone-key", ALG_AES128).unwrap();
        mark_clone_magic(&mut header).unwrap();
        assert_eq!(restore_clone_magic(&mut header), Ok(true));
        assert_eq!(
            luks1_parse(&header, b"clone-key").unwrap().data_offset,
            DATA_OFFSET
        );
    }

    #[test]
    fn flatten_restore_plan_names_the_magic_to_rewrite() {
        let (mut header, _) = luks2_create(b"clone-key", ALG_AES128).unwrap();
        assert_eq!(flatten_restore_plan(&header[..16]), Ok(None));
        mark_clone_magic(&mut header).unwrap();
        let size = u64::from_be_bytes(header[8..16].try_into().unwrap());
        assert_eq!(flatten_restore_plan(&header[..16]), Ok(Some(Some(size))));
        assert_eq!(&header[size as usize..size as usize + 6], CLONE_SECONDARY);
        let (mut header, _) = luks1_create(b"clone-key", ALG_AES128).unwrap();
        mark_clone_magic(&mut header).unwrap();
        assert_eq!(flatten_restore_plan(&header[..16]), Ok(Some(None)));
        assert_eq!(flatten_restore_plan(&[0u8; 16]), Ok(None));
    }

    #[test]
    fn aes_xts_round_trips() {
        let load = luks2_create(b"passphrase", ALG_AES256).unwrap().1;
        let xts = AesXts::new(&load.volume_key, SECTOR_SIZE as usize).unwrap();
        let mut data = vec![0u8; 4096];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        let original = data.clone();
        xts.apply(&mut data, 0, false).unwrap();
        assert_ne!(data, original);
        xts.apply(&mut data, 0, true).unwrap();
        assert_eq!(data, original);
    }

    #[test]
    fn aes_xts_sectors_differ() {
        let load = luks2_create(b"passphrase", ALG_AES256).unwrap().1;
        let xts = AesXts::new(&load.volume_key, SECTOR_SIZE as usize).unwrap();
        let data = vec![0u8; 4096];
        let mut s0 = data.clone();
        let mut s1 = data.clone();
        xts.apply(&mut s0, 0, false).unwrap();
        xts.apply(&mut s1, 1, false).unwrap();
        assert_ne!(s0, s1);
    }

    #[test]
    fn bad_magic_is_rejected() {
        let header = vec![0u8; 4096];
        assert_eq!(luks2_parse(&header, b"x"), Err(LuksError::BadHeader));
        assert_eq!(luks1_parse(&header, b"x"), Err(LuksError::BadHeader));
        assert_eq!(detect_format(&header), None);
    }

    #[test]
    fn wrong_passphrase_is_rejected() {
        let (h2, _) = luks2_create(b"right", ALG_AES256).unwrap();
        assert_eq!(luks2_parse(&h2, b"wrong"), Err(LuksError::WrongPassphrase));
        let (h1, _) = luks1_create(b"right", ALG_AES128).unwrap();
        assert_eq!(luks1_parse(&h1, b"wrong"), Err(LuksError::WrongPassphrase));
    }

    #[test]
    fn create_rejects_a_payload_offset_beyond_the_raw_image() {
        // A created header spans the whole reserved prefix, so an offset the
        // image cannot hold is rejected before anything is allocated.
        for offset in [DATA_OFFSET + 512, 1 << 40, u64::MAX - 511] {
            assert_eq!(
                luks1_create_at(b"x", ALG_AES128, offset, 1 << 20),
                Err(LuksError::BadHeader),
                "LUKS1 offset {offset}"
            );
            assert_eq!(
                luks2_create_at(b"x", ALG_AES128, offset, 1 << 20),
                Err(LuksError::BadHeader),
                "LUKS2 offset {offset}"
            );
        }
        // A representable offset still builds the exact reserved prefix.
        let (header, load) = luks2_create_at(b"x", ALG_AES128, 16 << 20, 16 << 20).unwrap();
        assert_eq!(header.len(), 16 << 20);
        assert_eq!(load.data_offset, 16 << 20);
    }

    #[test]
    fn raw_offset_rejects_an_unrepresentable_logical_offset() {
        let cryptor = Cryptor::new(&[7; 64], DATA_OFFSET, 4096).unwrap();
        assert_eq!(cryptor.raw_offset(0), Ok(DATA_OFFSET));
        assert_eq!(cryptor.raw_offset(4096), Ok(DATA_OFFSET + 4096));
        assert_eq!(
            cryptor.raw_offset(u64::MAX),
            Err(LuksError::BadHeader),
            "a shifted offset that overflows must not wrap"
        );
        assert_eq!(
            cryptor.raw_offset(u64::MAX - DATA_OFFSET),
            Ok(u64::MAX),
            "the highest representable raw offset stays accepted"
        );
    }

    #[test]
    fn cryptor_round_trips_across_sectors() {
        let load = luks2_create(b"passphrase", ALG_AES256).unwrap().1;
        let cryptor = Cryptor::new(&load.volume_key, DATA_OFFSET, SECTOR_SIZE as usize).unwrap();
        assert_eq!(cryptor.data_offset(), DATA_OFFSET);
        assert_eq!(cryptor.raw_offset(0), Ok(DATA_OFFSET));
        assert_eq!(cryptor.raw_offset(4096), Ok(DATA_OFFSET + 4096));
        // Encrypt a range spanning two sectors, then decrypt it back.
        let mut data = vec![0u8; 8192];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i % 199) as u8;
        }
        let original = data.clone();
        // `offset` is logical; the sector is derived from it.
        cryptor.encrypt(&mut data, 2 * 4096).unwrap();
        assert_ne!(data, original);
        cryptor.decrypt(&mut data, 2 * 4096).unwrap();
        assert_eq!(data, original);
    }

    #[test]
    fn ciphertext_does_not_depend_on_request_segmentation() {
        for sector in [512, 4096] {
            let cryptor = Cryptor::new(&[7; 64], DATA_OFFSET, sector).unwrap();
            let plain = vec![23; sector * 3];
            let mut whole = plain.clone();
            cryptor.encrypt(&mut whole, sector as u64).unwrap();
            let mut split = plain;
            for (index, part) in split.chunks_exact_mut(sector).enumerate() {
                cryptor
                    .encrypt(part, ((index + 1) * sector) as u64)
                    .unwrap();
            }
            assert_eq!(whole, split);
            for (index, part) in whole.chunks_exact_mut(sector).enumerate() {
                cryptor
                    .decrypt(part, ((index + 1) * sector) as u64)
                    .unwrap();
                assert!(part.iter().all(|byte| *byte == 23));
            }
        }
    }

    #[test]
    fn sparse_units_distinguish_holes_and_allocated_zero_ciphertext() {
        for unit in [512, 4096] {
            let cryptor = Cryptor::new(&[7; 64], DATA_OFFSET, unit).unwrap();
            let plain: Vec<u8> = (0..unit).map(|i| (i % 251) as u8).collect();
            let mut stored = plain.clone();
            cryptor.encrypt(&mut stored, 0).unwrap();
            let mut data = vec![0xabu8; unit * 3];
            data[..unit].copy_from_slice(&stored);
            data[2 * unit..].fill(0);
            let mut allocated_zero = vec![0u8; unit];
            cryptor
                .decrypt(&mut allocated_zero, 2 * unit as u64)
                .unwrap();
            assert!(allocated_zero.iter().any(|byte| *byte != 0));
            cryptor
                .decrypt_sparse_units(&mut data, 0, &[(0, unit), (2 * unit, unit)])
                .unwrap();
            assert_eq!(&data[..unit], plain);
            assert!(data[unit..2 * unit].iter().all(|byte| *byte == 0));
            assert_eq!(&data[2 * unit..], allocated_zero);

            let mut partial = vec![0xaau8; unit];
            partial[16..32].copy_from_slice(&stored[16..32]);
            let mut expected = vec![0u8; unit];
            expected[16..32].copy_from_slice(&stored[16..32]);
            cryptor.decrypt(&mut expected, 0).unwrap();
            cryptor
                .decrypt_sparse_units(&mut partial, 0, &[(16, 16)])
                .unwrap();
            assert_eq!(partial, expected);

            let before = partial.clone();
            assert_eq!(
                cryptor.decrypt_sparse_units(&mut partial, 0, &[(0, 32), (16, 16)]),
                Err(LuksError::BadHeader)
            );
            assert_eq!(partial, before, "invalid extents do not alter output");
        }
    }

    #[test]
    fn sparse_fragments_respect_crypto_boundaries_and_zero_ciphertext() {
        let cryptor = Cryptor::new(&[7; 64], DATA_OFFSET, 4096).unwrap();
        let offset = 3584u64;
        let mut fragment = vec![0xaau8; 1536];
        fragment[16..32].fill(0);
        let mut expected = vec![0u8; 512];
        cryptor.crypt_blocks(&mut expected, offset, true).unwrap();
        cryptor
            .decrypt_sparse_fragment(&mut fragment, offset, &[(16, 16)])
            .unwrap();
        assert_eq!(&fragment[..512], expected);
        assert!(fragment[512..].iter().all(|byte| *byte == 0));

        let before = fragment.clone();
        assert_eq!(
            cryptor.decrypt_sparse_fragment(&mut fragment, offset + 1, &[]),
            Err(LuksError::BadHeader)
        );
        assert_eq!(fragment, before);
    }

    #[test]
    fn fragmented_xts_blocks_match_full_sectors() {
        for key_len in [32, 64] {
            for unit in [512, 4096] {
                let key: Vec<u8> = (0..key_len).map(|v| v as u8).collect();
                let cryptor = Cryptor::new(&key, DATA_OFFSET, unit).unwrap();
                let original: Vec<u8> = (0..unit * 3).map(|i| (i % 251) as u8).collect();
                let offset = unit as u64 * 5;
                let mut reference = original.clone();
                cryptor.encrypt(&mut reference, offset).unwrap();
                let mut fragmented = original.clone();
                let sizes = [16usize, 512, 48, 1024, 128];
                let mut pos = 0;
                let mut index = 0;
                while pos < fragmented.len() {
                    let end = (pos + sizes[index % sizes.len()]).min(fragmented.len());
                    cryptor
                        .crypt_blocks(&mut fragmented[pos..end], offset + pos as u64, false)
                        .unwrap();
                    pos = end;
                    index += 1;
                }
                assert_eq!(fragmented, reference);
                cryptor.crypt_blocks(&mut fragmented, offset, true).unwrap();
                assert_eq!(fragmented, original);
                assert_eq!(
                    cryptor.crypt_blocks(&mut [0; 16], offset + 1, false),
                    Err(LuksError::BadKeySize)
                );
                assert_eq!(
                    cryptor.crypt_blocks(&mut [0; 15], offset, false),
                    Err(LuksError::BadKeySize)
                );
            }
        }
    }

    #[test]
    fn kdf_parameter_bounds_are_enforced() {
        let salt = [0u8; 32];
        // Argon2 memory: 4 GiB is the maximum; just above is rejected before
        // any allocation. Running the 4 GiB ceiling itself is prohibitive, so
        // the accepted side uses a small cost.
        assert_eq!(
            argon_key(
                b"p",
                &salt,
                4,
                ARGON2_MAX_MEMORY_KIB + 1,
                1,
                Algorithm::Argon2id,
                32
            ),
            Err(LuksError::Kdf)
        );
        assert!(argon_key(b"p", &salt, 4, 32, 1, Algorithm::Argon2id, 32).is_ok());
        // Argon2 cpus: 4 accepted at the smallest memory 8*lanes, 5 rejected.
        assert!(argon_key(b"p", &salt, 4, 32, 4, Algorithm::Argon2id, 32).is_ok());
        assert_eq!(
            argon_key(
                b"p",
                &salt,
                4,
                64,
                ARGON2_MAX_CPUS + 1,
                Algorithm::Argon2id,
                32
            ),
            Err(LuksError::Kdf)
        );
        // Argon2 work: a low-memory, many-pass header (beyond 1000 passes)
        // is accepted; passes x memory above the work bound is rejected.
        assert!(argon_key(b"p", &salt, 2_000, 32, 1, Algorithm::Argon2id, 32).is_ok());
        assert_eq!(
            argon_key(
                b"p",
                &salt,
                u32::try_from(ARGON2_MAX_WORK_KIB / 1024).unwrap() + 1,
                1024,
                1,
                Algorithm::Argon2id,
                32
            ),
            Err(LuksError::Kdf)
        );
        // PBKDF2 iterations: unbounded above like stock; zero stays a header
        // error.
        assert!(pbkdf("sha256", b"p", &salt, 1_000, 32).is_ok());
        assert_eq!(
            pbkdf("sha256", b"p", &salt, 0, 32),
            Err(LuksError::BadHeader)
        );
    }

    /// A decoded LUKS2 metadata object whose keyslot 0 carries the given KDF
    /// parameters; `unlock_luks2` rejects an out-of-bounds KDF before reading
    /// the keyslot area, so the header buffer can stay empty.
    fn unlock_luks2_json(kdf: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "keyslots": {
                "0": {
                    "type": "luks2",
                    "key_size": 32,
                    "af": { "type": "luks1", "stripes": STRIPES, "hash": "sha256" },
                    "area": {
                        "type": "raw",
                        "offset": (2 * HEADER_SIZE).to_string(),
                        "size": (32 * STRIPES).to_string(),
                        "encryption": "aes-xts-plain64",
                        "key_size": 32,
                    },
                    "kdf": kdf,
                }
            },
            "tokens": {},
            "segments": {
                "0": {
                    "type": "crypt",
                    "offset": DATA_OFFSET.to_string(),
                    "size": "dynamic",
                    "encryption": "aes-xts-plain64",
                    "iv_tweak": "0",
                    "sector_size": 4096,
                }
            },
            "digests": {},
            "config": {
                "json_size": (HEADER_SIZE - 4096).to_string(),
                "keyslots_size": (DATA_OFFSET as usize - 2 * HEADER_SIZE).to_string(),
            }
        })
    }

    #[test]
    fn luks2_unlock_rejects_out_of_bounds_kdf_parameters() {
        let salt = STANDARD.encode([0u8; 32]);
        let cases = [
            (
                serde_json::json!({"type":"argon2id","time":3,"memory":ARGON2_MAX_MEMORY_KIB+1,"cpus":4,"salt":salt.clone()}),
                LuksError::Kdf,
            ),
            (
                serde_json::json!({"type":"argon2i","time":3,"memory":65536,"cpus":ARGON2_MAX_CPUS+1,"salt":salt.clone()}),
                LuksError::Kdf,
            ),
            (
                serde_json::json!({"type":"argon2id","time":ARGON2_MAX_WORK_KIB/65536+1,"memory":65536,"cpus":4,"salt":salt}),
                LuksError::Kdf,
            ),
        ];
        for (kdf, expected) in cases {
            let value = unlock_luks2_json(kdf);
            assert_eq!(
                unlock_luks2(&[], b"passphrase", HEADER_SIZE, value),
                Err(expected)
            );
        }
    }
}
