// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! AES-128-GCM state per direction (spec 6.1): key, nonce layout/increment for v2.0 / v2.1.
use crate::{Error, Revision, TAG_LEN};
use aws_lc_rs::aead::{AES_128_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use core::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Which side of the TCP connection we are (selects nonce direction mapping).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Opened the connection: tx uses N_b (secret[28..40]), rx uses N_a (secret[16..28]).
    Client,
    /// Accepted the connection: tx uses N_a, rx uses N_b.
    Server,
}

/// Connection secret material from the auth layer (spec 6.1).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ConnSecret {
    key: [u8; 16],
    na: [u8; 12],
    nb: [u8; 12],
}

impl fmt::Debug for ConnSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConnSecret(..)")
    }
}

impl ConnSecret {
    /// Build from the raw connection secret (>= 40 bytes; Ceph hands out 64, only 40 are used).
    pub fn new(secret: &[u8]) -> Result<Self, Error> {
        if secret.len() < 40 {
            return Err(Error::BadSecret);
        }
        Ok(Self {
            key: secret[..16].try_into().unwrap(),
            na: secret[16..28].try_into().unwrap(),
            nb: secret[28..40].try_into().unwrap(),
        })
    }

    pub(crate) fn tx(&self, role: Role, rev: Revision) -> Result<Gcm, Error> {
        let mut g = Gcm::new(
            &self.key,
            if role == Role::Client {
                self.nb
            } else {
                self.na
            },
            rev,
        )?;
        g.stream = Some(StreamKey::new(&self.key)?);
        Ok(g)
    }

    pub(crate) fn rx(&self, role: Role, rev: Revision) -> Result<Gcm, Error> {
        Gcm::new(
            &self.key,
            if role == Role::Client {
                self.na
            } else {
                self.nb
            },
            rev,
        )
    }
}

/// Pieces of a [`Gcm::seal_append`] region shorter than this are copied into the frame and encrypted in place with
/// their neighbours: below it a separate cipher update (call, partial-block handling) costs more than the copy.
pub(crate) const STREAM_MIN: usize = 1024;

/// One direction's cipher + nonce counter.
pub(crate) struct Gcm {
    key: LessSafeKey,
    cur: [u8; 12],
    init: [u8; 12],
    rev: Revision,
    exhausted: bool,
    stream: Option<StreamKey>,
    /// Decrypt context for [`Gcm::open_to`] (rx, created on first use).
    opener: Option<OpenKey>,
    /// Raw session key copy (for the decrypt context), wiped on drop like the `ConnSecret` it came from.
    key_bytes: Zeroizing<[u8; 16]>,
}

impl fmt::Debug for Gcm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Gcm(..)")
    }
}

impl Gcm {
    fn new(key: &[u8; 16], nonce: [u8; 12], rev: Revision) -> Result<Self, Error> {
        let k = UnboundKey::new(&AES_128_GCM, key).map_err(|_| Error::Crypto)?;
        Ok(Self {
            key: LessSafeKey::new(k),
            cur: nonce,
            init: nonce,
            rev,
            exhausted: false,
            stream: None,
            opener: None,
            key_bytes: Zeroizing::new(*key),
        })
    }

    /// Take the current nonce and advance (v2.0: u32 at 0..4; v2.1: u64 at 4..12).
    fn take(&mut self) -> Result<[u8; 12], Error> {
        if self.exhausted {
            return Err(Error::NonceExhausted);
        }
        let out = self.cur;
        match self.rev {
            Revision::V20 => {
                let v = denc::le::rd_u32(&self.cur, 0).wrapping_add(1);
                denc::le::wr_u32(&mut self.cur, 0, v);
                self.exhausted = self.cur[..4] == self.init[..4];
            }
            Revision::V21 => {
                let v = denc::le::rd_u64(&self.cur, 4).wrapping_add(1);
                denc::le::wr_u64(&mut self.cur, 4, v);
                self.exhausted = self.cur[4..] == self.init[4..];
            }
        }
        Ok(out)
    }

    /// Encrypt `buf` in place with the next nonce; returns the tag.
    pub fn seal(&mut self, buf: &mut [u8]) -> Result<[u8; TAG_LEN], Error> {
        let n = self.take()?;
        let tag = self
            .key
            .seal_in_place_separate_tag(Nonce::assume_unique_for_key(n), Aad::empty(), buf)
            .map_err(|_| Error::Crypto)?;
        Ok(tag.as_ref().try_into().unwrap())
    }

    /// One authenticated GCM region across disjoint, uniquely owned frame runs.
    pub fn seal_chunks(&mut self, chunks: &mut [&mut [u8]]) -> Result<[u8; TAG_LEN], Error> {
        let _profile = crate::profile::span("crypto.inplace", 0);
        let nonce = self.take()?;
        self.stream
            .as_mut()
            .ok_or(Error::Crypto)?
            .seal(&nonce, chunks)
    }

    /// One authenticated GCM region: the plaintext already at `out[from..]`, then `pieces`, all encrypted into the end
    /// of `out`. A piece of at least [`STREAM_MIN`] bytes is encrypted from its source (no plaintext staging copy in
    /// the frame); shorter pieces are copied and encrypted in place together with their neighbours (one cipher update
    /// per span instead of one per piece). Returns the tag; the caller appends it. On error the bytes after `from` are
    /// unspecified and the caller discards the frame.
    pub fn seal_append<'a>(
        &mut self,
        out: &mut Vec<u8>,
        from: usize,
        pieces: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<[u8; TAG_LEN], Error> {
        let _profile = crate::profile::span("crypto.append", 0);
        let nonce = self.take()?;
        let stream = self.stream.as_mut().ok_or(Error::Crypto)?;
        stream.begin(&nonce)?;
        let mut plain = from;
        for piece in pieces {
            if piece.len() < STREAM_MIN {
                out.extend_from_slice(piece);
                continue;
            }
            stream.update_chunks(&mut [&mut out[plain..]])?;
            stream.append(piece, out)?;
            plain = out.len();
        }
        stream.update_chunks(&mut [&mut out[plain..]])?;
        stream.finish()
    }

    /// Encrypt immutable data directly into private ciphertext between mutable frame runs.
    pub fn seal_chunks_copy(
        &mut self,
        prefix: &mut [&mut [u8]],
        data: &[u8],
        suffix: &mut [&mut [u8]],
    ) -> Result<(bytes::BytesMut, [u8; TAG_LEN]), Error> {
        let _profile = crate::profile::span("crypto.separate", data.len());
        let mut output = bytes::BytesMut::with_capacity(data.len());
        #[cfg(feature = "profile")]
        let _layout_profile = {
            let different = data.as_ptr() as usize ^ output.as_ptr() as usize;
            let stage = if different & 4095 == 0 {
                "crypto.separate.alias4k"
            } else if different & 63 == 0 {
                "crypto.separate.alias64"
            } else {
                "crypto.separate.distinct64"
            };
            crate::profile::span(stage, data.len())
        };
        let nonce = self.take()?;

        let stream = self.stream.as_mut().ok_or(Error::Crypto)?;
        stream.begin(&nonce)?;
        stream.update_chunks(prefix)?;
        stream.copy_data(data, &mut output)?;
        stream.update_chunks(suffix)?;
        let tag = stream.finish()?;
        // SAFETY: copy_data initialized exactly data.len bytes. All authenticated
        // region updates, finalization and tag retrieval succeeded before exposure.
        unsafe { output.set_len(data.len()) };
        Ok((output, tag))
    }

    /// `buf` = ciphertext || tag; decrypts in place (plaintext at `buf[..len-16]`).
    pub fn open(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        let _profile = crate::profile::span("crypto.open", buf.len());
        let n = self.take()?;
        self.key
            .open_in_place(Nonce::assume_unique_for_key(n), Aad::empty(), buf)
            .map_err(|_| Error::AuthFailed)?;
        Ok(())
    }

    /// `src` = ciphertext || tag; decrypts into `dst` (`src.len() - 16` bytes, may be uninitialized) with the next
    /// nonce. On error `dst` holds unspecified bytes (unauthenticated: never use them).
    ///
    /// # Safety
    /// `dst` is valid for writes of `src.len() - TAG_LEN` bytes and does not overlap `src`.
    pub unsafe fn open_to(&mut self, src: &[u8], dst: *mut u8) -> Result<(), Error> {
        let _profile = crate::profile::span("crypto.open_to", src.len());
        let Some(clen) = src.len().checked_sub(TAG_LEN) else {
            return Err(Error::AuthFailed);
        };
        let n = self.take()?;
        if self.opener.is_none() {
            self.opener = Some(OpenKey::new(&self.key_bytes)?);
        }
        let o = self.opener.as_mut().ok_or(Error::Crypto)?;
        // SAFETY: forwarded caller contract.
        unsafe { o.open(&n, &src[..clen], &src[clen..], dst) }
    }

    /// Keystream for the first 32 data bytes under the CURRENT nonce (not consumed).
    /// Used for v2.0, where the preamble must be read before the tag is available.
    pub fn keystream32(&self) -> Result<[u8; 32], Error> {
        let mut z = [0u8; 32];
        let _tag = self
            .key
            .seal_in_place_separate_tag(
                Nonce::assume_unique_for_key(self.cur),
                Aad::empty(),
                &mut z,
            )
            .map_err(|_| Error::Crypto)?;
        Ok(z)
    }
}

/// An AWS-LC AES-128-GCM context keyed for encryption or decryption with the wire's 96-bit nonce; the IV is set per
/// operation. Allocated/keyed once per direction.
struct Ctx(std::ptr::NonNull<aws_lc_sys::EVP_CIPHER_CTX>);

// SAFETY: the context is exclusively owned; every mutation requires &mut self. It has no thread affinity.
unsafe impl Send for Ctx {}
// SAFETY: shared references expose no context operations.
unsafe impl Sync for Ctx {}

impl Drop for Ctx {
    fn drop(&mut self) {
        // SAFETY: this is the unique context returned by EVP_CIPHER_CTX_new, freed exactly once.
        unsafe { aws_lc_sys::EVP_CIPHER_CTX_free(self.0.as_ptr()) };
    }
}

impl Ctx {
    fn new(encrypt: bool, key: &[u8; 16]) -> Result<Self, Error> {
        // SAFETY: allocation needs no input pointers.
        let ptr = std::ptr::NonNull::new(unsafe { aws_lc_sys::EVP_CIPHER_CTX_new() })
            .ok_or(Error::Crypto)?;
        let ctx = Self(ptr);
        // SAFETY: valid owned context, standard AES-128-GCM descriptor and 16-byte key. IV set per operation.
        let ok = unsafe {
            let (c, cipher, k) = (ctx.as_ptr(), aws_lc_sys::EVP_aes_128_gcm(), key.as_ptr());
            if encrypt {
                aws_lc_sys::EVP_EncryptInit_ex(c, cipher, std::ptr::null_mut(), k, std::ptr::null())
            } else {
                aws_lc_sys::EVP_DecryptInit_ex(c, cipher, std::ptr::null_mut(), k, std::ptr::null())
            }
        };
        if ok != 1 {
            return Err(Error::Crypto);
        }
        // SAFETY: configure the existing GCM context for the wire's 96-bit nonce before any payload update.
        if unsafe {
            aws_lc_sys::EVP_CIPHER_CTX_ctrl(
                ctx.as_ptr(),
                aws_lc_sys::EVP_CTRL_GCM_SET_IVLEN,
                12,
                std::ptr::null_mut(),
            )
        } != 1
        {
            return Err(Error::Crypto);
        }
        // SAFETY: inspect the configured owned context. GCM's effective block size must be one before
        // exact-capacity separate-output updates are used.
        if unsafe { aws_lc_sys::EVP_CIPHER_CTX_block_size(ctx.as_ptr()) } != 1 {
            return Err(Error::Crypto);
        }
        Ok(ctx)
    }

    fn as_ptr(&self) -> *mut aws_lc_sys::EVP_CIPHER_CTX {
        self.0.as_ptr()
    }
}

/// Streaming AES-128-GCM encrypt context (TX setup).
struct StreamKey(Ctx);

impl StreamKey {
    fn new(key: &[u8; 16]) -> Result<Self, Error> {
        Ctx::new(true, key).map(Self)
    }

    fn seal(&mut self, nonce: &[u8; 12], chunks: &mut [&mut [u8]]) -> Result<[u8; TAG_LEN], Error> {
        self.begin(nonce)?;
        self.update_chunks(chunks)?;
        self.finish()
    }

    fn begin(&mut self, nonce: &[u8; 12]) -> Result<(), Error> {
        #[cfg(test)]
        test_fault(FaultPoint::Begin)?;
        let ctx = self.0.as_ptr();
        // SAFETY: existing keyed context, same AES-GCM cipher, fresh 12-byte IV. No AAD (wire format).
        if unsafe {
            aws_lc_sys::EVP_EncryptInit_ex(
                ctx,
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null(),
                nonce.as_ptr(),
            )
        } != 1
        {
            return Err(Error::Crypto);
        }
        Ok(())
    }

    fn update_chunks(&mut self, chunks: &mut [&mut [u8]]) -> Result<(), Error> {
        #[cfg(test)]
        test_fault(FaultPoint::Update)?;
        let ctx = self.0.as_ptr();
        for chunk in chunks {
            for chunk in chunk.chunks_mut(i32::MAX as usize) {
                let len = chunk.len() as i32;
                let mut written = 0;
                // SAFETY: exact in-place aliasing is supported by EVP; GCM writes exactly len bytes. Slices are disjoint.
                if unsafe {
                    aws_lc_sys::EVP_EncryptUpdate(
                        ctx,
                        chunk.as_mut_ptr(),
                        &mut written,
                        chunk.as_ptr(),
                        len,
                    )
                } != 1
                    || written != len
                {
                    return Err(Error::Crypto);
                }
            }
        }
        Ok(())
    }

    fn copy_data(&mut self, data: &[u8], output: &mut bytes::BytesMut) -> Result<(), Error> {
        if !output.is_empty() || output.capacity() < data.len() {
            return Err(Error::Crypto);
        }
        let mut offset = 0;
        for chunk in data.chunks(i32::MAX as usize) {
            let mut written = 0;
            // SAFETY: output has zero initialized length and capacity >= data.len.
            // Its fresh allocation is disjoint from retained immutable input and
            // other region runs. Setup validated effective block size one, so EVP
            // needs at most chunk.len output bytes. Each successful prior update
            // wrote exactly its input length; offset stays within this capacity.
            // No Rust reference to uninitialized output bytes is formed.
            let destination = unsafe { output.as_mut_ptr().add(offset) };
            let ok = unsafe {
                aws_lc_sys::EVP_EncryptUpdate(
                    self.0.as_ptr(),
                    destination,
                    &mut written,
                    chunk.as_ptr(),
                    chunk.len() as i32,
                )
            };
            #[cfg(test)]
            if take_fault(FaultPoint::ShortWrite) {
                written = written.saturating_sub(1);
            }
            if ok != 1 || written != chunk.len() as i32 {
                return Err(Error::Crypto);
            }
            offset += chunk.len();
        }
        Ok(())
    }

    /// Encrypt `data` (continuing the open region) to the end of `out`; `out.len()` grows only by bytes EVP reported
    /// as written in full.
    fn append(&mut self, data: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
        out.try_reserve(data.len())
            .map_err(|_| Error::AllocationFailed(out.len().saturating_add(data.len())))?;
        for chunk in data.chunks(i32::MAX as usize) {
            let mut written = 0;
            // SAFETY: `out` has spare capacity for all of `data` (reserved above) and grows only after each update by
            // exactly the bytes written, so the destination stays inside the spare capacity. `data` is a shared borrow
            // disjoint from the uniquely borrowed `out`. Setup validated effective block size one: EVP writes at most
            // chunk.len bytes. No Rust reference to the uninitialized spare bytes is formed.
            let ok = unsafe {
                aws_lc_sys::EVP_EncryptUpdate(
                    self.0.as_ptr(),
                    out.as_mut_ptr().add(out.len()),
                    &mut written,
                    chunk.as_ptr(),
                    chunk.len() as i32,
                )
            };
            #[cfg(test)]
            if take_fault(FaultPoint::ShortWrite) {
                written = written.saturating_sub(1);
            }
            if ok != 1 || written != chunk.len() as i32 {
                return Err(Error::Crypto);
            }
            // SAFETY: the successful update initialized exactly chunk.len bytes after the old length.
            unsafe { out.set_len(out.len() + chunk.len()) };
        }
        Ok(())
    }

    fn finish(&mut self) -> Result<[u8; TAG_LEN], Error> {
        #[cfg(test)]
        test_fault(FaultPoint::Final)?;
        let ctx = self.0.as_ptr();
        let mut last = [0u8; 16];
        let mut written = 0;
        // SAFETY: GCM has no buffered ciphertext; the final output buffer has a full block of room regardless.
        if unsafe { aws_lc_sys::EVP_EncryptFinal_ex(ctx, last.as_mut_ptr(), &mut written) } != 1
            || written != 0
        {
            return Err(Error::Crypto);
        }
        let mut tag = [0; TAG_LEN];
        #[cfg(test)]
        test_fault(FaultPoint::Tag)?;
        // SAFETY: finalised GCM context and writable 16-byte tag destination.
        if unsafe {
            aws_lc_sys::EVP_CIPHER_CTX_ctrl(
                ctx,
                aws_lc_sys::EVP_CTRL_GCM_GET_TAG,
                TAG_LEN as i32,
                tag.as_mut_ptr().cast(),
            )
        } != 1
        {
            return Err(Error::Crypto);
        }
        Ok(tag)
    }
}

/// Streaming AES-128-GCM decrypt context: decryption into a separate (uninitialized) destination, which the one-shot
/// `LessSafeKey` API only offers for initialized slices.
struct OpenKey(Ctx);

impl OpenKey {
    fn new(key: &[u8; 16]) -> Result<Self, Error> {
        Ctx::new(false, key).map(Self)
    }

    /// # Safety
    /// `dst` is valid for writes of `ct.len()` bytes and does not overlap `ct`.
    unsafe fn open(
        &mut self,
        nonce: &[u8; 12],
        ct: &[u8],
        tag: &[u8],
        dst: *mut u8,
    ) -> Result<(), Error> {
        let ctx = self.0.as_ptr();
        // SAFETY: keyed context, fresh 12-byte IV, no AAD (wire format).
        if unsafe {
            aws_lc_sys::EVP_DecryptInit_ex(
                ctx,
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null(),
                nonce.as_ptr(),
            )
        } != 1
        {
            return Err(Error::Crypto);
        }
        let mut at = 0;
        for chunk in ct.chunks(i32::MAX as usize) {
            let mut written = 0;
            // SAFETY: GCM (block size 1) writes exactly chunk.len bytes at dst + at, inside the caller's range; no Rust
            // reference to the uninitialized destination is formed.
            if unsafe {
                aws_lc_sys::EVP_DecryptUpdate(
                    ctx,
                    dst.add(at),
                    &mut written,
                    chunk.as_ptr(),
                    chunk.len() as i32,
                )
            } != 1
                || written != chunk.len() as i32
            {
                return Err(Error::AuthFailed);
            }
            at += chunk.len();
        }
        let mut t = [0u8; TAG_LEN];
        t.copy_from_slice(tag);
        // SAFETY: set the expected 16-byte tag before finalizing.
        if unsafe {
            aws_lc_sys::EVP_CIPHER_CTX_ctrl(
                ctx,
                aws_lc_sys::EVP_CTRL_GCM_SET_TAG,
                TAG_LEN as i32,
                t.as_mut_ptr().cast(),
            )
        } != 1
        {
            return Err(Error::Crypto);
        }
        let mut last = [0u8; 16];
        let mut written = 0;
        // SAFETY: GCM buffers nothing; a full block of room for the (empty) final output.
        if unsafe { aws_lc_sys::EVP_DecryptFinal_ex(ctx, last.as_mut_ptr(), &mut written) } != 1
            || written != 0
        {
            return Err(Error::AuthFailed);
        }
        Ok(())
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FaultPoint {
    Begin,
    Update,
    ShortWrite,
    Final,
    Tag,
}
#[cfg(test)]
thread_local! {
    static FAULT: std::cell::Cell<Option<FaultPoint>> = const { std::cell::Cell::new(None) };
}
#[cfg(test)]
pub(crate) fn inject_fault(point: FaultPoint) {
    FAULT.with(|fault| fault.set(Some(point)));
}
#[cfg(test)]
fn take_fault(point: FaultPoint) -> bool {
    FAULT.with(|fault| {
        if fault.get() == Some(point) {
            fault.set(None);
            true
        } else {
            false
        }
    })
}
#[cfg(test)]
fn test_fault(point: FaultPoint) -> Result<(), Error> {
    if take_fault(point) {
        Err(Error::Crypto)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret() -> ConnSecret {
        let s: Vec<u8> = (0..64u8).collect();
        ConnSecret::new(&s).unwrap()
    }

    #[test]
    fn nist_kat() {
        // GCM spec test case 3 (key feffe9928665731c6d6a8f9467308308, 12 byte IV, no AAD).
        let h = |s: &str| -> Vec<u8> {
            (0..s.len() / 2)
                .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
                .collect()
        };
        let key: [u8; 16] = h("feffe9928665731c6d6a8f9467308308").try_into().unwrap();
        let iv: [u8; 12] = h("cafebabefacedbaddecaf888").try_into().unwrap();
        let mut g = Gcm::new(&key, iv, Revision::V21).unwrap();
        let pt = h(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
        );
        let expected = h(
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
        );
        let mut buf = pt.clone();
        let ks = g.keystream32().unwrap();
        let tag = g.seal(&mut buf).unwrap();
        assert_eq!(buf, expected);
        assert_eq!(tag[..], h("4d5c2af327cd64a62cf35abd2ba6fab4")[..]);
        let mut stream = StreamKey::new(&key).unwrap();
        let mut streamed = pt.clone();
        let (first, rest) = streamed.split_at_mut(7);
        let (second, third) = rest.split_at_mut(24);
        let streamed_tag = stream.seal(&iv, &mut [first, second, third]).unwrap();
        assert_eq!(
            streamed_tag, tag,
            "streaming GCM differs from the frozen NIST tag"
        );
        assert_eq!(streamed, buf);
        for i in 0..32 {
            assert_eq!(ks[i], buf[i] ^ pt[i]);
        }
        for left in [0, 1, 7, 15, 16, 17, 31, pt.len()] {
            for right in [left, (left + 1).min(pt.len()), pt.len()] {
                let mut prefix = pt[..left].to_vec();
                let mut suffix = pt[right..].to_vec();
                let mut g = Gcm::new(&key, iv, Revision::V21).unwrap();
                g.stream = Some(StreamKey::new(&key).unwrap());
                let (data, actual_tag) = g
                    .seal_chunks_copy(
                        &mut [&mut [], &mut prefix],
                        &pt[left..right],
                        &mut [&mut suffix, &mut []],
                    )
                    .unwrap();
                assert_eq!(data.len(), right - left);
                assert_eq!([prefix.as_slice(), &data, &suffix].concat(), expected);
                assert_eq!(actual_tag, tag);
            }
        }
    }

    #[test]
    fn seal_append_equals_one_contiguous_seal() {
        let pt: Vec<u8> = (0..5000u32).map(|i| (i * 7 + 3) as u8).collect();
        let mut reference = secret().tx(Role::Client, Revision::V21).unwrap();
        let mut expected = pt.clone();
        let tag = reference.seal(&mut expected).unwrap();
        for in_place in [0, 1, 16, 33] {
            // short and long (>= STREAM_MIN) pieces, alone and mixed
            for cuts in [
                &[][..],
                &[0, 5],
                &[15, 16, 17],
                &[100, 513, 999],
                &[40, 1100, 1105, 3000],
                &[1024, 2048, 2049, 4999],
            ] {
                let mut g = secret().tx(Role::Client, Revision::V21).unwrap();
                let mut out = b"prior".to_vec();
                out.extend_from_slice(&pt[..in_place]);
                let mut pieces = Vec::new();
                let mut at = in_place;
                for &c in cuts.iter().filter(|&&c| c > in_place) {
                    pieces.push(&pt[at..c]);
                    at = c;
                }
                pieces.push(&pt[at..]);
                let actual_tag = g.seal_append(&mut out, 5, pieces).unwrap();
                assert_eq!(&out[..5], b"prior");
                assert_eq!(out[5..], expected[..], "in place {in_place} cuts {cuts:?}");
                assert_eq!(actual_tag, tag);
            }
        }
        for point in [
            FaultPoint::Begin,
            FaultPoint::Update,
            FaultPoint::ShortWrite,
            FaultPoint::Final,
        ] {
            let mut g = secret().tx(Role::Client, Revision::V21).unwrap();
            let before = g.cur;
            inject_fault(point);
            let mut out = Vec::new();
            assert!(matches!(
                g.seal_append(&mut out, 0, [&pt[..]]),
                Err(Error::Crypto)
            ));
            assert_ne!(g.cur, before, "failed region reused its nonce");
        }
    }

    #[test]
    fn separate_empty_region_and_failed_updates_never_publish_initialized_bytes() {
        let mut empty = Gcm::new(&[0; 16], [0; 12], Revision::V21).unwrap();
        empty.stream = Some(StreamKey::new(&[0; 16]).unwrap());
        let (data, tag) = empty.seal_chunks_copy(&mut [], &[], &mut []).unwrap();
        assert!(data.is_empty());
        assert_eq!(
            tag,
            [
                0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61, 0x36, 0x7f, 0x1d, 0x57, 0xa4, 0xe7,
                0x45, 0x5a
            ]
        );

        let mut stream = StreamKey::new(&[0; 16]).unwrap();
        stream.begin(&[0; 12]).unwrap();
        let input = [7; 17];
        let mut output = bytes::BytesMut::from(&[0xa5; 33][..]);
        output.clear();
        stream.copy_data(&input, &mut output).unwrap();
        assert!(
            output.is_empty(),
            "spare writes exposed an unfinished region"
        );
        // SAFETY: this allocation's 33 bytes were initialized with the sentinel
        // before clear; EVP was permitted to write only the first 17 bytes.
        let canary = unsafe { std::slice::from_raw_parts(output.as_ptr().add(17), 16) };
        assert_eq!(canary, [0xa5; 16]);
        assert_eq!(input, [7; 17]);

        for point in [
            FaultPoint::Begin,
            FaultPoint::Update,
            FaultPoint::ShortWrite,
            FaultPoint::Final,
            FaultPoint::Tag,
        ] {
            let mut g = secret().tx(Role::Client, Revision::V21).unwrap();
            let before = g.cur;
            inject_fault(point);
            assert!(matches!(
                g.seal_chunks_copy(&mut [], &input, &mut []),
                Err(Error::Crypto)
            ));
            assert_ne!(g.cur, before, "failed region reused its nonce");
            assert_eq!(input, [7; 17]);
        }
    }

    #[test]
    fn nonce_rules() {
        let s = secret();
        let mut g = s.tx(Role::Client, Revision::V21).unwrap();
        assert_eq!(g.cur, [28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39]);
        g.take().unwrap();
        assert_eq!(g.cur[..4], [28, 29, 30, 31]);
        assert_eq!(
            u64::from_le_bytes(g.cur[4..].try_into().unwrap()),
            u64::from_le_bytes([32, 33, 34, 35, 36, 37, 38, 39]) + 1
        );
        let mut g = s.rx(Role::Client, Revision::V20).unwrap();
        assert_eq!(g.cur[0], 16);
        g.take().unwrap();
        assert_eq!(g.cur[..4], [17, 17, 18, 19]);
        assert_eq!(g.cur[4..], [20, 21, 22, 23, 24, 25, 26, 27]);
        // server tx == client rx
        assert_eq!(
            s.tx(Role::Server, Revision::V21).unwrap().cur,
            s.rx(Role::Client, Revision::V21).unwrap().cur
        );
    }

    #[test]
    fn wrap_exhaust() {
        let mut g = Gcm::new(
            &[0; 16],
            [0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0],
            Revision::V20,
        )
        .unwrap();
        g.cur[..4].copy_from_slice(&0xFFFF_FFFEu32.to_le_bytes());
        g.take().unwrap();
        assert_eq!(g.take(), Err(Error::NonceExhausted));
        let mut g = Gcm::new(&[0; 16], [1; 12], Revision::V21).unwrap();
        g.cur[4..].copy_from_slice(&u64::MAX.to_le_bytes());
        g.init[4..].copy_from_slice(&0u64.to_le_bytes());
        g.take().unwrap();
        assert_eq!(g.take(), Err(Error::NonceExhausted));
    }
}
