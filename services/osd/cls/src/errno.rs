// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Errno convention: a class returns `-errno` (Linux values, also the Ceph wire values).
//! In this crate [`Errno`] holds the NEGATIVE value, so `Err(ENOENT)` is what the method returns.

/// Negative errno (the value a cls method returns / the op rval).
pub type Errno = i32;

pub const EPERM: Errno = -denc::errno::EPERM;
pub const ENOENT: Errno = -denc::errno::ENOENT;
pub const EIO: Errno = -denc::errno::EIO;
pub const ENXIO: Errno = -denc::errno::ENXIO;
pub const ENOEXEC: Errno = -denc::errno::ENOEXEC;
pub const EBADF: Errno = -denc::errno::EBADF;
pub const EBUSY: Errno = -denc::errno::EBUSY;
pub const EEXIST: Errno = -denc::errno::EEXIST;
pub const EXDEV: Errno = -denc::errno::EXDEV;
pub const EINVAL: Errno = -denc::errno::EINVAL;
pub const E2BIG: Errno = -7;
pub const EFBIG: Errno = -denc::errno::EFBIG;
pub const ENOSPC: Errno = -denc::errno::ENOSPC;
pub const ERANGE: Errno = -denc::errno::ERANGE;
pub const ENOSYS: Errno = -denc::errno::ENOSYS;
pub const ENODATA: Errno = -denc::errno::ENODATA;
pub const EOVERFLOW: Errno = -denc::errno::EOVERFLOW;
pub const EOPNOTSUPP: Errno = -denc::errno::EOPNOTSUPP;
pub const ESTALE: Errno = -denc::errno::ESTALE;
pub const EDQUOT: Errno = -denc::errno::EDQUOT;
pub const ECANCELED: Errno = -denc::errno::ECANCELED;
pub const EAGAIN: Errno = -denc::errno::EAGAIN;
pub const ENOMSG: Errno = -42;
pub const ENOLINK: Errno = -67;
pub const EBADMSG: Errno = -74;

/// Decode-failure mapping: any denc error becomes `-EINVAL` (cls.md s5).
pub trait Inval<T> {
    fn inval(self) -> Result<T, Errno>;
}
impl<T> Inval<T> for denc::Result<T> {
    #[inline]
    fn inval(self) -> Result<T, Errno> {
        self.map_err(|_| EINVAL)
    }
}
/// Decode failure of a STORED value: `-EIO`.
pub trait Eio<T> {
    fn eio(self) -> Result<T, Errno>;
}
impl<T> Eio<T> for denc::Result<T> {
    #[inline]
    fn eio(self) -> Result<T, Errno> {
        self.map_err(|_| EIO)
    }
}

/// Map a read result so that `ENOENT` (absent object / key) becomes `Ok(None)`; every other
/// error passes through.
#[inline]
pub fn rd_opt<T>(r: Result<T, Errno>) -> Result<Option<T>, Errno> {
    match r {
        Ok(v) => Ok(Some(v)),
        Err(ENOENT) => Ok(None),
        Err(e) => Err(e),
    }
}

// ---- shared codec (one error policy for every class) ------------------------------------------

/// Method result: reply bytes on success, negative errno otherwise.
pub type R = Result<Vec<u8>, Errno>;

/// Decode client input (whole buffer, trailing bytes tolerated like a bufferlist decode):
/// failure = `-EINVAL`.
#[inline]
pub fn dec_op<'a, T: denc::Decode<'a>>(b: &'a [u8]) -> Result<T, Errno> {
    T::decode(&mut denc::Decoder::new(b)).inval()
}
/// Decode a STORED value (omap / xattr / data the class wrote itself): failure = `-EIO`.
#[inline]
pub fn dec_stored<'a, T: denc::Decode<'a>>(b: &'a [u8]) -> Result<T, Errno> {
    T::decode(&mut denc::Decoder::new(b)).eio()
}
/// Encode a reply / stored value: failure = `-EIO` (in-memory encode cannot fail in practice;
/// the error is surfaced, never replaced by empty bytes).
#[inline]
pub fn enc<T: denc::Encode + ?Sized>(v: &T) -> Result<Vec<u8>, Errno> {
    v.encode_to_vec().eio()
}
/// [`enc`] with an explicit feature set.
#[inline]
pub fn enc_f<T: denc::Encode + ?Sized>(v: &T, features: u64) -> Result<Vec<u8>, Errno> {
    v.encode_to_vec_with_features(features).eio()
}
