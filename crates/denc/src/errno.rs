// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Linux errno values (also the Ceph wire values), POSITIVE. Op replies and cls methods carry
//! them negated.

pub const EPERM: i32 = 1;
pub const ENOENT: i32 = 2;
pub const EIO: i32 = 5;
pub const ENXIO: i32 = 6;
pub const ENOEXEC: i32 = 8;
pub const EBADF: i32 = 9;
pub const EAGAIN: i32 = 11;
pub const EACCES: i32 = 13;
pub const EBUSY: i32 = 16;
pub const EEXIST: i32 = 17;
pub const EXDEV: i32 = 18;
pub const ENOTDIR: i32 = 20;
pub const EISDIR: i32 = 21;
pub const EINVAL: i32 = 22;
pub const ENFILE: i32 = 23;
pub const EFBIG: i32 = 27;
pub const ENOSPC: i32 = 28;
pub const ERANGE: i32 = 34;
pub const ENAMETOOLONG: i32 = 36;
pub const ENOSYS: i32 = 38;
pub const ENOTEMPTY: i32 = 39;
pub const ENODATA: i32 = 61;
pub const EMULTIHOP: i32 = 72;
pub const EOVERFLOW: i32 = 75;
pub const EILSEQ: i32 = 84;
pub const EOLDSNAPC: i32 = 85;
/// OSD_WRITETOOBIG.
pub const EMSGSIZE: i32 = 90;
pub const EOPNOTSUPP: i32 = 95;
pub const ENOTCONN: i32 = 107;
pub const EBLOCKLISTED: i32 = 108;
pub const ETIMEDOUT: i32 = 110;
pub const EINPROGRESS: i32 = 115;
pub const ESTALE: i32 = 116;
pub const EDQUOT: i32 = 122;
pub const ECANCELED: i32 = 125;
/// Linux MAX_ERRNO: cmpext mismatch results are `-(MAX_ERRNO + index)`.
pub const MAX_ERRNO: i32 = 4095;
