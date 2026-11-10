// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! utime_t / ceph_timespec / chrono-style times (spec section 6).

use crate::buf::BufMut;
use crate::dec::{Decode, Decoder};
use crate::enc::{Encode, Encoder};
use crate::error::Result;

/// utime_t == ceph_timespec == default encoding of real_time: u32 sec, u32 nsec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct UTime {
    pub sec: u32,
    pub nsec: u32,
}

impl UTime {
    pub const fn new(sec: u32, nsec: u32) -> Self {
        UTime { sec, nsec }
    }
    /// Carry nsec > 1e9 into sec, seconds capped at `u32::MAX` (classic `utime_t` normalization: exactly 1e9 nsec is
    /// left as is, a carry never wraps into the past).
    pub fn normalized(self) -> Self {
        if self.nsec > 1_000_000_000 {
            UTime {
                sec: self.sec.saturating_add(self.nsec / 1_000_000_000),
                nsec: self.nsec % 1_000_000_000,
            }
        } else {
            self
        }
    }
    /// `self + d` like classic `utime_t` addition: seconds saturate at `u32::MAX`, nsec add (wrapping like the u32
    /// field) and are then normalized.
    pub fn saturating_add(self, d: UTime) -> Self {
        UTime {
            sec: self.sec.saturating_add(d.sec),
            nsec: self.nsec.wrapping_add(d.nsec),
        }
        .normalized()
    }
    pub fn as_nanos(&self) -> u64 {
        self.sec as u64 * 1_000_000_000 + self.nsec as u64
    }
}

impl Encode for UTime {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.u32(self.sec)?;
        e.u32(self.nsec)
    }
}
impl<'a> Decode<'a> for UTime {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        Ok(UTime {
            sec: d.u32()?,
            nsec: d.u32()?,
        })
    }
}

/// timespan / duration default encoding: i32 sec, i32 nsec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Timespan {
    pub sec: i32,
    pub nsec: i32,
}
impl Encode for Timespan {
    fn encode<B: BufMut>(&self, e: &mut Encoder<B>) -> Result<()> {
        e.i32(self.sec)?;
        e.i32(self.nsec)
    }
}
impl<'a> Decode<'a> for Timespan {
    fn decode(d: &mut Decoder<'a>) -> Result<Self> {
        Ok(Timespan {
            sec: d.i32()?,
            nsec: d.i32()?,
        })
    }
}
