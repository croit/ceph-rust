// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Checked numeric bounds for registered memory. A range does not prove that memory is mapped or accessible.
use std::{fmt, io};

/// A nonempty, nonnull range whose exclusive end fits in both `u64` and the host address space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryRange {
    address: u64,
    end: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryRangeError {
    Null,
    Empty,
    Overflow,
    Outside,
    Overlap,
}

impl fmt::Display for MemoryRangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Null => "null registered-memory address",
            Self::Empty => "empty registered-memory range",
            Self::Overflow => "registered-memory range exceeds the address space",
            Self::Outside => "registered-memory subrange exceeds its parent",
            Self::Overlap => "overlapping registered-memory ranges",
        })
    }
}

impl std::error::Error for MemoryRangeError {}

impl From<MemoryRangeError> for io::Error {
    fn from(error: MemoryRangeError) -> Self {
        Self::new(io::ErrorKind::InvalidInput, error)
    }
}

impl MemoryRange {
    pub fn new(address: u64, length: u64) -> Result<Self, MemoryRangeError> {
        if address == 0 {
            return Err(MemoryRangeError::Null);
        }
        if length == 0 {
            return Err(MemoryRangeError::Empty);
        }
        let end = address
            .checked_add(length)
            .ok_or(MemoryRangeError::Overflow)?;
        usize::try_from(end).map_err(|_| MemoryRangeError::Overflow)?;
        Ok(Self { address, end })
    }

    pub fn address(self) -> u64 {
        self.address
    }

    pub fn length(self) -> u64 {
        self.end - self.address
    }

    pub fn end(self) -> u64 {
        self.end
    }

    pub fn subrange(self, offset: u64, length: u64) -> Result<Self, MemoryRangeError> {
        let address = self
            .address
            .checked_add(offset)
            .ok_or(MemoryRangeError::Overflow)?;
        let range = Self::new(address, length)?;
        if range.end > self.end {
            return Err(MemoryRangeError::Outside);
        }
        Ok(range)
    }

    pub fn contains(self, address: u64, length: u64) -> bool {
        Self::new(address, length).is_ok_and(|r| r.address >= self.address && r.end <= self.end)
    }
}

#[cfg(any(test, all(feature = "verbs", target_os = "linux")))]
pub(crate) fn registration_ranges(
    ranges: &[(u64, u64)],
) -> Result<Vec<MemoryRange>, MemoryRangeError> {
    let mut ranges: Vec<_> = ranges
        .iter()
        .map(|&(a, n)| MemoryRange::new(a, n))
        .collect::<Result<_, _>>()?;
    ranges.sort_unstable_by_key(|r| r.address);
    if ranges.windows(2).any(|w| w[0].end > w[1].address) {
        return Err(MemoryRangeError::Overlap);
    }
    Ok(ranges)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_bounds_never_wrap_or_accept_an_empty_transfer() {
        assert_eq!(MemoryRange::new(0, 1), Err(MemoryRangeError::Null));
        assert_eq!(MemoryRange::new(1, 0), Err(MemoryRangeError::Empty));
        assert_eq!(
            MemoryRange::new(u64::MAX, 1),
            Err(MemoryRangeError::Overflow)
        );
        assert_eq!(
            MemoryRange::new(2, u64::MAX),
            Err(MemoryRangeError::Overflow)
        );
        let r = MemoryRange::new(0x1000, 4096).unwrap();
        assert_eq!(r.subrange(0, 4096), Ok(r));
        assert_eq!(r.subrange(4095, 1).unwrap().end(), r.end());
        assert_eq!(r.subrange(4096, 1), Err(MemoryRangeError::Outside));
        assert_eq!(r.subrange(4095, 2), Err(MemoryRangeError::Outside));
        assert_eq!(r.subrange(u64::MAX, 1), Err(MemoryRangeError::Overflow));
        assert_eq!(r.subrange(0, 0), Err(MemoryRangeError::Empty));
        assert!(!r.contains(r.end(), 0));
        assert!(!r.contains(r.address() - 1, 2));
        assert!(!r.contains(r.address(), u64::MAX));
        assert!(r.contains(r.address(), r.length()));
    }

    #[test]
    fn registrations_reject_every_invalid_range_before_any_provider_call() {
        assert!(registration_ranges(&[]).unwrap().is_empty());
        for ranges in [&[(1, 0)][..], &[(0, 1)], &[(u64::MAX, 1)]] {
            assert!(registration_ranges(ranges).is_err());
        }
        for ranges in [
            &[(10, 5), (10, 5)][..],
            &[(11, 1), (10, 5)],
            &[(10, 2), (11, 4)],
        ] {
            assert_eq!(registration_ranges(ranges), Err(MemoryRangeError::Overlap));
        }
        let r = registration_ranges(&[(20, 3), (10, 10)]).unwrap();
        assert_eq!(
            r,
            [
                MemoryRange::new(10, 10).unwrap(),
                MemoryRange::new(20, 3).unwrap()
            ]
        );
    }
}
