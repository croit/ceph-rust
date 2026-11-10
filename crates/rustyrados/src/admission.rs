// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Logical byte admission arithmetic; no reservations or allocation permission.

/// Pinned operation-vector contribution, excluding target/context and output allowances.
/// This does not replace request/wire validation or dispatch receive accounting.
pub(crate) fn logical_operation_bytes(
    operation: &opwire::OsdOp,
) -> Result<u64, crate::AdmissionError> {
    use opwire::op;
    match operation.op {
        op::MAPEXT => Ok(operation.extent().length),
        op::READ | op::SYNC_READ | op::SPARSE_READ | op::CMPEXT => {
            let length = operation.extent().length;
            if length > i64::MAX as u64 {
                Err(crate::AdmissionError::InvalidExtent)
            } else {
                Ok(length)
            }
        }
        op::GETXATTR | op::GETXATTRS | op::CMPXATTR => {
            let attr = operation.xattr();
            Ok(u64::from(attr.name_len) + u64::from(attr.value_len))
        }
        op::WRITE
        | op::WRITEFULL
        | op::APPEND
        | op::WRITESAME
        | op::ZERO
        | op::TRUNCATE
        | op::TRIMTRUNC
        | op::DELETE
        | op::CREATE
        | op::ROLLBACK
        | op::SET_ALLOC_HINT
        | op::SETXATTR
        | op::RMXATTR
        | op::OMAP_SET_VALS
        | op::OMAP_SET_HEADER
        | op::OMAP_RM_KEYS
        | op::OMAP_RM_KEY_RANGE
        | op::OMAP_CLEAR
        | op::TMAPUP
        | op::CACHE_PIN
        | op::CACHE_UNPIN
        | op::UNDIRTY
        | op::TIER_PROMOTE
        | op::UNSET_MANIFEST
        | op::COPY_FROM
        | op::COPY_FROM2
        | op::SET_REDIRECT
        | op::WATCH => {
            u64::try_from(operation.indata_len()).map_err(|_| crate::AdmissionError::NoCredit)
        }
        op::STAT
        | op::ASSERT_VER
        | op::ISDIRTY
        | op::LIST_SNAPS
        | op::LIST_WATCHERS
        | op::CHECKSUM
        | op::CALL
        | op::OMAP_GET_KEYS
        | op::OMAP_GET_VALS
        | op::OMAP_GET_HEADER
        | op::OMAP_GET_VALS_BY_KEYS
        | op::OMAP_CMP
        | op::CACHE_FLUSH
        | op::CACHE_TRY_FLUSH
        | op::CACHE_EVICT
        | op::TIER_FLUSH
        | op::TIER_EVICT
        | op::SET_CHUNK
        | op::NOTIFY
        | op::NOTIFY_ACK
        | op::PGLS
        | op::PGLS_FILTER
        | op::PGNLS
        | op::PGNLS_FILTER
        | op::PG_HITSET_LS
        | op::PG_HITSET_GET
        | op::SCRUBLS => Ok(0),
        _ => Err(crate::AdmissionError::UnsupportedOperation),
    }
}

/// Immutable permanent-ceiling/aggregate-target policy.
///
/// Callers enforce slot, API and wire bounds separately and commit counters only
/// after all admission checks pass. Compatible arithmetic alone does not select
/// a compatible queue/session/transport resource profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ByteAdmission {
    request_ceiling: Option<u64>,
    target: Option<u64>,
}

/// Why a candidate cannot enter its logical byte domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ByteAdmissionError {
    /// Charge exceeds the strict policy's permanent request ceiling.
    RequestTooLarge,
    /// Existing occupancy prevents admission; retirement can make it eligible.
    NoCredit,
    /// The next byte total cannot be represented.
    Overflow,
}

impl ByteAdmission {
    /// A permanent per-request ceiling and strict aggregate limit, including zero.
    #[inline]
    pub const fn strict(limit: u64) -> Self {
        Self {
            request_ceiling: Some(limit),
            target: Some(limit),
        }
    }

    /// A soft aggregate target with sole-oversize admission; zero disables bytes.
    /// Slot/API/actual-wire bounds remain the caller's responsibility.
    #[inline]
    pub const fn compatible(target: u64) -> Self {
        Self {
            request_ceiling: None,
            target: if target == 0 { None } else { Some(target) },
        }
    }

    /// Permanent single-request ceiling, absent for compatible arithmetic.
    #[inline]
    pub const fn request_ceiling(self) -> Option<u64> {
        self.request_ceiling
    }

    /// Aggregate byte target; absent when the compatible byte throttle is disabled.
    #[inline]
    pub const fn target(self) -> Option<u64> {
        self.target
    }

    /// Validate a charge independently of mutable occupancy.
    #[inline]
    pub fn check_request(self, charge: u64) -> Result<(), ByteAdmissionError> {
        if self.request_ceiling.is_some_and(|limit| charge > limit) {
            Err(ByteAdmissionError::RequestTooLarge)
        } else {
            Ok(())
        }
    }

    /// Return the next logical byte total without changing caller-owned counters.
    /// `occupied` includes zero-byte holders; it is not a slot-capacity check.
    #[inline]
    pub fn admit(self, used: u64, occupied: usize, charge: u64) -> Result<u64, ByteAdmissionError> {
        self.check_request(charge)?;
        let next = used
            .checked_add(charge)
            .ok_or(ByteAdmissionError::Overflow)?;
        if self.target.is_none_or(|target| next <= target)
            || (self.request_ceiling.is_none() && used == 0 && occupied == 0)
        {
            Ok(next)
        } else {
            Err(ByteAdmissionError::NoCredit)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ByteAdmission as B, ByteAdmissionError as E};

    #[test]
    fn strict_permanent_and_aggregate_boundaries_remain_distinct() {
        let strict = B::strict(8);
        assert_eq!(strict.request_ceiling(), Some(8));
        assert_eq!(strict.target(), Some(8));
        assert_eq!(strict.check_request(8), Ok(()));
        assert_eq!(strict.check_request(9), Err(E::RequestTooLarge));
        assert_eq!(strict.admit(0, 0, 8), Ok(8));
        assert_eq!(strict.admit(4, 1, 4), Ok(8));
        assert_eq!(strict.admit(4, 1, 5), Err(E::NoCredit));
        assert_eq!(strict.admit(0, 0, 9), Err(E::RequestTooLarge));
        assert_eq!(B::strict(0).admit(0, 0, 0), Ok(0));
        assert_eq!(B::strict(0).admit(0, 0, 1), Err(E::RequestTooLarge));
    }

    #[test]
    fn compatible_target_allows_only_idle_oversize_and_preserves_zero_holders() {
        let soft = B::compatible(8);
        assert_eq!(soft.request_ceiling(), None);
        assert_eq!(soft.target(), Some(8));
        assert_eq!(soft.check_request(u64::MAX), Ok(()));
        assert_eq!(soft.admit(4, 1, 4), Ok(8));
        assert_eq!(soft.admit(4, 1, 5), Err(E::NoCredit));
        assert_eq!(soft.admit(0, 0, 9), Ok(9));
        assert_eq!(soft.admit(9, 1, 0), Err(E::NoCredit));
        assert_eq!(soft.admit(9, 1, 1), Err(E::NoCredit));
        assert_eq!(soft.admit(0, 1, 9), Err(E::NoCredit));
        assert_eq!(soft.admit(1, 0, 9), Err(E::NoCredit));
        assert_eq!(soft.admit(0, 0, u64::MAX), Ok(u64::MAX));
    }

    #[test]
    fn disabled_bytes_and_exact_maximum_still_check_overflow() {
        let disabled = B::compatible(0);
        assert_eq!(disabled.target(), None);
        assert_eq!(disabled.admit(7, 99, u64::MAX - 7), Ok(u64::MAX));
        assert_eq!(disabled.admit(7, 99, u64::MAX - 6), Err(E::Overflow));
        assert_eq!(B::strict(u64::MAX).admit(u64::MAX - 1, 1, 1), Ok(u64::MAX));
        assert_eq!(B::strict(u64::MAX).admit(u64::MAX, 1, 1), Err(E::Overflow));
        assert_eq!(B::compatible(8).admit(u64::MAX, 1, 1), Err(E::Overflow));
    }
}
