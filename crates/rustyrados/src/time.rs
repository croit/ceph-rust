// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Checked client monotonic microseconds, independent of Unix/wire clocks.
//!
//! Absolute deadline interfaces reserve [`NO_DEADLINE`] for an enrolled
//! unlimited operation. Keep that enrollment for retry, but use [`timer`]
//! before arming a timer and [`is_due`] before expiration.
use std::time::Duration;

/// Finite signed-nanosecond scheduling domain at microsecond resolution.
pub const MAX_TIME_US: u64 = i64::MAX as u64 / 1000;
/// Enrolled unlimited operation; never a finite clock reading or timer key.
pub const NO_DEADLINE: u64 = u64::MAX;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeError {
    Overflow,
    Regression,
}
impl TimeError {
    /// Own scheduling errors, not reference overflow behavior.
    pub const fn errno(self) -> i32 {
        match self {
            Self::Overflow => -75,
            Self::Regression => -22,
        }
    }
}
pub const fn validate_clock(now: u64) -> Result<(), TimeError> {
    if now > MAX_TIME_US {
        Err(TimeError::Overflow)
    } else {
        Ok(())
    }
}
pub fn clock_us(now: Duration) -> Result<u64, TimeError> {
    if now.as_nanos() > i64::MAX as u128 {
        return Err(TimeError::Overflow);
    }
    Ok(now.as_micros() as u64)
}
pub fn advance(now: Duration, previous: Duration) -> Result<u64, TimeError> {
    let micros = clock_us(now)?;
    if now < previous {
        Err(TimeError::Regression)
    } else {
        Ok(micros)
    }
}
pub const fn validate_deadline(deadline: u64) -> Result<(), TimeError> {
    if deadline == NO_DEADLINE {
        Ok(())
    } else {
        validate_clock(deadline)
    }
}
/// Add a finite interval without clipping or accidentally creating unlimited.
pub fn add_us(now: u64, interval: u64) -> Result<u64, TimeError> {
    validate_clock(now)?;
    now.checked_add(interval)
        .filter(|end| *end <= MAX_TIME_US)
        .ok_or(TimeError::Overflow)
}
/// Zero ordinary timeout seconds means unlimited, not an immediately due timer.
pub fn deadline_after(now: u64, seconds: u64) -> Result<u64, TimeError> {
    validate_clock(now)?;
    if seconds == 0 {
        return Ok(NO_DEADLINE);
    }
    add_us(
        now,
        seconds.checked_mul(1_000_000).ok_or(TimeError::Overflow)?,
    )
}
/// Relative operation budgets can explicitly carry unlimited too; zero is finite.
pub fn operation_deadline(now: u64, interval_us: u64) -> Result<u64, TimeError> {
    validate_clock(now)?;
    if interval_us == NO_DEADLINE {
        Ok(NO_DEADLINE)
    } else {
        add_us(now, interval_us)
    }
}
pub const fn is_due(deadline: u64, now: u64) -> bool {
    deadline != NO_DEADLINE && now >= deadline
}
/// An unlimited enrollment has no timer, even though it retains its deadline contract.
pub const fn timer(deadline: u64) -> Option<u64> {
    if deadline == NO_DEADLINE {
        None
    } else {
        Some(deadline)
    }
}
pub fn timer_duration(deadline: u64) -> Option<Duration> {
    timer(deadline).map(Duration::from_micros)
}
/// Remaining finite budget, or unlimited; expiration yields finite zero.
pub const fn remaining(deadline: u64, now: u64) -> Option<u64> {
    if deadline == NO_DEADLINE {
        None
    } else {
        Some(deadline.saturating_sub(now))
    }
}
/// Granted request budget in seconds, as printed by the loud expiry line.
pub fn budget_seconds(micros: u64) -> f64 {
    Duration::from_micros(micros).as_secs_f64()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wide_seconds_are_exact_and_unlimited_is_not_a_clock_or_timer() {
        let end = deadline_after(5_000_000, 1u64 << 32).unwrap();
        assert_eq!(end, 4_294_967_301_000_000);
        assert!(!is_due(end, end - 1));
        assert!(is_due(end, end));
        assert_eq!(timer(end), Some(end));
        assert_eq!(deadline_after(7, 0), Ok(NO_DEADLINE));
        assert_eq!(timer(NO_DEADLINE), None);
        assert_eq!(remaining(NO_DEADLINE, MAX_TIME_US), None);
        assert_eq!(budget_seconds(0), 0.0);
        assert_eq!(budget_seconds(1_500_000), 1.5);
        assert!(!is_due(NO_DEADLINE, u64::MAX));
        assert_eq!(validate_clock(NO_DEADLINE), Err(TimeError::Overflow));
    }
    #[test]
    fn checked_boundary_never_wraps_shortens_or_turns_finite_into_unlimited() {
        assert_eq!(add_us(MAX_TIME_US - 1, 1), Ok(MAX_TIME_US));
        assert_eq!(add_us(MAX_TIME_US, 1), Err(TimeError::Overflow));
        assert_eq!(deadline_after(0, u64::MAX), Err(TimeError::Overflow));
        assert_eq!(
            clock_us(Duration::from_nanos(i64::MAX as u64)),
            Ok(MAX_TIME_US)
        );
        assert_eq!(
            clock_us(Duration::from_nanos(i64::MAX as u64 + 1)),
            Err(TimeError::Overflow)
        );
        assert_eq!(
            advance(Duration::ZERO, Duration::from_micros(1)),
            Err(TimeError::Regression)
        );
        assert_eq!(TimeError::Overflow.errno(), -75);
    }
}
