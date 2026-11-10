// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
use opwire::flag;

/// Wire routing classification and the independent linger-ping pause rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestGateContext {
    pub flags: u32,
    pub watch_ping: bool,
}
impl RequestGateContext {
    pub fn pausing_flags(self) -> u32 {
        pausing_flags(self.flags, self.watch_ping)
    }
}

/// Reference linger pings use their bound write route but bypass write/full
/// admission; PAUSERD still suppresses the ping. This does not change wire flags.
pub fn pausing_flags(flags: u32, watch_ping: bool) -> u32 {
    if watch_ping {
        (flags & !flag::WRITE) | flag::READ
    } else {
        flags
    }
}

/// Explicit server-owned fullness behavior; administrative pause always applies.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FullPolicy {
    #[default]
    Wait,
    Try,
    Force,
}
impl FullPolicy {
    pub(crate) fn wire_flags(self) -> u32 {
        match self {
            Self::Wait => 0,
            Self::Try => flag::FULL_TRY,
            Self::Force => flag::FULL_FORCE,
        }
    }
}

/// Missing placement is handled by routing, not presented as a pause.
pub fn map_pauses_request(map: &osdmap::OsdMap, pool: i64, request_flags: u32) -> bool {
    map_request_gate(map, pool, request_flags).unwrap_or(false)
}

/// Current base-pool policy, evaluated before overlay selection.
pub fn map_request_gate(
    map: &osdmap::OsdMap,
    pool: i64,
    request_flags: u32,
) -> Result<bool, crate::LocalRequestError> {
    use osdmap::consts::map_flags as mf;
    let Some(pool) = map.pool(pool) else {
        return Ok(false);
    };
    if pool.flags & osdmap::pool::flags::EIO != 0 {
        return Err(crate::LocalRequestError::PoolIo);
    }
    let reads = request_flags & flag::READ != 0;
    let writes = request_flags & flag::WRITE != 0;
    let override_full = request_flags & (flag::FULL_TRY | flag::FULL_FORCE) != 0;
    Ok((reads && map.flags & mf::PAUSERD != 0)
        || (writes
            && (map.flags & mf::PAUSEWR != 0
                || (!override_full
                    && (map.flags & mf::FULL != 0
                        || pool.flags & osdmap::pool::flags::FULL != 0)))))
}
