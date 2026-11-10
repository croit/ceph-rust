// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Helpers for the bounded child processes the daemon runs (`crush_location_hook`, the smart probes).
use std::io::Read;

/// Read once from the pipe `r` that `poll` reported with `revents`, keep at most `max` bytes in `b` and drop the rest,
/// so a chatty child never blocks on a full pipe. True = the pipe is done (EOF or a read error).
pub fn drain_pipe(r: &mut Option<impl Read>, b: &mut Vec<u8>, revents: i16, max: usize) -> bool {
    if revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) == 0 {
        return false;
    }
    let Some(f) = r.as_mut() else { return true };
    let mut buf = [0u8; 8 * 1024];
    match f.read(&mut buf) {
        Ok(0) => true,
        Ok(k) => {
            let room = max.saturating_sub(b.len());
            b.extend_from_slice(&buf[..k.min(room)]);
            false
        }
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
            ) =>
        {
            false
        }
        Err(_) => true,
    }
}
