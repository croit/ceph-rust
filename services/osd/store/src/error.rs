// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
use nvme::IoError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// Device IO failed.
    Io(IoError),
    /// No valid superblock / root slot.
    NotFormatted,
    /// On-disk structure inconsistent although checksums matched (engine bug or incompatible version).
    Corrupt(String),
    /// mkfs: device has a volatile write cache (PLP required, adr 0008) and no override was given.
    VolatileCache,
    /// mkfs: device geometry/params unusable.
    BadGeometry(String),
    /// Transient: queue/pipeline full, retry after poll.
    Busy,
    /// WAL ring has no room; release (checkpoint) first.
    WalFull,
    /// Single txn does not fit in one WAL unit / device transfer.
    TxnTooLarge,
    /// Caller bug (bad extent, double free, unreserved block, ...).
    Invalid(&'static str),
    /// Shard hit a fatal IO error earlier; all further submits fail.
    Failed,
    /// No space (data blocks or tree pages), also after a forced checkpoint.
    NoSpace,
    /// A tree page is not cached; its read was queued. Retry after `Event::Wake`.
    Miss,
    /// Mount refused: the WAL is cut at `lsn` but a unit written after `lsn` was acked proves txns `lsn..=acked_lsn`
    /// were acked and are now unreadable (media corruption, not a torn tail). Replacing the OSD recovers from
    /// replicas; `--accept-wal-loss` mounts anyway and loses them (ADR 0021 am. 9).
    WalLost {
        shard: u32,
        lsn: u64,
        acked_lsn: u64,
    },
    /// Mount refused: the store needs an offline format upgrade step first, or one was interrupted (adr 0611). The
    /// message names the step; the operator runs `croit-flashstore-tool upgrade` (the OSD exits 78 with the exact command).
    UpgradeNeeded(String),
    /// Mount refused: the store carries a format version or incompatible feature bit this build does not know (written
    /// by a newer build; downgrade is not possible, adr 0611). Nothing was written.
    Newer(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::WalLost {
                shard,
                lsn,
                acked_lsn,
            } => write!(
                f,
                "WAL CORRUPT shard {shard}: acked txns lsn {lsn}..={acked_lsn} unreadable (media corruption); \
refusing to mount, recover this OSD from replicas or force with --accept-wal-loss (DATA LOSS)"
            ),
            StoreError::UpgradeNeeded(m) => write!(f, "store upgrade needed: {m}"),
            StoreError::Newer(m) => write!(f, "{m}"),
            _ => write!(f, "{self:?}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<IoError> for StoreError {
    fn from(e: IoError) -> Self {
        StoreError::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, StoreError>;
