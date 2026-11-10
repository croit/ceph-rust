// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! `cls_get_config` surface (spec/cls.md s4): the few OSD options object classes read, as static
//! constants. The executor may override per instance via [`crate::ClsCtx::config`].

/// Options read by the RGW-family classes (upstream defaults).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClsConfig {
    /// `rgw_reshardlog_threshold`: in-logrecord reshard entries after which writes are blocked.
    pub rgw_reshardlog_threshold: u64,
    /// `rgw_pending_bucket_index_op_expiration` (seconds).
    pub rgw_pending_bucket_index_op_expiration: u64,
    /// `rgw_usage_log_key_transition`.
    pub rgw_usage_log_key_transition: bool,
    /// `rgw_bucket_index_transaction_instrumentation` (log level only; ignored).
    pub rgw_bucket_index_transaction_instrumentation: bool,
    /// `osd_max_omap_entries_per_request`.
    pub osd_max_omap_entries_per_request: u64,
    /// `osd_min_alloc_size` as used by `journal.append` padding (cls_journal.md s4).
    pub journal_min_alloc: u64,
    /// Pool stripe width for `journal.append` padding (0 = replicated).
    pub pool_stripe_width: u64,
    /// `journal.append` pads only if the pool min_compat_client >= octopus (classic parity; default luminous: off).
    pub journal_pad: bool,
    /// `rgw_gc_max_deferred_entries_size`: urgent-data bytes kept in the rgw_gc queue head (Ceph 21.2.0: option, default 3 KiB).
    pub rgw_gc_max_deferred_entries_size: u64,
}

impl ClsConfig {
    pub const DEFAULT: ClsConfig = ClsConfig {
        rgw_reshardlog_threshold: 30000,
        rgw_pending_bucket_index_op_expiration: 120,
        rgw_usage_log_key_transition: true,
        rgw_bucket_index_transaction_instrumentation: false,
        osd_max_omap_entries_per_request: 1024,
        journal_min_alloc: 4096,
        pool_stripe_width: 0,
        journal_pad: false,
        rgw_gc_max_deferred_entries_size: 3072,
    };

    /// `cls_get_config` by option name (numeric options; bools as 0/1). `None`: unknown option.
    pub fn get(&self, key: &str) -> Option<u64> {
        Some(match key {
            "rgw_reshardlog_threshold" => self.rgw_reshardlog_threshold,
            "rgw_pending_bucket_index_op_expiration" => self.rgw_pending_bucket_index_op_expiration,
            "rgw_usage_log_key_transition" => self.rgw_usage_log_key_transition as u64,
            "rgw_bucket_index_transaction_instrumentation" => {
                self.rgw_bucket_index_transaction_instrumentation as u64
            }
            "osd_max_omap_entries_per_request" => self.osd_max_omap_entries_per_request,
            "rgw_gc_max_deferred_entries_size" => self.rgw_gc_max_deferred_entries_size,
            _ => return None,
        })
    }
}

impl Default for ClsConfig {
    fn default() -> Self {
        Self::DEFAULT
    }
}
