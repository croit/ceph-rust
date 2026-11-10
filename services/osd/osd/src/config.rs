// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Layered runtime configuration (spec osd-lifecycle.md 2.7 / 10): defaults < mon < file < env < command line <
//! runtime override (the classic source levels). Only a [`DEFAULTS`] subset is interpreted by the core; any other name is stored and
//! shown (`config get/show`).
use std::collections::BTreeMap;

/// Config source levels (numbering as in MMgrOpen `config_bl`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    /// Built-in default.
    Default = 0,
    /// Centralized config from the mon.
    Mon = 1,
    /// Local conf file (`croit-flashstore-osd run` passes it as `--conf-set`).
    File = 2,
    /// Process environment (`run`: `FLASHSTORE_DATA_DIR`, passed as `--env-set`).
    Env = 3,
    /// Command line (`--set`, `run` flags).
    Cmdline = 4,
    /// Runtime override (`config set`, `injectargs`).
    Override = 5,
}

impl Level {
    /// The classic name of a level number (`config diff`), `None` for an unknown number.
    pub fn name(level: u8) -> Option<&'static str> {
        Some(match level {
            0 => "default",
            1 => "mon",
            2 => "file",
            3 => "env",
            4 => "cmdline",
            5 => "override",
            _ => return None,
        })
    }

    /// The level number is a startup source of the daemon itself (conf file, environment, command line).
    pub fn is_local(level: u8) -> bool {
        (Level::File as u8..=Level::Cmdline as u8).contains(&level)
    }
}

/// Where the entries of the daemon's local config (`OsdConfig::local_config`, built by [`local_layers`]) came from: the
/// first `file` entries are conf-file settings, the next `env` ones environment settings, the rest command-line
/// settings. The order is the level order, so the last setting of a key is also the one of the highest level.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LocalSources {
    pub file: usize,
    pub env: usize,
}

impl LocalSources {
    /// Level of entry `i` of the local config.
    pub fn level(self, i: usize) -> Level {
        if i < self.file {
            Level::File
        } else if i < self.file + self.env {
            Level::Env
        } else {
            Level::Cmdline
        }
    }
}

/// The daemon's local config from its conf-file, environment and command-line `k=v` settings (each as
/// [`local_config`]), in level order, with their [`LocalSources`].
pub fn local_layers<'a>(
    file: impl IntoIterator<Item = &'a str>,
    env: impl IntoIterator<Item = &'a str>,
    cmdline: impl IntoIterator<Item = &'a str>,
) -> (Vec<(String, String)>, LocalSources) {
    let mut all = local_config(file);
    let file = all.len();
    all.extend(local_config(env));
    let env = all.len() - file;
    all.extend(local_config(cmdline));
    (all, LocalSources { file, env })
}

/// Options interpreted by the core with their defaults.
pub const DEFAULTS: &[(&str, &str)] = &[
    ("osd_heartbeat_interval", "6"),
    ("osd_heartbeat_grace", "20"),
    ("osd_pool_default_read_lease_ratio", "0.8"),
    ("osd_heartbeat_min_peers", "10"),
    ("osd_heartbeat_min_size", "2000"),
    ("osd_heartbeat_min_healthy_ratio", "0.33"),
    ("osd_heartbeat_stale", "600"),
    // heartbeat RTT statistics (spec ops-observability 6.4)
    ("osd_mon_heartbeat_stat_stale", "3600"),
    ("debug_heartbeat_testing_span", "0"),
    ("mon_warn_on_slow_ping_time", "0"),
    ("mon_warn_on_slow_ping_ratio", "0.05"),
    ("osd_mon_heartbeat_interval", "30"),
    ("osd_mon_report_interval", "5"),
    ("osd_beacon_report_interval", "300"),
    ("osd_max_markdown_period", "600"),
    ("osd_max_markdown_count", "5"),
    ("osd_fast_fail_on_connection_refused", "true"),
    ("osd_fast_shutdown", "true"),
    ("osd_fast_shutdown_notify_mon", "true"),
    ("osd_mon_shutdown_timeout", "5"),
    ("osd_crush_update_on_start", "true"),
    ("osd_class_update_on_start", "true"),
    // object class policies (cls.md 2.1): classes served at all, and classes reachable with plain class-read/-write caps
    (
        "osd_class_load_list",
        opexec::clsx::ClassPolicy::CEPH_DEFAULT_LIST,
    ),
    (
        "osd_class_default_list",
        opexec::clsx::ClassPolicy::CEPH_DEFAULT_LIST,
    ),
    ("osd_crush_initial_weight", "-1"),
    ("crush_location", ""),
    ("osd_map_message_max", "40"),
    ("osd_failsafe_full_ratio", "0.97"),
    ("rotating_keys_bootstrap_timeout", "30"),
    ("max_rotating_auth_attempts", "10"),
    ("mgr_stats_period", "5"),
    ("mgr_stats_threshold", "5"),
    ("mgr_connect_retry_interval", "1"),
    ("osd_op_complaint_time", "30"),
    ("ms_bind_msgr2", "true"),
    ("ms_bind_msgr1", "false"), // v2 only; classic default true (doc/compat/ceph-21.2.0.md, reported values)
    ("osd_objectstore", "bluestore"),
    // store name reported toward mon/mgr/CLI: `bluestore` (default; classic mons gate features on it) or `flashstore`
    // (patched mons). Startup only (restart to change). Renames the `osd_objectstore` metadata and default, the
    // `bluestore_bdev_*` device metadata keys, the `bluestore` perf logger, the `bluestore ...` tell/asok commands and
    // the `BLUESTORE_*` health codes. Ceph config option names (`bluestore_compression_*`, `bluestore_log_op_age`,
    // `bluestore_slow_ops_*`) are never renamed.
    ("flashstore_report_objectstore", "bluestore"),
    ("debug_disable_randomized_ping", "false"),
    // ---- known but not (all) interpreted: shown by `config get/show/diff`, classic defaults ----
    ("osd_max_backfills", "1"),
    // inline compression defaults for pools without their own compression_* options (adr 0059 am. 1)
    ("bluestore_compression_mode", "none"),
    ("bluestore_compression_algorithm", "snappy"),
    ("bluestore_compression_required_ratio", "0.875"),
    ("bluestore_compression_min_blob_size", "0"),
    ("bluestore_compression_max_blob_size", "0"),
    ("bluestore_compression_min_blob_size_ssd", "8192"),
    ("bluestore_compression_max_blob_size_ssd", "65536"),
    // EC shard role (adr 0039): pools this OSD serves as an EC shard (off | all | pool ids/names); default all (am. 2)
    ("ec_enable_pools", "all"),
    // tracker 74943 alert (classic ISA OSDs before the fix in acting sets of ISA pools with several k/m shapes)
    ("flashstore_warn_isa_decode_cache", "true"),
    ("ec_enable_primary", "true"),
    // adr 0039 am. 1: erasure pools the gate rejects get empty-shard answers (classic peers without us) instead of silence
    ("ec_decline_unsupported", "true"),
    // optimized EC pools (adr 0067 am. 10): off | all | pool ids/names; default all; needs ec_enable_pools too
    ("ec_enable_optimized", "all"),
    // lead optimized EC PGs (mode O primary, plan S2); default on; needs ec_enable_primary and ec_enable_optimized
    ("ec_enable_optimized_primary", "true"),
    // serve EC_DIRECT_READ (client reads of one data shard) from our shard / as primary (adr 0067 am. 3); off = always EAGAIN
    ("ec_optimized_direct", "false"),
    // parity-delta writes + extent cache of the mode O primary (plan S5): off | auto | always
    ("ec_pdw", "off"),
    // EC primary: bound of the adaptive idle roll-forward deferral (adr 0160 am. 3); 0 = dummy round right away (classic)
    ("ec_rollforward_defer_us", "20000"),
    ("osd_min_recovery_priority", "0"),
    ("osd_mclock_override_recovery_settings", "false"),
    ("osd_recovery_max_active", "0"),
    ("osd_recovery_max_active_hdd", "3"),
    ("osd_recovery_max_active_ssd", "10"),
    ("osd_recovery_sleep", "0"),
    ("osd_recovery_sleep_hdd", "0.1"),
    ("osd_recovery_sleep_ssd", "0"),
    ("osd_recovery_sleep_hybrid", "0.025"),
    ("osd_recovery_sleep_degraded", "0"),
    ("osd_recovery_sleep_degraded_hdd", "0.1"),
    ("osd_recovery_sleep_degraded_ssd", "0"),
    ("osd_recovery_sleep_degraded_hybrid", "0.025"),
    ("osd_recovery_retry_interval", "30"),
    ("osd_backfill_retry_interval", "30"),
    ("osd_allow_recovery_below_min_size", "true"),
    // dev escape: the required past-interval bounds check (peering.md 3.8)
    ("osd_skip_check_past_interval_bounds", "false"),
    ("osd_recovery_op_priority", "3"),
    ("osd_recovery_max_single_start", "1"),
    ("osd_recovery_max_chunk", "8388608"),
    ("osd_recovery_delay_start", "0"),
    ("osd_backfill_scan_min", "64"),
    ("osd_backfill_scan_max", "512"),
    ("osd_client_op_priority", "63"),
    ("osd_op_queue", "mclock_scheduler"),
    ("osd_op_queue_cut_off", "high"),
    ("osd_mclock_profile", "balanced"),
    ("osd_op_num_shards", "0"),
    ("osd_op_num_threads_per_shard", "0"),
    ("osd_op_thread_timeout", "15"),
    ("osd_op_thread_suicide_timeout", "150"),
    ("osd_op_history_size", "20"),
    ("osd_op_history_duration", "600"),
    ("osd_op_log_threshold", "5"),
    // `bench` precheck bounds (spec osd-lifecycle.md 9.4): the duration only scales the accepted `count`
    ("osd_bench_duration", "30"),
    ("osd_bench_max_block_size", "67108864"),
    ("osd_bench_small_size_max_iops", "100"),
    ("osd_bench_large_size_max_throughput", "104857600"),
    ("osd_scrub_min_interval", "86400"),
    // mon "PG not scrubbed" health warning only; not an OSD scheduling input (spec scrub.md 12.1.4)
    ("osd_scrub_max_interval", "604800"),
    ("osd_deep_scrub_interval", "604800"),
    ("osd_deep_scrub_interval_cv", "0.2"),
    // accepted, no effect in v21.2.0 (spec scrub.md 12.1.4)
    ("osd_deep_scrub_randomize_ratio", "0.15"),
    ("osd_scrub_begin_hour", "0"),
    ("osd_scrub_end_hour", "0"),
    ("osd_scrub_begin_week_day", "0"),
    ("osd_scrub_end_week_day", "0"),
    ("osd_scrub_during_recovery", "false"),
    ("osd_scrub_load_threshold", "10.0"),
    ("osd_scrub_sleep", "0"),
    ("osd_scrub_chunk_min", "5"),
    ("osd_scrub_chunk_max", "15"),
    ("osd_shallow_scrub_chunk_min", "50"),
    ("osd_shallow_scrub_chunk_max", "100"),
    ("osd_max_scrubs", "3"),
    ("osd_scrub_max_preemptions", "5"),
    ("osd_scrub_priority", "5"),
    ("osd_scrub_invalid_stats", "true"),
    // operator scrubs observe osd_max_scrubs + replica reservations (off = classic: unlimited, no reservations)
    ("flashstore_scrub_operator_limits", "true"),
    // lab diagnostic: log primaries whose peering took at least this many ms, with the time per phase (0 = off)
    ("flashstore_peering_trace_ms", "0"),
    ("osd_scrub_auto_repair", "false"),
    ("osd_scrub_auto_repair_num_errors", "5"),
    ("osd_scrub_interval_randomize_ratio", "0.5"),
    ("osd_scrub_backoff_ratio", "0.66"),
    ("osd_deep_scrub_stride", "4194304"),
    ("osd_deep_scrub_keys", "1024"),
    ("osd_deep_scrub_large_omap_object_key_threshold", "200000"),
    (
        "osd_deep_scrub_large_omap_object_value_sum_threshold",
        "1073741824",
    ),
    ("osd_pool_default_size", "3"),
    ("osd_pool_default_min_size", "0"),
    ("osd_pool_default_pg_num", "32"),
    ("osd_pool_default_pgp_num", "0"),
    ("osd_pool_default_flag_hashpspool", "true"),
    ("osd_pool_default_crush_rule", "-1"),
    ("osd_pool_default_pg_autoscale_mode", "on"),
    ("osd_min_pg_log_entries", "250"),
    ("osd_max_pg_log_entries", "10000"),
    ("osd_pg_log_dups_tracked", "3000"),
    ("osd_pg_log_trim_max", "10000"),
    ("osd_pg_log_trim_min", "100"),
    ("osd_target_pg_log_entries_per_osd", "300000"),
    ("osd_max_object_size", "134217728"),
    ("osd_max_write_size", "90"),
    ("osd_client_message_size_cap", "524288000"),
    ("osd_client_message_cap", "256"),
    ("bluestore_log_op_age", "5"),
    ("bluestore_slow_ops_warn_lifetime", "86400"),
    ("bluestore_slow_ops_warn_threshold", "1"),
    ("flashstore_warn_on_read_errors", "true"),
    ("flashstore_read_errors_warn_lifetime", "86400"),
    ("osd_map_cache_size", "50"),
    ("osd_map_share_max_epochs", "40"),
    ("osd_pg_stat_report_interval_max_seconds", "5"),
    ("osd_pg_stat_report_interval_max_epochs", "500"),
    ("osd_memory_target", "4294967296"),
    ("osd_memory_base", "805306368"),
    ("osd_memory_cache_min", "134217728"),
    // classic PG deletion sleeps: accepted so automation that sets them keeps working, ignored (adr 0524: the store
    // adapter schedules deletion steps by client activity, no sleep)
    ("osd_delete_sleep", "0"),
    ("osd_delete_sleep_ssd", "0"),
    ("flashstore_scrub_slice_bytes", "1048576"),
    // deep-scrub reformat engines per pool when the pool option `deep_scrub_reformat` is unset (adr 0593-dedup-deep-scrub-reformat):
    // `<pool id>=<engine list>` entries separated by `|`, e.g. `3=collect_csum,recompress|5=defragment`
    ("flashstore_deep_scrub_reformat", ""),
    // content digest of dedup info records: md5 (fork-compatible) or sha256
    ("flashstore_dedup_digest", "md5"),
    // dedup info collection records objects whose bytes are all zero too (false: such objects get no record)
    ("flashstore_dedup_zero_objects", "false"),
    // LSM range deletion: a resident candidate upper bound below this selects point tombstones.
    // Changeable at runtime; zero preserves native range tombstones without estimating.
    ("flashstore_omap_delete_range_threshold", "0"),
    // Foreground LSM listings: batched demand misses and bounded adaptive look-ahead.
    // External OMAP database root; engine choice itself is a persistent mkfs property.
    ("flashstore_rocksdb_dir", ""),
    // Opt-in worker measurements, not a cache, batching or durability tuning switch.
    ("flashstore_rocksdb_profile", "false"),
    // RocksDB worker placement in the service CPU budget: next (owner+1), owner, float. Placement only.
    ("flashstore_rocksdb_worker_cpu", "next"),
    // RocksDB engine limits (adr 0726 am. 1: two compaction threads, four background jobs; 0 = library default trigger).
    ("flashstore_rocksdb_low_threads", "2"),
    ("flashstore_rocksdb_high_threads", "1"),
    ("flashstore_rocksdb_background_jobs", "4"),
    ("flashstore_rocksdb_write_buffer_number", "2"),
    ("flashstore_rocksdb_l0_slowdown_trigger", "0"),
    ("flashstore_rocksdb_l0_stop_trigger", "0"),
    ("flashstore_omap_scan_prefetch", "true"),
    // Adapt from one chunk up to flashstore_omap_scan_prefetch_max_chunks, with scan prefetch enabled.
    ("flashstore_omap_scan_prefetch_adaptive", "true"),
    ("flashstore_omap_scan_prefetch_max_chunks", "16"),
    // External backing only; persistent format, never a runtime engine switch.
    ("flashstore_store_splinterdb_dir", ""),
    ("flashstore_store_splinterdb_io", "buffered"),
    ("flashstore_store_splinterdb_prefetch_bytes", "1048576"),
    ("flashstore_store_splinterdb_scan_readahead_pages", "4"),
    ("flashstore_store_splinterdb_cache_stats", "false"),
    ("flashstore_store_splinterdb_cleaner_isolation", "false"),
    ("flashstore_store_splinterdb_normal_maintenance", "false"),
    // Experiments (default off): a SplinterDB memtable worker (needs normal maintenance) and
    // 1..=4 threads applying one overlay flush over the service CPU set.
    ("flashstore_store_splinterdb_memtable_maintenance", "false"),
    ("flashstore_store_splinterdb_apply_threads", "1"),
    ("flashstore_store_splinterdb_checkpoint_log_bytes", "0"),
    ("flashstore_store_splinterdb_pipelined_barrier", "false"),
    ("flashstore_store_splinterdb_defer_log_writeback", "false"),
    // Startup window per active run, 1..=16; shared memory and device admission remain bounded.
    ("flashstore_omap_scan_prefetch_chunks", "1"),
    // serve the dedup listing request (MOSDDedupList 137, feature bit 51 in MOSDBoot) and set the PG deep scrub start
    // stamp (pg_history_t v12 / pg_stat_t v32, adr 0628-pg-history-v12), croit fork wire formats; off = upstream v21.2.0
    // wire only. A croit fork build <= 21.1.x writes the start stamp as pg_history_t v11: unsupported against 21.2.0
    ("flashstore_dedup_list", "false"),
    // CPU budget of one core's part of a dedup listing request (ms); the reply is partial past it (protocol-allowed)
    ("flashstore_dedup_list_slice_ms", "5"),
    // max seconds of one dedup listing request / `bluestore dedup list` per core (0 = unlimited; fork option)
    ("osd_dedup_list_max_duration", "1"),
    // PG deletion progress log period
    ("flashstore_delete_log_s", "10"),
    ("flashstore_trace_sample", "0"),
    ("flashstore_trace_ring", "16384"),
    ("flashstore_obj_cache", "true"),
    // sender-side repop credits between croit-flashstore-osd peers (adr 0084 am. 3); false = old receive-side pausing only
    ("flashstore_repop_credit", "false"),
    // receiver-side pre-write of large writes while they arrive (adr 0477 Phase 1; default on since am. 3)
    ("flashstore_prewrite", "true"),
    ("flashstore_store_shared_clone", "true"),
    ("osd_snap_trim_sleep", "0"),
    ("osd_snap_trim_sleep_ssd", "0"),
    ("osd_max_trimming_pgs", "2"),
    ("osd_snap_trim_priority", "5"),
    ("osd_snap_trim_cost", "1048576"),
    ("osd_pg_max_concurrent_snap_trims", "2"),
    ("osd_max_pg_per_osd_hard_ratio", "3"),
    // reports what the daemon does (doc/compat/ceph-21.2.0.md): object info never carries a whole-object data digest,
    // the store checksums every block (spec client-ops.md 7.4 D1); classic default false
    ("osd_skip_data_digest", "true"),
    ("osd_backoff_on_unfound", "true"),
    ("osd_default_notify_timeout", "30"),
    ("osd_command_max_records", "256"),
    ("osd_data", "/var/lib/ceph/osd/$cluster-$id"),
    ("osd_journal", ""),
    ("public_network", ""),
    ("cluster_network", ""),
    ("public_network_interface", ""),
    ("cluster_network_interface", ""),
    ("ms_bind_ipv4", "true"),
    ("ms_bind_ipv6", "false"),
    ("ms_bind_prefer_ipv4", "false"),
    ("auth_cluster_required", "cephx"),
    ("auth_service_required", "cephx"),
    ("auth_client_required", "cephx, none"),
    ("auth_service_ticket_ttl", "3600"),
    ("ms_dispatch_throttle_bytes", "104857600"),
    ("ms_crc_data", "true"),
    ("ms_crc_header", "true"),
    ("ms_async_op_threads", "3"),
    // stderr -> journald first; file logging is opt-in (doc/compat/ceph-21.2.0.md, spec ops-observability 6.9)
    ("log_to_stderr", "true"),
    ("err_to_stderr", "true"),
    ("log_to_file", "false"),
    ("log_max_recent", "10000"),
    ("log_max_new", "1000"),
    ("debug_osd", "1/5"),
    ("debug_ms", "0/0"),
    ("debug_monc", "0/10"),
    ("debug_mgrc", "1/5"),
    ("debug_bluestore", "1/5"),
    ("mon_max_pg_per_osd", "500"),
    ("mon_osd_full_ratio", "0.95"),
    ("mon_osd_nearfull_ratio", "0.85"),
    ("mon_osd_backfillfull_ratio", "0.9"),
    ("crush_location_hook", ""),
    ("crush_location_hook_timeout", "10"),
    ("pid_file", ""),
];

/// The layered config.
#[derive(Clone, Debug)]
pub struct ConfigDb {
    layers: BTreeMap<String, BTreeMap<u8, String>>,
    /// Mon-level values a higher-priority local source overrides (reported to the mgr as `ignored_mon_values`).
    ignored_mon: BTreeMap<String, String>,
    /// Bumped on every change of the effective set; the mgr client sends `config_bl` only when it moved.
    version: u64,
}

impl Default for ConfigDb {
    fn default() -> Self {
        let mut c = ConfigDb {
            layers: BTreeMap::new(),
            ignored_mon: BTreeMap::new(),
            version: 0,
        };
        for (k, v) in DEFAULTS {
            // every default is a valid value (test `defaults_are_valid_values`)
            if let Err(e) = c.set(Level::Default, k, v) {
                eprintln!("WARNING config: built-in default {e}");
            }
        }
        c
    }
}

/// The options mclock's QoS defaults own unless `osd_mclock_override_recovery_settings` is set (spec replication.md 7.5).
pub const RECOVERY_QOS_KEYS: [&str; 4] = [
    "osd_max_backfills",
    "osd_recovery_max_active",
    "osd_recovery_max_active_hdd",
    "osd_recovery_max_active_ssd",
];

/// What the recovery QoS observer re-reads: [`RECOVERY_QOS_KEYS`] and the scheduler switch that gates them
/// (`ConfigDb::recovery_qos_gated`).
pub(crate) const RECOVERY_QOS_OBS_KEYS: [&str; 6] = [
    RECOVERY_QOS_KEYS[0],
    RECOVERY_QOS_KEYS[1],
    RECOVERY_QOS_KEYS[2],
    RECOVERY_QOS_KEYS[3],
    "osd_op_queue",
    "osd_mclock_override_recovery_settings",
];

/// Recovery/backfill sleep options. A running mclock scheduler overwrites all of them with 0 in memory, so `config
/// get/show` reports 0 even for a value set in the config db (spec peering.md 13.1).
pub const RECOVERY_SLEEP_KEYS: [&str; 8] = [
    "osd_recovery_sleep",
    "osd_recovery_sleep_hdd",
    "osd_recovery_sleep_ssd",
    "osd_recovery_sleep_hybrid",
    "osd_recovery_sleep_degraded",
    "osd_recovery_sleep_degraded_hdd",
    "osd_recovery_sleep_degraded_ssd",
    "osd_recovery_sleep_degraded_hybrid",
];

/// Ceph options croit-flashstore-osd shows (`config get/show/diff`) but whose mechanism it does not have, with the
/// reason. A value other than the default logs one WARNING per value (`ConfigDb::no_effect_warnings`), never silence
/// (doc/compat/ceph-21.2.0.md, adr 0062 am. 4).
pub const NO_EFFECT: [(&str, &str); 10] = [
    (
        "osd_mclock_profile",
        "no op scheduler: PG-per-core ownership runs client and recovery events in arrival order; recovery is \
         bounded by osd_max_backfills, osd_recovery_max_active* and the recovery sleeps (adr 0062)",
    ),
    (
        "osd_op_queue_cut_off",
        "no op queue: each core runs its PGs' events in arrival order (adr 0006, 0062)",
    ),
    (
        "osd_op_num_shards",
        "the OSD sizes its cores itself (thread per core, PG per core, adr 0006)",
    ),
    (
        "osd_op_num_threads_per_shard",
        "the OSD sizes its cores itself (thread per core, PG per core, adr 0006)",
    ),
    (
        "osd_client_op_priority",
        "no op queue priorities: each core runs its PGs' events in arrival order (adr 0062)",
    ),
    (
        "osd_recovery_max_single_start",
        "recovery starts are sized by the OSD-wide osd_recovery_max_active op lease (adr 0031 am. 10)",
    ),
    (
        "osd_snap_trim_priority",
        "no op queue priorities: snap trimming is bounded by osd_max_trimming_pgs, \
         osd_pg_max_concurrent_snap_trims and osd_snap_trim_sleep (adr 0062)",
    ),
    (
        "osd_snap_trim_cost",
        "no op queue costs: snap trimming is bounded by osd_max_trimming_pgs, osd_pg_max_concurrent_snap_trims \
         and osd_snap_trim_sleep (adr 0062)",
    ),
    (
        "ms_crc_header",
        "msgr1 only: msgr2 frames always carry the preamble CRC (classic too), and croit-flashstore-osd speaks \
         msgr2 only",
    ),
    (
        "osd_skip_data_digest",
        "object info never carries a whole-object data digest (the store checksums every block, spec \
         client-ops.md 7.4 D1)",
    ),
];

/// What the recovery options mean for this OSD.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryLimits {
    /// `osd_max_backfills`: slots of each reserver (local, remote).
    pub max_backfills: usize,
    /// `osd_recovery_max_active`, else the per-media variant (all-flash: `_ssd`): recovery ops in flight on the OSD.
    pub recovery_max_active: usize,
    /// `osd_min_recovery_priority`.
    pub min_priority: u32,
}

impl ConfigDb {
    /// With the mclock scheduler (the default) and no `osd_mclock_override_recovery_settings`, classic removes a changed
    /// [`RECOVERY_QOS_KEYS`] option again ("did not take effect") and keeps the QoS defaults.
    pub fn recovery_qos_gated(&self) -> bool {
        self.get("osd_op_queue") == Some("mclock_scheduler")
            && !self.bool("osd_mclock_override_recovery_settings", false)
    }

    /// One WARNING line per [`NO_EFFECT`] option whose effective value is not the default and differs from the value
    /// last seen (`seen`, updated): a value set in the local file, the mon config db or at runtime is reported once,
    /// again after it changed or went back to the default and was set again.
    pub fn no_effect_warnings(&self, seen: &mut BTreeMap<String, String>) -> Vec<String> {
        let mut out = Vec::new();
        for (k, why) in NO_EFFECT {
            let v = self.get(k).unwrap_or("");
            let default = self
                .layers
                .get(k)
                .and_then(|l| l.get(&(Level::Default as u8)))
                .map_or("", String::as_str);
            if seen.get(k).map(String::as_str) == Some(v) {
                continue;
            }
            if v != default {
                out.push(format!(
                    "WARNING config: {k} = {v} has no effect on croit-flashstore-osd: {why}"
                ));
            }
            seen.insert(k.to_owned(), v.to_owned());
        }
        out
    }

    /// Effective value of a [`RECOVERY_QOS_KEYS`] option: gated, only the local file / command line (what the daemon was
    /// started with, classic keeps it over the QoS default) counts; mon and runtime values are ignored.
    fn recovery_opt(&self, key: &str, default: u64) -> u64 {
        if !self.recovery_qos_gated() {
            return self.u64(key, default);
        }
        match self.get_with_level(key) {
            Some((lv, v)) if Level::is_local(lv) => parse_u64(v).unwrap_or(default),
            _ => default,
        }
    }

    pub fn recovery_limits(&self) -> RecoveryLimits {
        let active = self.recovery_opt("osd_recovery_max_active", 0);
        let active = if active > 0 {
            active
        } else {
            self.recovery_opt("osd_recovery_max_active_ssd", 10)
        };
        RecoveryLimits {
            max_backfills: self.recovery_opt("osd_max_backfills", 1) as usize,
            recovery_max_active: active as usize,
            min_priority: self.u64("osd_min_recovery_priority", 0) as u32,
        }
    }

    /// Pause before the next recovery/backfill invocation in ns: `(non-degraded, degraded)` (spec peering.md 13.1).
    /// A non-zero `osd_recovery_sleep` wins, else the all-flash `_ssd` variant; degraded needs a value > 0, else
    /// `_degraded_ssd`. A running mclock scheduler reports 0 (see [`Self::get`]).
    pub fn recovery_sleep_ns(&self) -> (u64, u64) {
        let base = self.f64("osd_recovery_sleep", 0.0);
        let normal = if base != 0.0 {
            base
        } else {
            self.f64("osd_recovery_sleep_ssd", 0.0)
        };
        let deg = self.f64("osd_recovery_sleep_degraded", 0.0);
        let degraded = if deg > 0.0 {
            deg
        } else {
            self.f64("osd_recovery_sleep_degraded_ssd", 0.0)
        };
        (
            (normal.max(0.0) * 1e9) as u64,
            (degraded.max(0.0) * 1e9) as u64,
        )
    }

    /// Replace the built-in default of `key` with `val`, without the Ceph schema check: the daemon's own default of a
    /// Ceph option (`osd_objectstore` = the store name this OSD reports, which the pinned schema's enum does not list).
    pub fn set_default_unchecked(&mut self, key: &str, val: &str) {
        self.layers
            .entry(norm(key))
            .or_default()
            .insert(Level::Default as u8, val.to_owned());
        self.version += 1;
    }

    /// Set `key` at `level` to the normalized `val` (spec osd-lifecycle.md 2.9). An invalid value of a Ceph option is
    /// rejected (`Err` = Ceph's `parse error setting '<key>' to '<val>' (<reason>)`) and the option keeps its value.
    pub fn set(&mut self, level: Level, key: &str, val: &str) -> Result<(), String> {
        self.set_reason(level, key, val)
            .map_err(|e| format!("parse error setting '{}' to '{val}' ({e})", norm(key)))
    }

    /// [`Self::set`] with the bare reason an invalid value was refused (the command handlers build their own text,
    /// spec osd-lifecycle.md 9.1).
    pub fn set_reason(&mut self, level: Level, key: &str, val: &str) -> Result<(), String> {
        let k = norm(key);
        let mut v = crate::optval::normalize(&k, val)?;
        if k == "flashstore_omap_delete_range_threshold" {
            // The store accepts the full u64 domain; reject before mutating any config layer.
            v = v
                .trim()
                .parse::<u64>()
                .map_err(|e| e.to_string())?
                .to_string();
        }
        if self
            .layers
            .entry(k.clone())
            .or_default()
            .insert(level as u8, v.clone())
            != Some(v)
        {
            self.version += 1;
        }
        Ok(())
    }

    /// Remove the value at `level` (e.g. `config unset`).
    pub fn unset(&mut self, level: Level, key: &str) {
        if let Some(l) = self.layers.get_mut(&norm(key))
            && l.remove(&(level as u8)).is_some()
        {
            self.version += 1;
        }
    }

    /// Replace the complete MON level with `m` (options absent now revert, spec 2.7). Returns the errors of the values
    /// it ignored (invalid, spec 2.9).
    pub fn apply_mon(&mut self, m: &BTreeMap<String, String>) -> Vec<String> {
        for l in self.layers.values_mut() {
            l.remove(&(Level::Mon as u8));
        }
        let errs: Vec<String> = m
            .iter()
            .filter_map(|(k, v)| self.set(Level::Mon, k, v).err())
            .collect();
        // spec 2.7: a mon value a higher-priority local source overrides is reported to the mgr as ignored
        self.ignored_mon = m
            .iter()
            .filter(|(k, _)| {
                self.get_with_level(k)
                    .is_some_and(|(lv, _)| lv > Level::Mon as u8)
            })
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        self.version += 1;
        errs
    }

    /// Mon values overridden by a local source (`config_bl` `ignored_mon_values`).
    pub fn ignored_mon_values(&self) -> &BTreeMap<String, String> {
        &self.ignored_mon
    }

    /// Changes whenever the stored option values changed; the mgr client uses it to decide whether a report carries
    /// `config_bl`.
    pub fn version(&self) -> u64 {
        self.version
    }

    /// Effective value and the level it comes from.
    pub fn get_with_level(&self, key: &str) -> Option<(u8, &str)> {
        self.layers
            .get(&norm(key))
            .and_then(|l| l.iter().next_back())
            .map(|(lv, v)| (*lv, v.as_str()))
    }

    /// Effective value.
    pub fn get(&self, key: &str) -> Option<&str> {
        // a running mclock scheduler zeroes the recovery/backfill sleeps in memory (spec peering.md 13.1)
        if self.mclock_running() && is_recovery_sleep(key) {
            return Some("0");
        }
        self.get_with_level(key).map(|x| x.1)
    }

    /// The mclock scheduler is the effective `osd_op_queue` (its QoS defaults own the recovery pacing).
    fn mclock_running(&self) -> bool {
        self.get_with_level("osd_op_queue").map(|x| x.1) == Some("mclock_scheduler")
    }

    /// Effective value as f64 (`default` if unset/unparsable).
    pub fn f64(&self, key: &str, default: f64) -> f64 {
        self.get(key)
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(default)
    }

    /// Effective value as u64.
    pub fn u64(&self, key: &str, default: u64) -> u64 {
        self.get(key).and_then(parse_u64).unwrap_or(default)
    }

    /// Effective boolean (`true/1/yes/on`).
    pub fn bool(&self, key: &str, default: bool) -> bool {
        match self.get(key).map(str::trim) {
            Some(v) => ["true", "1", "yes", "on"]
                .iter()
                .any(|t| v.eq_ignore_ascii_case(t)),
            None => default,
        }
    }

    /// All effective values.
    pub fn all(&self) -> BTreeMap<String, String> {
        let zero = self.mclock_running();
        self.layers
            .iter()
            .filter_map(|(k, l)| {
                l.iter().next_back().map(|(_, v)| {
                    let v = if zero && is_recovery_sleep(k) {
                        "0".to_owned()
                    } else {
                        v.clone()
                    };
                    (k.clone(), v)
                })
            })
            .collect()
    }

    /// Every stored option with its settings per level number (lowest level first).
    pub fn layers(&self) -> impl Iterator<Item = (&String, &BTreeMap<u8, String>)> {
        self.layers.iter()
    }

    /// `(name, default)` pairs.
    pub fn defaults(&self) -> Vec<(String, String)> {
        self.layers
            .iter()
            .filter_map(|(k, l)| l.get(&0).map(|v| (k.clone(), v.clone())))
            .collect()
    }
}

/// A ratio option that also takes the percent spelling: a value above 1.0 is divided by 100 (classic
/// `osd_failsafe_full_ratio`, spec osd-lifecycle.md 4.4).
pub fn ratio_or_percent(v: f64) -> f64 {
    if v > 1.0 { v / 100.0 } else { v }
}

/// A numeric option value (a float is truncated).
fn parse_u64(v: &str) -> Option<u64> {
    v.trim().parse::<f64>().ok().map(|f| f as u64)
}

/// The last setting of `key` in the daemon's local config (`--set k=v` pairs), the name normalized like [`ConfigDb`]'s.
pub fn local_get<'a>(local: &'a [(String, String)], key: &str) -> Option<&'a str> {
    let key = norm(key);
    local
        .iter()
        .rev()
        .find(|(k, _)| norm(k) == key)
        .map(|(_, v)| v.as_str())
}

/// The daemon's local config from its `--set k=v` arguments: each value normalized (spec osd-lifecycle.md 2.9); an
/// invalid one is dropped with a stderr warning (Ceph: `parse error setting ...`, the option keeps its default).
pub fn local_config<'a>(sets: impl IntoIterator<Item = &'a str>) -> Vec<(String, String)> {
    sets.into_iter()
        .filter_map(|s| s.split_once('='))
        .filter_map(|(k, v)| match crate::optval::normalize(&norm(k), v) {
            Ok(v) => Some((k.to_owned(), v)),
            Err(e) => {
                eprintln!(
                    "WARNING parse error setting '{}' to '{v}' ({e}); the option keeps its default",
                    norm(k)
                );
                None
            }
        })
        .collect()
}

/// `injectargs` tokens (spec osd-lifecycle.md 9.1) -> `(name, value)` pairs in order, and the tokens it could not
/// use (unknown option, missing value). `--name=value`, `--name value` (the next token, whatever it is); a bool option also takes a bare `--name`
/// (true; a following `true`/`false`/`1`/`0` is consumed as its value) and `--no-name` (false).
pub fn injectargs(toks: &[String]) -> (Vec<(String, String)>, Vec<String>) {
    let mut set = Vec::new();
    let mut bad = Vec::new();
    let mut it = toks.iter().peekable();
    while let Some(t) = it.next() {
        let Some(body) = t.strip_prefix("--") else {
            bad.push(t.clone());
            continue;
        };
        let (name, val) = match body.split_once('=') {
            Some((n, v)) => (norm(n), Some(v.to_owned())),
            None => (norm(body), None),
        };
        let is_bool =
            |n: &str| crate::optval::schema(n).map(|s| s.kind) == Some(crate::optval::Kind::Bool);
        if val.is_none()
            && let Some(n) = name.strip_prefix("no_")
            && is_bool(n)
        {
            set.push((n.to_owned(), "false".to_owned()));
            continue;
        }
        if classify(&name) == KeyClass::Unknown {
            bad.push(t.clone());
            continue;
        }
        let val = match val {
            Some(v) => v,
            None if is_bool(&name) => match it.peek().map(|n| n.as_str()) {
                Some(v @ ("true" | "false" | "1" | "0")) => {
                    let v = v.to_owned();
                    it.next();
                    v
                }
                _ => "true".to_owned(),
            },
            None => match it.next() {
                Some(v) => v.clone(),
                None => {
                    bad.push(t.clone());
                    continue;
                }
            },
        };
        set.push((name, val));
    }
    (set, bad)
}

/// Option names accept spaces/dashes as underscores.
pub(crate) fn norm(k: &str) -> String {
    k.trim().replace([' ', '-'], "_")
}

/// The normalized text of `val` for option `key` (spec osd-lifecycle.md 2.9), or the reason it is invalid.
pub fn normalized(key: &str, val: &str) -> Result<String, String> {
    crate::optval::normalize(&norm(key), val)
}

/// A recovery/backfill sleep option the mclock scheduler zeroes in memory.
fn is_recovery_sleep(k: &str) -> bool {
    RECOVERY_SLEEP_KEYS.contains(&norm(k).as_str())
}

/// Ceph options the daemon interprets itself: `croit-flashstore-osd run` forwards them as `--set k=v` (the local config).
pub fn forwarded(k: &str) -> bool {
    k.starts_with("debug_")
        || k.starts_with("log_")
        || k.starts_with("osd_op_")
        || k.starts_with("flashstore_") // every croit-flashstore-osd option: `config get/show` answer the effective startup value
        || matches!(
            k,
            "auth_cluster_required"
                | "auth_service_required"
                | "auth_client_required"
                | "auth_service_ticket_ttl"
        ) // method lists + rotating refresh cutoff: local at start (croit-flashstore-osd run bootstraps its mon session from them), then layered + runtime
        || (k.starts_with("ms_") && k.ends_with("_mode")) // msgr2 connection modes (ms_mon_cluster_mode needs the local file)
        || matches!(
            k,
            "ms_bind_port_min" | "ms_bind_port_max" | "ms_bind_retry_count" | "ms_bind_retry_delay"
        ) // listener port search (osd::portsel), read before the OSD boots
        || matches!(k, "osd_memory_target" | "osd_memory_base" | "osd_memory_cache_min") // envelope, sized before mount
        || matches!(
            k,
            "admin_socket"
                | "crash_dir"
                | "public_network"
                | "cluster_network"
                | "public_network_interface"
                | "cluster_network_interface"
                | "public_addr"
                | "cluster_addr"
                | "ms_bind_ipv4"
                | "ms_bind_ipv6"
                | "ms_bind_prefer_ipv4"
        ) // kernel tier address selection: families, networks, explicit addresses (adr 0659-ip-address-families)
        || matches!(
            k,
            "crush_location" | "crush_location_hook" | "crush_location_hook_timeout"
        ) // CRUSH location, fixed at start (crate::crushloc)
        || k == "pid_file" // written by the daemon at start
        || matches!(k, "key" | "keyfile" | "keyring" | "osd_data") // own cephx key sources (crate::keysrc), startup only
}

/// What the daemon does with a local-config key (`--set k=v`, adr 0021 am. 60).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyClass {
    /// Some consumer reads it: `flashstore_*` (daemon flag or store tunable), `mon_host`, `cluster`, the forwarded
    /// options, the store memory budget, the core's [`DEFAULTS`] table.
    Read,
    /// A valid option of the pinned Ceph version that croit-flashstore-osd does not use (accepted, reported).
    Ignored,
    /// Not a Ceph option and not `flashstore_*`.
    Unknown,
}

/// Classify `key` (any spelling of `_` / `-` / space).
pub fn classify(key: &str) -> KeyClass {
    let k = norm(key);
    let k = k.as_str();
    if k.starts_with("flashstore_")
        || forwarded(k)
        || matches!(
            k,
            "mon_host"
                | "cluster"
                | "osd_memory_target"
                | "osd_memory_base"
                | "osd_memory_cache_min"
        )
        || DEFAULTS.iter().any(|(d, _)| *d == k)
    {
        KeyClass::Read
    } else if crate::optval::schema(k).is_some() {
        KeyClass::Ignored
    } else {
        KeyClass::Unknown
    }
}

/// `name` is an option of the schema exactly as spelled: `config unset` does no whitespace (or dash) normalization
/// (spec osd-lifecycle.md 9.3).
pub fn known_name_exact(name: &str) -> bool {
    name == norm(name) && classify(name) != KeyClass::Unknown
}

#[cfg(test)]
mod tests {
    /// Every default of the core's table equals the pinned v21.2.0 default (as `config get` normalizes both), except
    /// the deliberate deviations doc/compat/ceph-21.2.0.md lists: a stale default (NT-config-05: `mon_max_pg_per_osd`
    /// 250 vs 500) fails here.
    #[test]
    fn defaults_match_the_pinned_schema_except_documented_deviations() {
        const COMPAT: &str = include_str!("../../../../doc/compat/ceph-21.2.0.md");
        const DELIBERATE: &[&str] = &[
            "ms_bind_msgr1",
            "bluestore_compression_min_blob_size_ssd",
            "osd_delete_sleep_ssd",
            "osd_skip_data_digest",
            "osd_journal",
            "log_to_stderr",
            "log_to_file",
        ];
        let mut deviating = Vec::new();
        for (k, v) in DEFAULTS {
            let Some(pinned) = crate::schema::effective_default(k) else {
                continue;
            };
            let ours = crate::optval::normalize(k, v).unwrap_or_else(|_| (*v).to_owned());
            if ours != pinned {
                deviating.push(*k);
            }
        }
        assert_eq!(deviating, DELIBERATE);
        for k in DELIBERATE {
            assert!(COMPAT.contains(&format!("`{k}`")), "{k} undocumented");
        }
    }

    #[test]
    fn omap_range_threshold_runtime_values_are_unsigned_canonical_and_layered() {
        use super::{ConfigDb, Level};
        let key = "flashstore_omap_delete_range_threshold";
        let mut c = ConfigDb::default();
        assert_eq!(c.get(key), Some("0"));
        c.set(Level::File, key, "1048576").unwrap();
        c.set(Level::Override, key, " 00032 ").unwrap();
        assert_eq!(c.get(key), Some("32"));
        let before = c.version();
        for bad in ["", "-1", "1.5", "NaN", "32K", "18446744073709551616"] {
            assert!(c.set(Level::Override, key, bad).is_err(), "{bad:?}");
            assert_eq!(c.get(key), Some("32"));
            assert_eq!(
                c.version(),
                before,
                "invalid input must not publish a change"
            );
        }
        c.set(Level::Override, key, &u64::MAX.to_string()).unwrap();
        assert_eq!(c.get(key), Some("18446744073709551615"));
        c.unset(Level::Override, key);
        assert_eq!(c.get(key), Some("1048576"));
        c.unset(Level::File, key);
        assert_eq!(c.get(key), Some("0"));
    }

    use super::*;

    /// Recovery limits (spec replication.md 7.5): the defaults are 1 backfill and the `_ssd` 10 ops (all-flash); with
    /// mclock and no override only the local file counts, with the override (or another scheduler) every level does;
    /// `osd_recovery_max_active` beats the per-media option when set.
    /// The local config keeps level order (file < env < command line) and each entry's level.
    #[test]
    fn local_layers_keep_the_source_level() {
        let (all, src) = local_layers(
            ["osd_max_backfills=2", "osd_max_backfills=bogus"],
            ["osd_data=/env"],
            ["osd_max_backfills=4"],
        );
        assert_eq!(src, LocalSources { file: 1, env: 1 });
        let levels: Vec<Level> = (0..all.len()).map(|i| src.level(i)).collect();
        assert_eq!(levels, [Level::File, Level::Env, Level::Cmdline]);
        assert_eq!(local_get(&all, "osd_max_backfills"), Some("4"));
        assert_eq!(LocalSources::default().level(0), Level::Cmdline);
    }

    #[test]
    fn recovery_limits_follow_mclock_override() {
        let mut c = ConfigDb::default();
        let d = c.recovery_limits();
        assert_eq!(
            (d.max_backfills, d.recovery_max_active, d.min_priority),
            (1, 10, 0)
        );
        assert!(c.recovery_qos_gated());
        let mut m = BTreeMap::new();
        for (k, v) in [
            ("osd_max_backfills", "4"),
            ("osd_recovery_max_active", "7"),
            ("osd_min_recovery_priority", "30"),
        ] {
            m.insert(k.to_owned(), v.to_owned());
        }
        c.apply_mon(&m);
        let l = c.recovery_limits();
        assert_eq!(
            (l.max_backfills, l.recovery_max_active, l.min_priority),
            (1, 10, 30),
            "mon values do not take effect under mclock, the priority floor is not a QoS option"
        );
        c.set(Level::File, "osd_max_backfills", "2").unwrap();
        assert_eq!(
            c.recovery_limits().max_backfills,
            2,
            "the local file is honoured"
        );
        c.set(Level::Cmdline, "osd_max_backfills", "3").unwrap();
        assert_eq!(
            c.recovery_limits().max_backfills,
            3,
            "the command line is honoured"
        );
        c.unset(Level::Cmdline, "osd_max_backfills");
        c.set(Level::Mon, "osd_mclock_override_recovery_settings", "true")
            .unwrap();
        let l = c.recovery_limits();
        assert_eq!(
            (l.max_backfills, l.recovery_max_active),
            (2, 7),
            "the file still beats mon"
        );
        c.apply_mon(&BTreeMap::new());
        c.set(Level::Override, "osd_op_queue", "wpq").unwrap();
        c.set(Level::Override, "osd_recovery_max_active", "0")
            .unwrap();
        c.set(Level::Override, "osd_recovery_max_active_ssd", "5")
            .unwrap();
        assert!(!c.recovery_qos_gated());
        assert_eq!(c.recovery_limits().recovery_max_active, 5);
    }

    /// PG-L4: a running mclock scheduler zeroes the eight recovery/backfill sleep options in memory (`config get/show`
    /// report 0); with another scheduler the configured values take effect, `_sleep` wins non-zero and degraded needs
    /// a value > 0 (spec peering.md 13.1).
    #[test]
    fn recovery_sleep_is_zeroed_under_mclock() {
        let mut c = ConfigDb::default();
        for k in RECOVERY_SLEEP_KEYS {
            c.set(Level::Override, k, "1.5").unwrap();
        }
        assert_eq!(c.recovery_sleep_ns(), (0, 0));
        for k in RECOVERY_SLEEP_KEYS {
            assert_eq!(c.get(k), Some("0"), "{k}");
            assert_eq!(c.all()[k], "0", "{k}");
        }
        c.set(Level::Override, "osd_op_queue", "wpq").unwrap();
        assert_eq!(c.recovery_sleep_ns(), (1_500_000_000, 1_500_000_000));
        c.set(Level::Override, "osd_recovery_sleep", "0.25")
            .unwrap();
        c.set(Level::Override, "osd_recovery_sleep_degraded", "0")
            .unwrap();
        c.set(Level::Override, "osd_recovery_sleep_degraded_ssd", "0")
            .unwrap();
        assert_eq!(
            c.recovery_sleep_ns(),
            (250_000_000, 0),
            "non-zero base wins; a degraded value of 0 falls back to the all-flash variant"
        );
    }

    #[test]
    fn scrub_defaults_match_the_scheduler() {
        let c = ConfigDb::default();
        let s = peering::ScrubCfg::default();
        assert_eq!(c.f64("osd_scrub_load_threshold", -1.0), s.load_threshold);
        assert_eq!(
            c.f64("osd_deep_scrub_interval_cv", -1.0),
            s.deep_interval_cv
        );
        assert_eq!(
            c.f64("osd_deep_scrub_interval_cv", -1.0),
            0.2,
            "classic default (spec scrub.md 12.1.4)"
        );
        assert_eq!(c.f64("osd_scrub_backoff_ratio", -1.0), s.backoff_ratio);
        assert_eq!(
            c.f64("osd_scrub_interval_randomize_ratio", -1.0),
            s.randomize_ratio
        );
        assert_eq!(c.f64("osd_scrub_min_interval", 0.0), s.min_interval);
        assert_eq!(c.f64("osd_deep_scrub_interval", 0.0), s.deep_interval);
        assert_eq!(c.u64("osd_scrub_priority", 0), s.priority as u64);
        assert_eq!(c.bool("osd_scrub_invalid_stats", false), s.invalid_stats);
        assert_eq!(c.bool("osd_scrub_during_recovery", true), s.during_recovery);
        assert_eq!(
            c.u64("osd_scrub_max_preemptions", 0),
            u64::from(s.max_preemptions)
        );
        assert_eq!(c.u64("osd_deep_scrub_stride", 0), 4 << 20);
        // osd_deep_scrub_randomize_ratio is accepted but has no effect in v21.2.0
        assert_eq!(c.f64("osd_deep_scrub_randomize_ratio", -1.0), 0.15);
    }

    /// NT-deadcode-01/03/04: a no-effect option at a non-default value warns once per value from any source (file,
    /// mon, runtime); the default and an unchanged value stay silent; every listed option is in the core table, so
    /// `config get/show/diff` keep reporting it.
    #[test]
    fn no_effect_options_warn_once_per_non_default_value() {
        for (k, why) in NO_EFFECT {
            assert!(DEFAULTS.iter().any(|(d, _)| *d == k), "{k} not shown");
            assert!(!why.is_empty(), "{k}");
        }
        let mut c = ConfigDb::default();
        let mut seen = BTreeMap::new();
        assert!(c.no_effect_warnings(&mut seen).is_empty(), "defaults");
        c.set(Level::File, "osd_op_num_shards", "8").unwrap();
        let mut m = BTreeMap::new();
        m.insert(
            "osd_mclock_profile".to_owned(),
            "high_recovery_ops".to_owned(),
        );
        c.apply_mon(&m);
        let w = c.no_effect_warnings(&mut seen);
        assert_eq!(w.len(), 2, "{w:?}");
        assert!(w.iter().all(|l| l.starts_with("WARNING config: ")), "{w:?}");
        assert!(
            w.iter()
                .any(|l| l.contains("osd_mclock_profile = high_recovery_ops has no effect"))
        );
        assert!(c.no_effect_warnings(&mut seen).is_empty(), "same values");
        c.set(Level::Override, "osd_skip_data_digest", "false")
            .unwrap();
        let w = c.no_effect_warnings(&mut seen);
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(w[0].contains("osd_skip_data_digest = false"), "{w:?}");
        // back to the default: silent; set again: warns again
        c.unset(Level::Override, "osd_skip_data_digest");
        assert!(c.no_effect_warnings(&mut seen).is_empty());
        c.set(Level::Override, "osd_skip_data_digest", "false")
            .unwrap();
        assert_eq!(c.no_effect_warnings(&mut seen).len(), 1);
    }

    #[test]
    fn layering() {
        let mut c = ConfigDb::default();
        assert_eq!(c.get("osd_heartbeat_grace"), Some("20"));
        let mut m = BTreeMap::new();
        m.insert("osd_heartbeat_grace".to_owned(), "30".to_owned());
        m.insert("some_unknown".to_owned(), "x".to_owned());
        c.apply_mon(&m);
        assert_eq!(c.u64("osd_heartbeat_grace", 0), 30);
        c.set(Level::Override, "osd-heartbeat-grace", "40").unwrap();
        assert_eq!(c.u64("osd_heartbeat_grace", 0), 40);
        c.unset(Level::Override, "osd_heartbeat_grace");
        c.apply_mon(&BTreeMap::new());
        assert_eq!(c.u64("osd_heartbeat_grace", 0), 20);
        assert!(c.get("some_unknown").is_none());
    }

    /// The version moves on every change that can move an effective value (the mgr client sends `config_bl` only
    /// then), and a mon value a local source overrides is reported as an ignored mon value (spec 2.7, 6.3).
    #[test]
    fn version_and_ignored_mon_values_follow_changes() {
        let mut c = ConfigDb::default();
        let v = c.version();
        c.set(Level::Mon, "osd_heartbeat_grace", "30").unwrap();
        assert!(c.version() > v);
        c.set(Level::Mon, "osd_heartbeat_grace", "30").unwrap();
        assert_eq!(c.version(), v + 1, "an unchanged value does not move");
        c.set(Level::Override, "osd_heartbeat_grace", "40").unwrap();
        let mut m = BTreeMap::new();
        m.insert("osd_heartbeat_grace".to_owned(), "30".to_owned());
        m.insert("osd_max_backfills".to_owned(), "2".to_owned());
        c.apply_mon(&m);
        assert_eq!(
            c.ignored_mon_values().get("osd_heartbeat_grace"),
            Some(&"30".to_owned()),
            "overridden by the local override"
        );
        assert!(!c.ignored_mon_values().contains_key("osd_max_backfills"));
        c.unset(Level::Override, "osd_heartbeat_grace");
        c.apply_mon(&m);
        assert!(c.ignored_mon_values().is_empty());
        c.apply_mon(&BTreeMap::new());
        assert!(c.ignored_mon_values().is_empty());
        assert_eq!(c.u64("osd_heartbeat_grace", 0), 20);
    }

    /// Values are parsed per option type and stored normalized; an invalid one is rejected and the old value stays
    /// (spec osd-lifecycle.md 2.9).
    #[test]
    fn typed_values_normalized_or_rejected() {
        let mut c = ConfigDb::default();
        c.set(Level::File, "osd_memory_target", "8G").unwrap();
        assert_eq!(c.get("osd_memory_target"), Some("8589934592"));
        assert_eq!(c.u64("osd_memory_target", 0), 8 << 30);
        c.set(Level::File, "osd_max_backfills", "2").unwrap();
        let e = c
            .set(Level::Override, "osd_max_backfills", "8_M")
            .unwrap_err();
        assert!(
            e.starts_with("parse error setting 'osd_max_backfills' to '8_M'"),
            "{e}"
        );
        assert_eq!(c.u64("osd_max_backfills", 0), 2, "old value kept");
        c.set(Level::Override, "osd_failsafe_full_ratio", "0.9")
            .unwrap();
        assert_eq!(c.get("osd_failsafe_full_ratio"), Some("0.900000"));
        assert!(
            c.set(Level::Override, "osd_scrub_auto_repair", "yes")
                .is_err()
        );
        c.set(Level::Override, "osd_scrub_auto_repair", "1")
            .unwrap();
        assert!(c.bool("osd_scrub_auto_repair", false));
        // no schema: as given
        c.set(Level::Override, "flashstore_x", "8_M").unwrap();
        assert_eq!(c.get("flashstore_x"), Some("8_M"));
        // mon values: invalid ones are reported and ignored
        let m: BTreeMap<String, String> = [
            ("osd_heartbeat_grace".to_owned(), "x".to_owned()),
            ("osd_max_backfills".to_owned(), "4".to_owned()),
        ]
        .into();
        assert_eq!(c.apply_mon(&m).len(), 1);
        assert_eq!(c.u64("osd_heartbeat_grace", 0), 20);
    }

    #[test]
    fn defaults_are_valid_values() {
        for (k, v) in DEFAULTS {
            crate::optval::normalize(k, v).unwrap_or_else(|e| panic!("{k}={v}: {e}"));
        }
    }

    #[test]
    fn local_config_drops_invalid_values() {
        let l = local_config([
            "osd_memory_target=4G",
            "osd_max_backfills=x",
            "flashstore_a=b",
            "junk",
        ]);
        assert_eq!(
            l,
            vec![
                ("osd_memory_target".to_owned(), "4294967296".to_owned()),
                ("flashstore_a".to_owned(), "b".to_owned())
            ]
        );
    }

    #[test]
    fn injectargs_tokens() {
        let t = |s: &str| {
            s.split_whitespace()
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        };
        let (set, bad) = injectargs(&t(
            "--osd_heartbeat_grace=25 --osd-heartbeat-interval 3 --osd_scrub_auto_repair \
             --no-osd_scrub_during_recovery --osd_scrub_auto_repair false --no_such_opt=1 plain --debug_osd",
        ));
        let p = |a: &str, b: &str| (a.to_owned(), b.to_owned());
        assert_eq!(
            set,
            vec![
                p("osd_heartbeat_grace", "25"),
                p("osd_heartbeat_interval", "3"),
                p("osd_scrub_auto_repair", "true"),
                p("osd_scrub_during_recovery", "false"),
                p("osd_scrub_auto_repair", "false"),
            ]
        );
        assert_eq!(bad, t("--no_such_opt=1 plain --debug_osd"));
    }

    #[test]
    fn classify_keys() {
        for k in [
            "flashstore_port_name",
            "ms_bind_port_min",
            "ms_bind_retry_delay",
            "flashstore-x",
            "osd_heartbeat_grace",
            "debug_osd",
            "mon_host",
            "osd_memory_target",
            "osd_class_load_list",
            "osd_class_default_list",
        ] {
            assert_eq!(classify(k), KeyClass::Read, "{k}");
        }
        for k in ["rgw_thread_pool_size", "mds-cache-memory-limit"] {
            assert_eq!(classify(k), KeyClass::Ignored, "{k}");
        }
        assert_eq!(classify("no_such_option"), KeyClass::Unknown);
        // start-time options `croit-flashstore-osd run` must hand from the conf file to the daemon
        for k in [
            "crush_location",
            "crush_location_hook",
            "crush_location_hook_timeout",
            "ms_bind_ipv4",
            "ms_bind_ipv6",
            "ms_bind_prefer_ipv4",
            "public_network_interface",
            "cluster_network_interface",
        ] {
            assert!(forwarded(k), "{k}");
        }
    }
}
