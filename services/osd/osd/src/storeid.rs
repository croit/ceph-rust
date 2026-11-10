// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! The store name this OSD presents toward mons, mgrs and CLIs (`flashstore_report_objectstore`).
//!
//! Classic mons enable some features only when every OSD reports `osd_objectstore = bluestore` (for example
//! `allow_ec_overwrites`), so the default presents the BlueStore names everywhere. `flashstore` is for mons patched
//! to know FlashStore: it renames every BlueStore-identity name the OSD exposes (the `osd_objectstore` metadata value
//! and default, the `<store>_bdev_*` device metadata keys, the `<store>` perf logger, the `<store> ...` tell/asok
//! commands and the `<STORE>_*` health codes). The option is read once at startup.
//!
//! Ceph config option names such as `bluestore_compression_mode`, `bluestore_log_op_age` or
//! `bluestore_slow_ops_warn_threshold` are never renamed in either mode: they are cluster config keys that operators
//! set.
use crate::config::ConfigDb;
use serde_json::Value;

/// Name of the startup-only option.
pub(crate) const OPTION: &str = "flashstore_report_objectstore";

/// The BlueStore spelling: the default and the internal spelling of the store commands.
const BLUESTORE: &str = "bluestore";
/// The FlashStore spelling.
const FLASHSTORE: &str = "flashstore";

/// Which store name the OSD reports (`flashstore_report_objectstore`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum StoreIdentity {
    /// `bluestore` (default): the classic names, byte-for-byte what classic OSDs report.
    #[default]
    BlueStore,
    /// `flashstore`: the FlashStore names (patched mons only).
    FlashStore,
}

impl StoreIdentity {
    /// Parse an option value; the error names the allowed values.
    pub(crate) fn parse(v: &str) -> Result<Self, String> {
        match v {
            BLUESTORE => Ok(Self::BlueStore),
            FLASHSTORE => Ok(Self::FlashStore),
            _ => Err(format!(
                "{OPTION} '{v}' is invalid (allowed: {BLUESTORE}, {FLASHSTORE})"
            )),
        }
    }

    /// The value of [`OPTION`] in `conf` (unset = the default); a bad value is an error.
    pub(crate) fn from_conf(conf: &ConfigDb) -> Result<Self, String> {
        conf.get(OPTION).map_or(Ok(Self::default()), Self::parse)
    }

    /// Lower-case store name: metadata value, perf logger and tell command word.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::BlueStore => BLUESTORE,
            Self::FlashStore => FLASHSTORE,
        }
    }

    /// Health check code `<STORE>_<suffix>` (`suffix` without the store word, e.g. `SLOW_OP_ALERT`).
    pub(crate) fn health_code(self, suffix: &str) -> String {
        format!("{}_{suffix}", self.as_str().to_ascii_uppercase())
    }

    /// Device metadata key `<store>_bdev_<suffix>`.
    pub(crate) fn bdev_key(self, suffix: &str) -> String {
        format!("{}_bdev_{suffix}", self.as_str())
    }

    /// An advertised command word list in this mode: the leading `bluestore` word becomes `flashstore`.
    pub(crate) fn external_words(self, words: &[&str]) -> Vec<String> {
        words
            .iter()
            .enumerate()
            .map(|(i, w)| match (i, self) {
                (0, Self::FlashStore) if *w == BLUESTORE => FLASHSTORE.to_owned(),
                _ => (*w).to_owned(),
            })
            .collect()
    }

    /// A help text in this mode (the store-command alias note and the "used by bluestore" notes name the advertised
    /// store).
    pub(crate) fn help(self, help: &str) -> std::borrow::Cow<'_, str> {
        match self {
            Self::BlueStore => help.into(),
            Self::FlashStore => help
                .replace("alias: bluestore ", "alias: flashstore ")
                .replace("used by bluestore", "used by flashstore")
                .into(),
        }
    }

    /// An accepted command in its internal spelling (the `bluestore ...` words the handlers match). In `flashstore`
    /// mode the store commands are renamed, not aliased: `flashstore ...` is accepted and `bluestore ...` is refused
    /// (`Err(prefix)`).
    pub(crate) fn internal_command(self, v: Value) -> Result<Value, String> {
        if self == Self::BlueStore {
            return Ok(v);
        }
        let prefix = v.get("prefix").and_then(Value::as_str).unwrap_or("");
        let (first, rest) = prefix.split_once(' ').unwrap_or((prefix, ""));
        match first {
            BLUESTORE => Err(prefix.to_owned()),
            FLASHSTORE => {
                let internal = if rest.is_empty() {
                    BLUESTORE.to_owned()
                } else {
                    format!("{BLUESTORE} {rest}")
                };
                let mut v = v;
                v["prefix"] = Value::String(internal);
                Ok(v)
            }
            _ => Ok(v),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_default_and_invalid() {
        assert_eq!(StoreIdentity::default(), StoreIdentity::BlueStore);
        assert_eq!(
            StoreIdentity::parse("bluestore"),
            Ok(StoreIdentity::BlueStore)
        );
        assert_eq!(
            StoreIdentity::parse("flashstore"),
            Ok(StoreIdentity::FlashStore)
        );
        let e = StoreIdentity::parse("kstore").unwrap_err();
        assert!(
            e.contains("bluestore") && e.contains("flashstore") && e.contains("kstore"),
            "{e}"
        );
        let conf = ConfigDb::default();
        assert_eq!(
            StoreIdentity::from_conf(&conf),
            Ok(StoreIdentity::BlueStore)
        );
    }

    #[test]
    fn names_follow_the_mode() {
        let b = StoreIdentity::BlueStore;
        let f = StoreIdentity::FlashStore;
        assert_eq!((b.as_str(), f.as_str()), ("bluestore", "flashstore"));
        assert_eq!(b.health_code("SLOW_OP_ALERT"), "BLUESTORE_SLOW_OP_ALERT");
        assert_eq!(f.health_code("SLOW_OP_ALERT"), "FLASHSTORE_SLOW_OP_ALERT");
        assert_eq!(b.bdev_key("size"), "bluestore_bdev_size");
        assert_eq!(f.bdev_key("size"), "flashstore_bdev_size");
        let w = ["bluestore", "dedup", "list"];
        assert_eq!(b.external_words(&w), ["bluestore", "dedup", "list"]);
        assert_eq!(f.external_words(&w), ["flashstore", "dedup", "list"]);
        assert_eq!(f.external_words(&["store", "free"]), ["store", "free"]);
        assert_eq!(
            b.help("(alias: bluestore allocator ...)"),
            "(alias: bluestore allocator ...)"
        );
        assert_eq!(
            f.help("(alias: bluestore allocator ...)"),
            "(alias: flashstore allocator ...)"
        );
        assert_eq!(
            f.help("kvdb which used by bluestore"),
            "kvdb which used by flashstore"
        );
        assert_eq!(
            b.help("kvdb which used by bluestore"),
            "kvdb which used by bluestore"
        );
    }

    #[test]
    fn commands_renamed_not_aliased() {
        let cmd = |p: &str| json!({"prefix": p, "pool": 1});
        let b = StoreIdentity::BlueStore;
        let f = StoreIdentity::FlashStore;
        assert_eq!(
            b.internal_command(cmd("bluestore dedup stats")).unwrap(),
            cmd("bluestore dedup stats")
        );
        assert_eq!(
            f.internal_command(cmd("flashstore dedup stats")).unwrap(),
            cmd("bluestore dedup stats")
        );
        assert_eq!(
            f.internal_command(cmd("flashstore allocator dump block"))
                .unwrap(),
            cmd("bluestore allocator dump block")
        );
        assert_eq!(
            f.internal_command(cmd("bluestore dedup stats")),
            Err("bluestore dedup stats".into())
        );
        assert_eq!(f.internal_command(cmd("status")).unwrap(), cmd("status"));
        assert_eq!(
            f.internal_command(cmd("bluestoreish")).unwrap(),
            cmd("bluestoreish")
        );
    }
}
