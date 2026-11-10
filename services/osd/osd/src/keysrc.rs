// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! The OSD's own cephx secret from its local config (spec cephx.md s2.2 "Key source precedence"): `key` (base64),
//! else `keyfile` (a file holding the base64 key), else the first existing file of the `keyring` search list
//! (default `$osd_data/keyring`). These options are startup-only and never come from the mon.
//!
//! Strictness: a source that is configured or found but unusable (bad base64, unreadable keyfile, a keyring that
//! does not parse or has no key for this OSD) is a startup error, never a silent fall-back to another source or to
//! auth none. Only "nothing found" returns `None`; the caller then uses the key recorded on the device at mkfs
//! (the analogue of the store label key that primes a classic OSD dir) and, failing that, drops cephx from the
//! method lists ([`crate::auth::AuthLists::without_cephx`], fatal when cephx is required).

use cephx::CryptoKey;
use zeroize::Zeroizing;

/// Default keyring search list of an OSD.
pub const DEFAULT_KEYRING: &str = "$osd_data/keyring";
/// Default data dir of an OSD (`osd_data`).
pub const DEFAULT_OSD_DATA: &str = "/var/lib/ceph/osd/$cluster-$id";

/// A key and where it came from (for the startup log; never the key itself).
#[derive(Debug)]
pub struct Found {
    pub key: CryptoKey,
    pub source: String,
}

/// The OSD data dir from the local config (`osd_data`, default [`DEFAULT_OSD_DATA`]), metavariables expanded.
pub fn osd_data(local: &[(String, String)], whoami: i64) -> String {
    expand_osd_data(
        crate::config::local_get(local, "osd_data").unwrap_or(DEFAULT_OSD_DATA),
        crate::config::local_get(local, "cluster").unwrap_or("ceph"),
        whoami,
    )
}

/// Expand the metavariables of an `osd_data` value (`$cluster`, `$type`, `$id`, `$name`, also as `${..}`): the same
/// single-pass engine and set the tools use ([`osddir::expand`]), so both resolve one path.
pub fn expand_osd_data(raw: &str, cluster: &str, whoami: i64) -> String {
    osddir::expand(raw, cluster, whoami)
}

fn decode(text: &str, what: &str) -> Result<CryptoKey, String> {
    CryptoKey::from_base64(text.trim())
        .map_err(|e| format!("{what}: not a base64 cephx key ({e:?})"))
}

/// Resolve the key of `osd.<whoami>` from the local config. `host` = short hostname (`$host`).
pub fn resolve(
    local: &[(String, String)],
    whoami: i64,
    host: &str,
) -> Result<Option<Found>, String> {
    let get = |k: &str| crate::config::local_get(local, k).filter(|v| !v.trim().is_empty());
    if let Some(k) = get("key") {
        return Ok(Some(Found {
            key: decode(k, "config option key")?,
            source: "config option key".into(),
        }));
    }
    if let Some(f) = get("keyfile") {
        // a keyfile holds the base64 key: wipe the text on drop
        let text = Zeroizing::new(
            std::fs::read_to_string(f).map_err(|e| format!("keyfile {f}: cannot read ({e})"))?,
        );
        return Ok(Some(Found {
            key: decode(&text, &format!("keyfile {f}"))?,
            source: format!("keyfile {f}"),
        }));
    }
    let entity = format!("osd.{whoami}");
    let cluster = crate::config::local_get(local, "cluster").unwrap_or("ceph");
    let id = whoami.to_string();
    let data = osd_data(local, whoami);
    let vars = [
        ("cluster", cluster),
        ("type", "osd"),
        ("id", id.as_str()),
        ("name", entity.as_str()),
        ("host", host),
        ("osd_data", data.as_str()),
    ];
    let list = get("keyring").unwrap_or(DEFAULT_KEYRING);
    for p in list
        .split([',', ';'])
        .map(str::trim)
        .filter(|p| !p.is_empty())
    {
        let p = osddir::expand_vars(p, &vars);
        let text = match std::fs::read_to_string(&p) {
            Ok(t) => Zeroizing::new(t),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(format!("keyring {p}: cannot read ({e})")),
        };
        let kr =
            cephx::keyring::Keyring::parse(&text).map_err(|e| format!("keyring {p}: {e:?}"))?;
        let key = kr
            .get(&entity)
            .and_then(|e| e.key.clone())
            .ok_or_else(|| format!("keyring {p}: no key for {entity}"))?;
        return Ok(Some(Found {
            key,
            source: format!("keyring {p}"),
        }));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cephx::KeyType;
    use denc::types::UTime;

    fn kv(p: &[(&str, &str)]) -> Vec<(String, String)> {
        p.iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    fn key() -> CryptoKey {
        CryptoKey::generate(KeyType::Aes256Krb5, UTime::new(1_700_000_000, 0)).unwrap()
    }

    fn tmp(tag: &str) -> std::path::PathBuf {
        let t = std::env::temp_dir().join(format!("keysrc-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&t);
        std::fs::create_dir_all(&t).unwrap();
        t
    }

    #[test]
    fn metavariables_expand() {
        let v = [("cluster", "c1"), ("id", "3"), ("name", "osd.3")];
        let x = |s: &str| osddir::expand_vars(s, &v);
        assert_eq!(x("/x/$cluster-$id/k"), "/x/c1-3/k");
        assert_eq!(x("/x/${cluster}.$name.keyring"), "/x/c1.osd.3.keyring");
        assert_eq!(x("$unknown/$"), "$unknown/$");
        assert_eq!(x("${cluster"), "${cluster");
        assert_eq!(
            osd_data(&kv(&[("cluster", "c1")]), 3),
            "/var/lib/ceph/osd/c1-3"
        );
        // the tool side (`osddir::expand`) resolves the same value to the same path
        assert_eq!(
            osddir::expand("/x/${cluster}/$type.$id", "c1", 3),
            expand_osd_data("/x/${cluster}/$type.$id", "c1", 3)
        );
    }

    /// `key` beats `keyfile` beats `keyring`; the search list takes the first existing file.
    #[test]
    fn precedence_and_search_list() {
        let t = tmp("prec");
        let (k1, k2, k3) = (key(), key(), key());
        let kf = t.join("osd.keyfile");
        std::fs::write(&kf, format!("{}\n", k2.to_base64().unwrap())).unwrap();
        let kr = t.join("c1.osd.3.keyring");
        std::fs::write(
            &kr,
            format!("[osd.3]\n\tkey = {}\n", k3.to_base64().unwrap()),
        )
        .unwrap();
        let list = format!(
            "{0}/missing, {0}/$cluster.$name.keyring;{0}/other",
            t.display()
        );
        let all = kv(&[
            ("cluster", "c1"),
            ("key", &k1.to_base64().unwrap()),
            ("keyfile", kf.to_str().unwrap()),
            ("keyring", &list),
        ]);
        assert_eq!(resolve(&all, 3, "h").unwrap().unwrap().key, k1);
        let no_key = &all[..1]
            .iter()
            .chain(&all[2..])
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(resolve(no_key, 3, "h").unwrap().unwrap().key, k2);
        let ring_only = kv(&[("cluster", "c1"), ("keyring", &list)]);
        let f = resolve(&ring_only, 3, "h").unwrap().unwrap();
        assert_eq!(f.key, k3);
        assert!(f.source.ends_with("c1.osd.3.keyring"), "{}", f.source);
        let _ = std::fs::remove_dir_all(&t);
    }

    /// Default: `$osd_data/keyring`; nothing found = `None` (not an error).
    #[test]
    fn default_is_the_data_dir_keyring() {
        let t = tmp("dflt");
        let local = kv(&[("osd_data", t.to_str().unwrap())]);
        assert!(resolve(&local, 5, "h").unwrap().is_none());
        let k = key();
        std::fs::write(
            t.join("keyring"),
            format!("[osd.5]\nkey = {}\n", k.to_base64().unwrap()),
        )
        .unwrap();
        assert_eq!(resolve(&local, 5, "h").unwrap().unwrap().key, k);
        let _ = std::fs::remove_dir_all(&t);
    }

    /// A configured or found source that is unusable fails loudly instead of falling through.
    #[test]
    fn unusable_sources_are_errors() {
        let t = tmp("bad");
        assert!(resolve(&kv(&[("key", "!!!")]), 1, "h").is_err());
        let missing = t.join("nope");
        let e = resolve(&kv(&[("keyfile", missing.to_str().unwrap())]), 1, "h").unwrap_err();
        assert!(e.contains("keyfile"), "{e}");
        std::fs::write(
            t.join("keyring"),
            format!("[osd.2]\nkey = {}\n", key().to_base64().unwrap()),
        )
        .unwrap();
        let local = kv(&[("osd_data", t.to_str().unwrap())]);
        let e = resolve(&local, 1, "h").unwrap_err();
        assert!(e.contains("no key for osd.1"), "{e}");
        std::fs::write(t.join("keyring"), "garbage\n").unwrap();
        assert!(resolve(&local, 1, "h").is_err());
        let _ = std::fs::remove_dir_all(&t);
    }
}
