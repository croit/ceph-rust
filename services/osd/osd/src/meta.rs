// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Persistent OSD identity + superblock + stored maps (spec osd-lifecycle.md 1.1-1.3).
//!
//! [`MetaStore`] is the seam to the future NVMe store. [`FileMetaStore`] is the dev-only
//! implementation on a plain directory (write temp + fsync + rename; not performance relevant).
use denc::types::Uuid;
#[cfg(any(feature = "lab", test))]
use denc::{Decode, Encode};
use messages::{OsdSuperblock, StoreStatfs};
use std::collections::BTreeMap;
#[cfg(any(feature = "lab", test))]
use std::path::{Path, PathBuf};

/// Store error.
#[derive(Debug)]
pub struct MetaError(pub String);
impl std::fmt::Display for MetaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "meta store: {}", self.0)
    }
}
impl std::error::Error for MetaError {}
impl From<std::io::Error> for MetaError {
    fn from(e: std::io::Error) -> Self {
        MetaError(e.to_string())
    }
}
/// Result alias.
pub type Result<T> = std::result::Result<T, MetaError>;

/// What a stored map blob is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MapKind {
    /// Full OSDMap.
    Full,
    /// OSDMap::Incremental (kept verbatim to be shared with peers).
    Inc,
}

/// Immutable identity of this OSD (written once by mkfs, spec 1.1).
#[derive(Clone, PartialEq, Eq)]
pub struct Identity {
    /// Osd id.
    pub whoami: i32,
    /// Cluster fsid.
    pub cluster_fsid: Uuid,
    /// This OSD's uuid.
    pub osd_fsid: Uuid,
    /// cephx secret, base64 (keyring `key =` form).
    pub key: String,
    /// Device class reported at start (`osd_class_update_on_start`); empty = none.
    pub crush_device_class: String,
    /// Informational meta echoed in boot metadata.
    pub created_at: String,
    /// Informational meta echoed in boot metadata.
    pub ceph_version_when_created: String,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("whoami", &self.whoami)
            .field("cluster_fsid", &self.cluster_fsid)
            .field("osd_fsid", &self.osd_fsid)
            .field("key", &format_args!("<redacted {} bytes>", self.key.len()))
            .field("crush_device_class", &self.crush_device_class)
            .field("created_at", &self.created_at)
            .field("ceph_version_when_created", &self.ceph_version_when_created)
            .finish()
    }
}

impl Identity {
    /// `key=value` text form (identity file / meta object).
    pub fn to_text(&self) -> String {
        format!(
            "whoami={}\ncluster_fsid={}\nosd_fsid={}\nkey={}\ncrush_device_class={}\ncreated_at={}\nceph_version_when_created={}\n",
            self.whoami,
            self.cluster_fsid,
            self.osd_fsid,
            self.key,
            self.crush_device_class,
            self.created_at,
            self.ceph_version_when_created
        )
    }

    /// Parse the text form.
    pub fn from_text(text: &str) -> Result<Identity> {
        let kv = parse_kv(text);
        let get = |k: &str| {
            kv.get(k)
                .cloned()
                .ok_or_else(|| MetaError(format!("identity: missing {k}")))
        };
        let uuid =
            |k: &str| Uuid::parse(&get(k)?).map_err(|e| MetaError(format!("identity {k}: {e}")));
        Ok(Identity {
            whoami: get("whoami")?
                .parse()
                .map_err(|_| MetaError("identity: whoami".into()))?,
            cluster_fsid: uuid("cluster_fsid")?,
            osd_fsid: uuid("osd_fsid")?,
            key: get("key")?,
            crush_device_class: kv.get("crush_device_class").cloned().unwrap_or_default(),
            created_at: kv.get("created_at").cloned().unwrap_or_default(),
            ceph_version_when_created: kv
                .get("ceph_version_when_created")
                .cloned()
                .unwrap_or_default(),
        })
    }
}

/// Capacity charged as used but not really held (`StoreStatfs::internally_reserved`: a hot or meta-bound shard, the
/// fullness clamps): `total - available - held`. DATA / META stay the real usage `held`; the full ratios, RAW USE and %USE
/// keep the charge. One definition for a single store and for the OSD aggregate.
pub(crate) fn internally_reserved(total: u64, available: u64, held: u64) -> u64 {
    total.saturating_sub(available).saturating_sub(held)
}

/// Durable state the OSD core needs. Writes must be durable when the call returns.
pub trait MetaStore {
    /// Identity, `None` if not mkfs'd.
    fn load_identity(&self) -> Result<Option<Identity>>;
    /// Write the identity (mkfs).
    fn store_identity(&mut self, id: &Identity) -> Result<()>;
    /// Current superblock.
    fn load_superblock(&self) -> Result<Option<OsdSuperblock>>;
    /// Replace the superblock durably.
    fn store_superblock(&mut self, sb: &OsdSuperblock) -> Result<()>;
    /// Persist map blobs, then the superblock (maps first: the superblock never refers to
    /// missing maps).
    fn commit_maps(&mut self, blobs: &[(u32, MapKind, Vec<u8>)], sb: &OsdSuperblock) -> Result<()>;
    /// A stored map blob.
    fn get_map(&self, epoch: u32, kind: MapKind) -> Result<Option<Vec<u8>>>;
    /// Sorted unique epochs with stored full or incremental maps, including blobs persisted before a
    /// crash that preceded their superblock update. Never enumerate unstored epoch gaps.
    fn map_epochs(&self, through: u32) -> Result<Vec<u32>>;
    /// Capacity / usage of the store.
    fn statfs(&self) -> StoreStatfs;
    /// `(size mkfs recorded, size of the device now)` when the device shrank since mkfs (os_alerts
    /// BLUESTORE_DISK_SIZE_MISMATCH). Default: never.
    fn size_mismatch(&self) -> Option<(u64, u64)> {
        None
    }
    /// Informational meta value.
    fn get_meta(&self, key: &str) -> Option<String>;
    /// Set an informational meta value.
    fn set_meta(&mut self, key: &str, val: &str) -> Result<()>;
    /// Drop stored maps older than the newest full map at or before `below` (that one is kept so every later
    /// epoch can still be rebuilt). Returns the oldest epoch still held. Default: keep everything.
    fn trim_maps(&mut self, _below: u32) -> Result<u32> {
        Ok(0)
    }
    /// `bench`: durably write one scratch object `bench.<slot>` (the caller cycles `BENCH_SLOTS` slots; blocks until durable).
    fn bench_put(&mut self, _slot: u64, _data: &[u8]) -> Result<()> {
        Err(MetaError("bench is not supported by this store".into()))
    }
    /// `bench`: remove the scratch objects `bench.0 .. bench.<slots>`.
    fn bench_cleanup(&mut self, _slots: u64) -> Result<()> {
        Ok(())
    }
}

/// Scratch objects a bench cycles through.
pub const BENCH_SLOTS: u64 = 16;

#[cfg(any(feature = "lab", test))]
/// Dev-only directory-backed store. Layout: `identity`, `superblock`, `meta/<k>`, `maps/<e>.full`,
/// `maps/<e>.inc`. The "device size" is the configured `size` (file `size`, default 8 GiB).
#[derive(Debug)]
pub struct FileMetaStore {
    dir: PathBuf,
    size: u64,
    #[cfg(test)]
    pub(crate) map_reads: std::cell::Cell<usize>,
}

#[cfg(any(feature = "lab", test))]
impl FileMetaStore {
    /// Default emulated device size.
    pub const DEFAULT_SIZE: u64 = 8 << 30;

    /// Open (creating directories) the store at `dir` with emulated capacity `size`.
    pub fn open(dir: impl Into<PathBuf>, size: u64) -> Result<Self> {
        let dir = dir.into();
        std::fs::create_dir_all(dir.join("maps"))?;
        std::fs::create_dir_all(dir.join("meta"))?;
        let s = match std::fs::read_to_string(dir.join("size")) {
            Ok(t) => t.trim().parse().unwrap_or(size),
            Err(_) => {
                osddir::write_atomic(&dir.join("size"), size.to_string().as_bytes())?;
                size
            }
        };
        Ok(Self {
            dir,
            size: s,
            #[cfg(test)]
            map_reads: std::cell::Cell::new(0),
        })
    }

    /// Data directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn map_path(&self, e: u32, k: MapKind) -> PathBuf {
        self.dir.join("maps").join(format!(
            "{e}.{}",
            if k == MapKind::Full { "full" } else { "inc" }
        ))
    }

    fn used(&self) -> u64 {
        let mut n = 0;
        for d in ["maps", "meta"] {
            if let Ok(rd) = std::fs::read_dir(self.dir.join(d)) {
                for e in rd.flatten() {
                    n += e.metadata().map_or(0, |m| m.len());
                }
            }
        }
        n
    }
}

pub(crate) fn parse_kv(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
        .collect()
}

#[cfg(any(feature = "lab", test))]
impl MetaStore for FileMetaStore {
    fn load_identity(&self) -> Result<Option<Identity>> {
        let text = match std::fs::read_to_string(self.dir.join("identity")) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        Ok(Some(Identity::from_text(&text)?))
    }

    fn store_identity(&mut self, id: &Identity) -> Result<()> {
        // both hold the secret: created 0600, never readable by others
        let t = id.to_text();
        osddir::write_atomic_mode(&self.dir.join("identity"), t.as_bytes(), 0o600)?;
        let kr = osddir::keyring_text(i64::from(id.whoami), &id.key);
        osddir::write_atomic_mode(&self.dir.join("keyring"), kr.as_bytes(), 0o600)?;
        Ok(())
    }

    fn load_superblock(&self) -> Result<Option<OsdSuperblock>> {
        match std::fs::read(self.dir.join("superblock")) {
            Ok(b) => Ok(Some(
                OsdSuperblock::decode(&mut denc::Decoder::new(&b))
                    .map_err(|e| MetaError(format!("superblock: {e}")))?,
            )),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn store_superblock(&mut self, sb: &OsdSuperblock) -> Result<()> {
        let b = sb
            .encode_to_vec()
            .map_err(|e| MetaError(format!("superblock encode: {e}")))?;
        Ok(osddir::write_atomic(&self.dir.join("superblock"), &b)?)
    }

    fn commit_maps(&mut self, blobs: &[(u32, MapKind, Vec<u8>)], sb: &OsdSuperblock) -> Result<()> {
        for (e, k, b) in blobs {
            osddir::write_atomic(&self.map_path(*e, *k), b)?;
        }
        self.store_superblock(sb)
    }

    fn get_map(&self, epoch: u32, kind: MapKind) -> Result<Option<Vec<u8>>> {
        #[cfg(test)]
        self.map_reads.set(self.map_reads.get() + 1);
        match std::fs::read(self.map_path(epoch, kind)) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn map_epochs(&self, through: u32) -> Result<Vec<u32>> {
        let mut epochs = std::collections::BTreeSet::new();
        for entry in std::fs::read_dir(self.dir.join("maps"))? {
            let entry = entry?;
            let name = entry.file_name();
            let Some((epoch, kind)) = name.to_str().and_then(|n| n.split_once('.')) else {
                continue;
            };
            if matches!(kind, "full" | "inc")
                && let Ok(epoch) = epoch.parse::<u32>()
                && epoch <= through
            {
                epochs.insert(epoch);
            }
        }
        Ok(epochs.into_iter().collect())
    }

    fn statfs(&self) -> StoreStatfs {
        let used = self.used();
        let total = self.size;
        StoreStatfs {
            total,
            available: total.saturating_sub(used),
            internally_reserved: 0,
            allocated: used as i64,
            data_stored: 0,
            internal_metadata: used as i64,
            ..Default::default()
        }
    }

    fn get_meta(&self, key: &str) -> Option<String> {
        std::fs::read_to_string(self.dir.join("meta").join(key))
            .ok()
            .map(|s| s.trim().to_owned())
    }

    fn set_meta(&mut self, key: &str, val: &str) -> Result<()> {
        Ok(osddir::write_atomic(
            &self.dir.join("meta").join(key),
            val.as_bytes(),
        )?)
    }

    fn bench_put(&mut self, slot: u64, data: &[u8]) -> Result<()> {
        Ok(osddir::write_atomic(
            &self.dir.join(format!("bench.{slot}")),
            data,
        )?)
    }

    fn bench_cleanup(&mut self, slots: u64) -> Result<()> {
        for k in 0..slots {
            match std::fs::remove_file(self.dir.join(format!("bench.{k}"))) {
                Ok(()) => {}
                // usually nothing to clean: only a crashed bench leaves slots behind
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(n: &str) -> PathBuf {
        let p =
            std::env::temp_dir().join(format!("croit-flashstore-meta-{n}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    #[test]
    fn identity_and_keyring_have_the_secret_mode_from_creation() {
        use std::os::unix::fs::PermissionsExt;
        let d = tmp("secrets");
        let id = Identity {
            whoami: 4,
            cluster_fsid: Uuid([1; 16]),
            osd_fsid: Uuid([2; 16]),
            key: "SECRET".into(),
            crush_device_class: "nvme".into(),
            created_at: "now".into(),
            ceph_version_when_created: "v".into(),
        };
        let mut s = FileMetaStore::open(&d, 1 << 20).unwrap();
        // a failing second write must not leave the first secret readable (the old code chmod'ed only after both)
        std::fs::create_dir_all(d.join("keyring.tmp")).unwrap();
        assert!(s.store_identity(&id).is_err());
        let mode = |n: &str| {
            std::fs::metadata(d.join(n))
                .map(|m| m.permissions().mode() & 0o777)
                .unwrap_or(0)
        };
        assert_eq!(mode("identity") & 0o077, 0, "identity is not 0600");
        let _ = std::fs::remove_dir_all(d.join("keyring.tmp"));
        store_identity_for(&d, &id);
        assert_eq!(mode("identity"), 0o600);
        assert_eq!(mode("keyring"), 0o600);
        let _ = std::fs::remove_dir_all(&d);
    }

    fn store_identity_for(d: &std::path::Path, id: &Identity) {
        FileMetaStore::open(d, 1 << 20)
            .unwrap()
            .store_identity(id)
            .unwrap();
    }

    #[test]
    fn roundtrip() {
        let d = tmp("rt");
        let mut s = FileMetaStore::open(&d, 1 << 30).unwrap();
        assert!(s.load_identity().unwrap().is_none() && s.load_superblock().unwrap().is_none());
        let id = Identity {
            whoami: 7,
            cluster_fsid: Uuid([1; 16]),
            osd_fsid: Uuid([2; 16]),
            key: "AQ==".into(),
            crush_device_class: "nvme".into(),
            created_at: "now".into(),
            ceph_version_when_created: "v".into(),
        };
        s.store_identity(&id).unwrap();
        let mut sb = OsdSuperblock {
            cluster_fsid: id.cluster_fsid,
            whoami: 7,
            osd_fsid: id.osd_fsid,
            compat_features: messages::CompatSet::osd_initial(),
            ..Default::default()
        };
        sb.current_epoch = 3;
        sb.mapc.insert(1, 3);
        s.commit_maps(&[(3, MapKind::Full, vec![9; 10])], &sb)
            .unwrap();
        let s2 = FileMetaStore::open(&d, 5).unwrap();
        assert_eq!(s2.load_identity().unwrap().unwrap(), id);
        assert_eq!(s2.load_superblock().unwrap().unwrap(), sb);
        assert_eq!(s2.get_map(3, MapKind::Full).unwrap().unwrap(), vec![9; 10]);
        assert!(s2.get_map(3, MapKind::Inc).unwrap().is_none());
        let st = s2.statfs();
        assert_eq!(st.total, 1 << 30); // size file wins
        assert!(st.available < st.total);
        let _ = std::fs::remove_dir_all(&d);
    }
}

#[cfg(test)]
mod debug_tests {
    use super::*;

    #[test]
    fn identity_debug_hides_the_cephx_key() {
        let id = Identity::from_text(
            "whoami=3\ncluster_fsid=00000000-0000-0000-0000-000000000001\nosd_fsid=00000000-0000-0000-0000-000000000002\nkey=QVFEU0VDUkVUS0VZ\ncrush_device_class=\ncreated_at=x\nceph_version_when_created=y\n",
        )
        .unwrap();
        let text = format!("{id:?}");
        assert!(!text.contains("QVFEU0VDUkVUS0VZ"), "{text}");
        assert!(text.contains("<redacted 16 bytes>"), "{text}");
    }
}
