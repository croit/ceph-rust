// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Private failed-incremental evidence, compiled only with `lab`.
//!
//! Set `MDS_OSDMAP_DUMP_DIR` to an absolute private results directory outside
//! every Git checkout or Cargo source tree (for example, below `LAB_RESULTS`). Each
//! failure writes `<pid>-<failure>-<epoch>.inc` (unmodified received bytes) and
//! `.base.full` (the held base encoded as a full map). Both files are mode 0600.
//! Capture errors are reported; they never replace normal full-map recovery.
use osdmap::OsdMap;
use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

pub(super) fn capture(base: &OsdMap, epoch: u32, raw_inc: &[u8], failure: u64) {
    let Some(directory) = std::env::var_os("MDS_OSDMAP_DUMP_DIR") else {
        return;
    };
    if let Err(error) = write_dump(Path::new(&directory), base, epoch, raw_inc, failure) {
        diag::diag!("ERROR MDS_OSDMAP_DUMP_DIR capture epoch {epoch}: {error}");
    }
}

fn check_directory(directory: &Path) -> io::Result<()> {
    if !directory.is_absolute() {
        return Err(io::Error::other("capture directory must be absolute"));
    }
    // Resolve existing ancestors too: a not-yet-created directory or a symlink
    // inside a checkout must not become a destination for private map bytes.
    let existing = directory
        .ancestors()
        .find(|path| path.exists())
        .ok_or_else(|| io::Error::other("capture directory has no existing ancestor"))?
        .canonicalize()?;
    if existing
        .ancestors()
        .any(|path| path.join(".git").exists() || path.join("Cargo.toml").is_file())
    {
        return Err(io::Error::other(
            "capture directory is inside a source checkout",
        ));
    }
    if std::env::var_os("HOME")
        .and_then(|home| fs::canonicalize(home).ok())
        .is_some_and(|home| directory.canonicalize().ok().as_ref() == Some(&home))
    {
        return Err(io::Error::other(
            "capture directory must not be the home directory",
        ));
    }
    Ok(())
}

fn write_dump(
    directory: &Path,
    base: &OsdMap,
    epoch: u32,
    raw_inc: &[u8],
    failure: u64,
) -> io::Result<()> {
    check_directory(directory)?;
    fs::create_dir_all(directory)?;
    check_directory(directory)?;
    let full = base.encode_full().map_err(io::Error::other)?;
    let prefix = format!("{}-{failure}-{epoch}", std::process::id());
    for (suffix, bytes) in [("base.full", full.as_slice()), ("inc", raw_inc)] {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(directory.join(format!("{prefix}.{suffix}")))?
            .write_all(bytes)?;
    }
    diag::diag!(
        "mds osdmap capture epoch={epoch} base_epoch={} prefix={prefix}",
        base.epoch
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use denc::types::Uuid;
    use std::{
        os::unix::fs::PermissionsExt,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn private_capture_keeps_raw_inc_and_reproducible_base() {
        let directory = std::env::temp_dir().join(format!(
            "mds-osdmap-capture-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut base = OsdMap::default();
        base.fsid = Uuid([7; 16]);
        base.epoch = 11;
        let raw = osdmap::Incremental {
            fsid: base.fsid,
            epoch: 12,
            full_crc: 123,
            ..Default::default()
        }
        .encode_inc()
        .unwrap();
        write_dump(&directory, &base, 12, &raw, 1).unwrap();
        let prefix = format!("{}-1-12", std::process::id());
        let inc = directory.join(format!("{prefix}.inc"));
        let full = directory.join(format!("{prefix}.base.full"));
        assert_eq!(fs::read(&inc).unwrap(), raw);
        assert_eq!(
            OsdMap::decode_from(&fs::read(&full).unwrap()).unwrap(),
            base
        );
        for path in [&inc, &full] {
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert!(write_dump(&directory, &base, 12, &raw, 1).is_err());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn capture_rejects_checkout_and_relative_destinations() {
        assert!(check_directory(Path::new(env!("CARGO_MANIFEST_DIR"))).is_err());
        assert!(check_directory(Path::new("relative-results")).is_err());
    }

    #[test]
    fn capture_rejects_archived_source_without_git_metadata() {
        let directory = std::env::temp_dir().join(format!(
            "mds-osdmap-source-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        fs::write(directory.join("Cargo.toml"), "[workspace]\n").unwrap();
        assert!(check_directory(&directory.join("capture")).is_err());
        assert!(!directory.join("capture").exists());
        fs::remove_dir_all(directory).unwrap();
    }
}
