// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Output files of `dump` and `support-bundle` (the tool runs as root, the output directory is operator-chosen and
//! often reused): a fixed file name never writes through a symlink and never replaces anything but a regular file.
use std::fs::{File, OpenOptions};
use std::io::{Error, ErrorKind};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// Create `path` for writing. A new path is created exclusively (`O_EXCL`: a symlink there, even a dangling one, is
/// refused). An existing regular file of a previous run is truncated; a symlink, directory, FIFO, device or anything
/// else is refused before a byte is written. The type check runs on the opened descriptor (opened `O_NOFOLLOW`,
/// non-blocking), so a path swapped after the lookup cannot slip through.
pub fn create_output(path: &Path) -> std::io::Result<File> {
    match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(f) => return Ok(f),
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    let refused = || {
        Error::new(
            ErrorKind::AlreadyExists,
            format!("{}: exists and is not a regular file", path.display()),
        )
    };
    if !std::fs::symlink_metadata(path)?.file_type().is_file() {
        return Err(refused());
    }
    let f = OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    if !f.metadata()?.file_type().is_file() {
        return Err(refused());
    }
    f.set_len(0)?;
    Ok(f)
}

/// Write `data` to a new output file (see [`create_output`]).
pub fn write_output(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    create_output(path)?.write_all(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(n: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("fsout-{n}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn new_and_previous_regular_file_are_written() {
        let d = dir("reg");
        let p = d.join("a.txt");
        write_output(&p, b"first long content").unwrap();
        write_output(&p, b"2nd").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"2nd");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn symlinks_are_never_followed() {
        use std::os::unix::fs::symlink;
        let d = dir("link");
        let victim = d.join("victim.conf");
        std::fs::write(&victim, b"precious").unwrap();
        let p = d.join("log.txt");
        symlink(&victim, &p).unwrap();
        assert!(write_output(&p, b"x").is_err());
        assert_eq!(std::fs::read(&victim).unwrap(), b"precious");
        // a dangling link is refused as well (nothing is created at its target)
        let q = d.join("dangling.txt");
        symlink(d.join("not-there"), &q).unwrap();
        assert!(write_output(&q, b"x").is_err());
        assert!(!d.join("not-there").exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn non_regular_targets_are_refused() {
        let d = dir("dir");
        let sub = d.join("sub");
        std::fs::create_dir(&sub).unwrap();
        assert!(write_output(&sub, b"x").is_err());
        let _ = std::fs::remove_dir_all(&d);
    }
}
