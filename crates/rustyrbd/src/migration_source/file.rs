// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! The `file` stream: a local path opened read-only.
//!
//! Spec: `doc/spec/rustyrbd/migration-source-raw-qcow-file.md`, "Stream
//! `file`". The path string is used verbatim: no normalisation, no `file://`
//! handling, no tilde expansion, no `O_NOFOLLOW`; a relative path resolves
//! against the process working directory. The size is the `SEEK_END`
//! offset (a directory fd may fail it `-EINVAL`, kernel dependent); reads
//! are exact-length at each extent's position, so a directory fails its
//! first read with `-EISDIR`.

use std::fs::File;
use std::io::{Seek, SeekFrom};
use std::os::unix::fs::FileExt;

use crate::journal_backend::{EINVAL, EIO, ERANGE};
use crate::migration_source::SourceStream;

/// A read-only stream on one literal path.
#[derive(Debug)]
pub struct FileStream {
    path: String,
    file: Option<File>,
}

impl FileStream {
    /// A stream on the literal path string.
    pub fn new(path: &str) -> Self {
        Self {
            path: path.to_owned(),
            file: None,
        }
    }

    /// The extents in list order, each one exact-length read at its
    /// position; the output receives them concatenated.
    fn read_into(&self, extents: &[(u64, u64)], out: &mut [u8]) -> Result<(), i32> {
        let file = self.file.as_ref().ok_or(EINVAL)?;
        let mut at = 0usize;
        for &(offset, length) in extents {
            let end = at.checked_add(length as usize).ok_or(EINVAL)?;
            if end > out.len() {
                return Err(EINVAL);
            }
            read_at_exact(file, offset, &mut out[at..end])?;
            at = end;
        }
        if at != out.len() {
            return Err(EINVAL);
        }
        Ok(())
    }
}

impl SourceStream for FileStream {
    fn open(&mut self) -> Result<(), i32> {
        let file = File::open(&self.path).map_err(|e| errno(&e, EINVAL))?;
        self.file = Some(file);
        Ok(())
    }

    fn size(&mut self) -> Result<u64, i32> {
        let file = self.file.as_mut().ok_or(EINVAL)?;
        file.seek(SeekFrom::End(0)).map_err(|e| errno(&e, EINVAL))
    }

    fn read(&self, extents: &[(u64, u64)], out: &mut [u8]) -> Result<(), i32> {
        let result = self.read_into(extents, out);
        if result.is_err() {
            out.fill(0);
        }
        result
    }

    fn close(&mut self) -> i32 {
        self.file = None;
        0
    }
}

/// One exact-length read at `offset`; a short read or EOF is `-ERANGE`
/// (never `-ENOENT`), any other error `-errno` (`-EIO`, `-EISDIR`, ...).
fn read_at_exact(file: &File, offset: u64, out: &mut [u8]) -> Result<(), i32> {
    let mut done = 0usize;
    while done < out.len() {
        match file.read_at(&mut out[done..], offset.saturating_add(done as u64)) {
            Ok(0) => return Err(ERANGE),
            Ok(n) => done += n,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Err(ERANGE),
            Err(e) => return Err(errno(&e, EIO)),
        }
    }
    Ok(())
}

/// `-errno` of a raw OS error, `fallback` when the error carries none.
fn errno(e: &std::io::Error, fallback: i32) -> i32 {
    e.raw_os_error().map_or(fallback, |n| -n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migration_source::testutil;

    #[test]
    fn open_missing_path_is_enoent() {
        let dir = testutil::temp_dir("file-missing");
        let mut stream = FileStream::new(&dir.as_ref().join("absent").to_string_lossy());
        assert_eq!(stream.open(), Err(-2));
    }

    #[test]
    fn size_and_exact_reads() {
        let dir = testutil::temp_dir("file-reads");
        let path = testutil::write(&dir, "data.bin", &[1u8; 100]);
        let mut stream = FileStream::new(&path);
        stream.open().expect("open");
        assert_eq!(stream.size(), Ok(100));
        // One extent.
        let mut out = [0u8; 4];
        assert_eq!(stream.read(&[(10, 4)], &mut out), Ok(()));
        assert_eq!(out, [1, 1, 1, 1]);
        // Extents concatenate in list order, unsorted offsets included.
        let mut out = [0u8; 3];
        assert_eq!(stream.read(&[(99, 1), (0, 2)], &mut out), Ok(()));
        assert_eq!(out, [1, 1, 1]);
        // A zero-length extent is a no-op.
        assert_eq!(stream.read(&[(5, 0)], &mut []), Ok(()));
        // EOF exactly at the end is -ERANGE.
        assert_eq!(stream.read(&[(100, 1)], &mut [0]), Err(-34));
        // A read past EOF is -ERANGE and clears the output.
        let mut out = [7u8; 4];
        assert_eq!(stream.read(&[(98, 4)], &mut out), Err(-34));
        assert_eq!(out, [0, 0, 0, 0]);
        // A mismatched output length is -EINVAL.
        assert_eq!(stream.read(&[(0, 4)], &mut [0; 3]), Err(-22));
        assert_eq!(stream.close(), 0);
        assert_eq!(stream.close(), 0);
        // After close the descriptor is released.
        assert_eq!(stream.size(), Err(-22));
        assert_eq!(stream.read(&[(0, 1)], &mut [0]), Err(-22));
    }

    #[test]
    fn directory_read_fails_with_eisdir() {
        // Spec vector 9 (execute part): a directory opens read-only and its
        // first data read fails with -EISDIR. The prepare-time size of a
        // directory fd is kernel dependent (`SEEK_END` may fail `-EINVAL`),
        // so it is not asserted here (spec OPEN).
        let dir = testutil::temp_dir("file-directory");
        let sub = dir.as_ref().join("subdir");
        std::fs::create_dir_all(&sub).expect("subdir");
        let mut stream = FileStream::new(&sub.to_string_lossy());
        stream.open().expect("directory open");
        assert_eq!(stream.read(&[(0, 1)], &mut [0]), Err(-21));
        stream.close();
    }
}
