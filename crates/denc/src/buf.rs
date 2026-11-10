// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Minimal output-buffer abstraction so encoders can target a Vec, a fixed slice or a sizing sink (no bytes kept).

use crate::error::{Error, Result};

/// Append-only byte sink with random-access patching of already written bytes.
pub trait BufMut {
    /// Bytes written so far (also the next write position).
    fn len(&self) -> usize;
    /// Append bytes.
    fn put_slice(&mut self, s: &[u8]) -> Result<()>;
    /// Overwrite `s.len()` already written bytes at `pos`. Caller guarantees range.
    fn patch(&mut self, pos: usize, s: &[u8]);
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl BufMut for Vec<u8> {
    #[inline]
    fn len(&self) -> usize {
        Vec::len(self)
    }
    #[inline]
    fn put_slice(&mut self, s: &[u8]) -> Result<()> {
        self.extend_from_slice(s);
        Ok(())
    }
    #[inline]
    fn patch(&mut self, pos: usize, s: &[u8]) {
        if let Some(d) = self.get_mut(pos..pos + s.len()) {
            d.copy_from_slice(s);
        }
    }
}

impl<B: BufMut + ?Sized> BufMut for &mut B {
    #[inline]
    fn len(&self) -> usize {
        (**self).len()
    }
    #[inline]
    fn put_slice(&mut self, s: &[u8]) -> Result<()> {
        (**self).put_slice(s)
    }
    #[inline]
    fn patch(&mut self, pos: usize, s: &[u8]) {
        (**self).patch(pos, s)
    }
}

/// Fixed-capacity buffer over a caller-provided slice.
#[derive(Debug)]
pub struct SliceBuf<'b> {
    buf: &'b mut [u8],
    pos: usize,
}

impl<'b> SliceBuf<'b> {
    pub fn new(buf: &'b mut [u8]) -> Self {
        SliceBuf { buf, pos: 0 }
    }
    pub fn written(&self) -> &[u8] {
        &self.buf[..self.pos]
    }
}

impl BufMut for SliceBuf<'_> {
    #[inline]
    fn len(&self) -> usize {
        self.pos
    }
    #[inline]
    fn put_slice(&mut self, s: &[u8]) -> Result<()> {
        let end = self.pos.checked_add(s.len()).ok_or(Error::NoSpace)?;
        let d = self.buf.get_mut(self.pos..end).ok_or(Error::NoSpace)?;
        d.copy_from_slice(s);
        self.pos = end;
        Ok(())
    }
    #[inline]
    fn patch(&mut self, pos: usize, s: &[u8]) {
        if let Some(d) = self.buf.get_mut(pos..pos + s.len()) {
            d.copy_from_slice(s);
        }
    }
}
