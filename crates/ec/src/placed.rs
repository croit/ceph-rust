// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Classic legacy index placement of a non-identity chunk mapping (spec ec-parity.md 3.2-3.4).
//!
//! A classic legacy primary of an isa / jerasure / clay pool places client chunk `r` at index `M'[r]` (= its shard)
//! and then runs the plugin's encode on indices: `0..k` are the inputs, `k..n` are overwritten with parity. With a
//! non-identity `M'` the stored shards form a codeword of the plugin code in SHARD index space; a client chunk placed
//! at an index `>= k` is replaced by parity and an input index no client chunk lands on holds whatever the buffer
//! held (classic: uninitialised memory, oracle `pools/isamap_DD` shard 0; here: zeros). Reads return shard `M'[r]`
//! as client chunk `r`, so the read data differs from the written data exactly like classic (readback MISMATCH).
//!
//! [`Placed`] speaks RAW (client chunk) indices like every [`Code`]: raw `r` = inner index `M'[r]`. Decode, read
//! planning and repair translate to the inner code; [`Placed::encode_all`] also rewrites data chunks.

use crate::code::Code;
use crate::gf::DecodeError;

#[derive(Clone, Debug)]
pub struct Placed {
    inner: Code,
    /// raw chunk -> inner index (= shard), the completed mapping M'.
    at: Vec<usize>,
    /// inner index -> raw chunk.
    of: Vec<usize>,
}

thread_local! {
    /// Zero chunk followed by the m parity chunks of the last call (grown, never shrunk): the literal sequence needs
    /// them on every stripe and they are chunk-sized.
    static SCRATCH: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Run `f` with a zeroed chunk of `len` bytes and `m` writable chunk-sized parity areas.
fn with_scratch<T>(len: usize, m: usize, f: impl FnOnce(&[u8], &mut [&mut [u8]]) -> T) -> T {
    SCRATCH.with_borrow_mut(|buf| {
        let need = len * (m + 1);
        if buf.len() < need {
            buf.resize(need, 0);
        }
        let (zero, par) = buf[..need].split_at_mut(len);
        zero.fill(0);
        let mut p: Vec<&mut [u8]> = Vec::with_capacity(m);
        if len == 0 {
            p.extend((0..m).map(|_| &mut [][..]));
        } else {
            p.extend(par.chunks_mut(len).take(m));
        }
        f(zero, &mut p)
    })
}

impl Placed {
    /// `None` unless `mapping` is a permutation of `0..n` of `inner`.
    pub fn new(inner: Code, mapping: &[u32]) -> Option<Placed> {
        let n = inner.n();
        if mapping.len() != n {
            return None;
        }
        let mut of = vec![usize::MAX; n];
        for (r, &s) in mapping.iter().enumerate() {
            let slot = of.get_mut(s as usize)?;
            if *slot != usize::MAX {
                return None;
            }
            *slot = r;
        }
        Some(Placed {
            inner,
            at: mapping.iter().map(|s| *s as usize).collect(),
            of,
        })
    }

    pub fn inner(&self) -> &Code {
        &self.inner
    }

    pub fn inner_mut(&mut self) -> &mut Code {
        &mut self.inner
    }

    /// Some client data chunk lands on a parity index: [`Self::encode_all`] must be used (data chunks change).
    pub fn rewrites_data(&self) -> bool {
        let k = self.inner.k();
        self.at[..k].iter().any(|&s| s >= k)
    }

    /// Inner input slots (index s < k: the client chunk placed there, else zeros), run the inner encode, then hand
    /// the inputs and the parity chunks to `f`.
    fn run<T>(&self, data: &[&[u8]], f: impl FnOnce(&[&[u8]], &mut [&mut [u8]]) -> T) -> T {
        let k = self.inner.k();
        let len = data.first().map_or(0, |d| d.len());
        with_scratch(len, self.inner.m(), |zero, par| {
            let ins: Vec<&[u8]> = (0..k)
                .map(|s| match self.of[s] {
                    r if r < k => data[r],
                    _ => zero,
                })
                .collect();
            self.inner.encode(&ins, par);
            f(&ins, par)
        })
    }

    /// Every raw chunk (`out.len() == n`) of the client chunks `data`: raw r = inner index M'[r] after the literal
    /// classic sequence (place, encode indices 0..k -> k..n).
    pub fn encode_all(&self, data: &[&[u8]], out: &mut [&mut [u8]]) {
        let k = self.inner.k();
        self.run(data, |ins, par| {
            for (r, o) in out.iter_mut().enumerate() {
                let s = self.at[r];
                o.copy_from_slice(if s < k { ins[s] } else { par[s - k] });
            }
        });
    }

    /// Raw parity chunks k..n only (data chunks unchanged: valid when ![`Self::rewrites_data`]).
    pub fn encode(&self, data: &[&[u8]], parity: &mut [&mut [u8]]) {
        let k = self.inner.k();
        self.run(data, |ins, par| {
            for (j, o) in parity.iter_mut().enumerate() {
                let s = self.at[k + j];
                o.copy_from_slice(if s < k { ins[s] } else { par[s - k] });
            }
        });
    }

    fn to_inner(&self, raws: &[usize]) -> Option<Vec<usize>> {
        raws.iter().map(|r| self.at.get(*r).copied()).collect()
    }

    pub fn decode_into(
        &self,
        have: &[(usize, &[u8])],
        want: &[usize],
        out: &mut [&mut [u8]],
    ) -> Result<(), DecodeError> {
        let h: Vec<(usize, &[u8])> = have
            .iter()
            .map(|(r, b)| self.at.get(*r).map(|s| (*s, *b)))
            .collect::<Option<_>>()
            .ok_or(DecodeError::Unrecoverable)?;
        let w = self.to_inner(want).ok_or(DecodeError::Unrecoverable)?;
        self.inner.decode_into(&h, &w, out)
    }

    pub fn read_set(&self, want: &[usize], avail: &[usize]) -> Option<Vec<usize>> {
        let set = self
            .inner
            .read_set(&self.to_inner(want)?, &self.to_inner(avail)?)?;
        Some(set.iter().map(|s| self.of[*s]).collect())
    }

    #[expect(clippy::type_complexity)]
    pub fn repair_plan(
        &self,
        lost: usize,
        avail: &[usize],
    ) -> Option<(Vec<usize>, Vec<(usize, usize)>)> {
        let (h, ranges) = self
            .inner
            .repair_plan(*self.at.get(lost)?, &self.to_inner(avail)?)?;
        Some((h.iter().map(|s| self.of[*s]).collect(), ranges))
    }

    pub fn repair(
        &self,
        lost: usize,
        helpers: &[(usize, &[u8])],
        out: &mut [u8],
    ) -> Result<(), DecodeError> {
        let h: Vec<(usize, &[u8])> = helpers
            .iter()
            .map(|(r, b)| self.at.get(*r).map(|s| (*s, *b)))
            .collect::<Option<_>>()
            .ok_or(DecodeError::Unrecoverable)?;
        let lost = *self.at.get(lost).ok_or(DecodeError::Unrecoverable)?;
        self.inner.repair(lost, &h, out)
    }
}
