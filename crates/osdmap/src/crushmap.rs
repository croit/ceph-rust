// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Decoded CRUSH map held by [`OsdMap`](crate::OsdMap) next to the verbatim blob, plus the
//! real [`CrushMapper`] with thread-local, allocation-free (after warm-up) scratch.

use crate::mapping::CrushMapper;
use std::cell::RefCell;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// A decoded CRUSH map; usable directly as a [`CrushMapper`].
#[derive(Debug)]
pub struct CrushState {
    id: u64,
    pub map: crush::CrushMap,
}

impl CrushState {
    pub fn new(map: crush::CrushMap) -> Self {
        Self {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            map,
        }
    }
}

#[derive(Default)]
struct Scratch {
    id: u64,
    ws: crush::Workspace,
    buf: Vec<i32>,
}

thread_local! {
    static SCRATCH: RefCell<Scratch> = RefCell::new(Scratch::default());
}

impl CrushMapper for CrushState {
    fn do_rule(
        &self,
        rule: i32,
        x: u32,
        result_max: usize,
        weights: &[u32],
        choose_args: i64,
        out: &mut Vec<i32>,
    ) {
        out.clear();
        if rule < 0 || result_max == 0 {
            return;
        }
        SCRATCH.with(|s| {
            let s = &mut *s.borrow_mut();
            if s.id != self.id {
                s.id = self.id;
                s.ws = crush::Workspace::default();
            }
            if s.ws.capacity() < result_max {
                s.ws.reserve(&self.map, result_max);
            }
            if s.buf.len() < result_max {
                s.buf.resize(result_max, 0);
            }
            let n = self.map.do_rule(
                rule as usize,
                x,
                &mut s.buf[..result_max],
                weights,
                self.map.choose_args_for(choose_args),
                &mut s.ws,
            );
            out.extend_from_slice(&s.buf[..n]);
        });
    }
}

/// Lazily decoded cache of `OsdMap::crush`. Always compares equal (derived data).
#[derive(Clone, Default)]
pub(crate) struct CrushCache(OnceLock<Option<Arc<CrushState>>>);

impl CrushCache {
    pub(crate) fn get(&self, blob: &[u8]) -> Option<&Arc<CrushState>> {
        self.0
            .get_or_init(|| {
                crush::CrushMap::decode(blob)
                    .ok()
                    .map(|m| Arc::new(CrushState::new(m)))
            })
            .as_ref()
    }
    pub(crate) fn with(m: crush::CrushMap) -> Self {
        Self(OnceLock::from(Some(Arc::new(CrushState::new(m)))))
    }
}
impl PartialEq for CrushCache {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}
impl std::fmt::Debug for CrushCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CrushCache")
    }
}
