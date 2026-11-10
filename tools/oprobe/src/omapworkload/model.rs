// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Acknowledged key ownership; pending mutations never lend keys to another RPC.
use super::config::{Config, Op};
use denc::Encode;
use opwire::{KvMap, OsdOp};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Key {
    pub id: u64,
    pub version: u64,
}
#[derive(Debug)]
pub struct Request {
    pub op: Op,
    pub object: usize,
    pub keys: Vec<Key>,
    pub version: u64,
}
pub fn key(c: &Config, id: u64) -> Result<Vec<u8>, String> {
    if !c.key_fits(id) {
        return Err("key namespace exhausted".into());
    }
    let mut b = vec![b'k'; c.key_bytes];
    let n = c.key_bytes.min(8);
    b[c.key_bytes - n..].copy_from_slice(&id.to_be_bytes()[8 - n..]);
    Ok(b)
}
pub fn value(c: &Config, k: Key) -> Vec<u8> {
    let mut seed = k.id ^ k.version.wrapping_mul(0x9e3779b97f4a7c15);
    seed = (seed ^ (seed >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    seed = (seed ^ (seed >> 27)).wrapping_mul(0x94d049bb133111eb);
    let bytes = (seed ^ (seed >> 31)).to_le_bytes();
    (0..c.value_bytes)
        .map(|i| bytes[i % 8] ^ (i / 8) as u8)
        .collect()
}
impl Request {
    pub fn wire(&self, c: &Config) -> Result<OsdOp, String> {
        let keys = self
            .keys
            .iter()
            .map(|k| key(c, k.id))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(match self.op {
            Op::Insert | Op::Update => OsdOp::omap_set_vals(
                &keys
                    .into_iter()
                    .zip(self.keys.iter().map(|&k| {
                        value(
                            c,
                            if self.op == Op::Update {
                                Key {
                                    version: self.version,
                                    ..k
                                }
                            } else {
                                k
                            },
                        )
                    }))
                    .collect::<KvMap>(),
            ),
            Op::Delete => OsdOp::omap_rm_keys(&keys.into_iter().collect::<BTreeSet<_>>()),
            Op::Read => {
                let mut op = OsdOp::new(opwire::op::OMAP_GET_VALS_BY_KEYS);
                op.indata = keys
                    .into_iter()
                    .collect::<BTreeSet<_>>()
                    .encode_to_vec()
                    .map_err(|e| e.to_string())?
                    .into();
                op
            }
        })
    }
}
pub struct Model {
    pub queues: BTreeMap<usize, VecDeque<Key>>,
    owned: Vec<usize>,
    next: BTreeMap<usize, (u64, u64)>,
    pub issued: u64,
    tracked: u64,
    limit: u64,
}
impl Model {
    pub fn new(c: &Config, client: usize) -> Self {
        let owned = c.owned(client);
        let mut queues = BTreeMap::new();
        let mut next = BTreeMap::new();
        let mut tracked = 0;
        for &o in &owned {
            let (a, b, r, n) = c.partition(client, o);
            tracked += b - a;
            queues.insert(o, (a..b).map(|id| Key { id, version: 0 }).collect());
            next.insert(o, (c.prefill.saturating_add(r), n));
        }
        Self {
            queues,
            owned,
            next,
            issued: 0,
            tracked,
            limit: c.live_limit(client),
        }
    }
    /// None means data dependency, not permission to reorder the operation stream.
    pub fn next(&mut self, c: &Config) -> Result<Option<Request>, String> {
        let op = c.operations[(self.issued % c.operations.len() as u64) as usize];
        let object = self.owned
            [((self.issued / c.operations.len() as u64) % self.owned.len() as u64) as usize];
        let mut keys = Vec::with_capacity(c.batch);
        if op == Op::Insert {
            if self
                .tracked
                .checked_add(c.batch as u64)
                .is_none_or(|n| n > self.limit)
            {
                return Ok(None);
            }
            let (next, stride) = self.next.get_mut(&object).unwrap();
            for _ in 0..c.batch {
                if !c.key_fits(*next) {
                    return Err("key namespace exhausted".into());
                }
                keys.push(Key {
                    id: *next,
                    version: 0,
                });
                *next = next.checked_add(*stride).ok_or("key sequence overflow")?;
            }
            self.tracked += c.batch as u64;
        } else {
            let queue = self.queues.get_mut(&object).unwrap();
            if queue.len() < c.batch {
                return Ok(None);
            }
            for _ in 0..c.batch {
                keys.push(queue.pop_front().unwrap());
            }
        }
        self.issued = self
            .issued
            .checked_add(1)
            .ok_or("operation sequence overflow")?;
        Ok(Some(Request {
            op,
            object,
            keys,
            version: self.issued,
        }))
    }
    /// Undo ONLY the most recent prepared request, before transport admission.
    pub fn unprepare(&mut self, r: Request) {
        self.issued -= 1;
        if r.op == Op::Insert {
            let (next, stride) = self.next.get_mut(&r.object).unwrap();
            *next -= r.keys.len() as u64 * *stride;
            self.tracked -= r.keys.len() as u64;
        } else {
            let queue = self.queues.get_mut(&r.object).unwrap();
            for k in r.keys.into_iter().rev() {
                queue.push_front(k);
            }
        }
    }
    pub fn complete(&mut self, mut r: Request) {
        if r.op == Op::Delete {
            self.tracked -= r.keys.len() as u64;
        } else {
            if r.op == Op::Update {
                for k in &mut r.keys {
                    k.version = r.version;
                }
            }
            self.queues.get_mut(&r.object).unwrap().extend(r.keys);
        }
    }
    pub fn keys(&self) -> u64 {
        self.queues.values().map(|q| q.len() as u64).sum()
    }
}
