// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
use crate::{ReadRoute, Target};
use denc::types::Hobject;
use opwire::{MOSDBackoff, consts::backoff};
use std::cmp::Ordering;
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackoffError {
    Invalid,
    NoCredit,
}
#[derive(Debug)]
struct Block {
    osd: i32,
    session: u64,
    message: MOSDBackoff,
    charge: u64,
}
#[derive(Debug)]
pub struct BackoffTable {
    slots: Vec<Option<Block>>,
    compatible: Option<BTreeMap<(i32, u64, u64), Block>>,
    byte_limit: u64,
    charged: u64,
    active: usize,
}
impl BackoffTable {
    pub fn new(capacity: usize, byte_limit: u64) -> Self {
        Self {
            slots: (0..capacity).map(|_| None).collect(),
            compatible: None,
            byte_limit,
            charged: 0,
            active: 0,
        }
    }
    /// Retain the server's population independently of application admission.
    pub fn new_compatible() -> Self {
        Self {
            compatible: Some(BTreeMap::new()),
            ..Self::new(0, 0)
        }
    }
    pub fn charged_bytes(&self) -> u64 {
        self.charged
    }
    pub fn clear(&mut self) {
        if let Some(blocks) = &mut self.compatible {
            blocks.clear();
        }
        for slot in &mut self.slots {
            *slot = None;
        }
        self.charged = 0;
        self.active = 0;
    }
    /// Revalidate retained ranges after a map installation, returning exact credit.
    pub fn retain(&mut self, mut valid: impl FnMut(i32, u64, &MOSDBackoff) -> bool) {
        if let Some(blocks) = &mut self.compatible {
            blocks.retain(|_, b| {
                if valid(b.osd, b.session, &b.message) {
                    true
                } else {
                    self.charged -= b.charge;
                    self.active -= 1;
                    false
                }
            });
            return;
        }
        for slot in &mut self.slots {
            if slot
                .as_ref()
                .is_some_and(|b| !valid(b.osd, b.session, &b.message))
            {
                let old = slot.take().unwrap();
                self.charged -= old.charge;
                self.active -= 1;
            }
        }
    }
    pub fn block_for_id(&self, osd: i32, session: u64, id: u64) -> Option<&MOSDBackoff> {
        if let Some(blocks) = &self.compatible {
            return blocks.get(&(osd, session, id)).map(|b| &b.message);
        }
        self.slots
            .iter()
            .flatten()
            .find(|b| b.osd == osd && b.session == session && b.message.id == id)
            .map(|b| &b.message)
    }
    pub fn contains(
        message: &MOSDBackoff,
        route: ReadRoute,
        target: &Target,
        snapshot: u64,
    ) -> bool {
        if message.pgid.pgid != route.pg || message.pgid.shard != route.pool.shard() {
            return false;
        }
        let lo = cmp_target(
            &message.begin,
            route.pg.pool as i64,
            route.hash,
            target,
            snapshot,
        );
        lo == Ordering::Equal
            || (lo == Ordering::Less
                && cmp_target(
                    &message.end,
                    route.pg.pool as i64,
                    route.hash,
                    target,
                    snapshot,
                ) == Ordering::Greater)
    }
    /// Driver validates the current authenticated session first, and, for a message of a map it has, PG interval
    /// and acting role (a message from a newer map is admitted by session alone).
    /// Some=ACK to send with IO priority; None=UNBLOCK/unknown release, no outbound.
    pub fn on_message(
        &mut self,
        osd: i32,
        session: u64,
        msg: MOSDBackoff,
    ) -> Result<Option<MOSDBackoff>, BackoffError> {
        if osd < 0 || session == 0 || msg.begin > msg.end {
            return Err(BackoffError::Invalid);
        }
        if let Some(blocks) = &mut self.compatible {
            let key = (osd, session, msg.id);
            match msg.op {
                backoff::BLOCK => {
                    if let Some(old) = blocks.get(&key) {
                        if old.message != msg {
                            return Err(BackoffError::Invalid);
                        }
                    } else {
                        let stored = msg.clone();
                        let charge = message_charge(&stored)?;
                        let next = self
                            .charged
                            .checked_add(charge)
                            .ok_or(BackoffError::NoCredit)?;
                        blocks.insert(
                            key,
                            Block {
                                osd,
                                session,
                                message: stored,
                                charge,
                            },
                        );
                        self.charged = next;
                        self.active += 1;
                    }
                    let mut ack = msg;
                    ack.op = backoff::ACK_BLOCK;
                    return Ok(Some(ack));
                }
                backoff::UNBLOCK => {
                    if let Some(old) = blocks.get(&key) {
                        if old.message.pgid != msg.pgid {
                            return Err(BackoffError::Invalid);
                        }
                        let old = blocks.remove(&key).unwrap();
                        self.charged -= old.charge;
                        self.active -= 1;
                    }
                    return Ok(None);
                }
                _ => return Err(BackoffError::Invalid),
            }
        }
        let existing = self.slots.iter().position(|e| {
            e.as_ref()
                .is_some_and(|b| b.osd == osd && b.session == session && b.message.id == msg.id)
        });
        match msg.op {
            backoff::BLOCK => {
                if let Some(i) = existing {
                    if self.slots[i].as_ref().unwrap().message != msg {
                        return Err(BackoffError::Invalid);
                    }
                } else {
                    let Some(i) = self.slots.iter().position(Option::is_none) else {
                        return Err(BackoffError::NoCredit);
                    };
                    let stored = msg.clone();
                    let charge = message_charge(&stored)?;
                    if charge > self.byte_limit - self.charged {
                        return Err(BackoffError::NoCredit);
                    }
                    self.slots[i] = Some(Block {
                        osd,
                        session,
                        message: stored,
                        charge,
                    });
                    self.charged += charge;
                    self.active += 1;
                }
                let mut ack = msg;
                ack.op = backoff::ACK_BLOCK;
                Ok(Some(ack))
            }
            backoff::UNBLOCK => {
                if let Some(i) = existing {
                    if self.slots[i].as_ref().unwrap().message.pgid != msg.pgid {
                        return Err(BackoffError::Invalid);
                    }
                    let old = self.slots[i].take().unwrap();
                    self.charged -= old.charge;
                    self.active -= 1;
                }
                Ok(None)
            }
            _ => Err(BackoffError::Invalid),
        }
    }
    pub fn blocked(&self, route: ReadRoute, target: &Target, snapshot: u64) -> bool {
        if self.active == 0 {
            return false;
        }
        if let Some(blocks) = &self.compatible {
            return blocks
                .range((route.osd, route.session, 0)..=(route.osd, route.session, u64::MAX))
                .any(|(_, b)| Self::contains(&b.message, route, target, snapshot));
        }
        self.slots.iter().flatten().any(|b| {
            b.osd == route.osd
                && b.session == route.session
                && Self::contains(&b.message, route, target, snapshot)
        })
    }
    pub fn reset_session(&mut self, osd: i32, session: u64) {
        if let Some(blocks) = &mut self.compatible {
            loop {
                let key = blocks
                    .range((osd, session, 0)..=(osd, session, u64::MAX))
                    .next()
                    .map(|(&key, _)| key);
                let Some(key) = key else { break };
                let old = blocks.remove(&key).unwrap();
                self.charged -= old.charge;
                self.active -= 1;
            }
            return;
        }
        for slot in &mut self.slots {
            if slot
                .as_ref()
                .is_some_and(|b| b.osd == osd && b.session == session)
            {
                let old = slot.take().unwrap();
                self.charged -= old.charge;
                self.active -= 1;
            }
        }
    }
}
fn range_charge(h: &Hobject) -> Result<u64, BackoffError> {
    h.key
        .capacity()
        .checked_add(h.oid.capacity())
        .and_then(|n| n.checked_add(h.nspace.capacity()))
        .and_then(|n| u64::try_from(n).ok())
        .ok_or(BackoffError::NoCredit)
}
fn message_charge(msg: &MOSDBackoff) -> Result<u64, BackoffError> {
    range_charge(&msg.begin)?
        .checked_add(range_charge(&msg.end)?)
        .ok_or(BackoffError::NoCredit)
}
/// Equivalent ordering to own Hobject spec; target borrows original binary metadata.
fn cmp_target(bound: &Hobject, pool: i64, hash: u32, target: &Target, snapshot: u64) -> Ordering {
    let key = if target.locator.is_empty() {
        &target.object
    } else {
        &target.locator
    };
    let bound_key = if bound.key.is_empty() {
        &bound.oid
    } else {
        &bound.key
    };
    bound
        .max
        .cmp(&false)
        .then(bound.pool.cmp(&pool))
        .then(bound.bitwise_key().cmp(&u64::from(hash.reverse_bits())))
        .then_with(|| bound.nspace.cmp(&target.namespace))
        .then_with(|| bound_key.cmp(key))
        .then_with(|| bound.oid.cmp(&target.object))
        .then(bound.snap.0.cmp(&snapshot))
}
