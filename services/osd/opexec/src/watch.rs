// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Volatile watch/notify state of a primary PG (client-ops.md s10). The persistent part (the watcher list) lives in
//! `object_info`; this tracks connections, ping deadlines and pending notifies. Everything is dropped on interval
//! change (clients re-register: Objecter linger resend).

use crate::engine::Out;
use crate::types::WatchKey;
use denc::types::{EntityAddr, EntityName, Hobject};
use opwire::{MWatchNotify, NotifyCompleteData, consts::notify as nop, errno};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

pub type Mono = u64;
const NS: u64 = 1_000_000_000;

#[derive(Debug, Clone)]
pub struct WState {
    pub conn: Option<u64>,
    pub addr: EntityAddr,
    pub timeout: u32,
    pub will_ping: bool,
    /// Remove the watcher when `now >= deadline` (None = not ticking: connected legacy watcher).
    pub deadline: Option<Mono>,
}

#[derive(Debug, Clone)]
struct Notify {
    head: Hobject,
    /// Notifier connection (None once it closed).
    conn: Option<u64>,
    gid: u64,
    cookie: u64,
    payload: Vec<u8>,
    ver: u64,
    pending: BTreeSet<WatchKey>,
    replies: BTreeMap<(u64, u64), Vec<u8>>,
    timeout: u32,
    deadline: Mono,
}

#[derive(Debug, Default)]
pub struct Watches {
    objs: HashMap<Hobject, HashMap<WatchKey, WState>>,
    notifies: HashMap<u64, Notify>,
    counter: u32,
    /// Multiset of every live deadline (watchers and notifies): `next_deadline` runs after every op of the PG, so
    /// it reads the minimum instead of scanning all watchers.
    due: BTreeMap<Mono, u32>,
    /// Per connection: the watchers bound to it and the notifies it issued, so a close costs O(that connection)
    /// instead of a scan of every watcher of the PG. Kept in step at every `conn` change.
    by_conn: HashMap<u64, ConnRefs>,
}

#[derive(Debug, Default)]
struct ConnRefs {
    watchers: HashSet<(Hobject, WatchKey)>,
    notifies: HashSet<u64>,
}

impl Watches {
    pub fn is_empty(&self) -> bool {
        self.objs.is_empty() && self.notifies.is_empty()
    }

    pub fn clear(&mut self) {
        self.objs.clear();
        self.notifies.clear();
        self.due.clear();
        self.by_conn.clear();
    }

    fn conn_add_watcher(&mut self, conn: u64, head: &Hobject, key: WatchKey) {
        self.by_conn
            .entry(conn)
            .or_default()
            .watchers
            .insert((head.clone(), key));
    }

    fn conn_del_watcher(&mut self, conn: u64, head: &Hobject, key: &WatchKey) {
        if let Some(r) = self.by_conn.get_mut(&conn) {
            r.watchers.remove(&(head.clone(), *key));
            if r.watchers.is_empty() && r.notifies.is_empty() {
                self.by_conn.remove(&conn);
            }
        }
    }

    fn conn_del_notify(&mut self, conn: u64, id: u64) {
        if let Some(r) = self.by_conn.get_mut(&conn) {
            r.notifies.remove(&id);
            if r.watchers.is_empty() && r.notifies.is_empty() {
                self.by_conn.remove(&conn);
            }
        }
    }

    fn due_add(&mut self, deadline: Option<Mono>) {
        if let Some(d) = deadline {
            *self.due.entry(d).or_default() += 1;
        }
    }

    fn due_del(&mut self, deadline: Option<Mono>) {
        if let Some(d) = deadline
            && let Some(n) = self.due.get_mut(&d)
        {
            *n -= 1;
            if *n == 0 {
                self.due.remove(&d);
            }
        }
    }

    /// Remove a notify from the registry (completion or expiry), keeping the timer index in step.
    fn take_notify(&mut self, id: u64) -> Option<Notify> {
        let n = self.notifies.remove(&id)?;
        self.due_del(Some(n.deadline));
        if let Some(c) = n.conn {
            self.conn_del_notify(c, id);
        }
        Some(n)
    }

    /// First load of an object with persisted watchers: they start out disconnected with their timeout running.
    pub fn populate(
        &mut self,
        head: &Hobject,
        watchers: &[(WatchKey, u32, EntityAddr)],
        now: Mono,
    ) {
        if watchers.is_empty() || self.objs.contains_key(head) {
            return;
        }
        // the head had no entry: every key is new
        let m = self.objs.entry(head.clone()).or_default();
        let mut deadlines = Vec::with_capacity(watchers.len());
        for (k, t, a) in watchers {
            let deadline = Some(now + u64::from(*t) * NS);
            m.insert(
                *k,
                WState {
                    conn: None,
                    addr: *a,
                    timeout: *t,
                    will_ping: true,
                    deadline,
                },
            );
            deadlines.push(deadline);
        }
        for d in deadlines {
            self.due_add(d);
        }
    }

    pub fn connected_keys(&self, head: &Hobject) -> Vec<WatchKey> {
        self.objs.get(head).map_or_else(Vec::new, |m| {
            m.iter()
                .filter(|(_, s)| s.conn.is_some())
                .map(|(k, _)| *k)
                .collect()
        })
    }

    #[expect(clippy::too_many_arguments)]
    /// Bind watcher `key` to `conn`; `None` = the connection already closed, so the lease starts now like in
    /// [`Self::conn_closed`] (a legacy watcher would otherwise never expire).
    pub fn connect(
        &mut self,
        head: &Hobject,
        key: WatchKey,
        conn: Option<u64>,
        addr: EntityAddr,
        timeout: u32,
        will_ping: bool,
        now: Mono,
        out: &mut Vec<Out>,
    ) {
        let deadline = (will_ping || conn.is_none()).then(|| now + u64::from(timeout) * NS);
        let m = self.objs.entry(head.clone()).or_default();
        if conn.is_some() && m.get(&key).is_some_and(|s| s.conn == conn) {
            // already bound to this connection: nothing to re-deliver, no new lease (classic Watch::connect)
            return;
        }
        let old = m.insert(
            key,
            WState {
                conn,
                addr,
                timeout,
                will_ping,
                deadline,
            },
        );
        if let Some(c) = old.as_ref().and_then(|s| s.conn) {
            self.conn_del_watcher(c, head, &key);
        }
        if let Some(c) = conn {
            self.conn_add_watcher(c, head, key);
        }
        self.due_del(old.and_then(|s| s.deadline));
        self.due_add(deadline);
        // pending notifies for this watcher are delivered now
        let Some(conn) = conn else {
            return;
        };
        let ids: Vec<u64> = self
            .notifies
            .iter()
            .filter(|(_, n)| n.head == *head && n.pending.contains(&key))
            .map(|(i, _)| *i)
            .collect();
        for id in ids {
            if let Some(n) = self.notifies.get(&id) {
                out.push(Out::Notify {
                    conn,
                    msg: MWatchNotify {
                        msg_ver: 1,
                        opcode: nop::NOTIFY,
                        cookie: key.0,
                        ver: n.ver,
                        notify_id: id,
                        bl: n.payload.clone(),
                        return_code: 0,
                        notifier_gid: n.gid,
                        data: Vec::new(),
                    },
                });
            }
        }
    }

    pub fn ping(&mut self, head: &Hobject, key: &WatchKey, now: Mono) {
        if let Some(s) = self.objs.get_mut(head).and_then(|m| m.get_mut(key))
            && s.will_ping
        {
            let new = now + u64::from(s.timeout) * NS;
            let old = s.deadline.replace(new);
            self.due_del(old);
            self.due_add(Some(new));
        }
    }

    /// Drop a watcher; DISCONNECT is sent if `notify_client` and it was connected.
    pub fn remove(
        &mut self,
        head: &Hobject,
        key: &WatchKey,
        notify_client: bool,
        out: &mut Vec<Out>,
    ) {
        let mut empty = false;
        let mut gone = None;
        if let Some(m) = self.objs.get_mut(head) {
            gone = m.remove(key);
            empty = m.is_empty();
        }
        if let Some(s) = gone {
            self.due_del(s.deadline);
            if let Some(c) = s.conn {
                self.conn_del_watcher(c, head, key);
            }
            if notify_client && let Some(c) = s.conn {
                out.push(Out::Notify {
                    conn: c,
                    msg: MWatchNotify {
                        msg_ver: 1,
                        opcode: nop::DISCONNECT,
                        cookie: key.0,
                        ..Default::default()
                    },
                });
            }
        }
        if empty {
            self.objs.remove(head);
        }
        // a removed watcher can no longer ack
        let ids: Vec<u64> = self
            .notifies
            .iter()
            .filter(|(_, n)| n.head == *head && n.pending.contains(key))
            .map(|(i, _)| *i)
            .collect();
        for id in ids {
            if let Some(n) = self.notifies.get_mut(&id) {
                n.pending.remove(key);
            }
            self.maybe_complete(id, out);
        }
    }

    pub fn remove_all(&mut self, head: &Hobject, out: &mut Vec<Out>) {
        let keys: Vec<WatchKey> = self
            .objs
            .get(head)
            .map_or_else(Vec::new, |m| m.keys().copied().collect());
        for k in keys {
            self.remove(head, &k, true, out);
        }
    }

    #[expect(clippy::too_many_arguments)]
    pub fn notify(
        &mut self,
        epoch: u32,
        head: &Hobject,
        watchers: &[WatchKey],
        conn: u64,
        gid: u64,
        cookie: u64,
        payload: Vec<u8>,
        timeout: u32,
        ver: u64,
        now: Mono,
        out: &mut Vec<Out>,
    ) -> u64 {
        self.counter = self.counter.wrapping_add(1);
        let id = (u64::from(epoch) << 32) | u64::from(self.counter);
        let n = Notify {
            head: head.clone(),
            conn: Some(conn),
            gid,
            cookie,
            payload: payload.clone(),
            ver,
            pending: watchers.iter().copied().collect(),
            replies: BTreeMap::new(),
            timeout,
            deadline: now + u64::from(timeout) * NS,
        };
        for k in watchers {
            if let Some(c) = self
                .objs
                .get(head)
                .and_then(|m| m.get(k))
                .and_then(|s| s.conn)
            {
                out.push(Out::Notify {
                    conn: c,
                    msg: MWatchNotify {
                        msg_ver: 1,
                        opcode: nop::NOTIFY,
                        cookie: k.0,
                        ver,
                        notify_id: id,
                        bl: payload.clone(),
                        return_code: 0,
                        notifier_gid: gid,
                        data: Vec::new(),
                    },
                });
            }
        }
        self.due_add(Some(n.deadline));
        self.by_conn.entry(conn).or_default().notifies.insert(id);
        self.notifies.insert(id, n);
        // completes later (after the caller queued the reply) if nobody is pending
        id
    }

    /// Completion check for a notify just created (called after the reply was queued).
    pub fn check_complete(&mut self, id: u64, out: &mut Vec<Out>) {
        self.maybe_complete(id, out);
    }

    #[expect(clippy::too_many_arguments)]
    pub fn ack(
        &mut self,
        head: &Hobject,
        who: EntityName,
        notify_id: u64,
        cookie: u64,
        legacy: bool,
        reply: Vec<u8>,
        out: &mut Vec<Out>,
    ) {
        let Some(n) = self.notifies.get_mut(&notify_id) else {
            return;
        };
        // A notify belongs to the object addressed by NOTIFY_ACK. Matching a
        // client/cookie alone would let an ACK on another object bypass that
        // object's capability check.
        if n.head != *head {
            return;
        }
        let keys: Vec<WatchKey> = if legacy {
            n.pending.iter().filter(|k| k.1 == who).copied().collect()
        } else {
            vec![(cookie, who)]
        };
        for k in keys {
            if n.pending.remove(&k) {
                n.replies.insert((who.num as u64, k.0), reply.clone());
            }
        }
        self.maybe_complete(notify_id, out);
    }

    fn maybe_complete(&mut self, id: u64, out: &mut Vec<Out>) {
        if self.notifies.get(&id).is_some_and(|n| n.pending.is_empty())
            && let Some(n) = self.take_notify(id)
        {
            Self::send_complete(id, n, 0, out);
        }
    }

    fn send_complete(id: u64, n: Notify, rc: i32, out: &mut Vec<Out>) {
        let Some(conn) = n.conn else { return };
        let data = NotifyCompleteData {
            replies: n.replies,
            missed: n.pending.iter().map(|k| (k.1.num as u64, k.0)).collect(),
        };
        out.push(Out::Notify {
            conn,
            msg: MWatchNotify {
                msg_ver: 1,
                opcode: nop::NOTIFY_COMPLETE,
                cookie: n.cookie,
                ver: n.ver,
                notify_id: id,
                bl: Vec::new(),
                return_code: rc,
                notifier_gid: n.gid,
                data: denc::to_vec(&data).unwrap_or_default(),
            },
        });
    }

    /// A connection closed: its watchers become disconnected (legacy ones start their timeout), its notifies lose
    /// their notifier. Returns whether any timer changed.
    pub fn conn_closed(&mut self, conn: u64, now: Mono) -> bool {
        let refs = self.by_conn.remove(&conn).unwrap_or_default();
        debug_assert_eq!(
            refs.watchers,
            self.objs
                .iter()
                .flat_map(|(h, m)| m.iter().map(move |(k, s)| (h, k, s)))
                .filter(|(_, _, s)| s.conn == Some(conn))
                .map(|(h, k, _)| (h.clone(), *k))
                .collect::<HashSet<_>>(),
            "connection index drifted from the watcher bindings"
        );
        debug_assert_eq!(
            refs.notifies,
            self.notifies
                .iter()
                .filter(|(_, n)| n.conn == Some(conn))
                .map(|(i, _)| *i)
                .collect::<HashSet<_>>(),
            "connection index drifted from the notify owners"
        );
        let mut started = Vec::new();
        for (h, k) in &refs.watchers {
            if let Some(s) = self.objs.get_mut(h).and_then(|m| m.get_mut(k)) {
                s.conn = None;
                if s.deadline.is_none() {
                    let d = now + u64::from(s.timeout) * NS;
                    s.deadline = Some(d);
                    started.push(Some(d));
                }
            }
        }
        for id in &refs.notifies {
            if let Some(n) = self.notifies.get_mut(id) {
                n.conn = None;
            }
        }
        let changed = !started.is_empty();
        for d in started {
            self.due_add(d);
        }
        changed
    }

    pub fn next_deadline(&self) -> Option<Mono> {
        let next = self.due.keys().next().copied();
        debug_assert_eq!(
            next,
            self.objs
                .values()
                .flat_map(|m| m.values())
                .filter_map(|s| s.deadline)
                .chain(self.notifies.values().map(|n| n.deadline))
                .min(),
            "timer index drifted from the watcher and notify deadlines"
        );
        next
    }

    /// Expired notifies are completed here; expired watchers are returned (the engine removes them through the PG).
    pub fn tick(&mut self, now: Mono, out: &mut Vec<Out>) -> Vec<(Hobject, WatchKey)> {
        let ids: Vec<u64> = self
            .notifies
            .iter()
            .filter(|(_, n)| n.deadline <= now)
            .map(|(i, _)| *i)
            .collect();
        for id in ids {
            if let Some(n) = self.take_notify(id) {
                eprintln!(
                    "WARNING TIMEOUT notify exceeded {}s (object={:?}, notify_id={}, pending={})",
                    n.timeout,
                    n.head,
                    id,
                    n.pending.len()
                );
                Self::send_complete(id, n, -errno::ETIMEDOUT, out);
            }
        }
        let mut dead = Vec::new();
        for (h, m) in &self.objs {
            for (k, s) in m {
                if s.deadline.is_some_and(|d| d <= now) {
                    dead.push((h.clone(), *k));
                }
            }
        }
        dead
    }

    /// Watchers whose address matches `pred` (blocklist).
    pub fn matching(&self, pred: impl Fn(&EntityAddr) -> bool) -> Vec<(Hobject, WatchKey)> {
        let mut v = Vec::new();
        for (h, m) in &self.objs {
            for (k, s) in m {
                if pred(&s.addr) {
                    v.push((h.clone(), *k));
                }
            }
        }
        v
    }

    /// Every watcher: `(object, (cookie, name), timeout s, address)`.
    pub fn all(&self) -> Vec<(Hobject, WatchKey, u32, EntityAddr)> {
        let mut v = Vec::new();
        for (h, m) in &self.objs {
            for (k, s) in m {
                v.push((h.clone(), *k, s.timeout, s.addr));
            }
        }
        v
    }
}
