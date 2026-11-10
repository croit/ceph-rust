// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Subscription bookkeeping (spec osd-lifecycle.md 2.4): `sub_new` (not yet sent) / `sub_sent`.
use messages::SubItem;
use std::collections::BTreeMap;

/// Pending / sent subscription tables.
#[derive(Debug, Default, Clone)]
pub struct Subs {
    new: BTreeMap<String, SubItem>,
    sent: BTreeMap<String, SubItem>,
}

impl Subs {
    /// `want(name,start,flags)`: no-op if identical to the current entry (pending wins). Returns true if queued.
    pub fn want(&mut self, name: &str, start: u64, flags: u8) -> bool {
        let it = SubItem { start, flags };
        if self.get(name) == Some(it) {
            return false;
        }
        self.new.insert(name.to_owned(), it);
        true
    }

    /// Remove local pending/sent state; it must not reappear on reconnect.
    pub fn unwant(&mut self, name: &str) {
        self.new.remove(name);
        self.sent.remove(name);
    }

    /// Queue even if identical (re-arm; used to ask for maps again).
    pub fn force(&mut self, name: &str, start: u64, flags: u8) {
        self.new.insert(name.to_owned(), SubItem { start, flags });
    }

    /// Only raise `start`.
    pub fn want_increment(&mut self, name: &str, start: u64, flags: u8) -> bool {
        let cur = self.new.get(name).or_else(|| self.sent.get(name));
        match cur {
            Some(c) if c.start >= start => false,
            _ => self.want(name, start, flags),
        }
    }

    /// Current entry (pending wins over sent).
    pub fn get(&self, name: &str) -> Option<SubItem> {
        self.new.get(name).or_else(|| self.sent.get(name)).copied()
    }

    /// We received up to `have`: onetime subs are done, standing subs move to `have + 1`.
    pub fn got(&mut self, name: &str, have: u64) {
        for t in [&mut self.new, &mut self.sent] {
            if let Some(it) = t.get_mut(name)
                && it.start <= have
            {
                if it.flags & SubItem::ONETIME != 0 {
                    t.remove(name);
                } else {
                    it.start = have.saturating_add(1);
                }
            }
        }
    }

    /// Anything to send?
    pub fn has_new(&self) -> bool {
        !self.new.is_empty()
    }

    /// Take the pending set for sending (moves into `sent`).
    pub fn take_new(&mut self) -> BTreeMap<String, SubItem> {
        let n = std::mem::take(&mut self.new);
        for (k, v) in &n {
            self.sent.insert(k.clone(), *v);
        }
        n
    }

    /// Handoff of a `take_new` set was refused: put the entries back as pending. An entry a re-entrant
    /// change already replaced or retired keeps that newer state.
    pub fn unsend(&mut self, n: BTreeMap<String, SubItem>) {
        for (k, v) in n {
            if self.sent.get(&k) == Some(&v) {
                self.sent.remove(&k);
                self.new.entry(k).or_insert(v);
            }
        }
    }

    /// Session reopened: resend everything (`new = sent U new`).
    pub fn reopen(&mut self) {
        let sent = std::mem::take(&mut self.sent);
        for (k, v) in sent {
            self.new.entry(k).or_insert(v);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_entry_takes_precedence_when_wanting_the_sent_value_again() {
        let mut s = Subs::default();
        s.want("osdmap", 5, 0);
        s.take_new();
        s.want("osdmap", 9, 0);
        assert!(s.want("osdmap", 5, 0));
        assert_eq!(s.get("osdmap").unwrap().start, 5);
        s.reopen();
        assert_eq!(s.take_new()["osdmap"].start, 5);
    }

    #[test]
    fn bookkeeping() {
        let mut removed = Subs::default();
        removed.want("log-info", 0, 0);
        removed.take_new();
        removed.want("log-info", 7, 0);
        removed.unwant("log-info");
        removed.reopen();
        assert!(!removed.has_new());
        assert!(removed.get("log-info").is_none());
        let mut s = Subs::default();
        assert!(s.want("osdmap", 5, SubItem::ONETIME));
        assert!(!s.want("osdmap", 5, SubItem::ONETIME));
        let m = s.take_new();
        assert_eq!(m.len(), 1);
        assert!(!s.want("osdmap", 5, SubItem::ONETIME)); // identical to sent
        s.got("osdmap", 4); // not yet satisfied
        assert!(s.get("osdmap").is_some());
        s.got("osdmap", 5); // onetime done
        assert!(s.get("osdmap").is_none());
        s.want("monmap", 0, 0);
        s.take_new();
        s.got("monmap", 3);
        assert_eq!(s.get("monmap").unwrap().start, 4);
        s.reopen();
        assert!(s.has_new());
        assert_eq!(s.take_new()["monmap"].start, 4);
        assert!(!s.want_increment("monmap", 2, 0));
        assert!(s.want_increment("monmap", 9, 0));
    }
}
