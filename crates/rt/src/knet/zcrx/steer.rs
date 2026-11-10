// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Which NIC rx queues this OSD may take for zcrx (doc/spec/knet-zcrx.md section 5). Pure rules over the NIC's
//! steering state (read by `nic`), testable anywhere.
//!
//! Payload of every flow that reaches a queue with a registered ifq lands in that ifq's area and is readable only
//! through `RECV_ZC` on the registering ring: a foreign flow there (another OSD, another daemon) would be lost. So a
//! queue qualifies only when the host steered it exclusively to this OSD's public port: it is outside the default RSS
//! table, and every flow rule that can reach it matches exactly this port (TCP destination port, fully masked). The
//! host layout is the one `croit-flashstore-tool host-tune --zcrx-queues K --host-queues M --osd-port P` installs; with more
//! OSDs on one NIC each needs its own queues (one rule set per port). Dialed links never land there (their reverse
//! flows carry our ephemeral port), cluster and heartbeat listeners neither (no rule may name their ports).
use std::collections::BTreeSet;

/// One flow steering rule of the NIC, as far as zcrx cares.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    /// TCP destination port with a full mask, `None` for any other match (other protocols, partial port masks).
    pub port: Option<u16>,
    /// Queues the rule can deliver to (one queue, or every queue of its RSS context).
    pub queues: Vec<u32>,
}

/// Steering state of one NIC.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Steering {
    /// Queues the default RSS context spreads over (its indirection table).
    pub rss: Vec<u32>,
    pub rules: Vec<Rule>,
}

/// Why the steering does not qualify (reason `no-steering` / `shared-queue` in the startup line).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refused {
    /// No rule sends this port to queues outside the default RSS table.
    NoSteering,
    /// A queue of this port's rules is also in the default RSS table (other flows reach it).
    InRss(u32),
    /// A rule for something else (`None` = not a plain TCP port rule) reaches queue `q` of this port.
    Foreign { q: u32, port: Option<u16> },
}

/// The queues reserved for `port`, ascending.
pub fn queues(s: &Steering, port: u16) -> Result<Vec<u32>, Refused> {
    let rss: BTreeSet<u32> = s.rss.iter().copied().collect();
    let mine: BTreeSet<u32> = s
        .rules
        .iter()
        .filter(|r| r.port == Some(port))
        .flat_map(|r| r.queues.iter().copied())
        .collect();
    if mine.is_empty() {
        return Err(Refused::NoSteering);
    }
    if let Some(&q) = mine.intersection(&rss).next() {
        return Err(Refused::InRss(q));
    }
    for r in s.rules.iter().filter(|r| r.port != Some(port)) {
        if let Some(&q) = r.queues.iter().find(|q| mine.contains(q)) {
            return Err(Refused::Foreign { q, port: r.port });
        }
    }
    Ok(mine.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(port: Option<u16>, q: &[u32]) -> Rule {
        Rule {
            port,
            queues: q.to_vec(),
        }
    }

    #[test]
    fn host_tune_layout_qualifies() {
        // 4 host queues in RSS, queues 4..8 in an RSS context for port 6800
        let s = Steering {
            rss: vec![0, 1, 2, 3, 0, 1, 2, 3],
            rules: vec![rule(Some(6800), &[4, 5, 6, 7])],
        };
        assert_eq!(queues(&s, 6800), Ok(vec![4, 5, 6, 7]));
        assert_eq!(queues(&s, 6801), Err(Refused::NoSteering));
    }

    #[test]
    fn rss_queue_is_refused() {
        let s = Steering {
            rss: vec![0, 1, 2, 3],
            rules: vec![rule(Some(6800), &[3, 4])],
        };
        assert_eq!(queues(&s, 6800), Err(Refused::InRss(3)));
    }

    #[test]
    fn foreign_rules_on_our_queues_are_refused() {
        let base = Steering {
            rss: vec![0, 1],
            rules: vec![rule(Some(6800), &[2, 3])],
        };
        let mut s = base.clone();
        s.rules.push(rule(Some(6801), &[3]));
        assert_eq!(
            queues(&s, 6800),
            Err(Refused::Foreign {
                q: 3,
                port: Some(6801)
            })
        );
        let mut s = base.clone();
        s.rules.push(rule(None, &[2]));
        assert_eq!(queues(&s, 6800), Err(Refused::Foreign { q: 2, port: None }));
        // a second OSD on its own queues is fine
        let mut s = base;
        s.rules.push(rule(Some(6801), &[4, 5]));
        assert_eq!(queues(&s, 6800), Ok(vec![2, 3]));
        assert_eq!(queues(&s, 6801), Ok(vec![4, 5]));
    }
}
