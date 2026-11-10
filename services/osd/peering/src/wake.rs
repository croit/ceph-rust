// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Store wake tokens as the op layer sees them (adr 0043 am. 9): what a gated op waits for ([`Cause`]) and what one wake
//! batch resolved ([`WakeSet`]). Plain data, no allocation.

/// Kind bits of the EC tokens: store tokens use kinds 1-3 in bits 62-63 (`store::toks`); kind 0 with bit 61 is EC, bit
/// 60 tells a client read ([`ec_rd_tok`]) from an object ([`ec_tok`]).
const EC_KIND: u64 = 1 << 61;
const EC_RD: u64 = 1 << 60;
const EC_MASK: u64 = EC_RD - 1;

/// Wake token of the EC primary state of object `soid` (any snap of it): a write on it finished. A read gated behind
/// that write names it; the PG's EC wake carries it. Equal tokens of different objects (hash collision) only probe an op
/// once more, never miss a wake.
pub fn ec_tok(soid: &denc::types::Hobject) -> u64 {
    // FNV-1a over name, namespace and locator key, seeded with the placement hash
    let mut h: u64 = 0xcbf2_9ce4_8422_2325 ^ u64::from(soid.hash);
    for b in soid.oid.iter().chain(&soid.nspace).chain(&soid.key) {
        h = (h ^ u64::from(*b)).wrapping_mul(0x0100_0000_01b3);
    }
    EC_KIND | (h & EC_MASK)
}

/// Wake token of the EC client read `id` (unique per PG instance): it finished (data cached, failed or stale). Only the
/// ops that wait for that read name it, so the completion of one read of a hot object probes its own ops, not every op
/// queued on the object.
pub fn ec_rd_tok(id: u64) -> u64 {
    EC_KIND | EC_RD | (id & EC_MASK)
}

/// Tokens one gated op can wait on (more = unknown).
pub const CAUSE_MAX: usize = 8;
/// Tokens one wake batch carries before it degrades to "everything" (`all`).
pub const WAKE_MAX: usize = 32;

/// What a probe that found the store not ready waits for. `n == 0` = unknown (no tracked cause, or too many): the op is
/// probed on every wake.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Cause {
    pub n: u8,
    pub t: [u64; CAUSE_MAX],
}

impl Cause {
    pub fn from_tokens(toks: &[u64], overflowed: bool) -> Cause {
        let mut c = Cause::default();
        if overflowed || toks.is_empty() || toks.len() > CAUSE_MAX {
            return c;
        }
        c.t[..toks.len()].copy_from_slice(toks);
        c.n = toks.len() as u8;
        c
    }
    pub fn tokens(&self) -> &[u64] {
        &self.t[..self.n as usize]
    }
    /// The cause of an op that waits for one token ([`ec_tok`] / [`ec_rd_tok`]).
    pub fn one(tok: u64) -> Cause {
        let mut c = Cause::default();
        c.t[0] = tok;
        c.n = 1;
        c
    }
    pub fn is_unknown(&self) -> bool {
        self.n == 0
    }
}

/// What the store resolved since the last wake pass.
#[derive(Clone, Copy, Debug, Default)]
pub struct WakeSet {
    /// Something not named by a token changed (or the set overflowed, or the caller doubts): wake every gated op.
    pub all: bool,
    n: u8,
    t: [u64; WAKE_MAX],
}

impl WakeSet {
    /// Nothing woke / everything woke (`const`: borrowed without building a set).
    pub const NONE: WakeSet = WakeSet {
        all: false,
        n: 0,
        t: [0; WAKE_MAX],
    };
    pub const ALL: WakeSet = WakeSet {
        all: true,
        n: 0,
        t: [0; WAKE_MAX],
    };
    pub fn push(&mut self, tok: u64) {
        let n = self.n as usize;
        if self.t[..n].contains(&tok) {
            return;
        }
        if n < WAKE_MAX {
            self.t[n] = tok;
            self.n += 1;
        } else {
            self.all = true;
        }
    }
    pub fn tokens(&self) -> &[u64] {
        &self.t[..self.n as usize]
    }
    /// Add everything `o` woke.
    pub fn merge(&mut self, o: &WakeSet) {
        self.all |= o.all;
        for &t in o.tokens() {
            self.push(t);
        }
    }
    /// Anything woke at all.
    pub fn any(&self) -> bool {
        self.all || self.n > 0
    }
    pub fn clear(&mut self) {
        self.all = false;
        self.n = 0;
    }
    /// Must an op with `c` run again? Unknown causes always do.
    pub fn hits(&self, c: &Cause) -> bool {
        self.all
            || c.is_unknown()
            || c.tokens()
                .iter()
                .any(|t| self.t[..self.n as usize].contains(t))
    }
}
