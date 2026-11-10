// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! OSD capabilities (spec osdcaps.md): grammar parser, profile expansion, per-message evaluation.
//! Parsed once per session into a flat grant list; evaluation does not allocate for messages with <= 64 calls.

use opwire::consts::watch_op;
use opwire::{ClsCap, MOSDOp, classify, op as code};
use std::collections::BTreeMap;

const R: u8 = 0x2;
const W: u8 = 0x4;
const CLS_R: u8 = 0x8;
const CLS_W: u8 = 0x10;
const X: u8 = CLS_R | CLS_W;
const ANY: u8 = 0xff;

/// `pool name -> application -> key -> value` of a pool.
pub type AppMeta = BTreeMap<String, BTreeMap<String, String>>;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Net {
    v6: bool,
    addr: [u8; 16],
    bits: u8,
}

impl Net {
    /// `ADDR/PREFIX` (IPv4 or IPv6 literal). A prefix longer than the address is clamped to the full address
    /// (a single-host match), as the reference does; only a missing or non-decimal prefix is unparsable.
    fn parse(s: &str) -> Option<Net> {
        let (a, p) = s.split_once('/')?;
        if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        // any decimal length: saturate instead of overflowing, the clamp below makes the value irrelevant
        let bits = p.parse::<u8>().unwrap_or(u8::MAX);
        if let Ok(v4) = a.parse::<std::net::Ipv4Addr>() {
            let mut addr = [0u8; 16];
            addr[..4].copy_from_slice(&v4.octets());
            return Some(Net {
                v6: false,
                addr,
                bits: bits.min(32),
            });
        }
        let v6 = a.parse::<std::net::Ipv6Addr>().ok()?;
        Some(Net {
            v6: true,
            addr: v6.octets(),
            bits: bits.min(128),
        })
    }

    fn contains(&self, p: &Peer) -> bool {
        let (v6, a): (bool, [u8; 16]) = match p {
            Peer::V4(x) => {
                let mut a = [0u8; 16];
                a[..4].copy_from_slice(x);
                (false, a)
            }
            Peer::V6(x) => (true, *x),
            Peer::Unknown => return false,
        };
        if v6 != self.v6 {
            return false;
        }
        let mut left = self.bits as usize;
        for (x, y) in a.iter().zip(self.addr.iter()) {
            if left == 0 {
                break;
            }
            let n = left.min(8);
            let mask = (0xffu16 << (8 - n)) as u8;
            if (x ^ y) & mask != 0 {
                return false;
            }
            left -= n;
        }
        true
    }
}

/// Peer socket address of the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Peer {
    V4([u8; 4]),
    V6([u8; 16]),
    Unknown,
}

impl Peer {
    pub fn from_addr(a: &denc::types::EntityAddr) -> Peer {
        if let Some(v) = a.ipv4() {
            Peer::V4(v)
        } else if let Some(v) = a.ipv6() {
            Peer::V6(v)
        } else {
            Peer::Unknown
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Match {
    pool: Option<String>,
    /// `(namespace, prefix match)`.
    ns: Option<(Vec<u8>, bool)>,
    /// `(app, key, value)`; `*` = any.
    tag: Option<(String, String, String)>,
    prefix: Option<Vec<u8>>,
}

/// `network` clause of a grant.
#[derive(Debug, Clone, PartialEq, Eq)]
enum NetSel {
    /// No clause.
    Any,
    Cidr(Net),
    /// Unparsable clause: the grant never accepts.
    Dead,
}

/// `class NAME [METHOD]` (method empty = any).
type ClassSel = (Vec<u8>, Vec<u8>);

#[derive(Debug, Clone, PartialEq, Eq)]
struct Grant {
    network: NetSel,
    m: Match,
    allow: u8,
    class: Option<ClassSel>,
}

/// What one MOSDOp needs (osdcaps.md s4).
#[derive(Debug)]
pub struct Need<'a> {
    pub read: bool,
    pub write: bool,
    pub classes: &'a [ClsCap],
}

/// Parsed caps of one session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caps {
    /// Some unrestricted grant without a network clause (op fast path).
    allow_all: bool,
    grants: Vec<Grant>,
}

/// Request context for one check.
#[derive(Debug)]
pub struct Ctx<'a> {
    pub pool: &'a [u8],
    pub apps: Option<&'a AppMeta>,
    pub ns: &'a [u8],
    /// Locator key if set, else the object name.
    pub key: &'a [u8],
    pub peer: Peer,
}

/// Read/write needs of a message (osdcaps.md s4); `cls` = classification of the `call` ops.
pub fn needs<'a>(op: &MOSDOp, cls: &'a [ClsCap]) -> Need<'a> {
    let mut read = false;
    let mut write = false;
    for o in &op.ops {
        if o.op == code::CALL {
            continue;
        }
        if o.op == code::WATCH {
            read = true;
            if o.watch().op == watch_op::PING {
                continue;
            }
        }
        if classify::reads(o.op) {
            read = true;
        }
        if classify::modifies(o.op) {
            write = true;
        }
    }
    Need {
        read,
        write,
        classes: cls,
    }
}

/// The `tag` selector against a pool's application metadata: can any object of the pool carry it?
fn tag_matches((app, key, val): &(String, String, String), apps: Option<&AppMeta>) -> bool {
    let Some(kv) = apps.and_then(|a| a.get(app)) else {
        return false;
    };
    let any = |s: &str| s == "*";
    match (any(key), any(val)) {
        (true, true) => true,
        (true, false) => kv.values().any(|v| v == val),
        (false, true) => kv.contains_key(key),
        (false, false) => kv.get(key).is_some_and(|v| v == val),
    }
}

impl Grant {
    /// `allow *` with no pool, namespace, tag or object_prefix restriction (network not consulted).
    fn unrestricted(&self) -> bool {
        self.allow == ANY && self.m == Match::default() && self.class.is_none()
    }

    /// Steps 1-3 of osdcaps.md s5: network, match, r/w needs.
    fn passes(&self, c: &Ctx<'_>, n: &Need<'_>) -> bool {
        self.net_ok(c.peer)
            && self.matches(c)
            && (!n.read || self.allow & R != 0)
            && (!n.write || self.allow & W != 0)
    }

    /// Step 1: the grant's network clause admits `peer` (an unparsable clause admits nobody).
    fn net_ok(&self, peer: Peer) -> bool {
        match &self.network {
            NetSel::Any => true,
            NetSel::Cidr(net) => net.contains(&peer),
            NetSel::Dead => false,
        }
    }

    /// Step 4 for one `call`: `*`, `class NAME [METHOD]`, or the class-read/class-write bits its flags need.
    fn covers(&self, k: &ClsCap) -> bool {
        self.allow == ANY
            || self
                .class
                .as_ref()
                .is_some_and(|(cn, mn)| *cn == k.class && (mn.is_empty() || *mn == k.method))
            // (b): the rwx bits reach only a class on `osd_class_default_list` (osdcaps.md 5.4)
            || (k.allowed
                && (!k.flags.rd || self.allow & CLS_R != 0)
                && (!k.flags.wr || self.allow & CLS_W != 0))
    }

    fn matches(&self, c: &Ctx<'_>) -> bool {
        let m = &self.m;
        if let Some(p) = &m.pool
            && p.as_bytes() != c.pool
        {
            return false;
        }
        if let Some((ns, prefix)) = &m.ns {
            let ok = if *prefix {
                c.ns.starts_with(ns)
            } else {
                c.ns == ns.as_slice()
            };
            if !ok {
                return false;
            }
        }
        if let Some(t) = &m.tag
            && !tag_matches(t, c.apps)
        {
            return false;
        }
        if let Some(p) = &m.prefix
            && !c.key.starts_with(p)
        {
            return false;
        }
        true
    }
}

impl Caps {
    /// Every op is allowed without evaluating grants (op fast path): an unrestricted `allow *` grant without a
    /// `network` clause. Not the admin test: see [`Caps::allows_admin`].
    pub fn is_allow_all(&self) -> bool {
        self.allow_all
    }

    /// Admin rights (tell / MCommand, osdcaps.md s1): some grant is `allow *` (or `all`) with no pool,
    /// namespace, tag or object_prefix restriction. Its `network` clause is not consulted, as in the reference;
    /// a scoped `allow * pool=x` never qualifies. Profiles never qualify (no profile expands to `*`).
    pub fn allows_admin(&self) -> bool {
        self.grants.iter().any(Grant::unrestricted)
    }

    /// Parse the cap text of a service ticket. Error text is for the log.
    pub fn parse(text: &str) -> Result<Caps, String> {
        let toks = lex(text)?;
        let mut p = Parser { t: &toks, i: 0 };
        let mut grants = Vec::new();
        loop {
            p.grant(&mut grants)?;
            match p.peek() {
                None => break,
                Some(Tok::Sep) => {
                    p.i += 1;
                }
                Some(t) => return Err(format!("unexpected {t:?}")),
            }
        }
        let allow_all = grants
            .iter()
            .any(|g| g.unrestricted() && g.network == NetSel::Any);
        Ok(Caps { allow_all, grants })
    }

    /// Client-op check (osdcaps.md s4/s5): may this session run `op` (its `call` ops classified as `cls`) from the
    /// transport source `peer_addr`? The object is `op`'s namespace and locator key (else its name); `pool_info` =
    /// pool name and application metadata, asked only for a restricted session.
    pub fn allows_op<'p>(
        &self,
        op: &MOSDOp,
        cls: &[ClsCap],
        peer_addr: &denc::types::EntityAddr,
        pool_info: impl FnOnce() -> (&'p [u8], Option<&'p AppMeta>),
    ) -> bool {
        if self.allow_all {
            return true;
        }
        let (pool, apps) = pool_info();
        // PG operations access a namespace/PG, not the supplied object. An ignored
        // oid or locator key must not turn a prefix-scoped grant into listing access.
        let key: &[u8] = if op.ops.iter().any(|o| classify::is_pg_op(o.op)) {
            &[]
        } else if op.oloc.key.is_empty() {
            &op.oid
        } else {
            &op.oloc.key
        };
        let ctx = Ctx {
            pool,
            apps,
            ns: &op.oloc.nspace,
            key,
            peer: Peer::from_addr(peer_addr),
        };
        self.is_capable(&ctx, &needs(op, cls))
    }

    /// Evaluate one message (osdcaps.md s5): some grant passes the network, match and r/w steps, and every `call` is
    /// covered by a grant that passes them. Same verdict as the reference's ordered walk with a shared per-class
    /// accumulator (coverage only grows, so the last passing grant sees the union); no allocation, any class count.
    pub fn is_capable(&self, c: &Ctx<'_>, n: &Need<'_>) -> bool {
        if self.allow_all {
            return true;
        }
        if n.classes.is_empty() {
            return self.grants.iter().any(|g| g.passes(c, n));
        }
        n.classes
            .iter()
            .all(|k| self.grants.iter().any(|g| g.passes(c, n) && g.covers(k)))
    }

    /// May this session write anywhere in `pool`? Asked before a receiver-side pre-write touches the device
    /// (adr 0477 am. 6), where the frame's object is not yet verified: true when a grant carries the write flag, its
    /// network (if any) admits `peer`, its pool selector (if any) names `pool` and its `tag` selector can match an
    /// object of `pool` (`apps` = the pool's application metadata). Namespace and object-prefix selectors narrow the
    /// objects of a pool, not the pool: a session allowed to write there may pre-write there, and the op's own
    /// [`allows_op`](Self::allows_op) check still decides whether the bytes are used.
    pub fn may_write_pool(&self, pool: &[u8], apps: Option<&AppMeta>, peer: Peer) -> bool {
        if self.allow_all {
            return true;
        }
        self.grants.iter().any(|g| {
            g.allow & W != 0
                && g.net_ok(peer)
                && g.m.pool.as_ref().is_none_or(|p| p.as_bytes() == pool)
                && g.m.tag.as_ref().is_none_or(|t| tag_matches(t, apps))
        })
    }
}

// ---------------------------------------------------------------------------------------------- lexer / parser

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Word(String),
    Quoted(String),
    Eq,
    Star,
    /// `*` written directly after a string (`namespace=n*`): only a namespace prefix glob takes it.
    Glob,
    Sep,
}

fn lex(s: &str) -> Result<Vec<Tok>, String> {
    let mut out = Vec::new();
    let mut it = s.chars().peekable();
    // the previous character closed a string token (a `*` right after it is a glob)
    let mut glue = false;
    while let Some(c) = it.next() {
        let tok = match c {
            c if c.is_whitespace() => None,
            '=' => Some(Tok::Eq),
            '*' if glue => Some(Tok::Glob),
            '*' => Some(Tok::Star),
            ';' | ',' => Some(Tok::Sep),
            '\'' | '"' => {
                let mut w = String::new();
                loop {
                    match it.next() {
                        Some(x) if x == c => break,
                        Some(x) => w.push(x),
                        None => return Err("unterminated quote".into()),
                    }
                }
                Some(Tok::Quoted(w))
            }
            c if word_char(c) => {
                let mut w = String::from(c);
                while let Some(&x) = it.peek().filter(|x| word_char(**x)) {
                    w.push(x);
                    it.next();
                }
                Some(Tok::Word(w))
            }
            c => return Err(format!("unexpected character {c:?}")),
        };
        glue = matches!(tok, Some(Tok::Word(_) | Tok::Quoted(_)));
        out.extend(tok);
    }
    Ok(out)
}

/// Unquoted word characters: STR plus the CIDR punctuation of `network` (`:` `[` `]`).
fn word_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || "_./-:[]".contains(c)
}

/// Unquoted STR characters (`[A-Za-z0-9_./-]`).
fn str_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || "_./-".contains(c)
}

struct Parser<'a> {
    t: &'a [Tok],
    i: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<&Tok> {
        self.t.get(self.i)
    }
    fn word(&self) -> Option<&str> {
        match self.peek() {
            Some(Tok::Word(w)) => Some(w),
            _ => None,
        }
    }
    fn eat(&mut self, t: &Tok) -> bool {
        let hit = self.peek() == Some(t);
        if hit {
            self.i += 1;
        }
        hit
    }
    fn eat_word(&mut self, w: &str) -> bool {
        let hit = self.word() == Some(w);
        if hit {
            self.i += 1;
        }
        hit
    }
    /// A string token: quoted (empty only if `empty_ok`) or an unquoted word made of `unquoted` characters.
    fn string(&mut self, empty_ok: bool, unquoted: fn(char) -> bool) -> Result<String, String> {
        let w = match self.peek() {
            Some(Tok::Word(w)) if w.chars().all(unquoted) => w.clone(),
            Some(Tok::Quoted(w)) if empty_ok || !w.is_empty() => w.clone(),
            t => return Err(format!("expected string, got {t:?}")),
        };
        self.i += 1;
        Ok(w)
    }
    /// Non-empty STR.
    fn str_(&mut self) -> Result<String, String> {
        self.string(false, str_char)
    }
    /// `pool` (`=` or blank) STR.
    fn pool(&mut self, m: &mut Match) -> Result<(), String> {
        if self.eat_word("pool") {
            self.eat(&Tok::Eq);
            m.pool = Some(self.str_()?);
        }
        Ok(())
    }
    /// `namespace` (`=` or blank) NSTR (quoted empty allowed) with an optional glued `*` (prefix match).
    fn namespace(&mut self, m: &mut Match) -> Result<(), String> {
        if self.eat_word("namespace") {
            self.eat(&Tok::Eq);
            let ns = self.string(true, str_char)?.into_bytes();
            m.ns = Some((ns, self.eat(&Tok::Glob)));
        }
        Ok(())
    }

    fn network(&mut self) -> Result<NetSel, String> {
        if !self.eat_word("network") {
            return Ok(NetSel::Any);
        }
        let w = self.string(false, word_char)?;
        Ok(Net::parse(&w).map_or(NetSel::Dead, NetSel::Cidr))
    }

    /// Tag KEY or VALUE: `*`, `all` (= any) or STR.
    fn tag_word(&mut self) -> Result<String, String> {
        if self.eat(&Tok::Star) {
            return Ok("*".into());
        }
        self.str_().map(|w| if w == "all" { "*".into() } else { w })
    }

    /// `match` (osdcaps.md s2): `[pool] [namespace] (tag APP KEY=VALUE | [object_prefix STR])`; no tag after a pool.
    fn selectors(&mut self, m: &mut Match) -> Result<(), String> {
        self.pool(m)?;
        self.namespace(m)?;
        if self.eat_word("tag") {
            if m.pool.is_some() {
                return Err("tag not allowed with pool".into());
            }
            let app = self.str_()?;
            let key = self.tag_word()?;
            if !self.eat(&Tok::Eq) {
                return Err("tag: expected '='".into());
            }
            m.tag = Some((app, key, self.tag_word()?));
        } else if self.eat_word("object_prefix") {
            m.prefix = Some(self.str_()?.into_bytes());
        }
        Ok(())
    }

    fn at_match(&self) -> bool {
        self.word()
            .is_some_and(|w| ["pool", "namespace", "object_prefix", "tag"].contains(&w))
    }

    fn grant(&mut self, out: &mut Vec<Grant>) -> Result<(), String> {
        if self.eat_word("profile") {
            self.eat(&Tok::Eq);
            let name = self.str_()?;
            let mut m = Match::default();
            self.pool(&mut m)?;
            self.namespace(&mut m)?;
            let net = self.network()?;
            expand_profile(&name, &m, net, out);
            return Ok(());
        }
        if !self.eat_word("allow") {
            return Err(format!(
                "expected 'allow' or 'profile', got {:?}",
                self.peek()
            ));
        }
        let mut m = Match::default();
        let pre = self.at_match();
        if pre {
            self.selectors(&mut m)?;
        }
        let (allow, class) = self.capspec()?;
        if !pre && self.at_match() {
            self.selectors(&mut m)?;
        }
        let network = self.network()?;
        out.push(Grant {
            network,
            m,
            allow,
            class,
        });
        Ok(())
    }

    /// `*` / `all`, `class NAME [METHOD]` (METHOD = any next string, keywords included, as the reference reads it),
    /// or rwx letters in order with optional `class-read` then `class-write`.
    fn capspec(&mut self) -> Result<(u8, Option<ClassSel>), String> {
        if self.eat(&Tok::Star) || self.eat_word("all") {
            return Ok((ANY, None));
        }
        if self.eat_word("class") {
            let name = self.str_()?;
            let method = match self.peek() {
                Some(Tok::Word(_) | Tok::Quoted(_)) => self.str_()?,
                _ => String::new(),
            };
            return Ok((0, Some((name.into_bytes(), method.into_bytes()))));
        }
        let mut allow = 0u8;
        let mut got = false;
        if let Some(w) = self.word()
            && !w.starts_with("class-")
        {
            let mut rest = w;
            for (ch, bit) in [('r', R), ('w', W), ('x', X)] {
                if let Some(r) = rest.strip_prefix(ch) {
                    allow |= bit;
                    rest = r;
                }
            }
            if !rest.is_empty() {
                return Err(format!("bad capability letters {w:?}"));
            }
            self.i += 1;
            got = true;
        }
        if self.eat_word("class-read") {
            allow |= CLS_R;
            got = true;
        }
        if self.eat_word("class-write") {
            allow |= CLS_W;
            got = true;
        }
        if !got {
            return Err(format!("expected capability, got {:?}", self.peek()));
        }
        Ok((allow, None))
    }
}

fn expand_profile(name: &str, sel: &Match, net: NetSel, out: &mut Vec<Grant>) {
    let g = |m: Match, allow: u8, class: Option<(&str, &str)>| Grant {
        network: net.clone(),
        m,
        allow,
        class: class.map(|(c, m)| (c.as_bytes().to_vec(), m.as_bytes().to_vec())),
    };
    let pfx = |p: &str| Match {
        prefix: Some(p.as_bytes().to_vec()),
        ..Match::default()
    };
    let with_prefix = |p: &str| Match {
        prefix: Some(p.as_bytes().to_vec()),
        ..sel.clone()
    };
    let ns_empty = |p: &str| Match {
        pool: sel.pool.clone(),
        ns: Some((Vec::new(), false)),
        prefix: Some(p.as_bytes().to_vec()),
        tag: None,
    };
    match name {
        "read-only" => out.push(g(sel.clone(), R, None)),
        "read-write" => out.push(g(sel.clone(), R | W, None)),
        "rbd" => {
            out.push(g(pfx("rbd_info"), R, None));
            out.push(g(pfx("rbd_children"), CLS_R, None));
            out.push(g(pfx("rbd_mirroring"), CLS_R, None));
            out.push(g(ns_empty("rbd_info"), 0, Some(("rbd", "metadata_list"))));
            out.push(g(sel.clone(), R | W | X, None));
        }
        "rbd-read-only" => {
            out.push(g(ns_empty("rbd_info"), 0, Some(("rbd", "metadata_list"))));
            out.push(g(sel.clone(), R | CLS_R, None));
            out.push(g(
                with_prefix("rbd_header."),
                0,
                Some(("rbd", "child_attach")),
            ));
            out.push(g(
                with_prefix("rbd_header."),
                0,
                Some(("rbd", "child_detach")),
            ));
        }
        // `rgw` (rwx on tag rgw) exists only in the dev tree, not in 21.2.0: grants nothing like osd/mgr/...
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opwire::ClsFlags;

    fn cls(c: &str, m: &str, rd: bool, wr: bool) -> ClsCap {
        cls_with(c, m, rd, wr, true)
    }

    fn cls_with(c: &str, m: &str, rd: bool, wr: bool, allowed: bool) -> ClsCap {
        ClsCap {
            class: c.into(),
            method: m.into(),
            flags: ClsFlags { rd, wr },
            allowed,
        }
    }

    /// A class kept off `osd_class_default_list` is not reached by rwx/class-read bits: only `allow class NAME`
    /// (osdcaps.md 5.4 (b)).
    #[test]
    fn class_off_the_default_list_needs_an_explicit_class_grant() {
        use denc::types::EntityAddr;
        let need = Need {
            read: false,
            write: false,
            classes: &[cls_with("lock", "list_locks", true, false, false)],
        };
        let ctx = Ctx {
            pool: b"p",
            apps: None,
            ns: b"",
            key: b"obj",
            peer: Peer::from_addr(&EntityAddr::v4(
                EntityAddr::TYPE_MSGR2,
                0,
                [10, 0, 0, 5],
                4000,
            )),
        };
        assert!(!Caps::parse("allow rwx").unwrap().is_capable(&ctx, &need));
        assert!(
            Caps::parse("allow rwx, allow class lock")
                .unwrap()
                .is_capable(&ctx, &need)
        );
        assert!(
            Caps::parse("allow class lock")
                .unwrap()
                .is_capable(&ctx, &need)
        );
        // the same class on the default list: the rwx bits suffice
        let on = Need {
            read: false,
            write: false,
            classes: &[cls_with("lock", "list_locks", true, false, true)],
        };
        assert!(Caps::parse("allow rwx").unwrap().is_capable(&ctx, &on));
    }

    #[test]
    fn pool_selector_compares_exact_bytes_without_lossy_or_nul_aliases() {
        let limited = Caps::parse("allow r pool='p�'").unwrap();
        let prefix = Caps::parse("allow r pool='p'").unwrap();
        let all = Caps::parse("allow r").unwrap();
        let need = Need {
            read: true,
            write: false,
            classes: &[],
        };
        for pool in [&[b'p', 255][..], b"p\0suffix".as_slice()] {
            let ctx = Ctx {
                pool,
                apps: None,
                ns: b"",
                key: b"",
                peer: Peer::Unknown,
            };
            assert!(!limited.is_capable(&ctx, &need));
            assert!(!prefix.is_capable(&ctx, &need));
            assert!(all.is_capable(&ctx, &need));
        }
        let ctx = Ctx {
            pool: "p�".as_bytes(),
            apps: None,
            ns: b"",
            key: b"",
            peer: Peer::Unknown,
        };
        assert!(limited.is_capable(&ctx, &need));
    }
    struct T {
        pool: &'static str,
        ns: &'static str,
        key: &'static str,
        peer: Peer,
        apps: AppMeta,
    }

    fn t(pool: &'static str, ns: &'static str, key: &'static str) -> T {
        T {
            pool,
            ns,
            key,
            peer: Peer::V4([10, 1, 2, 3]),
            apps: AppMeta::new(),
        }
    }

    fn chk(caps: &str, t: &T, read: bool, write: bool, classes: &[ClsCap]) -> bool {
        let c = Caps::parse(caps).unwrap_or_else(|e| panic!("{caps}: {e}"));
        c.is_capable(
            &Ctx {
                pool: t.pool.as_bytes(),
                apps: Some(&t.apps),
                ns: t.ns.as_bytes(),
                key: t.key.as_bytes(),
                peer: t.peer,
            },
            &Need {
                read,
                write,
                classes,
            },
        )
    }

    /// `allows_op` (the one client-op check of the engine, the EC direct read) grants and denies exactly like the
    /// check it replaced: `needs` + a `Ctx` of the op's namespace and locator key (else name) + `is_capable`. Matrix:
    /// allow-all, pool, namespace, object prefix, network, tag and class caps; plain, keyed and namespaced objects;
    /// read, write and class calls.
    #[test]
    fn allows_op_matches_the_hand_built_check() {
        use denc::types::EntityAddr;
        let caps = [
            "allow *",
            "allow r",
            "allow rw",
            "allow rwx",
            "allow r pool=p",
            "allow rw pool=q",
            "allow rw namespace=n",
            "allow rw namespace=\"\"",
            "allow rw object_prefix ob",
            "allow rw pool=p namespace=n object_prefix k",
            "allow r network 10.0.0.0/24",
            "allow rw network 192.168.0.0/16",
            "allow rw tag rbd *=*",
            "allow r, allow class lock",
            "allow rw, allow class lock lock",
            "allow class-read class-write",
            "profile rbd pool=p",
            "profile read-only",
        ];
        let lock = [cls("lock", "lock", true, true)];
        let info = [cls("lock", "get_info", true, false)];
        let mk = |oid: &[u8], key: &[u8], ns: &[u8], o: Vec<opwire::OsdOp>| {
            let mut m = MOSDOp {
                oid: oid.to_vec(),
                ops: o,
                ..Default::default()
            };
            m.oloc.key = key.to_vec();
            m.oloc.nspace = ns.to_vec();
            m
        };
        let rd = || vec![opwire::OsdOp::read(0, 1)];
        let wr = || vec![opwire::OsdOp::write(0, b"x".to_vec())];
        let call = |m: &[u8]| vec![opwire::OsdOp::call(b"lock", m, b"")];
        let ops: Vec<(MOSDOp, &[ClsCap])> = vec![
            (mk(b"obj", b"", b"", rd()), &[]),
            (mk(b"obj", b"", b"", wr()), &[]),
            (mk(b"xx", b"kk", b"", rd()), &[]),
            (mk(b"obj", b"xx", b"", wr()), &[]),
            (mk(b"obj", b"", b"n", rd()), &[]),
            (mk(b"kobj", b"", b"n", wr()), &[]),
            (mk(b"obj", b"", b"", call(b"lock")), &lock),
            (mk(b"obj", b"", b"", call(b"get_info")), &info),
        ];
        let mut apps = AppMeta::new();
        apps.insert("rbd".into(), Default::default());
        let peers = [
            EntityAddr::v4(EntityAddr::TYPE_MSGR2, 0, [10, 0, 0, 5], 4000),
            EntityAddr::v4(EntityAddr::TYPE_MSGR2, 0, [192, 168, 1, 1], 4000),
        ];
        let (mut granted, mut denied) = (0, 0);
        for text in caps {
            let c = Caps::parse(text).unwrap_or_else(|e| panic!("{text}: {e}"));
            for (op, cls) in &ops {
                for peer in &peers {
                    for (pool, apps) in [(&b"p"[..], Some(&apps)), (b"q", None), (b"", None)] {
                        let key = if op.oloc.key.is_empty() {
                            &op.oid
                        } else {
                            &op.oloc.key
                        };
                        let want = c.is_allow_all()
                            || c.is_capable(
                                &Ctx {
                                    pool,
                                    apps,
                                    ns: &op.oloc.nspace,
                                    key,
                                    peer: Peer::from_addr(peer),
                                },
                                &needs(op, cls),
                            );
                        let mut asked = false;
                        let got = c.allows_op(op, cls, peer, || {
                            asked = true;
                            (pool, apps)
                        });
                        assert_eq!(got, want, "{text} {op:?} {peer:?} {pool:?}");
                        // an unrestricted session never looks the pool up
                        assert_eq!(asked, !c.is_allow_all(), "{text}");
                        if got { granted += 1 } else { denied += 1 }
                    }
                }
            }
        }
        // the matrix exercises both outcomes broadly
        assert!(granted > 100 && denied > 100, "{granted} {denied}");
        // spot checks of the outcome itself
        let c = Caps::parse("allow rw pool=p namespace=n object_prefix k").unwrap();
        let p = || (&b"p"[..], None);
        assert!(c.allows_op(&ops[5].0, &[], &peers[0], p));
        assert!(!c.allows_op(&ops[4].0, &[], &peers[0], p));
        assert!(!c.allows_op(&ops[5].0, &[], &peers[0], || (&b"q"[..], None)));
        let c = Caps::parse("allow rw object_prefix ob").unwrap();
        assert!(c.allows_op(&ops[0].0, &[], &peers[0], p));
        // the locator key, not the name, is matched
        assert!(!c.allows_op(&ops[3].0, &[], &peers[0], p));
        let c = Caps::parse("allow class lock get_info").unwrap();
        assert!(c.allows_op(&ops[7].0, &info, &peers[0], p));
        assert!(!c.allows_op(&ops[6].0, &lock, &peers[0], p));
    }

    #[test]
    fn basics() {
        let a = t("a", "", "o");
        assert!(chk(
            "allow *",
            &a,
            true,
            true,
            &[cls("lock", "lock", true, true)]
        ));
        let lock = [cls("lock", "lock", true, true)];
        let info = [cls("lock", "get_info", true, false)];
        assert!(chk("allow rwx", &a, true, true, &lock));
        assert!(chk(
            "allow rwx",
            &a,
            false,
            false,
            &[cls("rbd", "get_size", true, false)]
        ));
        assert!(chk("allow rw", &a, true, true, &[]));
        assert!(!chk("allow rw", &a, false, false, &info));
        assert!(chk("allow r", &a, true, false, &[]));
        assert!(!chk("allow r", &a, true, true, &[]));
        // watch (read+write) denied by r
        assert!(!chk("allow r", &a, true, true, &[]));
        assert!(!chk("allow rw pool=a", &t("b", "", "o"), true, true, &[]));
        assert!(chk("allow rw pool=a", &a, true, true, &[]));
        assert!(!chk("allow rw pool=a namespace=n", &a, true, true, &[]));
        assert!(chk(
            "allow rw pool=a namespace=n",
            &t("a", "n", "o"),
            true,
            true,
            &[]
        ));
        assert!(chk(
            "allow r namespace=foo*",
            &t("a", "foobar", "o"),
            true,
            false,
            &[]
        ));
        assert!(!chk(
            "allow r namespace=foo*",
            &t("a", "fo", "o"),
            true,
            false,
            &[]
        ));
        assert!(chk(
            "allow rw object_prefix rbd_header.",
            &t("a", "", "rbd_header.1"),
            true,
            true,
            &[]
        ));
        assert!(!chk(
            "allow rw object_prefix rbd_header.",
            &t("a", "", "rbd_data.1"),
            true,
            true,
            &[]
        ));
        assert!(!chk(
            "allow rw object_prefix rbd_header.",
            &t("a", "", ""),
            true,
            true,
            &[]
        ));
    }

    #[test]
    fn tags() {
        let mut a = t("a", "", "o");
        a.apps.insert("rbd".into(), BTreeMap::new());
        assert!(chk("allow rw tag rbd *=*", &a, true, true, &[]));
        assert!(!chk(
            "allow rw tag rbd *=*",
            &t("a", "", "o"),
            true,
            true,
            &[]
        ));
        a.apps
            .get_mut("rbd")
            .unwrap()
            .insert("k".into(), "v".into());
        assert!(chk("allow rw tag rbd k=v", &a, true, true, &[]));
        assert!(chk("allow rw tag rbd k=*", &a, true, true, &[]));
        assert!(chk("allow rw tag rbd *=v", &a, true, true, &[]));
        assert!(!chk("allow rw tag rbd k=x", &a, true, true, &[]));
    }

    #[test]
    fn classes() {
        let a = t("a", "", "o");
        let rd = [cls("rbd", "get_size", true, false)];
        assert!(chk("allow class-read", &a, false, false, &rd));
        assert!(!chk("allow class-read", &a, true, false, &[]));
        // one grant must cover read + call
        let lock = [cls("lock", "lock", true, true)];
        assert!(!chk("allow r, allow class lock", &a, true, false, &lock));
        assert!(chk("allow r, allow class lock", &a, true, false, &[]));
        assert!(chk("allow r, allow class lock", &a, false, false, &lock));
        assert!(chk("allow class rbd get_size", &a, false, false, &rd));
        assert!(!chk(
            "allow class rbd get_size",
            &a,
            false,
            false,
            &[cls("rbd", "set_size", true, true)]
        ));
        assert!(chk(
            "allow rw pool=a, allow r",
            &t("b", "", "o"),
            true,
            false,
            &[]
        ));
        assert!(!chk(
            "allow rw pool=a, allow r",
            &t("b", "", "o"),
            true,
            true,
            &[]
        ));
    }

    #[test]
    fn profiles() {
        let rbd = t("rbd", "", "rbd_header.x");
        let create = [cls("rbd", "create", true, true)];
        assert!(chk("profile rbd pool=rbd", &rbd, true, true, &create));
        let other = t("other", "", "rbd_children");
        let gc = [cls("rbd", "get_children", true, false)];
        assert!(chk("profile rbd pool=rbd", &other, false, false, &gc));
        assert!(!chk("profile rbd pool=rbd", &other, true, true, &[]));
        assert!(chk(
            "profile rbd pool=rbd",
            &t("other", "", "rbd_info"),
            true,
            false,
            &[]
        ));
        let ml = [cls("rbd", "metadata_list", true, false)];
        assert!(chk(
            "profile rbd pool=rbd",
            &t("rbd", "", "rbd_info"),
            false,
            false,
            &ml
        ));
        let ro = "profile rbd-read-only pool=rbd";
        assert!(chk(ro, &rbd, true, false, &[]));
        assert!(chk(
            ro,
            &rbd,
            true,
            false,
            &[cls("rbd", "get_size", true, false)]
        ));
        assert!(!chk(
            ro,
            &rbd,
            true,
            false,
            &[cls("rbd", "snapshot_add", true, true)]
        ));
        assert!(chk(
            ro,
            &rbd,
            false,
            false,
            &[cls("rbd", "child_attach", true, true)]
        ));
        assert!(!chk(ro, &rbd, true, true, &[]));
        assert!(!chk("profile mgr", &rbd, true, false, &[]));
        // 21.2.0 has no `profile rgw` (dev tree: rwx on tag rgw): parses, grants nothing
        assert!(!chk("profile rgw", &rbd, true, false, &[]));
        assert!(chk("profile read-only", &rbd, true, false, &[]));
        assert!(!chk("profile read-only", &rbd, true, true, &[]));
        assert!(chk(
            "profile rbd",
            &t("any", "", "rbd_header.x"),
            true,
            true,
            &create
        ));
    }

    #[test]
    fn network() {
        let mut a = t("a", "", "o");
        assert!(chk("allow rw network 10.0.0.0/8", &a, true, true, &[]));
        a.peer = Peer::V4([192, 168, 0, 1]);
        assert!(!chk("allow rw network 10.0.0.0/8", &a, true, true, &[]));
        assert!(!chk("allow rw network bogus", &a, true, true, &[]));
        a.peer = Peer::V6([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert!(chk("allow rw network fe80::/10", &a, true, true, &[]));
        assert!(!chk("allow rw network 10.0.0.0/8", &a, true, true, &[]));
    }

    /// Accept/reject verdicts of a v21.2.0 mon (`lab/caps-oracle.sh`, `ceph auth add` with cap validation)
    /// for the rwx letter forms, class-read/class-write order and network edge cases. A text the mon accepts
    /// must parse (else the client's connection is refused); one it rejects never reaches an OSD, rejecting it
    /// too keeps the grammar honest.
    #[test]
    fn grammar_matches_reference_mon_verdicts() {
        let ok = [
            "allow r",
            "allow w",
            "allow x",
            "allow rw",
            "allow rx",
            "allow wx",
            "allow rwx",
            "allow rw class-read",
            "allow rw class-write",
            "allow rw class-read class-write",
            "allow class-read",
            "allow class-write",
            "allow class-read class-write",
            "allow x class-read",
            "allow pool p r class-read",
            "allow class-read pool p",
            "allow pool p class-read",
            "allow * network 10.0.0.0/8",
            "allow all",
            "allow * pool=p network 1.2.3.4/40",
            "allow rw network ::1/200",
            "allow rw network [::1]/64",
            "allow rw network 10.0.0.1",
            "allow rw network 10.0.0.1/",
            "allow rw network 10.0.0.1/033",
            "allow rw network 10.0.0.1/33",
            "allow rwx network 10.0.0.0/999999999999",
            "allow r  ,  allow w",
            "allow r;allow w",
            "profile rbd pool=p network 10.0.0.0/8",
            "allow class foo bar",
            "allow class foo bar pool p",
            "allow pool p class foo bar",
            "allow r namespace \"\"",
            "allow r tag a k=v network 1.2.3.4/32",
            "allow * tag a *=*",
            "allow rw pool=p namespace=n*",
            "allow * pool=images",
            "allow class pool",
            "allow r namespace=all",
            "allow r namespace n*",
            "allow namespace=n tag a k=v r",
            "allow r tag a k = v",
            "allow r tag a all=all",
            "profile rbd-read-only namespace=n*",
            "allow class foo bar network 1.2.3.4/32",
            "allow pool p r network 10.0.0.0/8",
        ];
        for c in ok {
            assert!(
                Caps::parse(c).is_ok(),
                "{c:?} accepted by the reference, must parse"
            );
        }
        for l in ["r", "w", "x", "rw", "rx", "wx", "rwx"] {
            assert!(Caps::parse(&format!("allow {l} pool=p")).is_ok(), "{l}");
        }
        let bad = [
            "allow wr",
            "allow xr",
            "allow xw",
            "allow rxw",
            "allow wrx",
            "allow wxr",
            "allow xrw",
            "allow xwr",
            "allow rwxr",
            "allow rr",
            "allow rww",
            "allow rw class-write class-read",
            "allow class-write class-read",
            "allow class-read r",
            "allow pool p class-read r",
            "allow r pool p class-read",
            "allow rwclass-read",
            "allow r,",
            "allow ALL",
            "allow r W",
            // unquoted STR is [A-Za-z0-9_./-]: CIDR punctuation only after `network`
            "allow rw pool=a:b",
            "allow rw pool=[a]",
            "allow rw object_prefix a:b",
            "allow rw namespace=a:b",
            // profile selectors: pool before namespace, each once
            "profile rbd namespace=n pool=p",
            "profile rbd pool=p pool=q",
            "allow r pool=p pool=q",
            // object_prefix takes no '='; the namespace glob is glued to the name
            "allow r object_prefix=x",
            "allow r namespace n *",
            "allow r namespace \"\" *",
            "allow r tag a k=v*",
            // `class NAME METHOD`: the word after NAME is the method, even a keyword
            "allow class foo network 10.0.0.0/8",
            "allow class foo pool p",
            "allow class foo object_prefix x",
            "allow class foo tag a k=v",
        ];
        for c in bad {
            assert!(
                Caps::parse(c).is_err(),
                "{c:?} rejected by the reference, must fail"
            );
        }
    }

    /// Admin rights need an unrestricted `*` grant; its network clause is ignored. The op fast path
    /// (`is_allow_all`) still requires no network clause, so network-scoped `allow *` is checked per op.
    #[test]
    fn admin_needs_unrestricted_star() {
        for (c, admin, all) in [
            ("allow *", true, true),
            ("allow all", true, true),
            ("allow r, allow *", true, true),
            ("allow * network 10.0.0.0/8", true, false),
            ("allow * network bogus", true, false),
            ("allow * pool=images", false, false),
            ("allow * namespace=n", false, false),
            ("allow * namespace=\"\"", false, false),
            ("allow * object_prefix x", false, false),
            ("allow * tag rbd *=*", false, false),
            ("allow rwx", false, false),
            ("allow rwx class-read class-write", false, false),
            ("profile rbd", false, false),
            ("profile read-write", false, false),
        ] {
            let p = Caps::parse(c).unwrap();
            assert_eq!(p.allows_admin(), admin, "{c}");
            assert_eq!(p.is_allow_all(), all, "{c}");
        }
    }

    /// Prefix lengths beyond the address width clamp to a host match (not a dead grant).
    #[test]
    fn network_prefix_clamps() {
        let mut a = t("a", "", "o");
        a.peer = Peer::V4([10, 0, 0, 1]);
        assert!(chk("allow rw network 10.0.0.1/33", &a, true, true, &[]));
        assert!(chk(
            "allow rw network 10.0.0.1/999999999999",
            &a,
            true,
            true,
            &[]
        ));
        assert!(chk("allow rw network 10.0.0.1/033", &a, true, true, &[]));
        a.peer = Peer::V4([10, 0, 0, 2]);
        assert!(!chk("allow rw network 10.0.0.1/33", &a, true, true, &[]));
        assert!(chk("allow rw network 10.0.0.1/0", &a, true, true, &[]));
        assert!(!chk("allow rw network 10.0.0.1/", &a, true, true, &[]));
        assert!(!chk("allow rw network 10.0.0.1", &a, true, true, &[]));
        a.peer = Peer::V6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert!(chk("allow rw network ::1/200", &a, true, true, &[]));
        a.peer = Peer::V6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        assert!(!chk("allow rw network ::1/200", &a, true, true, &[]));
        assert!(!chk("allow rw network [::1]/64", &a, true, true, &[]));
    }

    #[test]
    fn parse_failures_and_allow_all() {
        for bad in [
            "allow wr",
            "allow rw pool",
            "profile",
            "",
            "allow rw pool=a tag rbd *=*",
            "allow",
            "allow rw;",
            "deny rw",
        ] {
            assert!(Caps::parse(bad).is_err(), "{bad:?} must fail");
        }
        assert!(Caps::parse("allow *").unwrap().is_allow_all());
        assert!(Caps::parse("allow *, allow r").unwrap().is_allow_all());
        assert!(!Caps::parse("allow * pool=a").unwrap().is_allow_all());
        assert!(Caps::parse("allow all").unwrap().is_allow_all());
        assert!(Caps::parse("allow rw namespace=\"\"*").is_ok());
        assert!(Caps::parse("allow rwx pool=a namespace=x object_prefix y").is_ok());
        assert!(Caps::parse("allow pool=a rw").is_ok());
        assert!(Caps::parse("allow rw namespace=*").is_err());
        assert!(Caps::parse("allow r class-read class-write").is_ok());
        assert!(Caps::parse("profile rbd pool=rbd namespace=ns").is_ok());
        assert!(Caps::parse("profile=rbd pool = rbd").is_ok());
    }

    /// adr 0477 am. 6: the pool-wide write question asked before a pre-write, without an object.
    #[test]
    fn may_write_pool_needs_a_write_grant_for_that_pool_and_peer() {
        let peer = Peer::V4([10, 1, 2, 3]);
        let mut apps = AppMeta::new();
        apps.entry("rgw".into())
            .or_default()
            .insert("data_pool".into(), "rgw.buckets".into());
        let yes = |caps: &str| {
            Caps::parse(caps)
                .unwrap_or_else(|e| panic!("{caps}: {e}"))
                .may_write_pool(b"data", Some(&apps), peer)
        };
        assert!(yes("allow *"));
        assert!(yes("allow rw"));
        assert!(yes("allow rw pool=data"));
        assert!(yes("allow rw namespace=ns object_prefix k"));
        assert!(yes("allow rw pool=data network 10.0.0.0/8"));
        assert!(yes("allow rw tag rgw data_pool=rgw.buckets"));
        // no write flag, another pool, a peer outside the grant's network, a tag no object of the pool carries
        assert!(!yes("allow r"));
        assert!(!yes("allow r pool=data"));
        assert!(!yes("allow rw pool=other"));
        assert!(!yes("allow rw pool=data network 192.168.0.0/16"));
        assert!(!yes("allow rw network 192.168.0.0/16, allow r"));
        assert!(!yes("allow rw tag rgw data_pool=other"));
        assert!(!yes("allow rw tag rbd *=*"));
        // an unparsable network never authorizes anything
        assert!(!yes("allow rw network nonsense/8"));
        assert!(
            Caps::parse("allow rw")
                .unwrap()
                .may_write_pool(b"data", None, Peer::Unknown),
            "a grant without a network selector does not depend on the peer address"
        );
        assert!(
            !Caps::parse("allow rw network 10.0.0.0/8")
                .unwrap()
                .may_write_pool(b"data", None, Peer::Unknown),
            "a network-restricted grant with an unknown peer address stays closed"
        );
    }
}
