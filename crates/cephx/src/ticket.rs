// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! TicketReply (spec sec 5.1) encode/decode and client-side ticket bookkeeping (sec 10.2).

use std::time::Duration;

use denc::types::UTime;
use denc::{Decode, Decoder, Encode, Encoder};

use crate::envelope::{open_raw_t, open_wrapped, open_wrapped_t, seal_wrapped_t};
use crate::error::{Error, Result};
use crate::key::{CryptoKey, Usage};
use crate::types::{ServiceTicket, TicketBlob};

/// One ticket of a ticket reply, decrypted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TicketEntry {
    pub service_id: u32,
    pub session_key: CryptoKey,
    pub validity: UTime,
    pub blob: TicketBlob,
}

/// Encode a TicketReply. `principal` encrypts each msgA (usage 0x04). With `enc_with` (the OLD
/// AUTH session key) the ticket data is wrapped (enc_flag=1, usage 0x05). Mon-side layout; used
/// by tests and fakes.
pub fn encode_ticket_reply(
    entries: &[TicketEntry],
    principal: &CryptoKey,
    enc_with: Option<&CryptoKey>,
) -> Result<Vec<u8>> {
    let mut e = Encoder::new();
    e.u8(1)?;
    e.count(entries.len())?;
    for t in entries {
        e.u32(t.service_id)?;
        e.u8(1)?;
        let a = ServiceTicket {
            session_key: t.session_key.clone(),
            validity: t.validity,
        };
        e.raw(&seal_wrapped_t(principal, Usage::TicketSessionKey, &a)?)?;
        let x = t.blob.encode_to_vec()?;
        match enc_with {
            None => {
                e.u8(0)?;
                e.bytes(&x)?;
            }
            Some(k) => {
                e.u8(1)?;
                e.raw(&seal_wrapped_t(k, Usage::TicketBlob, &x)?)?;
            }
        }
    }
    Ok(e.into_vec())
}

/// Decode a TicketReply from `d`. `old_key` = current (old) AUTH session key, needed iff a
/// ticket has enc_flag=1.
pub fn decode_ticket_reply(
    d: &mut Decoder<'_>,
    principal: &CryptoKey,
    old_key: Option<&CryptoKey>,
) -> Result<Vec<TicketEntry>> {
    d.u8()?;
    let n = d.count()?;
    let mut out = Vec::with_capacity(n.min(8));
    for _ in 0..n {
        let service_id = d.u32()?;
        d.u8()?;
        let a: ServiceTicket = open_wrapped_t(principal, Usage::TicketSessionKey, d)?;
        let blob = if d.u8()? != 0 {
            let k = old_key.ok_or(Error::Protocol("encrypted ticket but no old AUTH key"))?;
            let x = open_wrapped(k, Usage::TicketBlob, d)?;
            let mut xd = Decoder::new(&x);
            let inner = xd.bytes()?;
            TicketBlob::decode(&mut Decoder::new(inner))?
        } else {
            TicketBlob::decode(&mut Decoder::new(d.bytes()?))?
        };
        out.push(TicketEntry {
            service_id,
            session_key: a.session_key,
            validity: a.validity,
            blob,
        });
    }
    Ok(out)
}

/// Client-side state of one service ticket. Times are unix wall time with nanosecond precision (`now` is passed in):
/// a monitor caps the ticket TTL by its newest rotating key's remaining lifetime, so validity is fractional and may be
/// shorter than one second.
#[derive(Debug, Clone)]
pub struct TicketHandler {
    pub service_id: u32,
    session_key: Option<CryptoKey>,
    blob: TicketBlob,
    /// Zero = already expired (installed with validity 0, spec sec 5.1/16.1).
    expires: Duration,
    renew_after: Duration,
    valid: bool,
}

impl TicketHandler {
    pub fn new(service_id: u32) -> Self {
        Self {
            service_id,
            session_key: None,
            blob: TicketBlob::default(),
            expires: Duration::ZERO,
            renew_after: Duration::ZERO,
            valid: false,
        }
    }

    /// Install a freshly received ticket (spec sec 5.1 client processing). Expiry keeps the full seconds+nanoseconds
    /// validity; renewal starts one quarter of the whole-seconds validity before expiry, so a subsecond ticket is
    /// renewed only once it expired.
    pub fn install(&mut self, e: TicketEntry, now: Duration) {
        let v = e.validity;
        if v.sec != 0 || v.nsec != 0 {
            self.expires = now + Duration::new(u64::from(v.sec), v.nsec);
            self.renew_after = self.expires - Duration::from_secs(u64::from(v.sec)) / 4;
        } else {
            self.expires = Duration::ZERO;
            self.renew_after = Duration::ZERO;
        }
        self.session_key = Some(e.session_key);
        self.blob = e.blob;
        self.valid = true;
    }

    /// Mark "no key" but keep blob + session key (old_ticket path after a new server challenge).
    pub fn invalidate(&mut self) {
        self.valid = false;
    }

    /// Has a key and now < expires (validity 0 -> expires 0 -> false at any now, sec 16.1).
    pub fn have_key(&self, now: Duration) -> bool {
        self.valid && self.session_key.is_some() && now < self.expires
    }

    /// No usable key (none, invalidated, or expired: a validity-0 ticket is expired at once), or past the renewal
    /// point. An expired ticket is always requested again (sec 5.1, 16.1).
    pub fn need_key(&self, now: Duration) -> bool {
        !self.have_key(now) || (!self.expires.is_zero() && now >= self.renew_after)
    }

    pub fn session_key(&self) -> Option<&CryptoKey> {
        self.session_key.as_ref()
    }
    pub fn blob(&self) -> &TicketBlob {
        &self.blob
    }
    pub fn expires(&self) -> Duration {
        self.expires
    }
    pub fn renew_after(&self) -> Duration {
        self.renew_after
    }
}

/// Decode the ticket info of a blob (service side helper, also for tests).
pub fn open_ticket_info(key: &CryptoKey, blob: &[u8]) -> Result<crate::types::ServiceTicketInfo> {
    open_raw_t(key, Usage::TicketInfo, blob)
}

/// Seal ticket info into a blob (mon side; tests).
pub fn seal_ticket_info(
    key: &CryptoKey,
    secret_id: u64,
    info: &crate::types::ServiceTicketInfo,
) -> Result<TicketBlob> {
    Ok(TicketBlob {
        secret_id,
        blob: crate::envelope::seal_raw_t(key, Usage::TicketInfo, info)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::KeyType;

    fn entry_ns(sec: u32, nsec: u32) -> TicketEntry {
        TicketEntry {
            service_id: 4,
            session_key: CryptoKey::new(KeyType::Aes, UTime::default(), &[7; 16]),
            validity: UTime::new(sec, nsec),
            blob: TicketBlob::default(),
        }
    }
    fn entry(validity: u32) -> TicketEntry {
        entry_ns(validity, 0)
    }
    fn s(secs: u64) -> Duration {
        Duration::from_secs(secs)
    }
    fn ms(millis: u64) -> Duration {
        Duration::from_millis(millis)
    }

    /// Sec 16.1: validity 0 -> expired at once (have_key false at any now) and never renewed.
    #[test]
    fn validity_zero_is_expired_and_requested_again() {
        let mut h = TicketHandler::new(4);
        h.install(entry(0), s(1000));
        assert_eq!(
            (h.expires(), h.renew_after()),
            (Duration::ZERO, Duration::ZERO)
        );
        for now in [Duration::ZERO, s(1000), s(u64::MAX - 1)] {
            assert!(!h.have_key(now), "have_key at now={now:?}");
            assert!(
                h.need_key(now),
                "an expired ticket is requested again (now={now:?})"
            );
        }
        // a later ticket with a real validity replaces it
        h.install(entry(3600), s(2000));
        assert!(h.have_key(s(2000)) && !h.need_key(s(2000)));
    }

    #[test]
    fn normal_validity_expires_and_renews_at_three_quarters() {
        let mut h = TicketHandler::new(4);
        h.install(entry(3600), s(1000));
        assert_eq!((h.expires(), h.renew_after()), (s(4600), s(3700)));
        assert!(h.have_key(s(4599)) && !h.have_key(s(4600)));
        assert!(!h.need_key(s(3699)) && h.need_key(s(3700)));
        assert!(h.need_key(s(4600)), "expired: requested again");
    }

    /// A monitor caps the TTL by its newest rotating key's remaining lifetime, so validity can be shorter than one
    /// second: the ticket is usable (and not requested again) until exactly that much time passed.
    #[test]
    fn subsecond_validity_is_usable_until_it_expires() {
        let mut h = TicketHandler::new(4);
        h.install(entry_ns(0, 500_000_000), s(1000) + ms(300));
        assert_eq!(h.expires(), s(1000) + ms(800));
        assert_eq!(h.renew_after(), h.expires(), "a quarter of 0 whole seconds");
        let now = s(1000) + ms(799);
        assert!(h.have_key(now) && !h.need_key(now));
        let now = s(1000) + ms(800);
        assert!(!h.have_key(now) && h.need_key(now));
    }

    /// The fractional part extends expiry; renewal subtracts a quarter of the whole seconds only.
    #[test]
    fn fractional_validity_keeps_nanoseconds() {
        let mut h = TicketHandler::new(4);
        h.install(entry_ns(10, 750_000_000), s(1000));
        assert_eq!(h.expires(), s(1010) + ms(750));
        assert_eq!(h.renew_after(), s(1008) + ms(250));
        assert!(h.have_key(s(1010) + ms(749)) && !h.have_key(s(1010) + ms(750)));
        assert!(!h.need_key(s(1008) + ms(249)) && h.need_key(s(1008) + ms(250)));
        // A non-normalized validity (nsec > 1e9) carries into expiry; renewal still uses the seconds field.
        h.install(entry_ns(1, 1_500_000_000), s(1000));
        assert_eq!(h.expires(), s(1002) + ms(500));
        assert_eq!(h.renew_after(), s(1002) + ms(250));
    }

    #[test]
    fn never_installed_needs_key_and_has_none() {
        let h = TicketHandler::new(4);
        assert!(h.need_key(Duration::ZERO) && !h.have_key(Duration::ZERO));
    }
}
