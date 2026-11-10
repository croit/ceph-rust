// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Borrowed local address projection; RC-ADDR60, msgr2 spec7.1.
use denc::types::EntityAddr;

#[derive(Clone, Copy, Debug)]
pub struct LocalAddresses<'a> {
    configured: &'a [EntityAddr],
    observed: Option<EntityAddr>,
}
impl<'a> LocalAddresses<'a> {
    pub(crate) fn new(configured: &'a [EntityAddr], observed: Option<EntityAddr>) -> Self {
        Self {
            configured,
            observed,
        }
    }
    /// Raw HELLO peer_addr: distinct from our advertised port and nonce.
    pub fn observed_by_peer(self) -> Option<EntityAddr> {
        self.observed
    }
    /// Same ordered identity vector used for CLIENT_IDENT/SESSION_RECONNECT.
    pub fn advertised(
        self,
    ) -> impl ExactSizeIterator<Item = EntityAddr> + DoubleEndedIterator + 'a {
        self.configured.iter().map(move |configured| {
            let mut address = *configured;
            // spec ip-addressing 3.3: only blank-IP entries of the learned address's family; an entry of the other
            // family stays blank (a family-less entry takes the learned family)
            if address.is_blank_ip()
                && let Some(observed) = self.observed
                && (address.family == 0 || address.family == observed.family)
            {
                address.family = observed.family;
                address.data = observed.data;
                address.data[..2].copy_from_slice(&configured.data[..2]);
                if address.ty == 0 {
                    address.ty = EntityAddr::TYPE_MSGR2;
                }
            }
            address
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn projection_preserves_configured_port_nonce_type_order_and_explicit_addresses() {
        let mut blank = EntityAddr::blank();
        blank.nonce = 4711;
        blank.data[..2].copy_from_slice(&6800u16.to_be_bytes());
        let explicit = EntityAddr::v4(EntityAddr::TYPE_ANY, 7, [192, 0, 2, 3], 99);
        let mut typed = blank;
        typed.ty = EntityAddr::TYPE_ANY;
        typed.nonce = 8;
        let configured = [blank, explicit, typed];
        let observed = EntityAddr::v4(EntityAddr::TYPE_LEGACY, 999, [10, 1, 2, 3], 40001);
        let view = LocalAddresses::new(&configured, Some(observed));
        let got = view.advertised().collect::<Vec<_>>();
        assert_eq!(
            got[0],
            EntityAddr::v4(EntityAddr::TYPE_MSGR2, 4711, [10, 1, 2, 3], 6800)
        );
        assert_eq!(got[1], explicit);
        assert_eq!(
            got[2],
            EntityAddr::v4(EntityAddr::TYPE_ANY, 8, [10, 1, 2, 3], 6800)
        );
        assert_eq!(view.observed_by_peer(), Some(observed));
        assert_eq!(view.advertised().len(), 3);
        assert_eq!(
            view.advertised().rev().collect::<Vec<_>>(),
            got.into_iter().rev().collect::<Vec<_>>()
        );
        assert_eq!(
            LocalAddresses::new(&configured, None)
                .advertised()
                .collect::<Vec<_>>(),
            configured
        );
        assert_eq!(configured[0], blank); // never mutate the source advertisement
    }
    /// Spec ip-addressing 3.3: the learned address fills blank entries of its own family only.
    #[test]
    fn learned_address_fills_only_blank_entries_of_its_family() {
        let observed = EntityAddr::v4(EntityAddr::TYPE_LEGACY, 5, [10, 1, 2, 3], 40000);
        let mut v4 = EntityAddr::v4(EntityAddr::TYPE_MSGR2, 21, [0; 4], 6800);
        v4.data[2..6].fill(0);
        let mut v6 = EntityAddr::v6(EntityAddr::TYPE_MSGR2, 21, [0; 16], 6802, 0);
        v6.data[6..22].fill(0);
        let got: Vec<_> = LocalAddresses::new(&[v4, v6], Some(observed))
            .advertised()
            .collect();
        assert_eq!(got[0].ipv4(), Some([10, 1, 2, 3]), "same family filled");
        assert_eq!(got[0].port(), 6800);
        assert_eq!(got[1].ipv6(), Some([0; 16]), "other family stays blank");
        // an IPv6 learned address fills only the v6 entry
        let observed = EntityAddr::v6(
            EntityAddr::TYPE_LEGACY,
            5,
            [0xfd, 0, 0, 0x77, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9],
            40001,
            0,
        );
        let got: Vec<_> = LocalAddresses::new(&[v4, v6], Some(observed))
            .advertised()
            .collect();
        assert_eq!(got[0].ipv4(), Some([0; 4]));
        assert_eq!(
            got[1].ipv6(),
            Some([0xfd, 0, 0, 0x77, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9])
        );
    }

    #[test]
    fn ipv6_scope_and_bytes_are_observed_but_advertised_port_nonce_stay_local() {
        let observed = EntityAddr::v6(2, 99, [7; 16], 49000, 41);
        let mut blank = EntityAddr::blank();
        blank.nonce = 23;
        let configured = [blank];
        let address = LocalAddresses::new(&configured, Some(observed))
            .advertised()
            .next()
            .unwrap();
        assert_eq!(address, EntityAddr::v6(2, 23, [7; 16], 0, 41));
        assert_eq!(
            LocalAddresses::new(&[], Some(observed)).advertised().len(),
            0
        );
        assert_eq!(LocalAddresses::new(&[], None).observed_by_peer(), None);
    }
}
