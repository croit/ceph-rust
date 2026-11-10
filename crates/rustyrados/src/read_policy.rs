// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Captured client-wide read policy, distinct from explicit operation flags.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ReplicaReadPolicy {
    #[default]
    Default,
    Balance,
    Localize,
}
impl ReplicaReadPolicy {
    pub fn flags(self) -> u32 {
        match self {
            Self::Default => 0,
            Self::Balance => opwire::flag::BALANCE_READS,
            Self::Localize => opwire::flag::LOCALIZE_READS,
        }
    }
    pub fn from_flags(flags: u32) -> Option<Self> {
        match flags {
            0 => Some(Self::Default),
            opwire::flag::BALANCE_READS => Some(Self::Balance),
            opwire::flag::LOCALIZE_READS => Some(Self::Localize),
            _ => None,
        }
    }
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "default" => Some(Self::Default),
            "balance" => Some(Self::Balance),
            "localize" => Some(Self::Localize),
            _ => None,
        }
    }
}
