// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
use crate::AdmissionError;
use denc::{Encode, Encoder, types::Hobject};

/// OSD-evaluated predicate. Binary arguments retain their wire meaning.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ListFilter {
    /// Raw store attribute: user xattr `name` is `_name`. Missing nonempty key rejects.
    /// Empty key compares an empty value, so empty key/value matches every candidate.
    Plain { raw_xattr: Vec<u8>, value: Vec<u8> },
    /// Opaque `class.filter` plus caller-serialized arguments, without an outer length.
    Class { name: Vec<u8>, parameters: Vec<u8> },
}
impl ListFilter {
    pub(crate) fn retained_bytes(&self) -> Option<u64> {
        let (a, b) = match self {
            Self::Plain { raw_xattr, value } => (raw_xattr, value),
            Self::Class { name, parameters } => (name, parameters),
        };
        (a.capacity() as u64).checked_add(b.capacity() as u64)
    }
    fn prefix_len(&self) -> Option<u64> {
        let (base, a, b) = match self {
            Self::Plain { raw_xattr, value } => (33, raw_xattr, value),
            Self::Class { name, parameters } => (20, name, parameters),
        };
        (base as u64)
            .checked_add(a.len() as u64)?
            .checked_add(b.len() as u64)
    }
    pub(crate) fn request_charge(&self) -> Option<u64> {
        self.retained_bytes()?.checked_add(self.prefix_len()?)
    }
    pub(crate) fn validate(&self) -> Result<(), AdmissionError> {
        let invalid = AdmissionError::InvalidOperation;
        let (a, b) = match self {
            Self::Plain { raw_xattr, value } => (raw_xattr, value),
            Self::Class { name, parameters } => {
                if !name
                    .iter()
                    .position(|&b| b == b'.')
                    .is_some_and(|i| i > 0 && i + 1 < name.len())
                {
                    return Err(invalid);
                }
                (name, parameters)
            }
        };
        if a.len() > u32::MAX as usize
            || b.len() > u32::MAX as usize
            || self.prefix_len().is_none_or(|n| n > u32::MAX as u64)
        {
            return Err(invalid);
        }
        Ok(())
    }
    pub(crate) fn payload_len(&self, cursor: &Hobject) -> Option<u64> {
        self.prefix_len()?
            .checked_add(39)?
            .checked_add(cursor.key.len() as u64)?
            .checked_add(cursor.oid.len() as u64)?
            .checked_add(cursor.nspace.len() as u64)
    }
    pub(crate) fn wire_op(&self, count: u32, cursor: &Hobject) -> opwire::OsdOp {
        let mut e =
            Encoder::with_capacity(self.payload_len(cursor).expect("validated length") as usize);
        e.bytes(b"pg").expect("vec");
        e.bytes(b"filter").expect("vec");
        match self {
            Self::Plain { raw_xattr, value } => {
                e.bytes(b"plain").expect("vec");
                e.bytes(raw_xattr).expect("vec");
                e.bytes(value).expect("vec");
            }
            Self::Class { name, parameters } => {
                e.bytes(name).expect("vec");
                e.raw(parameters).expect("vec");
            }
        }
        cursor.encode(&mut e).expect("validated cursor");
        let mut op = opwire::OsdOp::new(opwire::op::PGNLS_FILTER);
        op.set_pgls(opwire::Pgls {
            count: count as u64,
            start_epoch: 0,
        });
        op.indata = e.into_vec().into();
        op
    }
}
