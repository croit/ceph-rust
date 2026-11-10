// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Identity ownership for dispatches independent of their engine slot.
use super::{Request, RetainedRequest};
use bytes::Bytes;
use std::{fmt, hash::Hash, ops::Deref, sync::Arc};

#[derive(Clone, Copy)]
pub(super) enum IdentityField {
    Object,
    Namespace,
    Locator,
}
impl IdentityField {
    pub(super) fn bytes(self, request: &Request) -> &[u8] {
        let target = request.target();
        match self {
            Self::Object => &target.object,
            Self::Namespace => &target.namespace,
            Self::Locator => &target.locator,
        }
    }
}
#[derive(Clone)]
enum Owner {
    Request(Arc<RetainedRequest>, IdentityField),
    Bytes(Bytes),
}

/// Immutable dispatch identity bytes. Cloning retains the owner without copying
/// bytes. A dispatch may outlive its original engine slot, cancellation and
/// retries. This does not borrow a caller's C string or mutable Target selector.
/// It is not a registered READ destination grant and proves no provider completion.
///
/// Request input types still accept Vec identities. Constructing an explicit
/// replacement from Vec or Bytes transfers owned storage into this view.
#[derive(Clone)]
pub struct RequestIdentity(Owner);
impl RequestIdentity {
    pub(super) fn request(owner: &Arc<RetainedRequest>, field: IdentityField) -> Self {
        if field.bytes(owner).is_empty() {
            Self::default()
        } else {
            Self(Owner::Request(Arc::clone(owner), field))
        }
    }
}
impl Default for RequestIdentity {
    fn default() -> Self {
        Self(Owner::Bytes(Bytes::new()))
    }
}
impl From<Vec<u8>> for RequestIdentity {
    fn from(bytes: Vec<u8>) -> Self {
        Self(Owner::Bytes(bytes.into()))
    }
}
impl From<Bytes> for RequestIdentity {
    fn from(bytes: Bytes) -> Self {
        Self(Owner::Bytes(bytes))
    }
}
impl AsRef<[u8]> for RequestIdentity {
    fn as_ref(&self) -> &[u8] {
        match &self.0 {
            Owner::Request(owner, field) => field.bytes(owner),
            Owner::Bytes(bytes) => bytes,
        }
    }
}
impl Deref for RequestIdentity {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.as_ref()
    }
}
impl<B: AsRef<[u8]>> PartialEq<B> for RequestIdentity {
    fn eq(&self, other: &B) -> bool {
        self.as_ref() == other.as_ref()
    }
}
impl Eq for RequestIdentity {}
impl Hash for RequestIdentity {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_ref().hash(state);
    }
}
impl fmt::Debug for RequestIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("RequestIdentity")
            .field(&self.as_ref())
            .finish()
    }
}

impl PartialEq<RequestIdentity> for Vec<u8> {
    fn eq(&self, other: &RequestIdentity) -> bool {
        self.as_slice() == other.as_ref()
    }
}
