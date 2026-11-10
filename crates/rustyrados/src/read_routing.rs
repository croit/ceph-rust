// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Borrowed read shape for placement; request payload ownership stays in the queue.
use opwire::{Extent, OsdOp};

#[derive(Clone, Copy, Debug)]
pub enum ReadOperations<'a> {
    Scalar { offset: u64, length: u64 },
    Compound(&'a [OsdOp]),
}
impl ReadOperations<'_> {
    pub fn visit(self, mut visitor: impl FnMut(u16, Extent)) {
        match self {
            Self::Scalar { offset, length } => visitor(
                opwire::op::READ,
                Extent {
                    offset,
                    length,
                    ..Default::default()
                },
            ),
            Self::Compound(operations) => {
                for operation in operations {
                    visitor(operation.op, operation.extent());
                }
            }
        }
    }
}
#[derive(Clone, Copy, Debug)]
pub struct ReadRouting<'a> {
    pub operations: ReadOperations<'a>,
    pub snapid: u64,
    pub empty_write_context: bool,
    /// Routing must preserve authoritative object-version publication.
    pub version_required: bool,
    /// Conservatively classified class mutations cannot fan out an atomic op.
    pub may_write: bool,
}

/// Operations whose output belongs to the reference shard of a split.
pub fn is_primary_only_split_read(code: u16) -> bool {
    matches!(
        code,
        opwire::op::GETXATTRS
            | opwire::op::CHECKSUM
            | opwire::op::GETXATTR
            | opwire::op::STAT
            | opwire::op::CMPXATTR
            | opwire::op::CALL
    )
}
impl ReadRouting<'_> {
    pub fn split_eligible(self, flags: u32) -> bool {
        use opwire::{flag, op};
        if flags & (flag::READ | flag::WRITE | flag::BALANCE_READS | flag::RWORDERED)
            != (flag::READ | flag::BALANCE_READS)
            || self.snapid != opwire::NOSNAP
            || !self.empty_write_context
            || self.may_write
        {
            return false;
        }
        let mut data = false;
        let mut valid = true;
        self.operations.visit(|code, extent| {
            if matches!(code, op::READ | op::SPARSE_READ) {
                data = true;
                valid &=
                    extent.length != 0 && extent.offset.checked_add(extent.length - 1).is_some();
            } else {
                valid &= is_primary_only_split_read(code);
            }
        });
        data && valid
    }
}
