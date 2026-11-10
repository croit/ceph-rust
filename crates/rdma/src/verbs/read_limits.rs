// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Control-plane READ capability negotiation. No READ posting or source grant.
use super::{CoreHandles, Device, Endpoint, Qp, ffi};
use std::io;

/// Device upper bounds, not available resources or permission to read memory.
/// Peer values must belong to the authenticated peer of the same connection.
/// `initiator` is `max_qp_init_rd_atom`, `responder` is `max_qp_rd_atom` and
/// `max_sge` is `max_sge_rd` from `ibv_query_device`.
/// See <https://github.com/linux-rdma/rdma-core/blob/master/libibverbs/man/ibv_query_device.3>.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReadLimits {
    pub initiator: u32,
    pub responder: u32,
    pub max_sge: u32,
}

/// Negotiated local outgoing/incoming READ depths, bounded by both devices and
/// the verbs QP attributes width. Zero in a direction disables it. This is no
/// registration, memory grant, CQ retirement or data-visibility proof.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReadDepths {
    pub(super) outgoing: u8,
    pub(super) incoming: u8,
}

impl ReadLimits {
    /// Account for single-SGE READ support and the remote responder/initiator.
    /// Each direction is independent; a source-only endpoint can be a responder.
    pub fn negotiate(self, peer: Self) -> ReadDepths {
        let initiator = |caps: Self| if caps.max_sge == 0 { 0 } else { caps.initiator };
        ReadDepths {
            outgoing: initiator(self).min(peer.responder).min(u8::MAX.into()) as u8,
            incoming: self.responder.min(initiator(peer)).min(u8::MAX.into()) as u8,
        }
    }
}

impl ReadDepths {
    pub fn outgoing(self) -> u8 {
        self.outgoing
    }
    pub fn incoming(self) -> u8 {
        self.incoming
    }
}

impl Device {
    /// Query actual device READ capabilities. Control operation; default SEND
    /// setup does not call it. Provider/resource errors propagate without retries.
    pub fn read_limits(&self) -> io::Result<ReadLimits> {
        let (mut init, mut response, mut sge) = (0, 0, 0);
        // SAFETY: live device and three writable integers of the shim ABI.
        let rc = unsafe { ffi::rv_read_limits(self.p, &mut init, &mut response, &mut sge) };
        if rc != 0 {
            return Err(io::Error::from_raw_os_error(-rc));
        }
        let checked = |n| u32::try_from(n).map_err(|_| io::Error::from(io::ErrorKind::InvalidData));
        Ok(ReadLimits {
            initiator: checked(init)?,
            responder: checked(response)?,
            max_sge: checked(sge)?,
        })
    }
}

impl Qp {
    /// Prepare an INIT QP with READ capabilities queried once on the control
    /// thread. Responder access is enabled only for this explicit constructor.
    /// No MR/rkey is granted and no READ is posted by creating it.
    pub fn create_for_reads(
        dev: &std::sync::Arc<Device>,
        handles: CoreHandles,
        psn: u32,
    ) -> io::Result<Self> {
        let caps = dev.read_limits()?;
        Self::create_with_read_limits(dev, handles, psn, caps)
    }

    pub(crate) fn create_with_read_limits(
        dev: &std::sync::Arc<Device>,
        handles: CoreHandles,
        psn: u32,
        caps: ReadLimits,
    ) -> io::Result<Self> {
        let mut qp = Self::create_inner(dev, handles, psn, caps.responder > 0)?;
        qp.read_limits = Some(caps);
        Ok(qp)
    }

    pub(super) fn read_offer(&self, handles: &CoreHandles) -> Option<crate::ReadOffer> {
        let caps = self.read_limits?;
        let initiator = if caps.max_sge > 0 {
            caps.initiator.min(handles.cfg.sq_depth).min(u8::MAX.into()) as u8
        } else {
            0
        };
        let responder = caps.responder.min(u8::MAX.into()) as u8;
        (initiator != 0 || responder != 0).then_some(crate::ReadOffer {
            initiator,
            responder,
        })
    }

    /// Connect using the offer decoded from this authenticated peer's upgrade
    /// record. Either side lacking an explicit offer leaves READ disabled.
    /// This does not authorize an object protocol or grant access to any MR.
    pub fn connect_negotiated_reads(
        &self,
        handles: &CoreHandles,
        peer: &Endpoint,
    ) -> io::Result<ReadDepths> {
        match (self.read_limits, peer.reads) {
            (Some(_), Some(offer)) => self.connect_with_reads(
                handles,
                peer,
                ReadLimits {
                    initiator: offer.initiator.into(),
                    responder: offer.responder.into(),
                    max_sge: u32::from(offer.initiator != 0),
                },
            ),
            _ => {
                self.connect(handles, peer)?;
                Ok(ReadDepths::default())
            }
        }
    }

    /// Cached local capabilities of an explicitly prepared READ QP.
    pub fn local_read_limits(&self) -> Option<ReadLimits> {
        self.read_limits
    }

    /// INIT -> RTR -> RTS with separately supplied peer READ capabilities. The
    /// caller must authenticate them for `peer`. Normal upgrade control uses
    /// `connect_negotiated_reads` with the decoded endpoint offer instead.
    /// The provider may refuse resources even below reported upper bounds.
    pub fn connect_with_reads(
        &self,
        handles: &CoreHandles,
        peer: &Endpoint,
        peer_limits: ReadLimits,
    ) -> io::Result<ReadDepths> {
        let local = self.read_limits.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "QP was not prepared for READ capabilities",
            )
        })?;
        let mut depths = local.negotiate(peer_limits);
        // No READ can be admitted beyond the same connection's SQ capacity.
        let sq = handles.cfg.sq_depth.min(u8::MAX.into()) as u8;
        depths.outgoing = depths.outgoing.min(sq);
        self.connect_inner(handles, peer, depths.outgoing, depths.incoming)?;
        Ok(depths)
    }

    /// Successful setup's negotiated limits, cached for future admission. A
    /// connected default SEND/WRITE QP returns zero in both directions.
    pub fn read_depths(&self) -> ReadDepths {
        self.read_depths.get()
    }

    /// Query provider-programmed READ depths. Cold diagnostic, not an admission
    /// query for the hot path; providers can round supported attributes up.
    pub fn provider_read_depths(&self) -> io::Result<ReadDepths> {
        let (mut outgoing, mut incoming) = (0, 0);
        // SAFETY: live QP and two writable u8 values of the shim ABI.
        let rc = unsafe { ffi::rv_qp_read_depths(self.p, &mut outgoing, &mut incoming) };
        if rc != 0 {
            return Err(io::Error::from_raw_os_error(-rc));
        }
        Ok(ReadDepths { outgoing, incoming })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asymmetric_limits_intersect_in_opposite_directions() {
        let a = ReadLimits {
            initiator: 16,
            responder: 4,
            max_sge: 1,
        };
        let b = ReadLimits {
            initiator: 8,
            responder: 2,
            max_sge: 1,
        };
        assert_eq!(
            a.negotiate(b),
            ReadDepths {
                outgoing: 2,
                incoming: 4
            }
        );
        assert_eq!(
            b.negotiate(a),
            ReadDepths {
                outgoing: 4,
                incoming: 2
            }
        );
    }

    #[test]
    fn unsupported_initiator_preserves_source_only_responder() {
        let source = ReadLimits {
            initiator: 16,
            responder: 8,
            max_sge: 0,
        };
        let reader = ReadLimits {
            initiator: 4,
            responder: 2,
            max_sge: 1,
        };
        assert_eq!(
            source.negotiate(reader),
            ReadDepths {
                outgoing: 0,
                incoming: 4
            }
        );
        assert_eq!(
            reader.negotiate(source),
            ReadDepths {
                outgoing: 4,
                incoming: 0
            }
        );
        assert_eq!(
            ReadLimits::default().negotiate(reader),
            ReadDepths::default()
        );
    }

    #[test]
    fn attribute_width_is_a_bound_not_a_wrapping_conversion() {
        let caps = ReadLimits {
            initiator: u32::MAX,
            responder: u32::MAX,
            max_sge: 1,
        };
        assert_eq!(
            caps.negotiate(caps),
            ReadDepths {
                outgoing: u8::MAX,
                incoming: u8::MAX
            }
        );
    }
}
