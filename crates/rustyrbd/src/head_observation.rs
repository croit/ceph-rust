// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
//! Coherent observations of one image head object, before opening it.

use crate::{
    FEATURE_LAYERING, FEATURE_OPERATIONS, FEATURE_STRIPING_V2, ImageGroupSpec, ImageHeader,
    ImageSnapContext, ParentSpec, StripeGeometry, Versioned,
};

/// Why independently observed fields cannot describe one head version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeadObservationError {
    /// One reply belongs to a different version of the same header object.
    VersionChanged {
        field: &'static str,
        expected: u64,
        observed: u64,
    },
    /// STRIPINGV2 and the conditional stripe query disagree.
    StripeGeometryMismatch,
    /// OPERATIONS and the conditional operation-features query disagree.
    OperationFeaturesMismatch,
    /// An overlap was returned without a parent or past the captured image end.
    InvalidParentOverlap,
    /// A parent was returned while the LAYERING feature is absent.
    ParentWithoutLayering,
}

impl std::fmt::Display for HeadObservationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::VersionChanged {
                field,
                expected,
                observed,
            } => write!(
                f,
                "RBD header changed while reading {field}: expected version {expected}, observed {observed}"
            ),
            Self::StripeGeometryMismatch => f.write_str("RBD stripe feature and geometry disagree"),
            Self::OperationFeaturesMismatch => {
                f.write_str("RBD operations feature and observation disagree")
            }
            Self::InvalidParentOverlap => f.write_str("RBD head parent overlap is inconsistent"),
            Self::ParentWithoutLayering => {
                f.write_str("RBD parent exists without layering feature")
            }
        }
    }
}

impl std::error::Error for HeadObservationError {}

/// One coherent set of values from `rbd_header.<id>`. This does not grant
/// image access, parent data or write ownership after the last observation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeadObservation {
    header: ImageHeader,
    snap_context: ImageSnapContext,
    flags: u64,
    parent: Option<ParentSpec>,
    parent_overlap: Option<u64>,
    group: Option<ImageGroupSpec>,
    stripe: Option<StripeGeometry>,
    op_features: Option<u64>,
    user_version: u64,
}

/// Independently completed header getters to validate as one observation.
#[derive(Debug)]
pub struct HeadInputs {
    pub header: Versioned<ImageHeader>,
    pub snap_context: Versioned<ImageSnapContext>,
    pub flags: Versioned<u64>,
    pub parent: Versioned<Option<ParentSpec>>,
    pub parent_overlap: Versioned<Option<u64>>,
    pub group: Versioned<Option<ImageGroupSpec>>,
    pub stripe: Option<Versioned<StripeGeometry>>,
    pub op_features: Option<Versioned<u64>>,
}

impl HeadObservation {
    /// Accept separately read head metadata only when every reply describes
    /// the same header user version and the conditional fields agree.
    pub fn assemble(inputs: HeadInputs) -> Result<Self, HeadObservationError> {
        let HeadInputs {
            header,
            snap_context,
            flags,
            parent,
            parent_overlap,
            group,
            stripe,
            op_features,
        } = inputs;
        let version = header.user_version;
        for (field, observed) in [
            ("snapcontext", snap_context.user_version),
            ("flags", flags.user_version),
            ("parent", parent.user_version),
            ("parent overlap", parent_overlap.user_version),
            ("image group", group.user_version),
        ] {
            if observed != version {
                return Err(HeadObservationError::VersionChanged {
                    field,
                    expected: version,
                    observed,
                });
            }
        }
        if let Some(geometry) = &stripe
            && geometry.user_version != version
        {
            return Err(HeadObservationError::VersionChanged {
                field: "stripe geometry",
                expected: version,
                observed: geometry.user_version,
            });
        }
        if let Some(observed) = &op_features
            && observed.user_version != version
        {
            return Err(HeadObservationError::VersionChanged {
                field: "operation features",
                expected: version,
                observed: observed.user_version,
            });
        }
        if (header.value.features & FEATURE_STRIPING_V2 != 0) != stripe.is_some() {
            return Err(HeadObservationError::StripeGeometryMismatch);
        }
        if (header.value.features & FEATURE_OPERATIONS != 0) != op_features.is_some() {
            return Err(HeadObservationError::OperationFeaturesMismatch);
        }
        if parent.value.is_some() && header.value.features & FEATURE_LAYERING == 0 {
            return Err(HeadObservationError::ParentWithoutLayering);
        }
        if parent_overlap
            .value
            .is_some_and(|overlap| parent.value.is_none() || overlap > header.value.size)
        {
            return Err(HeadObservationError::InvalidParentOverlap);
        }
        Ok(Self {
            header: header.value,
            snap_context: snap_context.value,
            flags: flags.value,
            parent: parent.value,
            parent_overlap: parent_overlap.value,
            group: group.value,
            stripe: stripe.map(|geometry| geometry.value),
            op_features: op_features.map(|observed| observed.value),
            user_version: version,
        })
    }

    /// Version shared by these successful reads of the same header object.
    pub fn user_version(&self) -> u64 {
        self.user_version
    }

    /// Immutable image geometry and feature fields.
    pub fn header(&self) -> &ImageHeader {
        &self.header
    }

    /// Snapshot context required later for image data writes.
    pub fn snap_context(&self) -> &ImageSnapContext {
        &self.snap_context
    }

    /// Head flags, including invalid object-map and fast-diff bits.
    pub fn flags(&self) -> u64 {
        self.flags
    }

    /// Parent identity retained for snapshots even if head overlap is absent.
    pub fn parent(&self) -> Option<&ParentSpec> {
        self.parent.as_ref()
    }

    /// Head overlap range; `None` means no head bytes use the parent.
    pub fn parent_overlap(&self) -> Option<u64> {
        self.parent_overlap
    }

    /// Group reference captured during image open, if one exists.
    pub fn group(&self) -> Option<&ImageGroupSpec> {
        self.group.as_ref()
    }

    /// Captured STRIPINGV2 geometry, if the feature is enabled.
    pub fn stripe(&self) -> Option<StripeGeometry> {
        self.stripe
    }

    /// Captured operation bits if FEATURE_OPERATIONS is enabled.
    pub fn op_features(&self) -> Option<u64> {
        self.op_features
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observations(version: u64) -> HeadInputs {
        HeadInputs {
            header: Versioned {
                value: ImageHeader {
                    order: 22,
                    size: 8192,
                    features: FEATURE_LAYERING,
                    incompatible_features: 0,
                    object_prefix: b"rbd_data.child1".to_vec(),
                    data_pool_id: -1,
                },
                user_version: version,
            },
            snap_context: Versioned {
                value: ImageSnapContext {
                    sequence: 9,
                    ids: vec![9],
                },
                user_version: version,
            },
            flags: Versioned {
                value: 0,
                user_version: version,
            },
            parent: Versioned {
                value: Some(ParentSpec {
                    pool: 23,
                    namespace: b"ns".to_vec(),
                    image_id: b"parent1".to_vec(),
                    snapshot_id: 5,
                }),
                user_version: version,
            },
            parent_overlap: Versioned {
                value: Some(4096),
                user_version: version,
            },
            group: Versioned {
                value: None,
                user_version: version,
            },
            stripe: None,
            op_features: None,
        }
    }

    #[test]
    fn coherent_head_retains_parent_and_snapshot_context() {
        let view = HeadObservation::assemble(observations(37)).unwrap();
        assert_eq!(view.user_version(), 37);
        assert_eq!(view.header().size, 8192);
        assert_eq!(view.snap_context().ids, [9]);
        assert_eq!(view.parent().unwrap().image_id, b"parent1");
        assert_eq!(view.parent_overlap(), Some(4096));
        assert_eq!(view.group(), None);
    }

    #[test]
    fn changed_header_version_never_publishes_a_bundle() {
        let mut inputs = observations(37);
        inputs.flags.user_version = 38;
        assert_eq!(
            HeadObservation::assemble(inputs),
            Err(HeadObservationError::VersionChanged {
                field: "flags",
                expected: 37,
                observed: 38
            })
        );
    }

    #[test]
    fn group_observation_must_match_the_header_version() {
        let mut inputs = observations(37);
        inputs.group.user_version = 38;
        assert_eq!(
            HeadObservation::assemble(inputs),
            Err(HeadObservationError::VersionChanged {
                field: "image group",
                expected: 37,
                observed: 38,
            })
        );
    }

    #[test]
    fn rejects_inconsistent_parent_and_conditional_stripe() {
        let mut inputs = observations(37);
        inputs.parent.value = None;
        assert_eq!(
            HeadObservation::assemble(inputs),
            Err(HeadObservationError::InvalidParentOverlap)
        );
        let mut inputs = observations(37);
        inputs.header.value.features |= FEATURE_STRIPING_V2;
        assert_eq!(
            HeadObservation::assemble(inputs),
            Err(HeadObservationError::StripeGeometryMismatch)
        );
    }

    #[test]
    fn conditional_operation_bits_require_the_same_header_version() {
        let mut inputs = observations(37);
        inputs.header.value.features |= FEATURE_OPERATIONS;
        assert_eq!(
            HeadObservation::assemble(HeadInputs {
                header: inputs.header.clone(),
                snap_context: inputs.snap_context.clone(),
                flags: inputs.flags.clone(),
                parent: inputs.parent.clone(),
                parent_overlap: inputs.parent_overlap.clone(),
                group: inputs.group.clone(),
                stripe: None,
                op_features: None,
            }),
            Err(HeadObservationError::OperationFeaturesMismatch)
        );
        inputs.op_features = Some(Versioned {
            value: 3,
            user_version: 38,
        });
        assert_eq!(
            HeadObservation::assemble(HeadInputs {
                header: inputs.header.clone(),
                snap_context: inputs.snap_context.clone(),
                flags: inputs.flags.clone(),
                parent: inputs.parent.clone(),
                parent_overlap: inputs.parent_overlap.clone(),
                group: inputs.group.clone(),
                stripe: None,
                op_features: inputs.op_features.clone(),
            }),
            Err(HeadObservationError::VersionChanged {
                field: "operation features",
                expected: 37,
                observed: 38,
            })
        );
        inputs.op_features.as_mut().unwrap().user_version = 37;
        let view = HeadObservation::assemble(inputs).unwrap();
        assert_eq!(view.op_features(), Some(3));
    }
}
