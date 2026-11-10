// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Class `rgw` (spec/cls_rgw.md): bucket-index shard methods (index, OLH/versioning, raw `bi_*`,
//! bilog, reshard), lc, usage, legacy gc, multipart and data-pool object helpers.

pub mod bi;
pub mod gc;
pub mod index;
pub mod keys;
pub mod lc;
pub mod mp;
pub mod obj;
pub mod olh;
pub mod reshard;
pub mod types;
pub mod usage;
