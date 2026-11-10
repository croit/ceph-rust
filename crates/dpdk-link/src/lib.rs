// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 croit GmbH
// SPDX-FileContributor: Martin Verges, croit GmbH
// SPDX-FileContributor: Igor Fedotov, croit GmbH
// SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
//! Single owner of the native DPDK link line (see build.rs). Contains no code: depend on it with the feature
//! (`spdk`) and the archives are linked exactly once, however many crates in the build need DPDK.
