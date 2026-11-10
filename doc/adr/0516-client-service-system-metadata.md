<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0516 Service registrations collect host metadata independently

Status: accepted
Date: 2026-10-22

## Context

Both reference versions collect system metadata before merging application
service metadata. The adapter currently supplies only hostname, omitting fields
visible to manager modules and applications.

## Decision

Collect Linux system metadata independently from uname, environment and the
source-specified proc, cgroup and distribution inputs. Preserve raw bytes,
probe omission rules and automatic-key precedence. Use the pinned compatibility
version for ceph_version_short and its release name for ceph_release; retain the
documented debug-version override. Identify the implementation honestly in
ceph_version as `rustyrados <package-version> (Ceph compatibility <version>)`.
Do not claim a Ceph implementation Git revision or build identity.
Parse complete distribution lines instead of reproducing fixed-buffer fragments.

## Rationale

Manager-visible host/container/resource identity is part of service registration.
Version metadata must distinguish this independent implementation. Complete-line
parsing removes reference truncation without changing ordinary valid inputs.

## Consequences

- + Required host, container and platform fields are populated when available.
- + Applications retain ownership of caller-only metadata keys.
- - Full implementation-version text differs intentionally from stock librados.
- + Overlong distribution values remain intact instead of fragmenting.

## Alternatives

- Hostname alone: omits observable supported metadata.
- Claim the reference binary's revision/build: misidentifies the implementation.
- Copy the platform collector: prohibited by ADR0003.

## Open questions

None for Linux collection; non-Linux runtime qualification is separate from the
Linux build-host gates.
