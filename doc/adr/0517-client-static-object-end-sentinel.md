<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# 0517 Public object-list end sentinel has independent static state

Status: accepted
Date: 2026-10-22

## Context

The source-qualified nobject-end-data-contract.md identifies current public
NObjectIterator static data in both versions. A null implementation is a default
iterator, distinct from an initialized contextless end iterator. The replacement
currently omits the data export and conflates those states.

## Decision

Export the exact current symbol as pointer-sized NObjectIterator object storage.
Its private implementation is a fully initialized static, contextless state.
The public object and private state use constant initialization; no heap owner,
cluster handle, startup allocation or destructor registration is needed.
Public copies allocate independent owned implementations and use normal iterator
destruction. Borrowed static storage is never transferred into an owned copy.

Compare missing implementation pointers by pointer identity. For two initialized
implementations, compare live contexts by identity; a contextless implementation
matches another contextless implementation or an exhausted listing. Default
iterators therefore remain distinct from the initialized static end marker.

## Rationale

Application ABI requires the exported object, stable reference identity and
state/ownership behavior. Reproducing the reference's private startup allocation
adds no required behavior. Static ownership expresses the end marker's lifetime
without a leaked allocation, alternate runtime or special-case destructor.

## Consequences

- Public direct data references and nobjects_end designate one object.
- Copies, assignment and default/end comparison preserve the pinned contracts.
- Artifact storage differs: initialized data instead of the reference's BSS plus
  dynamic constructor. Size/alignment and application-visible ready state match.
- Verify the actual ELF export and independent-consumer symbol/reference binding;
  unit construction alone is not an ELF or unchanged-consumer qualification.
- Library teardown owns no heap/listing resource for the static sentinel.

## Alternatives

- Omit the data export: direct current-ABI consumers cannot link/load.
- Export a null placeholder: changes default/end comparison.
- Allocate at startup and register destruction: unnecessary private machinery.

## Open questions

Both profiles passed independent GLOB_DAT and COPY-relocation consumers on the
build host. Exact dynamic symbols, pointer-sized data, stable reference identity,
default/end distinction and owned copies were checked in the built own ELF.
Versioned package and wider unchanged-consumer qualification remain separate.
