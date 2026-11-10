<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# Journal Entry reference vectors

These are `journal::Entry` dencoder test instances 1 and 2 emitted by the
`quay.io/ceph/ceph:v21.2.0` container. Export them into a new private
directory with `lab/rustyrbd/journal-event-vectors.sh OUTPUT --type entry`.
They cover empty and nonempty data with reference CRC values.
