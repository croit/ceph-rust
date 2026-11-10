<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 croit GmbH -->
<!-- SPDX-FileContributor: Martin Verges, croit GmbH -->
# Journal EventEntry reference vectors

The numbered files are `librbd::journal::EventEntry` dencoder test instances
1–30 emitted by the `quay.io/ceph/ceph:v21.2.0` container. Regenerate into a
new private directory with `lab/rustyrbd/journal-event-vectors.sh`; the script
also exports reference JSON for inspecting the selected instance semantics.
The vectors cover the instances exposed by that release, not every valid event
or the journal data-object envelope.
