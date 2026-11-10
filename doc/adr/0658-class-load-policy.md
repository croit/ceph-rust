# 0658 Object class load and default lists are honoured

Status: accepted
Date: 2026-11-05

## Context

The classic OSD serves a class only if `osd_class_load_list` names it, and a plain `class-read`/`class-write` cap
reaches a class only if `osd_class_default_list` names it (`allow class NAME` reaches any loaded class). croit-flashstore-osd
registered its classes statically and treated every registered class as loaded and default-allowed (cls.md s2.1
"[V1]"), so an operator could not narrow the class set or the cap surface, and the upstream test probe `sdk` (on
neither Ceph list) was callable by any `allow rwx` client.

## Decision

- The static registry is the available set (the `.so` directory); the two options select from it at op classification.
- `osd_class_load_list`: a registered class not on it fails the whole message with `-EPERM` before caps are
  evaluated (a class outside the registry stays `-EPERM`, an unknown method of a loaded class `-EOPNOTSUPP`).
- `osd_class_default_list`: sets the `class_allowed` bit of each `call` need. With it, the grant's class-read/-write
  bits suffice; without it only `allow class NAME [METHOD]` (or `allow *`) reaches the class.
- Both options are whitespace-separated class names, `*` = every class (classic `in_class_list`), default = the 20
  classic names (cls.md s2.1), an empty value loads / default-allows nothing. Values are re-read on config change and
  apply to later messages of existing sessions.

## Rationale

The options are part of the pinned version's client-visible contract and the only way to gate classes the operator
does not use; the check is two set lookups per `call` op, off the data path. The registry cannot be narrowed at build
time because RGW/CephFS need the full set in the default configuration.

## Consequences

- + `sdk`/`lua`-style probes are not served by default; narrowing the lists removes classes from clients without a rebuild.
- + `allow rwx` no longer reaches a class the operator took off the default list; clients that relied on it need
  `allow class NAME`, as on classic.
- - A class added to the registry later does nothing until it is added to the default list of both options.

## Alternatives

- Build-time class selection: rejected, breaks RGW/CephFS parity in the default binary.
- Keeping the "[V1]" behaviour (registry = both lists): rejected, leaves the operator gate unimplemented (security
  review K-3).
