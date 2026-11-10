# ADR0305: current pinned ABI scope
Status: accepted. Date: 2026-10-17. Supersedes the historical-behavior scope of 0304 (RC190; former ADR 0247 folded into specs, no file).
User explicitly confirms current ABI suffices; historical binary compatibility is
not required. Target unchanged programs built against pinned Ceph v20.2.4 / v21.2.0 current (21.1.2 replaced by 21.2.0, 2026-10-30; adr 0306)
headers/default symbol versions. Retain currently imported LIBRADOS_14.2.0 default
symbols, SONAME2 and current128byte pool statistics. Omit historical unversioned
aliases/96byte writer/TMAP engine. Current TMAP defaults remain unsupported as pin.
Keep independent staticlib/localize/final-link packaging proven by own ELF probe;
only current aliases emitted. No Ceph linkage/forwarding, global install or push.
Current C++/foreign-context ABI and remaining application/platform/fault/resource
qualification remain explicit gates. Version labels/namespaces mentioning14.2.0
are current API when selected by pinned headers, not automatically legacy.
