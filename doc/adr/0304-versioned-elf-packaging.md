# ADR0304: independent versioned ELF packaging
Status: accepted; historical-behavior scope superseded by 0305 (RC191). Date: 2026-10-17.
Context: four pinned C exports have historical base and default14.2.0 versions;
base pool statistics writes96bytes vs modern128. Raw Rust cdylib is insufficient.
Decision: own staticlib, partial link, localize non-API globals, assembly aliases
and explicit named-node final ELF link. Preserve unversioned other C exports.
Own standalone linker/loader probe rc190b verified unchanged old unversioned\nconsumer96 and modern default-version consumer128 against the same artifact; no original
implementation linkage/forwarding or ELF binary patching. Spec190; native ARM and
C++/foreign contexts remain separate gates. Compatibility needed historical behavior
implemented on existing native operations, never a new legacy storage subsystem.
