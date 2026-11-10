# 0098: io_uring capability detection
Status: accepted
Date: 2026-10-14
Supersedes: the kernel-version startup gate in ADR 0053.

Context: kernel release numbers do not identify distribution backports, build configuration, or runtime restrictions. The kernel TCP transport requires multishot accept/receive and provided buffers; opcode probing alone cannot identify multishot modifiers.

Decision:
- No release-number gate. Create the actual transport ring, retaining setup-flag fallbacks and unavailable/permission diagnostics.
- Require `IORING_FEAT_EXT_ARG` for bounded idle waits; probe required ACCEPT, RECV, SENDMSG, CONNECT, LINK_TIMEOUT, ASYNC_CANCEL and READ opcodes.
- Use a separate small scratch ring and provided-buffer group to exercise multishot accept and receive on a private loopback TCP connection. Require successful completions with MORE, buffer selection and correct received data. Bound each completion wait to one second.
- Close the scratch ring before freeing its buffer storage on success and failure. No startup-test requests enter the production ring.
- Keep optional zero-copy send and NAPI detection unchanged. Report failed capabilities without asserting a minimum kernel release.

Consequences: backported implementations can qualify; unavailable or restricted io_uring fails startup. Each core adds a small ring and loopback connection during startup; the data path is unchanged. This probe verifies required multishot behavior, not every kernel implementation detail or future runtime resource failure.
