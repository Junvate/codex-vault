# Daemon Protocol

Status: `v0.2.0-alpha.1`. The current protocol is a security boundary prototype, not a complete
privileged launcher.

## Transport

- Linux Unix domain socket with an absolute path.
- Socket parent directory must be owned by the daemon UID and inaccessible to group/other users.
- Socket mode is `0600`.
- The server reads peer PID, UID, and GID from Linux `SO_PEERCRED`; client-supplied identity fields
  are never trusted.
- Each connection carries one request and one response.
- Client and server socket reads and writes have a five-second timeout in the alpha service.

## Framing

Messages use a four-byte big-endian length followed by UTF-8 JSON. Frames must contain between 1
and 16,384 bytes. Oversized, truncated, malformed, and unknown-field messages are rejected before
dispatch.

Protocol version `1` supports only a status request. The response reports the daemon version,
kernel-authenticated peer identity, daemon UID, and explicit enabled/disabled capability states.

## Alpha Capability Boundary

`v0.2.0-alpha.1` implements:

- Versioned bounded framing.
- Strict request and response schemas.
- Linux kernel peer-credential checks.
- Private socket creation, stale-socket recovery, and inode-aware cleanup.
- Foreground service operation with graceful `SIGINT` and `SIGTERM` shutdown.

It does not send passwords, keys, tokens, or decrypted Codex state over IPC. PAM authentication,
dedicated session UIDs, encrypted mounts, privilege separation, and Codex process creation remain
disabled and are reported as `disabled` capabilities.

Before secret-bearing requests are added, the protocol requires a dedicated authentication state
machine, request binding to peer credentials, replay handling, cancellation semantics, and tests
for partial writes, disconnects, resource exhaustion, and confused-deputy behavior.
