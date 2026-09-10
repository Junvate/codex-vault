# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

- Extended real-Codex regression coverage to reject Bob's explicit Alice thread ID without
  contacting the fixture provider, and verify Alice can resume that same ID with her own history.

- Added Linux and macOS real-Codex compatibility CI using version 0.153.4 release archives with
  pinned SHA-256 verification; both file-auth and exec/resume tests run explicitly without credentials.

- Made explicit runtime overrides fail closed instead of silently falling back to another directory.
  Environment and library overrides require absolute paths and share canonical private-root checks.
- Added isolated-process coverage for environment selection and regressions for invalid paths,
  unchanged shared directories, and profile-lock release after rejecting a runtime override.

- Fixed real Codex 0.153.4 resume failures after a Vault close/reopen by using stable per-profile
  runtime paths under a canonical runtime root; directories are still created exclusively.
- Refused pre-existing runtime directories/files/symlinks without modifying them.
- Removed plaintext runtime before releasing the profile lock and propagated cleanup errors.
- Added opt-in real-Codex exec/resume tests against a loopback Responses fixture, plus stable-path
  and stale-path regressions. No real credentials or model service are needed.
- Older sessions created under random paths and runtime-root relocation still require migration;
  no automatic database rewriting is performed.

## 0.2.0-alpha.1 - 2026-09-10

- Added the `codex-vaultd` foreground Linux daemon and `codex-vault daemon status` client.
- Added a versioned, 16 KiB-bounded Unix socket protocol with strict JSON schemas.
- Added Linux `SO_PEERCRED` PID/UID/GID validation and a same-UID default policy.
- Added private socket permissions, stale-socket recovery, inode-aware cleanup, and graceful signal
  shutdown.
- Kept PAM, dedicated UID execution, encrypted mounts, secret transport, and Codex launching
  disabled behind explicit capability flags.
- Added Linux integration tests for protocol versions, peer rejection, socket permissions, and
  stale path handling.
- Updated GitHub Actions checkout to the Node 24-based v7 release.
- Configured the operating-system test matrix to report every platform result independently.

## 0.1.2 - 2026-09-10

- Refused pre-existing private-storage and runtime directories with unsafe permissions instead of
  silently changing their mode.
- Added regression tests proving shared directories remain unchanged after rejection.

## 0.1.1 - 2026-09-10

- Added atomic password rotation that rewraps the existing per-user data key.
- Preserved encrypted state bytes during password changes and blocked rotation while a profile is active.
- Classified authenticated-stream failures as vault integrity errors at the CLI boundary.
- Added regression coverage for authenticated frame reordering, archive path traversal, stale lock contents, and password rotation rollback.
- Added the independent Ubuntu 22.04 validation report for v0.1.0.

## 0.1.0 - 2026-09-10

- Replaced the initial TypeScript design prototype with a Rust CLI and reusable Rust library.
- Added Argon2id key derivation and per-user envelope encryption.
- Added chunked AES-256-GCM vault storage with integrity checks.
- Added the Codex launcher, private runtime handling, signal forwarding, and system file locks.
- Added UID ownership and private permission enforcement.
- Added key-buffer zeroization for controlled secret lifetimes.
- Stabilized manifest authentication with a fixed binary associated-data encoding.
- Upgraded the pre-release vault format to `cdxvlt02` with a 96-bit random nonce seed.
- Added security limitations, threat model, roadmap, and automated tests.
