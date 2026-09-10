# Changelog

All notable changes to this project will be documented in this file.

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
