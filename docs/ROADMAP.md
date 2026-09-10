# Roadmap

Last updated: 2026-09-10.

## v0.1: Rust CLI Baseline

- [x] Rust CLI launcher.
- [x] User registration and password login.
- [x] Independent encrypted `CODEX_HOME` per user.
- [x] UID ownership and private permission checks.
- [x] Argon2id password derivation and per-user envelope encryption.
- [x] Authenticated streaming vault format.
- [x] System file locks and automatic resealing after Codex exits.
- [x] Tests for tampering, truncation, user isolation, permissions, and process launch.
- [ ] Password rotation by rewrapping the data key.
- [ ] Stale plaintext runtime scanner and recovery command.

## v0.2: Daemon And OS Isolation

- Background `codex-vaultd` service.
- Dedicated UID for every active user session.
- PAM authentication.
- Automatic encrypted-directory mount and unmount.
- Private process group, mount namespace, environment, and runtime.
- Installable `codex` shim with bypass detection.

## v0.3: Container And Workspace Isolation

- Container isolation for Codex processes.
- Per-user Git worktrees.
- Idle session locking and termination.
- Abnormal-exit detection and recovery.
- Plaintext runtime inventory and cleanup after crashes or restarts.

## v0.4: Organization Management

- LDAP and OIDC authentication.
- Administrator console.
- Account disablement and active-session revocation.
- Password, data-key, and master-key rotation.
- Encrypted backup, restore, and optional administrator recovery.
- Per-user OpenAI credential and usage policy.

## v1.0: Audited Release

- Independent cryptographic and system-security audit.
- Final threat model and hardened deployment guide.
- Fuzzing for vault parsing, archive extraction, daemon IPC, and authentication messages.
- Signed installation packages and release artifacts.
- Reproducible builds, dependency attestations, and incident-response process.
