# Roadmap

## 0.1: Encrypted Prototype

- [x] Git repository and Apache-2.0 licensing.
- [x] Per-user manifests and isolated `CODEX_HOME` state.
- [x] Argon2id password derivation and envelope encryption.
- [x] Authenticated streaming vault format.
- [x] Codex subprocess launcher and automatic resealing.
- [x] Unit and integration tests for encryption and user isolation.
- [ ] Password rotation by rewrapping the data key.
- [ ] Explicit recovery-key design.
- [ ] Stale plaintext runtime scanner and secure cleanup command.

## 0.2: Linux Security Boundary

- Privileged `codex-vaultd` system service.
- PAM, LDAP, or OIDC authentication adapters.
- Dedicated UID, mount namespace, process group, and private runtime per session.
- Encrypted filesystem mount rather than archive extraction.
- Terminal proxy and clean environment construction.
- Audit events without prompt or transcript content.
- Installable `codex` shim with bypass detection.

## 0.3: Team Operations

- Per-user OpenAI credential policy and central API gateway option.
- Account disablement, session revocation, idle locking, and key rotation.
- Encrypted backup, restore, and optional administrator recovery.
- Per-user Git worktrees and shared-project access policy.
- Signed packages, reproducible builds, and dependency attestations.

## 1.0: Audited Release

- Stable vault format and documented migration policy.
- Independent cryptographic and system-security review.
- Fuzzing for vault parsing, archive extraction, and daemon IPC.
- Supported Linux distributions and hardened deployment guide.
- Incident response and private vulnerability-reporting channel.
