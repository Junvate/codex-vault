# Threat Model

Last reviewed: 2026-09-10.

## Assets

- Codex conversation history and session metadata.
- ChatGPT authentication tokens and API keys stored under `CODEX_HOME`.
- Codex configuration, logs, rules, and skills.
- The per-user data-encryption key.

## Intended Security Boundary

The target architecture protects one non-root server user from other non-root users by combining:

1. Application authentication.
2. A dedicated operating-system UID or container per user session.
3. A private encrypted `CODEX_HOME`.
4. A privileged launcher that controls unlocking, process creation, cleanup, and key lifetime.

Encryption alone is not a process-isolation mechanism. If two people share the same UID, the operating system treats them as the same principal.

## Version 0.1 Protected Scenarios

- An offline copy of `state.cvlt` without the password.
- Accidental use of another profile through `codex resume`.
- Modification, reordering, truncation, or extension of encrypted state.
- Concurrent attempts to unlock the same application profile.
- Profile directories or files with unsafe owner or group/world permissions.

## Version 0.1 Out of Scope

- A malicious person using the same Unix account while a vault is unlocked.
- Root, kernel, hypervisor, firmware, or physical-memory attacks.
- Malicious or compromised Codex, Node.js, npm dependencies, or operating system.
- Data intentionally or accidentally written outside `CODEX_HOME`.
- Network confidentiality beyond the protections supplied by Codex and OpenAI.
- Availability attacks, deletion, rollback to an older valid vault, and denial of service.

## Cryptographic Construction

- Password input is transformed into a 256-bit key with Argon2id and a unique 128-bit salt.
- A random 256-bit data key encrypts the user's Codex state.
- AES-256-GCM wraps the data key and authenticates the user identity, creation time, KDF parameters, format version, and vault version.
- State is divided into bounded frames from a random 96-bit nonce seed. Every frame authenticates the file header, frame type, sequence number, and plaintext length.
- A separately authenticated final frame makes complete-frame truncation detectable.

## Required Security Tests

- Wrong-password rejection without partial extraction.
- Ciphertext bit flips, frame reordering, truncation, and appended bytes.
- Archive path traversal and symbolic-link rejection.
- State isolation between two users.
- Crash cleanup and stale lock recovery.
- Password rotation and data-key rewrapping.
- Dedicated-UID process, `/proc`, signal, terminal, and filesystem isolation.
- Rollback detection once an authenticated monotonic state mechanism is designed.
