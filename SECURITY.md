# Security Policy

Codex Vault is currently a security prototype and has not received an independent audit. Do not use version 0.1 as the sole control for regulated, highly sensitive, or adversarial multi-user environments.

## Version 0.1 Guarantee

When a user is logged out and the runtime directory has been removed, Codex state is protected at rest by a password-wrapped random data key and authenticated encryption. Incorrect passwords and modified, reordered, truncated, or extended ciphertext are rejected.

## Version 0.1 Limitations

- A person with the same operating-system UID can inspect another user's processes and runtime files while that user is active.
- A root user, kernel administrator, hypervisor administrator, or compromised host can read unlocked data.
- `SIGKILL`, power loss, kernel panic, or runtime failure can leave a plaintext runtime directory behind.
- Files Codex writes outside `CODEX_HOME`, including shared repositories, shell history, caches, and editor state, are outside the vault.
- Rust-owned password and key buffers are cleared where possible, but operating-system, terminal, allocator, dependency, and process copies cannot be proven absent.
- Usernames and creation timestamps are metadata and are not encrypted.

For hostile shared-account deployments, wait for the daemon and dedicated-UID isolation milestone described in the roadmap.

The Rust rewrite has not received an independent cryptographic audit. Passing tests and using established primitives are necessary controls, not substitutes for third-party review.

## Version 0.2 Alpha Boundary

The alpha daemon accepts only a status request over a private Linux Unix socket and validates the
client identity using kernel-provided peer credentials. It does not yet authenticate through PAM,
change UID, mount encrypted storage, handle secrets, or launch Codex. Running the alpha daemon does
not improve the `v0.1` same-UID isolation guarantee.

## Reporting a Vulnerability

Do not open a public issue containing exploit details, credentials, private transcripts, or decrypted data. Until a private security contact is configured, prepare a minimal reproduction and disclose only that a private report is available.

Security fixes take priority over feature work. Affected releases will be documented in the changelog, and keys or formats will be rotated when a vulnerability affects cryptographic guarantees.
