# Codex Vault

Codex Vault is an early-stage security launcher for isolating and encrypting local Codex CLI state on shared machines.

It gives every application-level user a separate encrypted `CODEX_HOME`. Running Codex through the launcher decrypts only that user's state, starts the real Codex CLI, then reseals the state after Codex exits.

> Status: security prototype. Version 0.1 protects data at rest and prevents accidental cross-user `codex resume` access. It is not yet a complete isolation boundary for hostile people sharing the same operating-system account. See [SECURITY.md](SECURITY.md) before deployment.

## Current Features

- Per-user encrypted Codex state.
- Argon2id password-based key derivation.
- Random data key per user with authenticated key wrapping.
- Chunked AES-256-GCM encryption with tamper, frame-order, truncation, and trailing-data detection.
- Private runtime directory and cleanup after Codex exits.
- Per-user process lock to prevent concurrent state corruption.
- Passwords are read from a hidden terminal prompt, never accepted as command-line arguments or environment variables.

## Requirements

- Node.js 22 or newer.
- An installed `codex` executable.

## Build

```bash
npm install
npm run verify
```

## Quick Start

```bash
node dist/cli.js init
node dist/cli.js user add alice
node dist/cli.js run --user alice --
node dist/cli.js run --user alice -- resume
```

To preserve the normal `codex` command on a personal shell, add this function after building:

```bash
codex() {
  command node /absolute/path/to/codex-vault/dist/cli.js run -- "$@"
}
```

Set `CODEX_VAULT_USER=alice` to skip the username prompt. The password is still requested for every launch. Set `CODEX_VAULT_REAL_CODEX` only when the real executable has a different name or absolute path.

## Storage

The default encrypted state root is `~/.codex-vault`. Override it with `CODEX_VAULT_HOME`.

On Linux, runtime plaintext prefers `XDG_RUNTIME_DIR`, then `/dev/shm`. On other systems it uses the operating-system temporary directory. Override this with `CODEX_VAULT_RUNTIME_DIR`.

## Project Direction

Version 0.2 will introduce a privileged Linux daemon that authenticates through PAM or OIDC and launches Codex under a dedicated UID or container. That isolation layer is required before the project can claim protection against malicious users who share a shell account.

See [docs/ROADMAP.md](docs/ROADMAP.md), [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md), and [docs/MAINTENANCE.md](docs/MAINTENANCE.md).

## License

Apache License 2.0.
