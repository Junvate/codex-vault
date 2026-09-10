# Codex Vault

Codex Vault is a Rust security launcher that gives each application-level user an isolated, encrypted `CODEX_HOME` on a shared machine.

The current `v0.1` baseline provides encrypted state at rest and prevents accidental cross-user access through `codex resume`. It is not yet a complete isolation boundary for hostile people sharing the same operating-system UID. Read [SECURITY.md](SECURITY.md) before deployment.

## Security Design

```text
username + password
        -> Argon2id wrapping key
        -> decrypt random per-user data key
        -> decrypt private CODEX_HOME into a restricted runtime
        -> run the real Codex CLI
        -> authenticate and encrypt the updated state
        -> remove the runtime and release the system file lock
```

- Argon2id uses 64 MiB memory, three passes, and a unique 128-bit salt.
- Every user receives a random 256-bit data key.
- Data keys are wrapped with AES-256-GCM and authenticated manifest metadata.
- Codex state uses chunked AES-256-GCM with a 96-bit random nonce seed plus frame sequence, ordering, tamper, truncation, and trailing-data checks.
- Passwords are accepted only through a hidden terminal prompt.
- Secret key buffers use Rust `Zeroizing` where the implementation controls their lifetime.
- Storage is restricted to the current UID, `0700` directories, and `0600` files.

## Build

Install Rust with `rustup`, then run:

```bash
cargo build --release
cargo test
```

The executable is `target/release/codex-vault`. Install it for the current user with:

```bash
cargo install --path .
```

## Usage

```bash
codex-vault init
codex-vault user add alice
codex-vault user passwd alice
codex-vault user list

codex-vault run --user alice --
codex-vault run --user alice -- resume
codex-vault run --user alice -- resume --last
```

Set `CODEX_VAULT_USER=alice` to skip the username prompt. The password is still requested for every launch.

Password rotation creates a fresh Argon2id salt and AES-GCM wrapping nonce, then atomically replaces
the manifest. The random data key and encrypted `state.cvlt` remain unchanged.

To keep the original command shape, add this shell function after installing `codex-vault`:

```bash
codex() {
  command codex-vault run -- "$@"
}
```

The launcher invokes the real `codex` executable directly from `PATH`; shell functions are not used by the child process. Set `CODEX_VAULT_REAL_CODEX` to an absolute executable path when explicit resolution is required.

## Daemon Alpha

On Linux, `v0.2.0-alpha.1` includes a status-only daemon protocol prototype:

```bash
codex-vaultd
codex-vault daemon status
codex-vault daemon status --json
```

The Unix socket is private and the daemon verifies client PID/UID/GID using Linux `SO_PEERCRED`.
This alpha does not yet perform PAM authentication, dedicated-UID execution, encrypted mounts, or
Codex launch. No password, key, token, or decrypted state is sent over the protocol.

## Storage

Runtime paths are stable per profile UUID under the same canonical runtime root. This is required
for Codex's persisted session references; normal close still removes the entire plaintext runtime.
An existing runtime directory, file, or symlink is refused, never overwritten or auto-deleted.
After a crash, preserve and inspect leftovers before recovery. Changing the runtime root or
upgrading a profile created with random runtime paths can leave older Codex session references
unresolvable. Automatic migration is not implemented; keep an encrypted backup before upgrading.

- `CODEX_VAULT_HOME`: encrypted root, default `~/.codex-vault`.
- `CODEX_VAULT_RUNTIME_DIR`: private plaintext runtime override.
- `XDG_RUNTIME_DIR`: preferred runtime on Linux when no override is set.
- `/dev/shm`: Linux memory-backed fallback.

## Project Status

Upstream contribution work is tracked in [Upstream Readiness](docs/UPSTREAM_READINESS.md).
As checked on 2026-09-10, Codex accepts issue discussions but not external PRs. A discussion
draft is available; no upstream PR or issue has been submitted by this project in this iteration.

`v0.1.2` is the maintained patch line. `v0.2.0-alpha.1` starts the Linux daemon protocol while PAM authentication, dedicated UID execution, and encrypted filesystem mounts remain under development.

See [Architecture](docs/ARCHITECTURE.md), [Daemon Protocol](docs/DAEMON_PROTOCOL.md), [Threat Model](docs/THREAT_MODEL.md), [Roadmap](docs/ROADMAP.md), and [Maintenance Policy](docs/MAINTENANCE.md).

## License

Apache License 2.0.
