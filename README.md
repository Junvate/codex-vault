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

## Storage

- `CODEX_VAULT_HOME`: encrypted root, default `~/.codex-vault`.
- `CODEX_VAULT_RUNTIME_DIR`: private plaintext runtime override.
- `XDG_RUNTIME_DIR`: preferred runtime on Linux when no override is set.
- `/dev/shm`: Linux memory-backed fallback.

## Project Status

`v0.1.2` is the maintained prototype line. `v0.2` will add the privileged Linux daemon, PAM authentication, dedicated UID execution, and encrypted filesystem mounts required for hostile-user isolation.

See [Architecture](docs/ARCHITECTURE.md), [Threat Model](docs/THREAT_MODEL.md), [Roadmap](docs/ROADMAP.md), and [Maintenance Policy](docs/MAINTENANCE.md).

## License

Apache License 2.0.
