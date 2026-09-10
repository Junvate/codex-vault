# Architecture

## v0.1 Components

```text
codex-vault CLI
    -> VaultStore
        -> manifest authentication
        -> Argon2id key derivation
        -> AES-256-GCM data-key unwrap
        -> authenticated archive extraction
    -> Codex runner with private CODEX_HOME
    -> authenticated archive sealing
```

### CLI

`src/main.rs` owns argument parsing and hidden password prompts. Passwords are never accepted as command-line options or environment variables.

### Store

`src/store.rs` owns users, file permissions, exclusive file locks, runtime directories, and the unlock/reseal lifecycle. `VaultStore` is also the reusable boundary for the future daemon.

### Manifest And Keys

`src/manifest.rs` defines the versioned public metadata. The password-derived key does not encrypt session data directly; it wraps a random per-user data key. Password rotation can therefore rewrap the data key without rewriting every session.

### Vault Stream

`src/crypto/vault_stream.rs` implements bounded authenticated frames. Every encrypted file receives a random 96-bit starting nonce, and each frame advances that nonce by its sequence number. The file header and frame header are associated data, so changes to order, type, or length fail authentication.

### Archive

`src/archive.rs` streams a tar archive through the encrypted frame writer. Extraction rejects paths outside the runtime and does not restore symbolic or hard links. The reader is drained after tar parsing to ensure the final authentication frame is verified.

### Runner

`src/runner.rs` passes the unlocked runtime as `CODEX_HOME`, inherits terminal I/O, forwards Unix termination signals, waits for Codex, then reseals the state before returning.

## v0.2 Boundary

The daemon will move authentication, keys, mounts, and process creation into a privileged service. The CLI will become an unprivileged terminal client. Each authenticated session will run under a dedicated UID so people sharing an entry account are no longer treated as the same operating-system principal.

### Alpha 1 Protocol Slice

`src/daemon_protocol.rs` defines a bounded, versioned JSON protocol. `src/daemon.rs` owns private
Unix socket creation, stale-socket handling, Linux `SO_PEERCRED` verification, and graceful service
shutdown. `src/bin/codex-vaultd.rs` is the foreground service entry point, suitable for later
supervision by systemd.

The alpha service exposes only status and capability discovery. It intentionally keeps passwords,
keys, vault state, PAM, UID transitions, mounts, and child process creation outside the daemon until
those interfaces have dedicated threat-model and negative-test coverage.
