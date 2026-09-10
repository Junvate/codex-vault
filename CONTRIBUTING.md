# Contributing

Security properties are part of the public API. Changes to authentication, key derivation, vault formats, extraction, process isolation, or cleanup must include tests and update the threat model.

## Development

```bash
cargo fmt -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-targets --all-features --locked
```

Keep pull requests focused. Do not add custom cryptographic primitives or replace established algorithms without a written design review and migration plan.

Commit messages should explain the behavior or security property being changed. Security-sensitive changes should identify the attacker capability they address and any remaining limitation.
