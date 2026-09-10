# Real Codex Resume Compatibility

Date: 2026-09-10. macOS aarch64, codex-cli 0.153.4; executable SHA-256
`b973d440acac501fd2594a43e7ca9ce41e0a65b9dfb28d0d7a7837c99e1261e3`.

## Failure And Fix

The first real-binary regression run with random per-unlock runtime paths failed when Alice
reopened her profile: `thread/resume failed: no rollout found for thread id ...`.
Alice's initial exec and Bob's independent exec resume --last --all had succeeded.
This contradicts the earlier assumption that moving CODEX_HOME alone preserves resume behavior.

The store now recreates the same profile-UUID directory under the canonical runtime root,
exclusively, after authentication and while holding the profile lock. Normal close removes it
before unlocking. Existing files, directories, and symlinks are rejected without alteration.
The same real-binary regression then passed. This is a Vault integration fix, not evidence of
an upstream security vulnerability. Persisted absolute state references are the working root-cause
explanation; no upstream database schema is modified by this fix.

## Verified Behavior

The actual Codex binary was invoked with empty inherited environment, disposable HOME/workspace,
and a custom provider bound to 127.0.0.1 on an ephemeral port. The fixture returns text-only SSE
responses, rejects Authorization headers, and records JSON request bodies. No tool calls or
real credentials are supplied. This is not an OS-enforced network isolation test.

- Alice's exec returned a thread.started event and the fixture reply, then Vault resealed state.
- Bob's exec resume --last --all returned a different thread ID and sent no Alice marker.
- Alice's reopened profile used the same CODEX_HOME path and resumed her original thread ID.
- Alice's request included her prior prompt, prior assistant reply, and new prompt, but no Bob marker.
- The plaintext runtime root was empty after final close.
- Both real-binary tests passed together in 72.97 seconds (file auth and resume).

Reproduction (native binary required):

```bash
CODEX_VAULT_TEST_CODEX=/absolute/path/to/codex \
CODEX_VAULT_TEST_CODEX_VERSION='codex-cli 0.153.4' \
cargo test --test real_codex --locked -- --ignored --nocapture --test-threads=1
```

## Limits And Migration

This test uses VaultStore directly and an isolated test process launcher. It does not test the
interactive password prompt, production process-launch environment, interactive resume picker,
explicit foreign session IDs, real OAuth, keyring/MCP, Linux, or adversarial same-UID processes.
Earlier random-path sessions and moving the canonical runtime root can still break references.
No automatic migration or encrypted backup restoration workflow has been verified. An existing
runtime after a crash is deliberately refused, not recovered or destroyed automatically.
Stable naming is a compatibility measure, not a stronger OS security boundary.
