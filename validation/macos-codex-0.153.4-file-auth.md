# Real Codex File-Auth Compatibility

Date: 2026-09-10. Platform: macOS, native aarch64 Codex executable.

## Pinned Executable

- Version output: `codex-cli 0.153.4`.
- SHA-256: `b973d440acac501fd2594a43e7ca9ce41e0a65b9dfb28d0d7a7837c99e1261e3`.
- The executable was already installed locally. This digest records the tested artifact;
  it is not a publisher-signature verification or an upstream source-commit attestation.

## Test

`tests/real_codex.rs` contains an opt-in integration test. It uses the Vault library to
create, unlock, and reseal disposable profiles, and invokes the actual Codex binary with
an empty inherited environment, a disposable HOME and working directory, and explicit
file credential storage. It does not use the interactive Vault password prompt or its
production process-launch function, so this is a storage compatibility test, not a full
launcher acceptance test.

The fixture is an intentionally invalid API key serialized to auth.json. No existing
account credentials or sessions were loaded. No model call or interactive login was made.
Subprocess stdout/stderr are captured in disposable files; each invocation has a 15-second
deadline and is killed and reaped on timeout. Temporary state is removed after the test.
The test does not install a network sandbox or prove absence of network traffic.

## Results

The explicit test run passed on 2026-09-10 in 28.23 seconds:

1. Exact binary version matched the caller-supplied version.
2. Alice's fictional file credential was recognized by `login status` (exit 0).
3. Alice's plaintext runtime was removed after resealing.
4. Bob's independent profile returned `Not logged in` (exit 1).
5. Alice's next unlock used a different runtime path; her file credential was still recognized.
6. `logout` returned exit 0 and removed Alice's auth.json.
7. After resealing and reopening, Alice returned `Not logged in` (exit 1).
8. The plaintext runtime root was empty after final close.

These results prove local file-credential recognition and persistence only. Codex accepting
the fixture locally does not mean the API key is valid or that server authentication succeeded.

## Reproduction

Use an absolute path to a trusted native Codex executable, not a shell function or Node wrapper.
Set the expected exact version explicitly. The test is ignored during ordinary cargo test runs.

```bash
CODEX_VAULT_TEST_CODEX=/absolute/path/to/codex \
CODEX_VAULT_TEST_CODEX_VERSION='codex-cli 0.153.4' \
cargo test --test real_codex --locked -- --ignored --nocapture
```

## Not Covered

Real OAuth/API authentication, keyring and auto backends, MCP credentials, actual exec/resume
behavior, model requests, Linux runtime behavior of this test, host configuration outside HOME,
same-UID adversaries, dedicated UIDs, mounts, and crash recovery remain unverified here.
This is not a security audit or a claim of complete Codex compatibility.
