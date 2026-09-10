# Pinned Real Codex Cross-Platform Validation

Validation run: [34540169959](https://github.com/Junvate/codex-vault/actions/runs/34540169959).
Tested Vault commit: `c5be5edfe57843cc521b6a7dbcab96f900685b04`.
Codex release: `rust-v0.153.4`; expected executable output: `codex-cli 0.153.4`.

## Verified Artifacts

The CI workflow downloads these upstream release archives over HTTPS and checks their pinned
SHA-256 before extracting and executing the named native binary. Digests were obtained from the
GitHub release asset API. This is artifact-integrity verification, not publisher-signature verification.

| Runner | Archive | SHA-256 |
| --- | --- | --- |
| ubuntu-latest | codex-x86_64-unknown-linux-musl.tar.gz | f479424eca092484dc40d87ae28c44f4cc40234a60045d6131e493800d814a30 |
| macos-14 | codex-aarch64-apple-darwin.tar.gz | 8cf911ea676523bfb2121ec561848d2aba564890ad536db4d8a3353f2b9850b1 |

## Results

Both real-codex jobs passed archive verification and explicitly executed both ignored tests in
`tests/real_codex.rs` with `--ignored --nocapture --test-threads=1`:

- File-credential recognition survives moving the runtime root; Bob has no Alice credential;
  logout remains effective after resealing and reopening.
- Under an unchanged canonical runtime root, Alice's exec/resume preserves her thread ID and
  prior prompt/reply; Bob's resume --last --all uses a different thread without Alice's marker.
- Runtime directories are empty after normal close.

The file-auth fixture uses a fictional key. The exec/resume fixture uses a loopback Responses
server without Authorization headers, real credentials, model services, or tool calls. Child
environments and HOME directories are isolated by the test harness. This is not an OS network
sandbox, a production launcher environment test, or a successful real authentication test.

## Remaining Gates

Interactive password prompts and resume picker, explicit foreign session IDs, real OAuth,
keyring/auto/MCP persistence, old-path migration, hostile same-UID access, dedicated UID/PAM,
encrypted mounts, and abnormal-exit recovery are not proven by these jobs. Ordinary platform CI
and dependency auditing are separate jobs; their status must be checked separately.

The pinned compatibility jobs now run on pushes and pull requests. Version upgrades must update
the archive hashes and expected executable version together, then rerun both platforms. Do not
silently switch to an unpinned latest binary or treat ignored tests in ordinary CI as executed.
