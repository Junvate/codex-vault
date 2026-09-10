# Draft Comment For openai/codex #4432

Not submitted. Policy and issue state rechecked on 2026-09-11; recheck again before posting.

## External Encrypted State Launchers And Profile Boundaries

We are developing an external Rust launcher that unlocks an encrypted per-profile CODEX_HOME,
launches Codex, and reseals state afterward. This addresses accidental profile mixing and
encrypted storage at rest, not hostile processes sharing a Unix UID. Privileged isolation,
PAM, UID management, and encryption should remain outside Codex.

This relates to the profile-scoping discussion here. We would like to clarify whether Codex can
document a supported external state-root contract for config, sessions, resume selection, and
credentials, including which state is intentionally outside CODEX_HOME.

One integration question is credential persistence when the same encrypted profile is unlocked
at a different runtime path. At commit b348fc26674189f758d5941cdab3f78f258b2aa7,
codex-rs/login/src/auth/storage.rs derives direct-keyring keys from the canonical CODEX_HOME
path, while file credentials use CODEX_HOME/auth.json. We infer that ephemeral runtime paths
may change keyring lookup identity. We have not reproduced this with real OAuth credentials
and are not reporting it as a vulnerability or claiming an upstream defect.

Would maintainers prefer a documented stable-path requirement, guidance on credential backend
selection for external launchers, or another supported approach? Our pinned-release tests against
codex-cli 0.153.4 now pass on Linux and macOS for file-credential recognition across runtime
relocation, a second profile with no credentials, and persisted logout. These use a fictional
API key and do not authenticate to OpenAI. Keyring, auto, and MCP remain unverified.

We also reproduced a resume failure in our integration when restoring CODEX_HOME at a new random
runtime path: Codex 0.153.4 reported no rollout found for the selected thread. Keeping our runtime
path stable fixed the regression. A loopback-only model fixture confirmed that Alice resumed her
original thread with prior history, while Bob's resume --last --all did not include Alice's prompt.
This is evidence for documenting path-stability expectations, not a claim that Codex violates an
existing contract. Migration of old paths and hostile same-UID access remain out of scope of this test.

The extended test also rejects Bob's explicit Alice thread ID without a provider request and
successfully resumes that ID as Alice. See the [passing CI run](https://github.com/Junvate/codex-vault/actions/runs/34541080564)
and [pinned regression source](https://github.com/Junvate/codex-vault/blob/ba3c17028016745af3102ebf706ac0997eea0ed3/tests/real_codex.rs).

We recognize the current policy does not accept external PRs. This is a design discussion,
not a request to merge the launcher or to add shared-UID password isolation to Codex.
