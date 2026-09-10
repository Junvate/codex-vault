# Draft Comment For openai/codex #4432

Not submitted. Recheck issue status and contribution policy before posting.

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
selection for external launchers, or another supported approach? Our next validation step is a
pinned-release matrix covering resume and additional credential backends using only disposable
state. An initial macOS test against codex-cli 0.153.4 passed file-credential recognition across
runtime relocation, a second profile with no credentials, and persisted logout. It used a
fictional API key and did not authenticate to OpenAI or exercise real resume behavior.

We recognize the current policy does not accept external PRs. This is a design discussion,
not a request to merge the launcher or to add shared-UID password isolation to Codex.
