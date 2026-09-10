# Upstream Contribution Readiness

Checked on 2026-09-10 against openai/codex commit
`b348fc26674189f758d5941cdab3f78f258b2aa7`.

## Contribution Gate

The [upstream contribution policy](https://github.com/openai/codex/blob/b348fc26674189f758d5941cdab3f78f258b2aa7/docs/contributing.md)
does not accept external code contributions or pull requests. It accepts issue reports,
reproductions, analysis, and feature requests. Code readiness cannot override that policy.
Do not open a PR unless the policy changes or maintainers explicitly invite one.

The open [multi-account proposal #4432](https://github.com/openai/codex/issues/4432)
already discusses profile-scoped config, credentials, and sessions. Prefer a relevant comment
over a duplicate feature request. A draft is provided in UPSTREAM_DISCUSSION.md; it has not
been posted. Follow upstream SECURITY.md privately for any newly discovered vulnerability.

## Smallest Useful Upstream Scope

Discuss an explicit, documented state-root contract for external launchers, including credential
backend behavior and resume scope. Keep password handling, privileged daemons, PAM, UID allocation,
mounts, and Vault encryption in this project. Do not propose that profile selection itself
protects mutually hostile processes sharing a Unix UID.

## Evidence And Limits

- The independent v0.1.0 Linux report is in validation/. It covers that pinned version only.
- Local runner tests exercise mock process argument fidelity, application-user state separation,
  nonzero exit handling, spawn failure, resealing, runtime removal, and lock release.
- These tests do not exercise the real Codex resume database, OAuth, keyring, MCP, or subprocesses.
- A separate opt-in real-binary test verifies file-credential recognition across runtime relocation,
  Bob's empty credential state, and persisted logout using fictional credentials. The macOS result
  and artifact digest are in [the compatibility report](../validation/macos-codex-0.153.4-file-auth.md).
  This is not real authentication, a resume test, or a test of the production launcher path.
- Upstream login/src/auth/storage.rs stores file credentials under CODEX_HOME/auth.json.
  Its compute_store_key hashes the canonical CODEX_HOME path. Vault now uses a stable runtime path
  under an unchanged canonical runtime root. Inference: relocating that root may change keyring lookup.
  This is a compatibility hypothesis, not a reproduced upstream bug or security finding.
- CODEX_HOME does not constrain files written elsewhere, inherited credentials, network access,
  shared workspaces, host administrators, or same-UID process access.

## Required Gates Before Claiming Readiness

1. Obtain an accepted upstream contribution route; record any maintainer invitation.
2. Pin a real Codex release and verify login, logout, exec, resume, and resume --last with
   disposable accounts/state. Never use production credentials in automated tests.
3. Test file, keyring, auto, and MCP credential storage across two launches. Identify all state
   outside the encrypted root. Do not silently change a user's credential backend.
4. Verify two independent Unix identities, adversarial access attempts, process descendants,
   crash recovery, and cleanup before claiming active-session isolation.
5. Complete focused regression tests, Linux/macOS CI, dependency audit, and a documented
   threat-model review. Dependency auditing is not a third-party security audit.
6. Prepare a minimal patch only for the agreed upstream scope. Include compatibility evidence,
   migration behavior, failure handling, and test commands. Signing and external security review
   remain separate release gates.

Current status: discussion draft, launcher regressions, real-Codex file-auth persistence, and
[exec/resume evidence](../validation/macos-codex-0.153.4-resume.md) available;
full compatibility matrix and active-session isolation incomplete;
external PR route unavailable.

Pinned real-Codex file-auth and exec/resume tests also passed in both Linux and macOS CI;
see [cross-platform evidence](../validation/ci-codex-0.153.4.md). This closes only the platform
gap for those specific scenarios, not the remaining authentication or security gates above.

The resume regression additionally checks explicit foreign-thread rejection with no provider
request, and explicit owner-thread restoration. This exercises the selected profile while Alice
is sealed; it does not prove isolation from hostile same-UID access to an active runtime.
