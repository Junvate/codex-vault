# Upstream Delivery Audit And Held PR Outline

Audit date: 2026-09-11. This is a readiness record, not an assertion of completion.

## Objective

Prepare Codex Vault for a reviewable contribution to openai/codex: establish the contribution
route, identify the minimal upstream change, implement and verify relevant work, and provide
security boundaries and review materials. If approval is required, prepare the proposal and
state the external dependency explicitly. Do not equate this proposal route with completion
of the Vault security roadmap.

## Authoritative Evidence

- Upstream policy at `1b83e5cdf99889e72fbf3f92d9848fdf31de652e`, docs/contributing.md,
  was fetched on the audit date. External code contributions and PRs are not accepted.
- Issue #4432 remains open. It already covers profile-scoped credentials and sessions.
- Vault implementation/test commit `ba3c17028016745af3102ebf706ac0997eea0ed3` passed
  [all five CI jobs](https://github.com/Junvate/codex-vault/actions/runs/34541080564).
- The pinned real-Codex 0.153.4 jobs verify archive hashes and actually run the otherwise
  ignored integration tests on Linux and macOS. Ordinary cargo test alone is insufficient.
- The independent v0.1.0 report is historical evidence, not validation of later code.

## Requirement Audit

| Requirement | Status | Evidence or missing work |
| --- | --- | --- |
| Verify upstream policy | Verified | Pinned policy above prohibits external PRs |
| Establish accepted PR route | Blocked | No invitation, policy change, or approved scope |
| Identify minimal proposal | Prepared, not approved | Document stable state-root and credential-backend expectations for external launchers |
| Implement related Vault changes | Verified for bounded scenarios | Stable exclusive runtime creation, fail-closed overrides, resealing, lock cleanup, regression tests |
| Validate real exec/resume | Partial | File auth, last-thread and explicit-ID cases pass on two platforms; interactive picker and production launch path remain untested here |
| Validate authentication backends | Partial | Fictional file-key recognition only; no real OAuth, keyring, auto, or MCP validation |
| Prove hostile-user isolation | Incomplete | Dedicated UID/PAM/mount implementation and adversarial process tests remain absent |
| Validate migration and recovery | Incomplete | Old random-path sessions and abnormal-exit plaintext require explicit recovery work |
| Prepare upstream review materials | Prepared | UPSTREAM_DISCUSSION.md plus held outline below |
| Implement approved upstream patch | Blocked | No agreed upstream scope or permitted external contribution route |
| Security audit and signed releases | Incomplete | Dependency auditing and hashes are not independent security review or publisher signatures |

## Proposed Minimal Upstream Change

Ask maintainers to document whether a stable canonical CODEX_HOME is required for preserved
session references, how credential backends relate to that path, and what data remains outside
the state root. This can be reviewed without importing Vault's encryption, password handling,
daemon, UID allocator, PAM policy, or mount management into Codex.

The observed failure was in the Vault integration: restoring at random paths broke resume,
and stable paths repaired the tested behavior. Do not label it an upstream vulnerability or
promise portability of internal databases. Further upstream implementation is contingent on
the maintainer-selected contract and contribution policy.

## Held PR Outline

Not submitted; not a ready-to-merge patch. Proposed title:
`docs: clarify state-root expectations for external Codex launchers`.

Summary: describe path stability, backend-specific credential location, and limitations of
profile separation, scoped to behaviors maintainers confirm as supported.

Motivation: encrypted launchers may restore identical files to a new directory, yet absolute
session references and path-derived credential namespaces can depend on the original location.

Evidence: include the pinned reproduction, before/after Vault behavior, tests and CI above.
Separate observed file/exec behavior from the untested keyring hypothesis. Provide the minimal
launcher configuration and use only disposable fixtures.

Compatibility: no change to Codex defaults, cryptographic format, account authentication, or
resume authorization. Do not add password prompts or privileged hooks as part of this proposal.

Validation after invitation: check the agreed documentation against the then-current source,
add upstream-native tests only for the agreed behavior, follow current repository instructions,
and record any unsupported or version-dependent behavior. Do not copy Vault tests into Codex
without adapting them to the upstream test framework.

Security: file/profile separation is not process isolation between hostile same-UID users.
No protection from root, compromised host, external state writes, or unhandled crash leftovers
is claimed. Any actual vulnerability should follow the upstream private disclosure policy.

## External Decision Needed

The next upstream-facing action is a user-approved comment on #4432 using the prepared draft,
not an unsolicited PR. There is no guarantee of a response, invitation, or acceptance. A policy
change or explicit maintainer route is required before the PR part of the objective can proceed.
More local tests cannot establish that authorization. Independent Vault security development
remains possible, but does not remove this upstream delivery blocker.
