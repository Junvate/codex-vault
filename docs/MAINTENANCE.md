# Maintenance Policy

Effective date: 2026-09-10.

## Priorities

Maintenance decisions use this order:

1. Preserve confidentiality and vault integrity.
2. Prevent data loss and provide format migrations.
3. Keep the login and Codex launch path predictable.
4. Add deployment and team-management features.

## Release Gates

Every release must satisfy all of the following:

- `npm run verify` passes on supported Node.js versions.
- Production dependencies have no unreviewed known vulnerability.
- Cryptographic or isolation changes include negative security tests.
- Vault-format changes include a versioned migration and rollback plan.
- Threat-model assumptions and limitations remain accurate.
- The changelog describes security-relevant behavior changes.
- Built packages contain no test vault, credential, transcript, or plaintext runtime data.

## Compatibility

The `state.cvlt` magic and user-manifest version are compatibility contracts. Readers must reject unknown versions rather than guessing. Breaking format changes require a new version and an explicit migration command.

## Dependency Updates

Automated dependency pull requests run weekly. Cryptographic, archive, process-management, and authentication updates require the full test suite and a review of upstream security notes before merging.

## Security Changes

Security fixes take precedence over feature releases. A fix must state:

- The attacker capability being addressed.
- The affected versions and data formats.
- Whether passwords, data keys, or OpenAI credentials require rotation.
- Whether existing vaults require migration or re-encryption.
- The residual risk after the change.

## Current Maintained Line

The maintained development line is `0.1.x`. It is a prototype line and does not yet claim hostile same-UID isolation. The next security milestone is `0.2.0`, which introduces the Linux daemon and dedicated-UID execution boundary.
