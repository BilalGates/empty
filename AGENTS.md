# Space agent map

Space is a zero-knowledge password manager. Never weaken cryptography or persist plaintext to fix a functional bug.

## Sources of truth

- Architecture and ADRs: `ARCHITECTURE.md`, `docs/architecture/`, `docs/decisions/`
- Security protocol and threat model: `docs/security/`
- Product and design: `docs/product/`, `docs/design/`
- Active and completed execution plans: `docs/exec-plans/`
- Testing and operations: `docs/testing/`, `docs/operations/`
- Release state: `docs/releases/`

## Required procedures

Project Skills live in `.agents/skills/`. Load the matching Skill before changing its area. Every crypto, vault-format, recovery, WebAuthn, unlock, or secret-storage change must use `space-crypto-change-gate` and receive security plus adversarial review.

## Commands

`npm run check` is the normal local gate. Also run `npm run security:secrets` and `npm run security:permissions` before release. Never commit `.env`, credentials, plaintext vaults, import CSVs, signing material, or generated secrets.

