# Space

Space is a deliberately minimal, zero-knowledge personal password manager. This repository contains a shared protocol and cryptographic core, a Chrome Manifest V3 extension, a PostgreSQL sync API, and a native iOS/AutoFill project skeleton.

The project is in security-focused MVP development and is **not yet suitable for storing real credentials**. See `docs/releases/release-readiness.md` for the exact release status.

## Local development

Requirements: Node.js 22+, npm 10+, Docker for PostgreSQL. Copy `.env.example` to `.env`, then:

```sh
npm ci
docker compose up -d postgres
npm run check
npm run dev --workspace @space/api
```

Build the unpacked Chrome extension with `npm run build --workspace @space/extension`; load `apps/extension/dist` from `chrome://extensions` in developer mode.

Security design starts in `docs/security/cryptographic-protocol.md`. Operational setup is in `docs/operations/deployment.md`.

