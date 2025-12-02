# Changelog

## Unreleased

- Add migration tracking table and enforce foreign keys across auth tables with automatic `updated_at` triggers.
- Introduce per-query transactions with configurable statement timeouts, retries, and a built-in health check helper.
- Document production guidance, health checks, and new adapter options in the README.

## 3.0.0

- Initial release of the PostgreSQL storage adapter for `@kitiumai/auth`.
- Automatic schema bootstrap for users, sessions, API keys, orgs, email verification, events, RBAC, SSO, and 2FA tables with indexes.
- Full `StorageAdapter` implementation for core CRUD, RBAC role management, SSO providers/links/sessions, and two-factor devices/backup codes/sessions.
- Type updates aligned with `@kitiumai/auth` v3 (Role metadata, 2FA device secrets/phone numbers, SSO timestamps).
