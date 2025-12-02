---
'@kitiumai/auth-postgres': minor
---

- Add migration tracking table and enforce foreign keys across auth tables with automatic `updated_at` triggers.- Introduce per-query transactions with configurable statement timeouts, retries, and a built-in health check helper.- Document production guidance, health checks, and new adapter options in the README.
