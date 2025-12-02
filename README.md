# @kitiumai/auth-postgres

PostgreSQL storage adapter for `@kitiumai/auth`. It manages all persistence (users, sessions, API keys, orgs, RBAC, SSO, 2FA) and boots an enterprise-friendly schema with migrations, foreign keys, and operational safeguards.

## Installation

```bash
pnpm add @kitiumai/auth-postgres pg
```

Requires PostgreSQL 12+ and Node 16+.

## Quick start

```ts
import { PostgresStorageAdapter } from '@kitiumai/auth-postgres';
import { AuthCore, createStorageConfig } from '@kitiumai/auth';

const storage = new PostgresStorageAdapter(process.env.DATABASE_URL!, {
  max: 10,
  idleTimeoutMillis: 30_000,
  statementTimeoutMs: 5_000,
  maxRetries: 2,
});

await storage.connect(); // creates tables and indexes if missing through migrations

const auth = new AuthCore({
  appUrl: 'https://example.com',
  providers: [], // add your email/OAuth/SAML providers
  storage: createStorageConfig({ driver: 'postgres', url: process.env.DATABASE_URL }),
  apiKeys: { prefix: 'kit', hash: { algo: 'argon2id' } },
  sessions: { cookieName: 'kitium_session', ttlSeconds: 60 * 60 * 24 },
});
```

### Resilient connection options

```ts
const storage = new PostgresStorageAdapter(process.env.DATABASE_URL!, {
  max: 20, // pg pool size
  maxRetries: 3, // retry failed statements with backoff
  statementTimeoutMs: 10_000, // per-statement timeout (SET LOCAL)
});
```

### Health checks

```ts
const health = await storage.healthCheck();
if (health.status !== 'ok') {
  throw new Error(`database unhealthy (latency ${health.latencyMs}ms)`);
}
```

## What it creates

- Tables: `auth_migrations` (schema versioning), `users`, `api_keys`, `sessions`, `organizations`, `email_verification_tokens`, `email_verification_token_attempts`, `auth_events`, `roles`, `user_roles`, `sso_providers`, `sso_links`, `sso_sessions`, `twofa_devices`, `twofa_backup_codes`, `twofa_sessions`
- Foreign keys across all relationships for safer deletes and tenant isolation support.
- Indexes on common lookup columns (ids, foreign keys, expirations, email, etc.) and triggers to keep `updated_at` current.

## Core API

All methods come from the `StorageAdapter` interface in `@kitiumai/auth`.

- Connection: `connect()`, `disconnect()`
- API keys: `createApiKey`, `getApiKey`, `getApiKeyByHash`, `getApiKeysByPrefixAndLastFour`, `updateApiKey`, `deleteApiKey`, `listApiKeys`
- Sessions: `createSession`, `getSession`, `updateSession`, `deleteSession`
- Users: `createUser`, `getUser`, `getUserByEmail`, `getUserByOAuth`, `updateUser`, `deleteUser`, `linkOAuthAccount`
- Organizations: `createOrganization`, `getOrganization`, `updateOrganization`, `deleteOrganization`
- Email verification: `createEmailVerificationToken`, `getEmailVerificationTokens`, `getEmailVerificationTokenById`, `markEmailVerificationTokenAsUsed`, `deleteExpiredEmailVerificationTokens`, `getEmailVerificationTokenAttempts`, `incrementEmailVerificationTokenAttempts`
- Events: `emitEvent`
- RBAC: `createRole`, `getRole`, `updateRole`, `deleteRole`, `listRoles`, `assignRoleToUser`, `revokeRoleFromUser`, `getUserRoles`
- SSO: `createSSOProvider`, `getSSOProvider`, `updateSSOProvider`, `deleteSSOProvider`, `listSSOProviders`, `createSSOLink`, `getSSOLink`, `getUserSSOLinks`, `deleteSSOLink`, `createSSOSession`, `getSSOSession`
- 2FA: `createTwoFactorDevice`, `getTwoFactorDevice`, `updateTwoFactorDevice`, `listTwoFactorDevices`, `deleteTwoFactorDevice`, `createBackupCodes`, `getBackupCodes`, `markBackupCodeUsed`, `createTwoFactorSession`, `getTwoFactorSession`, `completeTwoFactorSession`

## Usage snippets

Create a user and session:

```ts
const user = await storage.createUser({ email: 'hi@example.com', entitlements: [] });
const session = await storage.createSession({
  userId: user.id,
  entitlements: [],
  expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24),
});
```

Issue an API key:

```ts
const apiKey = await storage.createApiKey({
  principalId: user.id,
  hash: 'argon2-hash',
  prefix: 'kit',
  lastFour: 'abcd',
  scopes: ['read'],
  metadata: { name: 'cli' },
  expiresAt: null,
});
```

Record an auth event:

```ts
await storage.emitEvent({
  type: 'user.login',
  principalId: user.id,
  orgId: undefined,
  data: { ip: '127.0.0.1' },
  timestamp: new Date(),
});
```

## Production checklist

- **Resiliency:** configure `statementTimeoutMs`, `maxRetries`, and pool limits to protect upstream Postgres during traffic spikes.
- **Migrations:** run `connect()` as part of deploys to apply schema changes; the adapter records applied migrations in `auth_migrations` for safe rollbacks.
- **Backups and DR:** schedule logical/physical backups of the database and practice restores; auth data is critical to user access.
- **Security:** enable TLS on Postgres, restrict network access, and consider PostgreSQL row-level security (RLS) for multi-tenant isolation.
- **Observability:** forward the adapter's structured debug logs to your logging stack and export database metrics (connections, locks, statement timeouts) to your monitoring system.

## Notes

- `connect()` is idempotent and safe to call on startup; it will run pending migrations and create missing tables/indexes.
- All JSONB columns are parsed to plain objects for convenience.
- Each query is executed in its own transaction with a configurable statement timeout and retry policy to survive transient issues.
- Errors are wrapped in `InternalError` with retry hints where applicable, and a `healthCheck()` helper is provided for readiness probes.
