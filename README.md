# @kitiumai/auth-postgres

PostgreSQL storage adapter for `@kitiumai/auth`. It manages all persistence (users, sessions, API keys, orgs, RBAC, SSO, 2FA) and bootstraps the database schema on first connection.

## Installation

```bash
pnpm add @kitiumai/auth-postgres pg
```

Requires PostgreSQL 12+ and Node 16+.

## Quick start

```ts
import { PostgresStorageAdapter } from '@kitiumai/auth-postgres';
import { AuthCore, createStorageConfig } from '@kitiumai/auth';

const storage = new PostgresStorageAdapter(process.env.DATABASE_URL!);
await storage.connect(); // creates tables and indexes if missing

const auth = new AuthCore({
  appUrl: 'https://example.com',
  providers: [], // add your email/OAuth/SAML providers
  storage: createStorageConfig({ driver: 'postgres', url: process.env.DATABASE_URL }),
  apiKeys: { prefix: 'kit', hash: { algo: 'argon2id' } },
  sessions: { cookieName: 'kitium_session', ttlSeconds: 60 * 60 * 24 },
});
```

### Custom pool options

```ts
const storage = new PostgresStorageAdapter(process.env.DATABASE_URL!, {
  max: 10,
  idleTimeoutMillis: 30_000,
});
```

## What it creates

- Tables: `users`, `api_keys`, `sessions`, `organizations`, `email_verification_tokens`, `email_verification_token_attempts`, `auth_events`, `roles`, `user_roles`, `sso_providers`, `sso_links`, `sso_sessions`, `twofa_devices`, `twofa_backup_codes`, `twofa_sessions`
- Indexes on common lookup columns (ids, foreign keys, expirations, email, etc.)

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

## Notes

- `connect()` is idempotent and safe to call on startup; it will create missing tables/indexes.
- All JSONB columns are parsed to plain objects for convenience.
- Errors are wrapped in `InternalError` with retry hints where applicable.
