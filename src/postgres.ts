import { Pool, PoolClient, PoolConfig } from 'pg';
import { getLogger } from '@kitiumai/logger';
import { InternalError } from '@kitiumai/error';
import { generateId, generateApiKey, hashApiKey } from '@kitiumai/auth/utils';
import { setTimeout as delay } from 'node:timers/promises';
import type {
  StorageAdapter,
  ApiKeyRecord,
  SessionRecord,
  OrganizationRecord,
  AuthEvent,
  UserRecord,
  CreateUserInput,
  UpdateUserInput,
  OAuthLink,
  EmailVerificationToken,
  OrganizationMember,
  RoleRecord,
  TwoFactorDevice,
  BackupCode,
  TwoFactorSession,
  SSOLink,
  SSOSession,
} from '@kitiumai/auth';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type DbRecord = Record<string, any>;

type QueryOptions = {
  operation?: string;
  timeoutMs?: number;
  retries?: number;
};

type PostgresAdapterOptions = PoolConfig & {
  statementTimeoutMs?: number;
  maxRetries?: number;
};

export class PostgresStorageAdapter implements StorageAdapter {
  private pool: Pool;
  private readonly logger = getLogger();
  private readonly defaultQueryTimeoutMs: number;
  private readonly defaultRetries: number;

  constructor(connectionString: string, options?: PostgresAdapterOptions) {
    const { statementTimeoutMs, maxRetries, ...poolOptions } = options ?? {};
    this.pool = new Pool({
      connectionString,
      ...(poolOptions ?? {}),
    });
    this.defaultQueryTimeoutMs = statementTimeoutMs ?? 5_000;
    this.defaultRetries = maxRetries ?? 2;
  }

  async connect(): Promise<void> {
    try {
      await this.runMigrations();
      this.logger.info('PostgreSQL adapter connected successfully');
    } catch (error) {
      this.logger.error('Failed to connect to PostgreSQL', { error });
      throw new InternalError({
        code: 'auth-postgres/connection_failed',
        message: 'Failed to connect to PostgreSQL',
        severity: 'error',
        retryable: true,
        cause: error,
        context: { connectionString: this.maskConnectionString() },
      });
    }
  }

  private maskConnectionString(): string {
    // Mask sensitive connection string for logging
    return '***';
  }

  async disconnect(): Promise<void> {
    try {
      await this.pool.end();
      this.logger.info('PostgreSQL adapter disconnected');
    } catch (error) {
      this.logger.error('Error disconnecting from PostgreSQL', { error });
      throw new InternalError({
        code: 'auth-postgres/disconnect_failed',
        message: 'Failed to disconnect from PostgreSQL',
        severity: 'error',
        retryable: false,
        cause: error,
      });
    }
  }

  private async withClient<T>(fn: (client: PoolClient) => Promise<T>): Promise<T> {
    const client = await this.pool.connect();
    try {
      return await fn(client);
    } finally {
      client.release();
    }
  }

  private async query<T extends DbRecord = DbRecord>(
    text: string,
    values: unknown[] = [],
    options?: QueryOptions
  ): Promise<{ rows: T[]; rowCount: number | null }> {
    const retries = options?.retries ?? this.defaultRetries;
    const timeoutMs = options?.timeoutMs ?? this.defaultQueryTimeoutMs;
    let lastError: unknown;

    for (let attempt = 0; attempt <= retries; attempt += 1) {
      try {
        return await this.withClient(async (client) => {
          const start = Date.now();
          await client.query('BEGIN');

          try {
            if (timeoutMs) {
              await client.query('SET LOCAL statement_timeout = $1', [timeoutMs]);
            }

            const result = await client.query<T>(text, values);
            await client.query('COMMIT');

            const durationMs = Date.now() - start;

            this.logger.debug('postgres.query', {
              operation: options?.operation,
              durationMs,
            });

            return result;
          } catch (error) {
            await client.query('ROLLBACK');
            throw error;
          }
        });
      } catch (error) {
        lastError = error;
        const retryable = attempt < retries;
        this.logger.warn('PostgreSQL query failed', {
          operation: options?.operation,
          attempt,
          retryable,
          error,
        });

        if (!retryable) {
          throw new InternalError({
            code: 'auth-postgres/query_failed',
            message: 'Failed to execute PostgreSQL query',
            severity: 'error',
            retryable: false,
            cause: error,
          });
        }

        await delay(50 * 2 ** attempt);
      }
    }

    throw lastError;
  }

  async healthCheck(): Promise<{ status: 'ok' | 'error'; latencyMs: number }> {
    const start = Date.now();
    try {
      await this.query('SELECT 1', [], { operation: 'health_check', retries: 0 });
      return { status: 'ok', latencyMs: Date.now() - start };
    } catch (error) {
      this.logger.error('PostgreSQL health check failed', { error });
      return { status: 'error', latencyMs: Date.now() - start };
    }
  }

  private async runMigrations(): Promise<void> {
    await this.query(
      `CREATE TABLE IF NOT EXISTS auth_migrations (
        id VARCHAR(255) PRIMARY KEY,
        applied_at TIMESTAMP NOT NULL DEFAULT NOW()
      )`
    );

    const migrationId = '0001_initial_schema_v2';
    const existing = await this.query('SELECT id FROM auth_migrations WHERE id = $1', [
      migrationId,
    ]);

    if (existing.rows.length > 0) {
      return;
    }

    const createTables = `
      -- Users table
      CREATE TABLE IF NOT EXISTS users (
        id VARCHAR(255) PRIMARY KEY,
        email VARCHAR(255) UNIQUE,
        name VARCHAR(255),
        picture VARCHAR(1024),
        plan VARCHAR(50) DEFAULT 'free',
        entitlements TEXT[] NOT NULL DEFAULT '{}',
        oauth JSONB DEFAULT '{}',
        metadata JSONB DEFAULT '{}',
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      );

      -- Organizations table
      CREATE TABLE IF NOT EXISTS organizations (
        id VARCHAR(255) PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        plan VARCHAR(50) NOT NULL,
        seats INTEGER NOT NULL DEFAULT 1,
        members JSONB NOT NULL DEFAULT '[]',
        metadata JSONB DEFAULT '{}',
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      );

      -- API Keys table
      CREATE TABLE IF NOT EXISTS api_keys (
        id VARCHAR(255) PRIMARY KEY,
        principal_id VARCHAR(255) NOT NULL,
        hash VARCHAR(255) NOT NULL UNIQUE,
        prefix VARCHAR(50) NOT NULL,
        last_four VARCHAR(4) NOT NULL,
        scopes TEXT[] NOT NULL DEFAULT '{}',
        metadata JSONB DEFAULT '{}',
        expires_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW(),
        CONSTRAINT fk_api_keys_principal_user FOREIGN KEY (principal_id) REFERENCES users(id) ON DELETE CASCADE
      );

      -- Sessions table
      CREATE TABLE IF NOT EXISTS sessions (
        id VARCHAR(255) PRIMARY KEY,
        user_id VARCHAR(255) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        org_id VARCHAR(255),
        plan VARCHAR(50),
        entitlements TEXT[] NOT NULL DEFAULT '{}',
        expires_at TIMESTAMP NOT NULL,
        metadata JSONB DEFAULT '{}',
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW(),
        CONSTRAINT fk_sessions_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE SET NULL
      );

      -- Email Verification Tokens table
      CREATE TABLE IF NOT EXISTS email_verification_tokens (
        id VARCHAR(255) PRIMARY KEY,
        email VARCHAR(255) NOT NULL,
        code VARCHAR(255) NOT NULL,
        code_hash VARCHAR(255) NOT NULL,
        type VARCHAR(50) NOT NULL,
        user_id VARCHAR(255),
        metadata JSONB DEFAULT '{}',
        expires_at TIMESTAMP NOT NULL,
        used_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW(),
        CONSTRAINT fk_email_verification_tokens_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
      );

      -- Email Verification Token Attempts table
      CREATE TABLE IF NOT EXISTS email_verification_token_attempts (
        token_id VARCHAR(255) PRIMARY KEY REFERENCES email_verification_tokens(id) ON DELETE CASCADE,
        attempts INTEGER DEFAULT 0
      );

      -- Events table
      CREATE TABLE IF NOT EXISTS auth_events (
        id SERIAL PRIMARY KEY,
        type VARCHAR(100) NOT NULL,
        principal_id VARCHAR(255) NOT NULL,
        org_id VARCHAR(255),
        data JSONB NOT NULL DEFAULT '{}',
        timestamp TIMESTAMP DEFAULT NOW()
      );

      -- Roles table
      CREATE TABLE IF NOT EXISTS roles (
        id VARCHAR(255) PRIMARY KEY,
        org_id VARCHAR(255) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
        name VARCHAR(255) NOT NULL,
        description TEXT,
        is_system BOOLEAN DEFAULT FALSE,
        permissions JSONB NOT NULL DEFAULT '[]',
        metadata JSONB DEFAULT '{}',
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      );

      -- User Roles table
      CREATE TABLE IF NOT EXISTS user_roles (
        id VARCHAR(255) PRIMARY KEY,
        user_id VARCHAR(255) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        role_id VARCHAR(255) NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
        org_id VARCHAR(255) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
        assigned_at TIMESTAMP DEFAULT NOW()
      );

      -- SSO Providers table
      CREATE TABLE IF NOT EXISTS sso_providers (
        id VARCHAR(255) PRIMARY KEY,
        type VARCHAR(50) NOT NULL,
        name VARCHAR(255) NOT NULL,
        org_id VARCHAR(255),
        metadata_url TEXT,
        client_id VARCHAR(255),
        client_secret TEXT,
        token_endpoint_auth_method VARCHAR(50),
        idp_entity_id TEXT,
        idp_sso_url TEXT,
        idp_slo_url TEXT,
        idp_certificate TEXT,
        sp_entity_id TEXT,
        sp_acs_url TEXT,
        sp_slo_url TEXT,
        signing_cert TEXT,
        signing_key TEXT,
        encryption_enabled BOOLEAN DEFAULT FALSE,
        force_authn BOOLEAN DEFAULT FALSE,
        scopes TEXT[] DEFAULT '{}',
        redirect_uris TEXT[] DEFAULT '{}',
        claim_mapping JSONB DEFAULT '{}',
        attribute_mapping JSONB DEFAULT '{}',
        metadata JSONB DEFAULT '{}',
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW(),
        CONSTRAINT fk_sso_providers_org FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE SET NULL
      );

      -- SSO Links table
      CREATE TABLE IF NOT EXISTS sso_links (
        id VARCHAR(255) PRIMARY KEY,
        user_id VARCHAR(255) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        provider_id VARCHAR(255) NOT NULL REFERENCES sso_providers(id) ON DELETE CASCADE,
        provider_type VARCHAR(50) NOT NULL,
        provider_subject VARCHAR(255) NOT NULL,
        provider_email VARCHAR(255),
        auto_provisioned BOOLEAN DEFAULT FALSE,
        metadata JSONB DEFAULT '{}',
        linked_at TIMESTAMP DEFAULT NOW(),
        last_auth_at TIMESTAMP
      );

      -- SSO Sessions table
      CREATE TABLE IF NOT EXISTS sso_sessions (
        id VARCHAR(255) PRIMARY KEY,
        user_id VARCHAR(255) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        provider_id VARCHAR(255) NOT NULL REFERENCES sso_providers(id) ON DELETE CASCADE,
        provider_type VARCHAR(50) NOT NULL,
        provider_subject VARCHAR(255) NOT NULL,
        session_token TEXT,
        expires_at TIMESTAMP NOT NULL,
        linked_at TIMESTAMP DEFAULT NOW(),
        last_auth_at TIMESTAMP
      );

      -- 2FA Devices table
      CREATE TABLE IF NOT EXISTS twofa_devices (
        id VARCHAR(255) PRIMARY KEY,
        user_id VARCHAR(255) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        method VARCHAR(50) NOT NULL,
        name VARCHAR(255),
        verified BOOLEAN DEFAULT FALSE,
        phone_number VARCHAR(50),
        secret TEXT,
        last_used_at TIMESTAMP,
        metadata JSONB DEFAULT '{}',
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      );

      -- 2FA Backup Codes table
      CREATE TABLE IF NOT EXISTS twofa_backup_codes (
        id VARCHAR(255) PRIMARY KEY,
        user_id VARCHAR(255) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        code VARCHAR(255) NOT NULL,
        used BOOLEAN DEFAULT FALSE,
        used_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW()
      );

      -- 2FA Sessions table
      CREATE TABLE IF NOT EXISTS twofa_sessions (
        id VARCHAR(255) PRIMARY KEY,
        user_id VARCHAR(255) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        session_id VARCHAR(255) NOT NULL,
        device_id VARCHAR(255) NOT NULL REFERENCES twofa_devices(id) ON DELETE CASCADE,
        method VARCHAR(50) NOT NULL,
        verification_code VARCHAR(10),
        attempt_count INTEGER DEFAULT 0,
        max_attempts INTEGER DEFAULT 5,
        expires_at TIMESTAMP NOT NULL,
        completed_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW()
      );

      -- Indexes
      CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
      CREATE INDEX IF NOT EXISTS idx_api_keys_principal_id ON api_keys(principal_id);
      CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(hash);
      CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
      CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
      CREATE INDEX IF NOT EXISTS idx_organizations_plan ON organizations(plan);
      CREATE INDEX IF NOT EXISTS idx_email_verification_tokens_email ON email_verification_tokens(email);
      CREATE INDEX IF NOT EXISTS idx_email_verification_tokens_type ON email_verification_tokens(type);
      CREATE INDEX IF NOT EXISTS idx_email_verification_tokens_expires_at ON email_verification_tokens(expires_at);
      CREATE INDEX IF NOT EXISTS idx_auth_events_principal_id ON auth_events(principal_id);
      CREATE INDEX IF NOT EXISTS idx_auth_events_type ON auth_events(type);
      CREATE INDEX IF NOT EXISTS idx_auth_events_timestamp ON auth_events(timestamp);
      CREATE INDEX IF NOT EXISTS idx_roles_org_id ON roles(org_id);
      CREATE INDEX IF NOT EXISTS idx_user_roles_user_id ON user_roles(user_id);
      CREATE INDEX IF NOT EXISTS idx_user_roles_role_id ON user_roles(role_id);
      CREATE INDEX IF NOT EXISTS idx_user_roles_org_id ON user_roles(org_id);
      CREATE INDEX IF NOT EXISTS idx_sso_providers_org_id ON sso_providers(org_id);
      CREATE INDEX IF NOT EXISTS idx_sso_links_user_id ON sso_links(user_id);
      CREATE INDEX IF NOT EXISTS idx_sso_links_provider_id ON sso_links(provider_id);
      CREATE INDEX IF NOT EXISTS idx_sso_sessions_user_id ON sso_sessions(user_id);
      CREATE INDEX IF NOT EXISTS idx_twofa_devices_user_id ON twofa_devices(user_id);
      CREATE INDEX IF NOT EXISTS idx_twofa_backup_codes_user_id ON twofa_backup_codes(user_id);
      CREATE INDEX IF NOT EXISTS idx_twofa_sessions_user_id ON twofa_sessions(user_id);
      CREATE INDEX IF NOT EXISTS idx_twofa_sessions_session_id ON twofa_sessions(session_id);

      -- Updated at trigger
      CREATE OR REPLACE FUNCTION set_updated_at()
      RETURNS TRIGGER AS $$
      BEGIN
        NEW.updated_at = NOW();
        RETURN NEW;
      END;
      $$ LANGUAGE plpgsql;

      DO $$
      DECLARE
        tbl TEXT;
      BEGIN
        FOR tbl IN SELECT UNNEST(ARRAY['users','api_keys','sessions','organizations','roles','twofa_devices']) LOOP
          EXECUTE format('CREATE TRIGGER %I_set_updated_at BEFORE UPDATE ON %I FOR EACH ROW EXECUTE FUNCTION set_updated_at();', tbl, tbl);
        END LOOP;
      END;
      $$;
    `;

    await this.query(createTables, [], {
      operation: 'migration:initial',
      timeoutMs: 30_000,
      retries: 0,
    });
    await this.query('INSERT INTO auth_migrations (id) VALUES ($1)', [migrationId]);
  }

  private mapEmailVerificationToken(row: Record<string, unknown>): EmailVerificationToken {
    return {
      id: String(row.id),
      email: String(row.email),
      code: String(row.code),
      codeHash: String(row.code_hash),
      type: String(row.type) as EmailVerificationToken['type'],
      userId: (row.user_id as string | null) ?? undefined,
      metadata: (row.metadata as Record<string, unknown>) || {},
      expiresAt: new Date(row.expires_at as string),
      createdAt: new Date(row.created_at as string),
      usedAt: row.used_at ? new Date(row.used_at as string) : undefined,
    };
  }

  /**
   * Create an API key with plaintext secret (convenience method)
   * @param principalId - Principal ID for the key
   * @param scopes - Scopes for the key
   * @param prefix - Optional prefix (default: 'api')
   * @returns Object with the record and plaintext key
   */
  async createApiKeyWithSecret(
    principalId: string,
    scopes: string[],
    prefix: string = 'api'
  ): Promise<{ record: ApiKeyRecord; key: string }> {
    const key = generateApiKey(prefix);
    const hash = hashApiKey(key);
    const parts = key.split('_');
    const lastFour = parts[parts.length - 1]!.slice(-4);

    const record = await this.createApiKey({
      principalId,
      hash,
      prefix,
      lastFour,
      scopes,
    });

    return { record, key };
  }

  // API Key methods
  async createApiKey(
    data: Omit<ApiKeyRecord, 'id' | 'createdAt' | 'updatedAt'>
  ): Promise<ApiKeyRecord> {
    const query = `
      INSERT INTO api_keys (id, principal_id, hash, prefix, last_four, scopes, metadata, expires_at, updated_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      RETURNING *
    `;

    const values = [
      generateId(),
      data['principalId'],
      data['hash'],
      data['prefix'],
      data['lastFour'],
      data['scopes'],
      JSON.stringify(data['metadata'] || {}),
      data['expiresAt'] || null,
      new Date(),
    ];

    const result = await this.query(query, values);
    if (!result.rows[0]) {
      throw new InternalError({
        code: 'auth-postgres/create_failed',
        message: 'Failed to create API key',
        severity: 'error',
        retryable: false,
      });
    }
    return this.mapApiKeyRecord(result.rows[0]!);
  }

  async getApiKey(id: string): Promise<ApiKeyRecord | null> {
    const query = 'SELECT * FROM api_keys WHERE id = $1';
    const result = await this.query(query, [id]);

    if (result.rows.length === 0) {
      return null;
    }

    return this.mapApiKeyRecord(result.rows[0]!);
  }

  async getApiKeyByHash(hash: string): Promise<ApiKeyRecord | null> {
    const query = 'SELECT * FROM api_keys WHERE hash = $1';
    const result = await this.query(query, [hash]);

    if (result.rows.length === 0) {
      return null;
    }

    return this.mapApiKeyRecord(result.rows[0]!);
  }

  async getApiKeysByPrefixAndLastFour(prefix: string, lastFour: string): Promise<ApiKeyRecord[]> {
    const query = 'SELECT * FROM api_keys WHERE prefix = $1 AND last_four = $2';
    const result = await this.query(query, [prefix, lastFour]);

    return result.rows
      .filter((row): row is DbRecord => !!row)
      .map((row) => this.mapApiKeyRecord(row));
  }

  async updateApiKey(id: string, data: Partial<ApiKeyRecord>): Promise<ApiKeyRecord> {
    const fields = [];
    const values = [];
    let paramCount = 1;

    for (const [key, value] of Object.entries(data)) {
      if (key === 'id' || key === 'createdAt') {
        continue;
      }

      if (key === 'metadata') {
        fields.push(`metadata = $${paramCount}`);
        values.push(JSON.stringify(value));
      } else if (key === 'principalId') {
        fields.push(`principal_id = $${paramCount}`);
        values.push(value);
      } else if (key === 'lastFour') {
        fields.push(`last_four = $${paramCount}`);
        values.push(value);
      } else if (key === 'expiresAt') {
        fields.push(`expires_at = $${paramCount}`);
        values.push(value || null);
      } else {
        const snakeKey = this.camelToSnake(key);
        fields.push(`${snakeKey} = $${paramCount}`);
        values.push(value);
      }
      paramCount++;
    }

    if (fields.length === 0) {
      throw new InternalError({
        code: 'auth-postgres/no_fields_to_update',
        message: 'No fields to update',
        severity: 'error',
        retryable: false,
      });
    }

    fields.push(`updated_at = $${paramCount}`);
    values.push(new Date());
    values.push(id);

    const query = `
      UPDATE api_keys 
      SET ${fields.join(', ')} 
      WHERE id = $${paramCount + 1}
      RETURNING *
    `;

    const result = await this.query(query, values);
    if (!result.rows[0]) {
      throw new InternalError({
        code: 'auth-postgres/update_failed',
        message: 'Failed to update API key',
        severity: 'error',
        retryable: false,
      });
    }
    return this.mapApiKeyRecord(result.rows[0]!);
  }

  async deleteApiKey(id: string): Promise<void> {
    const query = 'DELETE FROM api_keys WHERE id = $1';
    await this.query(query, [id]);
  }

  async listApiKeys(principalId: string): Promise<ApiKeyRecord[]> {
    const query = 'SELECT * FROM api_keys WHERE principal_id = $1 ORDER BY created_at DESC';
    const result = await this.query(query, [principalId]);

    return result.rows
      .filter((row): row is DbRecord => !!row)
      .map((row) => this.mapApiKeyRecord(row));
  }

  // Session methods
  async createSession(data: Omit<SessionRecord, 'id' | 'createdAt'>): Promise<SessionRecord> {
    const query = `
      INSERT INTO sessions (id, user_id, org_id, plan, entitlements, expires_at, metadata, updated_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      RETURNING *
    `;

    const values = [
      generateId(),
      data.userId,
      data.orgId || null,
      data.plan || null,
      data.entitlements || [],
      data.expiresAt,
      JSON.stringify(data.metadata || {}),
      new Date(),
    ];

    const result = await this.query(query, values);
    if (!result.rows[0]) {
      throw new InternalError({
        code: 'auth-postgres/create_failed',
        message: 'Failed to create session',
        severity: 'error',
        retryable: false,
      });
    }
    return this.mapSessionRecord(result.rows[0]!);
  }

  async getSession(id: string): Promise<SessionRecord | null> {
    const query = 'SELECT * FROM sessions WHERE id = $1';
    const result = await this.query(query, [id]);

    if (result.rows.length === 0) {
      return null;
    }

    return this.mapSessionRecord(result.rows[0]!);
  }

  async updateSession(id: string, data: Partial<SessionRecord>): Promise<SessionRecord> {
    const fields = [];
    const values = [];
    let paramCount = 1;

    for (const [key, value] of Object.entries(data)) {
      if (key === 'id' || key === 'createdAt') {
        continue;
      }

      if (key === 'metadata') {
        fields.push(`metadata = $${paramCount}`);
        values.push(JSON.stringify(value));
      } else if (key === 'userId') {
        fields.push(`user_id = $${paramCount}`);
        values.push(value);
      } else if (key === 'orgId') {
        fields.push(`org_id = $${paramCount}`);
        values.push(value || null);
      } else if (key === 'expiresAt') {
        fields.push(`expires_at = $${paramCount}`);
        values.push(value);
      } else {
        const snakeKey = this.camelToSnake(key);
        fields.push(`${snakeKey} = $${paramCount}`);
        values.push(value);
      }
      paramCount++;
    }

    if (fields.length === 0) {
      throw new InternalError({
        code: 'auth-postgres/no_fields_to_update',
        message: 'No fields to update',
        severity: 'error',
        retryable: false,
      });
    }

    fields.push(`updated_at = $${paramCount}`);
    values.push(new Date());
    values.push(id);

    const query = `
      UPDATE sessions 
      SET ${fields.join(', ')} 
      WHERE id = $${paramCount + 1}
      RETURNING *
    `;

    const result = await this.query(query, values);
    if (!result.rows[0]) {
      throw new InternalError({
        code: 'auth-postgres/update_failed',
        message: 'Failed to update session',
        severity: 'error',
        retryable: false,
      });
    }
    return this.mapSessionRecord(result.rows[0]!);
  }

  async deleteSession(id: string): Promise<void> {
    const query = 'DELETE FROM sessions WHERE id = $1';
    await this.query(query, [id]);
  }

  // Organization methods
  async createOrganization(
    data: Omit<OrganizationRecord, 'id' | 'createdAt' | 'updatedAt'>
  ): Promise<OrganizationRecord> {
    const query = `
      INSERT INTO organizations (id, name, plan, seats, members, metadata)
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING *
    `;

    const values = [
      generateId(),
      data.name,
      data.plan,
      data.seats,
      JSON.stringify(data.members),
      JSON.stringify(data.metadata || {}),
    ];

    const result = await this.query(query, values);
    if (!result.rows[0]) {
      throw new InternalError({
        code: 'auth-postgres/create_failed',
        message: 'Failed to create organization',
        severity: 'error',
        retryable: false,
      });
    }
    return this.mapOrganizationRecord(result.rows[0]!);
  }

  async getOrganization(id: string): Promise<OrganizationRecord | null> {
    const query = 'SELECT * FROM organizations WHERE id = $1';
    const result = await this.query(query, [id]);

    if (result.rows.length === 0) {
      return null;
    }

    return this.mapOrganizationRecord(result.rows[0]!);
  }

  async updateOrganization(
    id: string,
    data: Partial<OrganizationRecord>
  ): Promise<OrganizationRecord> {
    const fields = [];
    const values = [];
    let paramCount = 1;

    for (const [key, value] of Object.entries(data)) {
      if (key === 'id' || key === 'createdAt') {
        continue;
      }

      if (key === 'members' || key === 'metadata') {
        fields.push(`${key} = $${paramCount}`);
        values.push(JSON.stringify(value));
      } else {
        fields.push(`${key} = $${paramCount}`);
        values.push(value);
      }
      paramCount++;
    }

    if (fields.length === 0) {
      throw new InternalError({
        code: 'auth-postgres/no_fields_to_update',
        message: 'No fields to update',
        severity: 'error',
        retryable: false,
      });
    }

    fields.push(`updated_at = $${paramCount}`);
    values.push(new Date());
    values.push(id);

    const query = `
      UPDATE organizations 
      SET ${fields.join(', ')} 
      WHERE id = $${paramCount + 1}
      RETURNING *
    `;

    const result = await this.query(query, values);
    if (!result.rows[0]) {
      throw new InternalError({
        code: 'auth-postgres/update_failed',
        message: 'Failed to update organization',
        severity: 'error',
        retryable: false,
      });
    }
    return this.mapOrganizationRecord(result.rows[0]!);
  }

  async deleteOrganization(id: string): Promise<void> {
    const query = 'DELETE FROM organizations WHERE id = $1';
    await this.query(query, [id]);
  }

  // User methods
  async createUser(data: CreateUserInput): Promise<UserRecord> {
    const id = generateId();

    const query = `
      INSERT INTO users (id, email, name, picture, plan, entitlements, oauth, metadata)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      RETURNING *
    `;

    const values = [
      id,
      data.email || null,
      data.name || null,
      data.picture || null,
      data.plan || 'free',
      data.entitlements || [],
      JSON.stringify({}),
      JSON.stringify(data.metadata || {}),
    ];

    const result = await this.query(query, values);
    if (!result.rows[0]) {
      throw new InternalError({
        code: 'auth-postgres/create_failed',
        message: 'Failed to create user',
        severity: 'error',
        retryable: false,
      });
    }
    return this.mapUserRecord(result.rows[0]!);
  }

  async getUser(id: string): Promise<UserRecord | null> {
    const query = 'SELECT * FROM users WHERE id = $1';
    const result = await this.query(query, [id]);

    if (result.rows.length === 0) {
      return null;
    }

    return this.mapUserRecord(result.rows[0]!);
  }

  async getUserByEmail(email: string): Promise<UserRecord | null> {
    const query = 'SELECT * FROM users WHERE email = $1';
    const result = await this.query(query, [email]);

    if (result.rows.length === 0) {
      return null;
    }

    return this.mapUserRecord(result.rows[0]!);
  }

  async getUserByOAuth(provider: string, sub: string): Promise<UserRecord | null> {
    const query = `
      SELECT * FROM users
      WHERE oauth->>$1 IS NOT NULL
        AND oauth->$1->>'sub' = $2
    `;
    const result = await this.query(query, [provider, sub]);

    if (result.rows.length === 0) {
      return null;
    }

    return this.mapUserRecord(result.rows[0]!);
  }

  async updateUser(id: string, data: UpdateUserInput): Promise<UserRecord> {
    const fields = [];
    const values = [];
    let paramCount = 1;

    for (const [key, value] of Object.entries(data)) {
      if (key === 'metadata') {
        fields.push(`${this.camelToSnake(key)} = $${paramCount}`);
        values.push(JSON.stringify(value));
      } else if (key === 'entitlements') {
        fields.push(`${this.camelToSnake(key)} = $${paramCount}`);
        values.push(value);
      } else {
        fields.push(`${this.camelToSnake(key)} = $${paramCount}`);
        values.push(value);
      }
      paramCount++;
    }

    if (fields.length === 0) {
      return this.getUser(id) as Promise<UserRecord>;
    }

    fields.push(`updated_at = $${paramCount}`);
    values.push(new Date());
    values.push(id);

    const query = `
      UPDATE users
      SET ${fields.join(', ')}
      WHERE id = $${paramCount + 1}
      RETURNING *
    `;

    const result = await this.query(query, values);
    if (!result.rows[0]) {
      throw new InternalError({
        code: 'auth-postgres/update_failed',
        message: 'Failed to update user',
        severity: 'error',
        retryable: false,
      });
    }
    return this.mapUserRecord(result.rows[0]!);
  }

  async deleteUser(id: string): Promise<void> {
    const query = 'DELETE FROM users WHERE id = $1';
    await this.query(query, [id]);
  }

  async linkOAuthAccount(
    userId: string,
    provider: string,
    oauthLink: OAuthLink
  ): Promise<UserRecord> {
    const query = `
      UPDATE users
      SET oauth = jsonb_set(oauth, $2, $3),
          updated_at = NOW()
      WHERE id = $1
      RETURNING *
    `;

    const oauthData = {
      provider: oauthLink.provider,
      sub: oauthLink.sub,
      email: oauthLink.email,
      name: oauthLink.name,
      linkedAt: oauthLink.linkedAt.toISOString(),
    };

    const values = [userId, `{${provider}}`, JSON.stringify(oauthData)];

    const result = await this.query(query, values);
    if (!result.rows[0]) {
      throw new InternalError({
        code: 'auth-postgres/link_failed',
        message: 'Failed to link OAuth account',
        severity: 'error',
        retryable: false,
      });
    }
    return this.mapUserRecord(result.rows[0]!);
  }

  // Email Verification Token methods
  async createEmailVerificationToken(
    data: Omit<EmailVerificationToken, 'id'>
  ): Promise<EmailVerificationToken> {
    const id = generateId();

    const query = `
      INSERT INTO email_verification_tokens (id, email, code, code_hash, type, user_id, metadata, expires_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      RETURNING *
    `;

    const values = [
      id,
      data.email,
      data.code,
      data.codeHash,
      data.type,
      data.userId || null,
      JSON.stringify(data.metadata || {}),
      data.expiresAt,
    ];

    const result = await this.query(query, values);
    if (!result.rows[0]) {
      throw new InternalError({
        code: 'auth-postgres/create_failed',
        message: 'Failed to create email verification token',
        severity: 'error',
        retryable: false,
      });
    }
    return this.mapEmailVerificationToken(result.rows[0]!);
  }

  async getEmailVerificationTokens(
    email: string,
    type?: string
  ): Promise<EmailVerificationToken[]> {
    let query = 'SELECT * FROM email_verification_tokens WHERE email = $1';
    const values: (string | undefined)[] = [email];

    if (type) {
      query += ' AND type = $2';
      values.push(type);
    }

    query += ' ORDER BY created_at DESC';

    const result = await this.query(query, values);
    return result.rows
      .filter((row): row is DbRecord => !!row)
      .map((row) => this.mapEmailVerificationToken(row));
  }

  async getEmailVerificationTokenById(id: string): Promise<EmailVerificationToken | null> {
    const query = 'SELECT * FROM email_verification_tokens WHERE id = $1';
    const result = await this.query(query, [id]);

    if (result.rows.length === 0) {
      return null;
    }

    return this.mapEmailVerificationToken(result.rows[0]!);
  }

  async markEmailVerificationTokenAsUsed(id: string): Promise<EmailVerificationToken> {
    const query = `
      UPDATE email_verification_tokens
      SET used_at = NOW()
      WHERE id = $1
      RETURNING *
    `;

    const result = await this.query(query, [id]);
    if (!result.rows[0]) {
      throw new InternalError({
        code: 'auth-postgres/update_failed',
        message: 'Failed to mark email verification token as used',
        severity: 'error',
        retryable: false,
      });
    }
    return this.mapEmailVerificationToken(result.rows[0]!);
  }

  async deleteExpiredEmailVerificationTokens(): Promise<number> {
    const query = 'DELETE FROM email_verification_tokens WHERE expires_at < NOW()';
    const result = await this.query(query);
    return result.rowCount || 0;
  }

  async getEmailVerificationTokenAttempts(tokenId: string): Promise<number> {
    const query = 'SELECT attempts FROM email_verification_token_attempts WHERE token_id = $1';
    const result = await this.query(query, [tokenId]);

    if (result.rows.length === 0) {
      return 0;
    }

    return result.rows[0]!.attempts;
  }

  async incrementEmailVerificationTokenAttempts(tokenId: string): Promise<number> {
    const query = `
      INSERT INTO email_verification_token_attempts (token_id, attempts)
      VALUES ($1, 1)
      ON CONFLICT (token_id)
      DO UPDATE SET attempts = attempts + 1
      RETURNING attempts
    `;

    const result = await this.query(query, [tokenId]);
    if (!result.rows[0]) {
      throw new InternalError({
        code: 'auth-postgres/update_failed',
        message: 'Failed to increment token attempts',
        severity: 'error',
        retryable: false,
      });
    }
    return result.rows[0]!.attempts;
  }

  // Event methods
  async emitEvent(event: AuthEvent): Promise<void> {
    const query = `
      INSERT INTO auth_events (type, principal_id, org_id, data, timestamp)
      VALUES ($1, $2, $3, $4, $5)
    `;

    const values = [
      event.type,
      event.principalId,
      event.orgId,
      JSON.stringify(event.data),
      event.timestamp,
    ];

    await this.query(query, values);
  }

  // RBAC methods
  async createRole(data: Omit<RoleRecord, 'id' | 'createdAt' | 'updatedAt'>): Promise<RoleRecord> {
    const id = generateId();

    const query = `
      INSERT INTO roles (id, org_id, name, description, is_system, permissions, metadata)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING *
    `;

    const values = [
      id,
      data.orgId,
      data.name,
      data.description || null,
      data.isSystem || false,
      JSON.stringify(data.permissions || []),
      JSON.stringify(data.metadata || {}),
    ];

    const result = await this.query(query, values);
    if (!result.rows[0]) {
      throw new InternalError({
        code: 'auth-postgres/create_failed',
        message: 'Failed to create role',
        severity: 'error',
        retryable: false,
      });
    }
    return this.mapRoleRecord(result.rows[0]!);
  }

  async getRole(roleId: string): Promise<RoleRecord | null> {
    const query = 'SELECT * FROM roles WHERE id = $1';
    const result = await this.query(query, [roleId]);

    if (result.rows.length === 0) {
      return null;
    }

    return this.mapRoleRecord(result.rows[0]!);
  }

  async updateRole(roleId: string, data: Partial<RoleRecord>): Promise<RoleRecord> {
    const fields = [];
    const values = [];
    let paramCount = 1;

    for (const [key, value] of Object.entries(data)) {
      if (key === 'id' || key === 'createdAt') {
        continue;
      }

      const snakeKey = this.camelToSnake(key);
      if (key === 'permissions' || key === 'metadata') {
        fields.push(`${snakeKey} = $${paramCount}`);
        values.push(JSON.stringify(value));
      } else {
        fields.push(`${snakeKey} = $${paramCount}`);
        values.push(value);
      }
      paramCount++;
    }

    if (fields.length === 0) {
      const existing = await this.getRole(roleId);
      if (!existing) {
        throw new InternalError({
          code: 'auth-postgres/role_not_found',
          message: 'Role not found',
          severity: 'error',
          retryable: false,
          context: { roleId },
        });
      }
      return existing;
    }

    fields.push(`updated_at = $${paramCount}`);
    values.push(new Date());
    values.push(roleId);

    const query = `
      UPDATE roles
      SET ${fields.join(', ')}
      WHERE id = $${paramCount + 1}
      RETURNING *
    `;

    const result = await this.query(query, values);
    if (!result.rows[0]) {
      throw new InternalError({
        code: 'auth-postgres/update_failed',
        message: 'Failed to update role',
        severity: 'error',
        retryable: false,
      });
    }
    return this.mapRoleRecord(result.rows[0]!);
  }

  async deleteRole(roleId: string): Promise<void> {
    const query = 'DELETE FROM roles WHERE id = $1';
    await this.query(query, [roleId]);
  }

  async listRoles(orgId: string): Promise<RoleRecord[]> {
    const query = 'SELECT * FROM roles WHERE org_id = $1 ORDER BY created_at DESC';
    const result = await this.query(query, [orgId]);

    return result.rows.map((row) => this.mapRoleRecord(row));
  }

  async assignRoleToUser(userId: string, roleId: string, orgId: string): Promise<RoleRecord> {
    const id = generateId();

    const query = `
      INSERT INTO user_roles (id, user_id, role_id, org_id)
      VALUES ($1, $2, $3, $4)
      RETURNING *
    `;

    const values = [id, userId, roleId, orgId];
    await this.query(query, values);

    const role = await this.getRole(roleId);
    if (!role) {
      throw new InternalError({
        code: 'auth-postgres/role_not_found',
        message: 'Role not found',
        severity: 'error',
        retryable: false,
        context: { roleId },
      });
    }
    return role;
  }

  async revokeRoleFromUser(userId: string, roleId: string, orgId: string): Promise<void> {
    const query = 'DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2 AND org_id = $3';
    await this.query(query, [userId, roleId, orgId]);
  }

  async getUserRoles(userId: string, orgId: string): Promise<RoleRecord[]> {
    const query = `
      SELECT r.*
      FROM roles r
      INNER JOIN user_roles ur ON r.id = ur.role_id
      WHERE ur.user_id = $1 AND ur.org_id = $2
      ORDER BY r.created_at DESC
    `;
    const result = await this.query(query, [userId, orgId]);

    return result.rows
      .filter((row): row is DbRecord => !!row)
      .map((row) => this.mapRoleRecord(row));
  }

  // SSO methods
  async createSSOProvider(data: DbRecord): Promise<unknown> {
    const id = generateId();

    const query = `
      INSERT INTO sso_providers (
        id, type, name, org_id, metadata_url, client_id, client_secret,
        token_endpoint_auth_method, idp_entity_id, idp_sso_url, idp_slo_url,
        idp_certificate, sp_entity_id, sp_acs_url, sp_slo_url, signing_cert,
        signing_key, encryption_enabled, force_authn, scopes, redirect_uris,
        claim_mapping, attribute_mapping, metadata
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24)
      RETURNING *
    `;

    const values = [
      id,
      data.type,
      data.name,
      data.orgId || null,
      data.metadata_url || data.metadataUrl || null,
      data.client_id || data.clientId || null,
      data.client_secret || data.clientSecret || null,
      data.token_endpoint_auth_method || data.tokenEndpointAuthMethod || null,
      data.idp_entity_id || data.idpEntityId || null,
      data.idp_sso_url || data.idpSsoUrl || null,
      data.idp_slo_url || data.idpSloUrl || null,
      data.idp_certificate || data.idpCertificate || null,
      data.sp_entity_id || data.spEntityId || null,
      data.sp_acs_url || data.spAcsUrl || null,
      data.sp_slo_url || data.spSloUrl || null,
      data.signing_cert || data.signingCert || null,
      data.signing_key || data.signingKey || null,
      data.encryption_enabled || data.encryptionEnabled || false,
      data.force_authn || data.forceAuthn || false,
      data.scopes || [],
      data.redirect_uris || data.redirectUris || [],
      JSON.stringify(data.claim_mapping || data.claimMapping || {}),
      JSON.stringify(data.attribute_mapping || data.attributeMapping || {}),
      JSON.stringify(data.metadata || {}),
    ];

    const result = await this.query(query, values);
    if (!result.rows[0]) {
      throw new InternalError({
        code: 'auth-postgres/create_failed',
        message: 'Failed to create SSO provider',
        severity: 'error',
        retryable: false,
      });
    }
    return this.mapSSOProviderRecord(result.rows[0]!);
  }

  async getSSOProvider(providerId: string): Promise<unknown | null> {
    const query = 'SELECT * FROM sso_providers WHERE id = $1';
    const result = await this.query(query, [providerId]);

    if (result.rows.length === 0) {
      return null;
    }

    return this.mapSSOProviderRecord(result.rows[0]!);
  }

  async updateSSOProvider(providerId: string, data: Partial<unknown>): Promise<unknown> {
    const fields = [];
    const values = [];
    let paramCount = 1;

    for (const [key, value] of Object.entries(data)) {
      if (key === 'id' || key === 'createdAt') {
        continue;
      }

      const snakeKey = this.camelToSnake(key);
      if (key === 'claimMapping' || key === 'attributeMapping' || key === 'metadata') {
        fields.push(`${snakeKey} = $${paramCount}`);
        values.push(JSON.stringify(value));
      } else {
        fields.push(`${snakeKey} = $${paramCount}`);
        values.push(value);
      }
      paramCount++;
    }

    if (fields.length === 0) {
      return this.getSSOProvider(providerId) as Promise<unknown>;
    }

    fields.push(`updated_at = $${paramCount}`);
    values.push(new Date());
    values.push(providerId);

    const query = `
      UPDATE sso_providers
      SET ${fields.join(', ')}
      WHERE id = $${paramCount + 1}
      RETURNING *
    `;

    const result = await this.query(query, values);
    if (!result.rows[0]) {
      throw new InternalError({
        code: 'auth-postgres/update_failed',
        message: 'Failed to update SSO provider',
        severity: 'error',
        retryable: false,
      });
    }
    return this.mapSSOProviderRecord(result.rows[0]!);
  }

  async deleteSSOProvider(providerId: string): Promise<void> {
    const query = 'DELETE FROM sso_providers WHERE id = $1';
    await this.query(query, [providerId]);
  }

  async listSSOProviders(orgId?: string): Promise<unknown[]> {
    let query = 'SELECT * FROM sso_providers';
    const values: unknown[] = [];

    if (orgId) {
      query += ' WHERE org_id = $1 OR org_id IS NULL';
      values.push(orgId);
    }

    query += ' ORDER BY created_at DESC';

    const result = await this.query(query, values);
    return result.rows
      .filter((row): row is DbRecord => !!row)
      .map((row) => this.mapSSOProviderRecord(row));
  }

  async createSSOLink(data: Omit<SSOLink, 'id' | 'linkedAt'>): Promise<SSOLink> {
    const id = generateId();

    const query = `
      INSERT INTO sso_links (
        id, user_id, provider_id, provider_type, provider_subject,
        provider_email, auto_provisioned, metadata, last_auth_at
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      RETURNING *
    `;

    const values = [
      id,
      data.userId,
      data.providerId,
      data.providerType,
      data.providerSubject,
      data.providerEmail || null,
      data.autoProvisioned || false,
      JSON.stringify(data.metadata || {}),
      data.lastAuthAt || new Date(),
    ];

    const result = await this.query(query, values);
    if (!result.rows[0]) {
      throw new InternalError({
        code: 'auth-postgres/create_failed',
        message: 'Failed to create SSO link',
        severity: 'error',
        retryable: false,
      });
    }
    return this.mapSSOLinkRecord(result.rows[0]!);
  }

  async getSSOLink(linkId: string): Promise<SSOLink | null> {
    const query = 'SELECT * FROM sso_links WHERE id = $1';
    const result = await this.query(query, [linkId]);

    if (result.rows.length === 0) {
      return null;
    }

    return this.mapSSOLinkRecord(result.rows[0]!);
  }

  async getUserSSOLinks(userId: string): Promise<SSOLink[]> {
    const query = 'SELECT * FROM sso_links WHERE user_id = $1 ORDER BY linked_at DESC';
    const result = await this.query(query, [userId]);

    return result.rows
      .filter((row): row is DbRecord => !!row)
      .map((row) => this.mapSSOLinkRecord(row));
  }

  async deleteSSOLink(linkId: string): Promise<void> {
    const query = 'DELETE FROM sso_links WHERE id = $1';
    await this.query(query, [linkId]);
  }

  async createSSOSession(data: Omit<SSOSession, 'id' | 'linkedAt'>): Promise<SSOSession> {
    const id = generateId();

    const query = `
      INSERT INTO sso_sessions (
        id, user_id, provider_id, provider_type, provider_subject,
        session_token, expires_at, last_auth_at
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      RETURNING *
    `;

    const values = [
      id,
      data.userId,
      data.providerId,
      data.providerType,
      data.providerSubject,
      data.sessionToken || null,
      data.expiresAt,
      data.lastAuthAt || new Date(),
    ];

    const result = await this.query(query, values);
    if (!result.rows[0]) {
      throw new InternalError({
        code: 'auth-postgres/create_failed',
        message: 'Failed to create SSO session',
        severity: 'error',
        retryable: false,
      });
    }
    return this.mapSSOSessionRecord(result.rows[0]!);
  }

  async getSSOSession(sessionId: string): Promise<SSOSession | null> {
    const query = 'SELECT * FROM sso_sessions WHERE id = $1';
    const result = await this.query(query, [sessionId]);

    if (result.rows.length === 0) {
      return null;
    }

    return this.mapSSOSessionRecord(result.rows[0]!);
  }

  // 2FA methods
  async createTwoFactorDevice(
    data: Omit<TwoFactorDevice, 'id' | 'createdAt'>
  ): Promise<TwoFactorDevice> {
    const id = generateId();

    const query = `
      INSERT INTO twofa_devices (
        id, user_id, method, name, verified, phone_number, secret, metadata
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      RETURNING *
    `;

    const values = [
      id,
      data.userId,
      data.method,
      data.name || null,
      data.verified || false,
      data.phoneNumber || null,
      data.secret || null,
      JSON.stringify(data.metadata || {}),
    ];

    const result = await this.query(query, values);
    if (!result.rows[0]) {
      throw new InternalError({
        code: 'auth-postgres/create_failed',
        message: 'Failed to create two-factor device',
        severity: 'error',
        retryable: false,
      });
    }
    return this.mapTwoFactorDeviceRecord(result.rows[0]!);
  }

  async getTwoFactorDevice(deviceId: string): Promise<TwoFactorDevice | null> {
    const query = 'SELECT * FROM twofa_devices WHERE id = $1';
    const result = await this.query(query, [deviceId]);

    if (result.rows.length === 0) {
      return null;
    }

    return this.mapTwoFactorDeviceRecord(result.rows[0]!);
  }

  async listTwoFactorDevices(userId: string): Promise<TwoFactorDevice[]> {
    const query = 'SELECT * FROM twofa_devices WHERE user_id = $1 ORDER BY created_at DESC';
    const result = await this.query(query, [userId]);

    return result.rows
      .filter((row): row is DbRecord => !!row)
      .map((row) => this.mapTwoFactorDeviceRecord(row));
  }

  async updateTwoFactorDevice(
    deviceId: string,
    data: Partial<TwoFactorDevice>
  ): Promise<TwoFactorDevice> {
    const fields = [];
    const values = [];
    let paramCount = 1;

    for (const [key, value] of Object.entries(data)) {
      if (key === 'id' || key === 'createdAt') {
        continue;
      }

      const snakeKey = this.camelToSnake(key);
      if (key === 'metadata') {
        fields.push(`${snakeKey} = $${paramCount}`);
        values.push(JSON.stringify(value));
      } else {
        fields.push(`${snakeKey} = $${paramCount}`);
        values.push(value);
      }
      paramCount++;
    }

    if (fields.length === 0) {
      const existing = await this.getTwoFactorDevice(deviceId);
      if (!existing) {
        throw new InternalError({
          code: 'auth-postgres/twofa_device_not_found',
          message: 'Two-factor device not found',
          severity: 'error',
          retryable: false,
          context: { deviceId },
        });
      }
      return existing;
    }

    fields.push(`updated_at = $${paramCount}`);
    values.push(new Date());
    values.push(deviceId);

    const query = `
      UPDATE twofa_devices
      SET ${fields.join(', ')}
      WHERE id = $${paramCount + 1}
      RETURNING *
    `;

    const result = await this.query(query, values);
    if (!result.rows[0]) {
      throw new InternalError({
        code: 'auth-postgres/update_failed',
        message: 'Failed to update two-factor device',
        severity: 'error',
        retryable: false,
      });
    }
    return this.mapTwoFactorDeviceRecord(result.rows[0]!);
  }

  async deleteTwoFactorDevice(deviceId: string): Promise<void> {
    const query = 'DELETE FROM twofa_devices WHERE id = $1';
    await this.query(query, [deviceId]);
  }

  async createBackupCodes(userId: string, codes: BackupCode[]): Promise<BackupCode[]> {
    const createdCodes: BackupCode[] = [];

    for (const codeData of codes) {
      const id = generateId();

      const query = `
        INSERT INTO twofa_backup_codes (id, user_id, code, used)
        VALUES ($1, $2, $3, $4)
        RETURNING *
      `;

      const codeValue = typeof codeData === 'string' ? codeData : codeData.code || '';
      const values = [id, userId, codeValue, false];

      const result = await this.query(query, values);
      if (result.rows[0]) {
        createdCodes.push(this.mapBackupCodeRecord(result.rows[0]));
      }
    }

    return createdCodes;
  }

  async getBackupCodes(userId: string): Promise<BackupCode[]> {
    const query = 'SELECT * FROM twofa_backup_codes WHERE user_id = $1 ORDER BY created_at DESC';
    const result = await this.query(query, [userId]);

    return result.rows
      .filter((row): row is DbRecord => !!row)
      .map((row) => this.mapBackupCodeRecord(row));
  }

  async markBackupCodeUsed(codeId: string): Promise<void> {
    const query = `
      UPDATE twofa_backup_codes
      SET used = TRUE, used_at = NOW()
      WHERE id = $1
    `;
    await this.query(query, [codeId]);
  }

  async createTwoFactorSession(data: TwoFactorSession): Promise<TwoFactorSession> {
    const id = generateId();

    const query = `
      INSERT INTO twofa_sessions (
        id, user_id, session_id, device_id, method, verification_code,
        attempt_count, max_attempts, expires_at
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      RETURNING *
    `;

    const values = [
      id,
      data.userId,
      data.sessionId,
      data.deviceId,
      data.method,
      data.verificationCode || null,
      data.attemptCount || 0,
      data.maxAttempts || 5,
      data.expiresAt,
    ];

    const result = await this.query(query, values);
    if (!result.rows[0]) {
      throw new InternalError({
        code: 'auth-postgres/create_failed',
        message: 'Failed to create two-factor session',
        severity: 'error',
        retryable: false,
      });
    }
    return this.mapTwoFactorSessionRecord(result.rows[0]!);
  }

  async getTwoFactorSession(sessionId: string): Promise<TwoFactorSession | null> {
    const query = 'SELECT * FROM twofa_sessions WHERE id = $1';
    const result = await this.query(query, [sessionId]);

    if (result.rows.length === 0) {
      return null;
    }

    return this.mapTwoFactorSessionRecord(result.rows[0]!);
  }

  async completeTwoFactorSession(sessionId: string): Promise<void> {
    const query = `
      UPDATE twofa_sessions
      SET completed_at = NOW()
      WHERE id = $1
    `;
    await this.query(query, [sessionId]);
  }

  // Helper methods
  private mapApiKeyRecord(row: DbRecord): ApiKeyRecord {
    // Parse metadata from JSONB if it's a string
    let metadata: Record<string, string> = {};
    if (row.metadata) {
      if (typeof row.metadata === 'string') {
        try {
          metadata = JSON.parse(row.metadata);
        } catch {
          metadata = {};
        }
      } else {
        metadata = row.metadata as Record<string, string>;
      }
    }

    return {
      id: row.id,
      principalId: row.principal_id,
      hash: row.hash,
      prefix: row.prefix,
      lastFour: row.last_four,
      scopes: row.scopes || [],
      metadata,
      expiresAt: row.expires_at ? new Date(row.expires_at) : undefined,
      createdAt: new Date(row.created_at),
      updatedAt: new Date(row.updated_at),
    };
  }

  private mapSessionRecord(row: DbRecord): SessionRecord {
    // Parse metadata from JSONB if it's a string
    let metadata: Record<string, unknown> = {};
    if (row.metadata) {
      if (typeof row.metadata === 'string') {
        try {
          metadata = JSON.parse(row.metadata);
        } catch {
          metadata = {};
        }
      } else {
        metadata = row.metadata as Record<string, unknown>;
      }
    }

    return {
      id: row.id,
      userId: row.user_id,
      orgId: row.org_id || undefined,
      plan: row.plan || undefined,
      entitlements: row.entitlements || [],
      expiresAt: new Date(row.expires_at),
      metadata,
      createdAt: new Date(row.created_at),
      updatedAt: new Date(row.updated_at),
    };
  }

  private mapOrganizationRecord(row: DbRecord): OrganizationRecord {
    // Parse members and metadata from JSONB
    let members: OrganizationMember[] = [];
    if (row.members) {
      if (typeof row.members === 'string') {
        try {
          members = JSON.parse(row.members);
        } catch {
          members = [];
        }
      } else {
        members = row.members as OrganizationMember[];
      }
    }

    let metadata: Record<string, unknown> = {};
    if (row.metadata) {
      if (typeof row.metadata === 'string') {
        try {
          metadata = JSON.parse(row.metadata);
        } catch {
          metadata = {};
        }
      } else {
        metadata = row.metadata as Record<string, unknown>;
      }
    }

    return {
      id: row.id,
      name: row.name,
      plan: row.plan,
      seats: row.seats,
      members,
      metadata,
      createdAt: new Date(row.created_at),
      updatedAt: new Date(row.updated_at),
    };
  }

  private mapUserRecord(row: DbRecord): UserRecord {
    // Parse JSONB fields if they're strings
    let entitlements: string[] = [];
    if (row.entitlements) {
      if (Array.isArray(row.entitlements)) {
        entitlements = row.entitlements;
      } else {
        entitlements = [];
      }
    }

    let oauth: Record<string, OAuthLink> = {};
    if (row.oauth) {
      if (typeof row.oauth === 'string') {
        try {
          oauth = JSON.parse(row.oauth);
        } catch {
          oauth = {};
        }
      } else {
        oauth = row.oauth as Record<string, OAuthLink>;
      }
    }

    let metadata: Record<string, unknown> = {};
    if (row.metadata) {
      if (typeof row.metadata === 'string') {
        try {
          metadata = JSON.parse(row.metadata);
        } catch {
          metadata = {};
        }
      } else {
        metadata = row.metadata as Record<string, unknown>;
      }
    }

    return {
      id: row.id,
      email: row.email || undefined,
      name: row.name || undefined,
      picture: row.picture || undefined,
      plan: row.plan || undefined,
      entitlements,
      oauth,
      metadata,
      createdAt: new Date(row.created_at),
      updatedAt: new Date(row.updated_at),
    };
  }

  private camelToSnake(str: string): string {
    return str.replace(/[A-Z]/g, (letter) => `_${letter.toLowerCase()}`);
  }

  private mapRoleRecord(row: DbRecord): RoleRecord {
    return {
      id: row.id,
      orgId: row.org_id,
      name: row.name,
      description: row.description,
      isSystem: row.is_system,
      permissions: row.permissions || [],
      metadata: row.metadata || {},
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }

  private mapSSOProviderRecord(row: DbRecord): unknown {
    return {
      id: row.id,
      type: row.type,
      name: row.name,
      orgId: row.org_id,
      metadataUrl: row.metadata_url,
      clientId: row.client_id,
      clientSecret: row.client_secret,
      tokenEndpointAuthMethod: row.token_endpoint_auth_method,
      idpEntityId: row.idp_entity_id,
      idpSsoUrl: row.idp_sso_url,
      idpSloUrl: row.idp_slo_url,
      idpCertificate: row.idp_certificate,
      spEntityId: row.sp_entity_id,
      spAcsUrl: row.sp_acs_url,
      spSloUrl: row.sp_slo_url,
      signingCert: row.signing_cert,
      signingKey: row.signing_key,
      encryptionEnabled: row.encryption_enabled,
      forceAuthn: row.force_authn,
      scopes: row.scopes || [],
      redirectUris: row.redirect_uris || [],
      claimMapping: row.claim_mapping || {},
      attributeMapping: row.attribute_mapping || {},
      metadata: row.metadata || {},
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }

  private mapSSOLinkRecord(row: DbRecord): SSOLink {
    return {
      id: row.id,
      userId: row.user_id,
      providerId: row.provider_id,
      providerType: row.provider_type,
      providerSubject: row.provider_subject,
      providerEmail: row.provider_email,
      autoProvisioned: row.auto_provisioned,
      metadata: row.metadata || {},
      linkedAt: row.linked_at,
      lastAuthAt: row.last_auth_at,
    };
  }

  private mapSSOSessionRecord(row: DbRecord): SSOSession {
    return {
      id: row.id,
      userId: row.user_id,
      providerId: row.provider_id,
      providerType: row.provider_type,
      providerSubject: row.provider_subject,
      sessionToken: row.session_token,
      expiresAt: row.expires_at,
      linkedAt: row.linked_at,
      lastAuthAt: row.last_auth_at,
    };
  }

  private mapTwoFactorDeviceRecord(row: DbRecord): TwoFactorDevice {
    return {
      id: row.id,
      userId: row.user_id,
      method: row.method,
      name: row.name,
      verified: row.verified,
      phoneNumber: row.phone_number,
      secret: row.secret,
      lastUsedAt: row.last_used_at,
      metadata: row.metadata || {},
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }

  private mapBackupCodeRecord(row: DbRecord): BackupCode {
    return {
      id: row.id,
      userId: row.user_id,
      code: row.code,
      used: row.used,
      usedAt: row.used_at,
      createdAt: row.created_at,
    };
  }

  private mapTwoFactorSessionRecord(row: DbRecord): TwoFactorSession {
    return {
      id: row.id,
      userId: row.user_id,
      sessionId: row.session_id,
      deviceId: row.device_id,
      method: row.method,
      verificationCode: row.verification_code,
      attemptCount: row.attempt_count,
      maxAttempts: row.max_attempts,
      expiresAt: row.expires_at,
      completedAt: row.completed_at,
      createdAt: row.created_at,
    };
  }
}
