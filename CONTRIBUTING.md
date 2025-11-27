# Contributing to @kitiumai/auth-postgres

Thanks for helping improve the PostgreSQL adapter!

## Development setup

### Workspace (monorepo)

1. Install dependencies at the repo root: `pnpm install`.
2. Build this package: `pnpm --filter @kitiumai/auth-postgres build`.
3. Run type-checks/tests: `pnpm --filter @kitiumai/auth-postgres typecheck` and `pnpm --filter @kitiumai/auth-postgres test`.

### Standalone clone

If you’re working on the adapter outside the monorepo:

1. Install deps: `pnpm install`.
2. Build: `pnpm run build`.
3. Type-check: `pnpm run typecheck`.
4. Tests: `pnpm test`.

## Coding standards

- Keep TypeScript strict and prefer explicit types.
- Run `pnpm lint` && `pnpm build` before opening a PR.
- Keep files formatted (`pnpm format`).

## Pull requests

- Describe the change and rationale clearly.
- Add/adjust tests when behavior changes.
- Update docs/README/CHANGELOG when user-facing behavior changes.

## Reporting issues

Open an issue with reproduction steps, expected vs actual behavior, database version, and environment details (Node version, OS, package version).
