# Docker Local Development Design

## Intent

Run the .NET 10 registration API and PostgreSQL from Docker Desktop, with the local database schema migrated automatically before API startup.

## Scope and constraints

- Add a multi-stage API `Dockerfile`, `compose.yaml`, and `.dockerignore`.
- Compose runs PostgreSQL 16 with a named data volume and a health check; the API waits for database health.
- Map the API to `http://localhost:5117`; do not bind PostgreSQL's 5432 port on the host, avoiding conflict with a local PostgreSQL service.
- Apply EF Core migrations at API startup only when the environment is Development and `Database:ApplyMigrations=true`; Compose sets this opt-in. The container uses the Compose service name `db` in its connection string.
- Add concise Docker Desktop run and stop commands to README.
- Keep development database credentials local-only; this setup is not a production deployment configuration.

## Approaches

1. **Development-only API startup migration (selected):** API applies pending migrations before serving requests. One Compose startup is enough, and no EF CLI is needed in the runtime image. The startup migration path is limited to Development.
2. **Separate one-shot migration container:** keeps migration execution outside the API, but needs an SDK/tooling container and more Compose wiring for this local workflow.

## Non-goals

Production deployment, TLS termination, secret management, persistent production backups, and database administration UI.

## Verification

Validate Compose configuration, build the API image, run existing tests, and confirm `/health` responds from the Compose API. Confirm migrations create the existing application schema before registration requests.