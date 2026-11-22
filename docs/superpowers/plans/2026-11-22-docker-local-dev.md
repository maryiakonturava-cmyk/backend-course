# Docker Local Development Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run the registration API and PostgreSQL in Docker Desktop, applying EF migrations before the local API serves requests.

**Architecture:** A multi-stage .NET 10 Dockerfile builds the API. Compose starts PostgreSQL 16 with a named volume and health check, then starts the API using the `db` service hostname. The API applies migrations only when running in Development with `Database:ApplyMigrations=true`; Compose and the PostgreSQL integration-test factory opt in.

**Tech Stack:** .NET 10, ASP.NET Core, EF Core 10, PostgreSQL 16, Docker Compose.

**Spec:** `docs/superpowers/specs/2026-11-22-docker-local-dev-design.md`

## Global Constraints

- Compose runs PostgreSQL 16 with a named data volume and a health check; the API waits for database health.
- Map the API to `http://localhost:5117`; do not bind PostgreSQL's 5432 port on the host, avoiding conflict with a local PostgreSQL service.
- Apply EF Core migrations at API startup only when the environment is Development and `Database:ApplyMigrations=true`; Compose sets this opt-in.
- Keep development database credentials local-only; this setup is not a production deployment configuration.

## Review Focus

- Non-opted-in hosts must not require a database to start; preserve the existing health test without a database connection.
- Compose must use `db`, not `localhost`, for the container-to-container PostgreSQL connection; inspect rendered configuration.
- API startup must wait for PostgreSQL readiness before migrations; verify service health dependency and run a container startup smoke test.
- The database must persist across ordinary Compose down/up; use a named volume and verify without `down -v`.
- PostgreSQL must not claim host port 5432; inspect Compose port mappings.

---

### Task 1: Opt-In Startup Migrations

**Files:**
- Modify: `src/FEDept.BackendCourse.GroupA1.Api.Template/Program.cs`
- Modify: `tests/FEDept.BackendCourse.GroupA1.Api.Template.Tests/RegistrationTestFactory.cs`

**Interfaces:**
- Program reads `Database:ApplyMigrations` as a boolean and applies migrations with `AppDbContext.Database.MigrateAsync()` only when that flag is true and the environment is Development.
- The PostgreSQL test factory supplies `Database:ApplyMigrations=true` and relies on API startup instead of calling `Database.Migrate()` itself.

- [x] **Step 1: Make integration tests rely on the startup migration path**

Set `Database:ApplyMigrations` to `true` in `RegistrationTestFactory.ConfigureWebHost` and remove its explicit `Database.Migrate()` call from `InitializeAsync`.

- [x] **Step 2: Run registration tests and confirm they fail before the startup migration exists**

Run: `dotnet test tests/FEDept.BackendCourse.GroupA1.Api.Template.Tests --filter FullyQualifiedName~RegisterEndpointTests`
Expected: FAIL because the test database has no migrated tables.

- [x] **Step 3: Add guarded startup migration in `Program.cs`**

Before `app.Run()`, create an async DI scope and call `Database.MigrateAsync()` only when `app.Environment.IsDevelopment()` and `builder.Configuration.GetValue<bool>("Database:ApplyMigrations")` are both true.

- [x] **Step 4: Run integration tests**

Run: `dotnet test tests/FEDept.BackendCourse.GroupA1.Api.Template.sln`
Expected: PASS; existing health test still starts without a database because it does not opt in.

### Task 2: Add Docker Build and Compose Setup

**Files:**
- Create: `src/FEDept.BackendCourse.GroupA1.Api.Template/Dockerfile`
- Create: `compose.yaml`
- Create: `.dockerignore`

**Interfaces:**
- Dockerfile builds and publishes `src/FEDept.BackendCourse.GroupA1.Api.Template/FEDept.BackendCourse.GroupA1.Api.Template.csproj` on .NET 10 and runs its published DLL on the ASP.NET runtime image.
- Compose exposes API host port `5117` to container port `8080`, sets `ASPNETCORE_ENVIRONMENT=Development`, sets `Database__ApplyMigrations=true`, and supplies a `ConnectionStrings__Default` whose host is `db`.
- Compose uses a PostgreSQL 16 service, `pg_isready` health check, healthy dependency, and named data volume; it publishes no PostgreSQL host port.

- [x] **Step 1: Create a multi-stage API Dockerfile**

Use the .NET 10 SDK image to publish the API project and the .NET 10 ASP.NET runtime image to run the published output. Configure the container to listen on `http://+:8080`.

- [x] **Step 2: Create `.dockerignore`**

Exclude `.git`, IDE files, local-only environment/secret files, and all `bin`/`obj` directories from the build context.

- [x] **Step 3: Create `compose.yaml`**

Define `db` and `api` services, Postgres 16 health check, `depends_on` with `condition: service_healthy`, development-only API settings, API port mapping `5117:8080`, and a named PostgreSQL data volume. Do not publish container port 5432 to the host.

- [x] **Step 4: Validate rendered Compose configuration**

Run: `docker compose config --quiet`
Expected: exit code 0.

### Task 3: Document and Verify Docker Desktop Workflow

**Files:**
- Modify: `README.md`

**Interfaces:**
- README documents `docker compose up --build`, default API URL `http://localhost:5117`, optional `API_PORT` override, and `docker compose down`; it warns that `docker compose down -v` removes the database volume.

- [x] **Step 1: Add concise Docker Desktop instructions**

Document start, API URL, logs, and stop commands. Explain that Compose applies pending migrations on API startup and that the named volume preserves data unless removed with `-v`.

- [x] **Step 2: Build and start the Compose app**

Run: `API_PORT=5118 docker compose up --build -d`
Expected: `db` becomes healthy and `api` starts successfully after migrations on the unused host port.

- [x] **Step 3: Verify the health endpoint and generated OpenAPI**

Run: `curl --fail http://localhost:5118/health` and `curl --fail http://localhost:5118/openapi/v1.json`
Expected: health returns HTTP 200 and the OpenAPI document returns HTTP 200.

- [x] **Step 4: Verify volume persistence**

Stop with `API_PORT=5118 docker compose down` (without `-v`), start again, and confirm API starts with the existing named volume and migrated database.
