# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development commands

Requires .NET 10 SDK (`global.json` pins 10.0.402 with `latestFeature` roll-forward).

```bash
dotnet build FEDept.BackendCourse.GroupA1.Api.Template.sln
dotnet test FEDept.BackendCourse.GroupA1.Api.Template.sln
dotnet test tests/FEDept.BackendCourse.GroupA1.Api.Template.Tests --filter FullyQualifiedName~GetHealth_ReturnsOk
dotnet format FEDept.BackendCourse.GroupA1.Api.Template.sln --verify-no-changes
dotnet run --project src/FEDept.BackendCourse.GroupA1.Api.Template
```

The default HTTP development profile listens on `http://localhost:5117`; use `--launch-profile https` to also listen on `https://localhost:7135`. `dotnet dev-certs https --trust` may be needed for local HTTPS. The `.editorconfig` defines formatting and C# style; there is no separate lint project or script.

`dotnet test` needs Docker, and `dotnet run` needs user secrets plus `docker compose up -d db mailpit`.

## Architecture

ASP.NET Core Web API for internship exercises with two projects plus tests. `Infrastructure` holds EF Core (`AppDbContext`, PostgreSQL via Npgsql, migrations), `Registration/` (sign-up with OTP or magic-link confirmation) and `Authentication/` (`LoginService`, `JwtTokenService`, `login_challenges`, `FailedLoginLimiter`, `AuthAudit`). The API project holds controllers, contracts and `Authentication/` (cookie helper, `AccessCookie` authentication handler, CSRF and HTTPS middleware, startup validation of auth settings).

`Program.cs` is the composition root. Auth keys are required at startup (user secrets locally, `.env` for Compose). Tests run the API in memory through `WebApplicationFactory<Program>` against a Testcontainers PostgreSQL; `RegistrationTestFactory` injects random keys. Development applies migrations on startup when `Database:ApplyMigrations` is true. The OpenAPI contract is maintained by hand in `docs/openapi.yaml`.
