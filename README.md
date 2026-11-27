# .NET Core Web API Template for Front End Department / Back End Course

Starter ASP.NET Core Web API for full-stack internship exercises. It includes account registration and email confirmation, plus sign-in with optional email challenges and cookie-based sessions. Exercises can add domain features progressively.

## Repository layout

```text
src/FEDept.BackendCourse.GroupA1.Api.Template/             API project
src/FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure/  Infrastructure and persistence
tests/FEDept.BackendCourse.GroupA1.Api.Template.Tests/    Integration tests
```

## Prerequisites

- .NET 10 SDK

The repository pins its SDK feature band in [`global.json`](global.json). Install SDK `10.0.402` or a later `10.0.x` feature band.

Verify the installed SDK:

```bash
dotnet --version
```

## Run locally

Store authentication keys in .NET User Secrets as described in [Authentication keys](#authentication-keys). This host-run flow needs no Compose `.env`; start PostgreSQL and Mailpit, then run the API:

```bash
docker compose up -d db mailpit
dotnet run --project src/FEDept.BackendCourse.GroupA1.Api.Template
```

The host-run API connects to this project's PostgreSQL at `localhost:5433` and applies pending migrations in Development. Port `5432` remains available for other local PostgreSQL instances. Mailpit is at `http://localhost:8025`.

By default, the development profiles expose the API at:

- HTTP: `http://localhost:5117`
- HTTPS: `https://localhost:7135`

To run a specific profile:

```bash
dotnet run --project src/FEDept.BackendCourse.GroupA1.Api.Template --launch-profile https
```

If the HTTPS development certificate is not trusted, run:

```bash
dotnet dev-certs https --trust
```

## Run with Docker Desktop

Set up the Compose authentication keys as described in [Authentication keys](#authentication-keys), then start the API, PostgreSQL, and Mailpit containers:

```bash
docker compose up --build -d
```

The API is available at `http://localhost:5117`; OpenAPI is at `http://localhost:5117/openapi/v1.json`. Compose applies pending EF Core migrations before the API starts. PostgreSQL data persists in a named volume.

Mailpit captures registration and sign-in emails locally. View them at `http://localhost:8025`; SMTP listens on `localhost:1025`. The Compose API uses `mailpit:1025`; an API running outside Docker uses `localhost:1025`.

If another service already uses port `5117`, choose another host port:

```bash
API_PORT=5118 docker compose up --build -d
```

With this override, use `http://localhost:5118` and `http://localhost:5118/openapi/v1.json`.

Rebuild and start only the API. Compose starts PostgreSQL if it is stopped:

```bash
docker compose up --build -d api
```

If port `5117` is busy, use `API_PORT=5118 docker compose up --build -d api`.

Start only PostgreSQL:

```bash
docker compose up -d db
```

View API logs:

```bash
docker compose logs -f api
```

Stop containers:

```bash
docker compose down
```

`docker compose down` keeps the database volume. `docker compose down -v` removes the volume and its data.

## Authentication keys

The API refuses to start without four random keys of at least 32 bytes, all different:
`Jwt:AccessSecret`, `Jwt:RefreshSecret`, `Login:ChallengeHmacKey`, and `Login:AuditHmacKey`.
Nothing in the repository provides them.

For `dotnet run`, store them in user secrets once:

```bash
for key in Jwt:AccessSecret Jwt:RefreshSecret Login:ChallengeHmacKey Login:AuditHmacKey; do
  dotnet user-secrets set "$key" "$(openssl rand -base64 32)" --project src/FEDept.BackendCourse.GroupA1.Api.Template
done
```

For Docker Compose, put them in a local `.env` file next to `compose.yaml` (it is git-ignored):

```bash
{ for name in JWT_ACCESS_SECRET JWT_REFRESH_SECRET LOGIN_CHALLENGE_HMAC_KEY LOGIN_AUDIT_HMAC_KEY; do
  echo "$name=$(openssl rand -base64 32)"
done; } > .env
```

Other sign-in settings:

| Key | Default | Meaning |
| --- | --- | --- |
| `Login:ConfirmationEnabled` | `false` | Require an emailed OTP or link after the password. |
| `Login:ConfirmationMethod` | `Otp` | `Otp` or `MagicLink`; applies to new attempts only. |
| `Login:MagicLinkBaseUrl` | — | Absolute HTTPS URL without a fragment; HTTP is allowed only in Development. Validated whenever `Login:ConfirmationMethod=MagicLink`. Frontend page reads `#token=` and posts it to `/auth/login/confirm`. |
| `Login:LoginPermitPerMinute` | `30` | Login requests allowed per IP per minute. |
| `Login:RefreshPermitPerMinute` | `30` | Refresh requests allowed per IP per minute. |
| `Jwt:Issuer`, `Jwt:Audience` | `groupa1-api`, `groupa1-web` | Must match on issue and verification. |
| `Frontend:Origin` | — | Exact trusted frontend origin for CORS with credentials. |
| `Frontend:CrossSite` | `false` | `true` switches the cookies to `SameSite=None`. |

Cross-origin browser POSTs must send `X-CSRF-Protection: 1` and use `credentials: "include"`.
Forwarded headers trust loopback proxies only. Add non-loopback proxy addresses to `KnownProxies` or `KnownIPNetworks`; do not clear those trust lists.

## Endpoints

| Method | Route | Purpose |
| --- | --- | --- |
| `GET` | `/health` | Confirms that the API is running. Returns `200 OK`. |
| `POST` | `/auth/register` | Register an account; may send an email confirmation. |
| `POST` | `/auth/register/confirm` | Confirm registration with an OTP or magic-link token. |
| `POST` | `/auth/register/resend` | Send a new registration code or link. |
| `POST` | `/auth/login` | Sign in; sets cookies or starts an email challenge. |
| `POST` | `/auth/login/confirm` | Confirm sign-in with an OTP or a magic-link token. |
| `POST` | `/auth/login/resend` | Send a new code or link for an attempt. |
| `POST` | `/auth/refresh` | New token pair from the refresh cookie. |
| `POST` | `/auth/logout` | Clear both session cookies. |

Example requests are available in [`FEDept.BackendCourse.GroupA1.Api.Template.http`](src/FEDept.BackendCourse.GroupA1.Api.Template/FEDept.BackendCourse.GroupA1.Api.Template.http).

## OpenAPI

OpenAPI is enabled in the Development environment. After starting the API, the document is available at:

```text
http://localhost:5117/openapi/v1.json
```

The template currently exposes the OpenAPI document only; it does not include a Swagger or Scalar user interface.

## Frontend integration

Set `Frontend:Origin` to the frontend's exact origin (for example `http://localhost:3000`). CORS allows that origin with credentials and the `Content-Type` and `X-CSRF-Protection` headers. Cross-origin POSTs must send `X-CSRF-Protection: 1` and use `credentials: "include"`; other origins or missing headers are rejected with `403 csrf_rejected`.

## Build

```bash
dotnet build FEDept.BackendCourse.GroupA1.Api.Template.sln
```

## Test

```bash
dotnet test FEDept.BackendCourse.GroupA1.Api.Template.sln
```

Tests start PostgreSQL in Docker through Testcontainers, so Docker must be running.

## Repository conventions

- `.editorconfig` defines shared whitespace and C# style settings.
- `.gitignore` excludes build products, IDE-specific files, test output, and local-only configuration.
- Do not commit secrets. Use environment variables or .NET User Secrets for development credentials; `appsettings.Local.json` is ignored for non-secret local overrides.
