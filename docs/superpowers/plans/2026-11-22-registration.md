# Registration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A guest registers with email + password; the account is `active` at once when confirmation is off, or `pending` until an emailed OTP confirms it when confirmation is on.

**Architecture:** B-lite — two projects. The existing `…Api` project holds controllers, DI, pipeline, and config; a new `…Infrastructure` project holds one shared EF Core `AppDbContext`, entities, and migrations, foldered by module (`Users/`, `Registration/`) so later user-CRUD/RBAC/auth modules reuse it. Controllers are thin; `RegistrationService` owns rules and the activation transaction.

**Tech Stack:** .NET 10, ASP.NET Core controllers, EF Core 10 + Npgsql `10.0.3` (PostgreSQL), `BCrypt.Net-Next` (work factor 12), HMAC-SHA256 + `CryptographicOperations.FixedTimeEquals`, MailKit (Mailpit on stand), ASP.NET Core rate limiting, xUnit + `WebApplicationFactory<Program>` + Testcontainers for PostgreSQL.

**Spec:** `docs/superpowers/specs/2026-11-22-registration-design.md`

## Global Constraints

- .NET 10 SDK; `global.json` pins `10.0.402`, `latestFeature`. Target `net10.0`, `Nullable` enabled, `ImplicitUsings` enabled.
- Namespace/solution root: `FEDept.BackendCourse.GroupA1.Api.Template`.
- `Program` stays a `public partial class` for `WebApplicationFactory<Program>`.
- Password hash: bcrypt **work factor 12** (minimum). Never store/log/return the password, hash, OTP code, or full request body.
- OTP: 6 digits, TTL **600** seconds, **5** input attempts (5th wrong consumes), resend floor **60** seconds. `method` is always `otp` (magic link out of scope).
- Email normalized before compare/store: trim edges, lowercase; password edge-spaces preserved; reject password > 72 bytes before hashing.
- `secret_hash` = HMAC-SHA256(code, configured key); compare with `CryptographicOperations.FixedTimeEquals`.
- Response bodies: register-off → **201** `{id, email, status:"active"}`; register-on / resend → **202** `{confirmationRequired:true, method:"otp", attemptId, expiresInSeconds:600, resendAfterSeconds:60}`; confirm → **200** `{id, email, status:"active"}`.
- Taken-email is **neutral**: the same `202` shape as above, never `409`, never the active body, never an existing account's identity.
- Every task ends green: `dotnet build`, `dotnet test`, `dotnet format FEDept.BackendCourse.GroupA1.Api.Template.sln --verify-no-changes`.

## Review Focus

- **Concurrent same-email register** (two requests race the unique index): expected neutral `202`, never an unhandled 500 — covered in Task 3.
- **Decoy vs genuine-wrong-code at `confirm`** (active/unknown email's decoy id confirmed): expected identical `400` to a real wrong code, no enumeration — covered in Task 6.
- **Pending owner re-registers or resends** (email already `pending`): expected a real working OTP to the owner, real `attemptId`, neutral shape — covered in Tasks 3 and 7.
- **5th wrong code then correct code** (attempt consumed on 5th wrong input): expected the later correct code rejected as `429` exhausted — covered in Task 5.
- **Expired attempt** (confirm after TTL): expected `400`, counter **not** incremented — covered in Task 5.

---

### Task 1: Infrastructure project + shared DbContext + users migration

**Files:**
- Create: `src/FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure/FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.csproj`
- Create: `src/FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure/AppDbContext.cs`
- Create: `src/FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure/Users/User.cs`
- Create: `src/…Infrastructure/Users/UserStatus.cs`
- Create (generated): `src/…Infrastructure/Migrations/*`
- Modify: `FEDept.BackendCourse.GroupA1.Api.Template.sln` (add project)
- Modify: `src/…Api/FEDept.BackendCourse.GroupA1.Api.Template.csproj` (ProjectReference + Npgsql EF Core package)
- Modify: `src/…Api/Program.cs` (register `AppDbContext` with `UseNpgsql`)
- Modify: `src/…Api/appsettings.json`, `appsettings.Development.json` (connection string)
- Create: `tests/…Tests/RegistrationTestFactory.cs` (Testcontainers-backed factory)
- Modify: `tests/…Tests/…Tests.csproj` (Testcontainers.PostgreSql, Npgsql, Infrastructure ProjectReference)
- Test: `tests/…Tests/MigrationTests.cs`

**Interfaces:**
- Produces:
  - `enum UserStatus { Pending, Active }`
  - `class User { Guid Id; string Email; string PasswordHash; UserStatus Status; DateTimeOffset CreatedAt; DateTimeOffset UpdatedAt; }`
  - `class AppDbContext(DbContextOptions<AppDbContext>) : DbContext { DbSet<User> Users { get; } }` — `Users` has a unique index on `Email`.
  - `RegistrationTestFactory : WebApplicationFactory<Program>, IAsyncLifetime` — starts a `PostgreSqlContainer`, overrides the connection string, runs `db.Database.Migrate()` on startup; exposes `CreateClient()` with HTTPS base and cleared logging (match `HealthEndpointTests`).

- [ ] **Step 1: Write the failing test** `tests/…Tests/MigrationTests.cs`

```csharp
public sealed class MigrationTests(RegistrationTestFactory factory) : IClassFixture<RegistrationTestFactory>
{
    [Fact]
    public async Task Migrations_Apply_And_UsersTable_Exists()
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        Assert.True(await db.Database.CanConnectAsync());
        Assert.Empty(await db.Users.ToListAsync());
    }
}
```

- [ ] **Step 2: Run to verify it fails** — `dotnet test …Tests --filter FullyQualifiedName~MigrationTests`. Expected: FAIL (project/type not found).

- [ ] **Step 3: Create the Infrastructure project and entities.** `User`, `UserStatus`, `AppDbContext` as in Interfaces. In `OnModelCreating`, give `Users` a unique index on `Email` and map `Status` as a string. Add package `Npgsql.EntityFrameworkCore.PostgreSQL` `10.0.3` to Infrastructure. Add Infrastructure to the `.sln` and as a ProjectReference from `.Api` and `.Tests`.

- [ ] **Step 4: Wire `Program.cs`** — `builder.Services.AddDbContext<AppDbContext>(o => o.UseNpgsql(builder.Configuration.GetConnectionString("Default")));`. Add `ConnectionStrings:Default` to both appsettings files.

- [ ] **Step 5: Create the initial migration** — Run: `dotnet ef migrations add InitialUsers --project src/…Infrastructure --startup-project src/…Api`. (Install `dotnet-ef` if absent.)

- [ ] **Step 6: Write `RegistrationTestFactory`** using `Testcontainers.PostgreSql`; override `ConnectionStrings:Default` via `ConfigureAppConfiguration`, call `Database.Migrate()` in `InitializeAsync`.

- [ ] **Step 7: Run to verify it passes** — same filter. Expected: PASS.

- [ ] **Step 8: Commit** — `git add -A && git commit -m "feat: add Infrastructure project, AppDbContext, users migration"`

---

### Task 2: Register DTOs, validation, email normalization, password policy

**Files:**
- Create: `src/…Infrastructure/Registration/EmailNormalizer.cs`
- Create: `src/…Api/Contracts/RegisterRequest.cs`
- Create: `src/…Api/Contracts/RegisterActiveResponse.cs`, `ConfirmationRequiredResponse.cs`
- Test: `tests/…Tests/EmailNormalizerTests.cs`, `tests/…Tests/RegisterValidationTests.cs`

**Interfaces:**
- Produces:
  - `static class EmailNormalizer { static string Normalize(string email); }` — trims, lowercases.
  - `record RegisterRequest(string Email, string Password)` with validation attributes.
  - `record RegisterActiveResponse(Guid Id, string Email, string Status)`.
  - `record ConfirmationRequiredResponse(bool ConfirmationRequired, string Method, Guid AttemptId, int ExpiresInSeconds, int ResendAfterSeconds)`.

- [ ] **Step 1: Failing tests.** `EmailNormalizerTests`: `Normalize(" User@Example.com ") == "user@example.com"`. `RegisterValidationTests` (via `MiniValidator`/model validation): password `"abc12"` (<8) invalid; `"abcdefgh"` (no digit) invalid; `"12345678"` (no letter) invalid; `"abcd1234"` valid; a 73-byte password invalid (bcrypt-72 rule).

- [ ] **Step 2: Run to verify fail.**

- [ ] **Step 3: Implement `EmailNormalizer.Normalize`** (trim + `ToLowerInvariant`). Implement `RegisterRequest` with: `[Required][EmailAddress]` email; `[Required]` password plus a custom validation attribute enforcing ≥8 chars, ≥1 letter (`char.IsLetter`), ≥1 digit, and UTF-8 byte length ≤ 72.

- [ ] **Step 4: Run to verify pass.**

- [ ] **Step 5: Commit** — `feat: add register DTOs, email normalization, password policy`

---

### Task 3: `POST /auth/register` — confirmation-off path + neutral taken-email

**Files:**
- Create: `src/…Infrastructure/Registration/PasswordHasher.cs`
- Create: `src/…Infrastructure/Registration/RegistrationOptions.cs`
- Create: `src/…Infrastructure/Registration/RegistrationService.cs`
- Create: `src/…Api/Controllers/RegistrationController.cs`
- Modify: `Program.cs` (DI: options, hasher, service, controllers + `MapControllers`)
- Test: `tests/…Tests/RegisterEndpointTests.cs`

**Interfaces:**
- Consumes: Task 1 `AppDbContext`, `User`, `UserStatus`; Task 2 DTOs + `EmailNormalizer`.
- Produces:
  - `class RegistrationOptions { bool ConfirmationEnabled; string HmacKey; int RateLimitPermitPerWindow; }` (bound from config section `Registration`).
  - `static class PasswordHasher { string Hash(string pw); bool Verify(string pw, string hash); }` — bcrypt work factor 12.
  - `class RegistrationService(AppDbContext db, IOptions<RegistrationOptions> opts, …)` with `Task<RegisterResult> RegisterAsync(string email, string password, CancellationToken ct)`.
  - `abstract record RegisterResult` with cases `Active(Guid Id, string Email)` and `ConfirmationRequired(Guid AttemptId)`; controller maps to 201 / 202.

- [ ] **Step 1: Failing tests** `RegisterEndpointTests` (confirmation **off** via factory config override `Registration:ConfirmationEnabled=false`):
  - POST valid email/password → **201**, body `status == "active"`, `email` normalized, response JSON contains no `password`/`hash`/`token` field.
  - POST same email twice → second is **neutral 202** (not 201, not 409), carries no active body / no existing id.
  - Concurrent duplicate (two parallel POSTs, same email) → exactly one 201, the other neutral 202; neither is 500. (Review Focus: concurrent same-email.)
  - Pending email re-register (seed a `pending` user) → neutral 202. (Review Focus: pending owner.)

- [ ] **Step 2: Run to verify fail.**

- [ ] **Step 3: Implement.** `PasswordHasher` (BCrypt.Net-Next). `RegistrationService.RegisterAsync`: normalize email; look up by email. If found (pending or active) → neutral branch (Task 7 completes decoy/real-OTP; here, for confirmation-off, return `ConfirmationRequired` neutral shape with a persisted decoy challenge id — see Task 7 for the row, in this task a minimal decoy insert is acceptable). If new and confirmation off → hash, insert `active` user, return `Active`. Wrap the insert in a transaction; catch `DbUpdateException` from the unique index and convert to the neutral branch (no 500). Add `BCrypt.Net-Next` package to Infrastructure. Controller maps results to status codes; `[ApiController]` triggers 400 on model-validation failure.

- [ ] **Step 4: Run to verify pass.**

- [ ] **Step 5: Commit** — `feat: POST /auth/register active path with neutral taken-email`

---

### Task 4: `registration_challenges` entity + migration + OTP/HMAC helpers

**Files:**
- Create: `src/…Infrastructure/Registration/RegistrationChallenge.cs`, `ChallengeMethod.cs`
- Create: `src/…Infrastructure/Registration/OtpGenerator.cs`, `SecretHasher.cs`
- Modify: `AppDbContext.cs` (`DbSet<RegistrationChallenge>`)
- Create (generated): new migration
- Test: `tests/…Tests/SecretHasherTests.cs`, `tests/…Tests/OtpGeneratorTests.cs`

**Interfaces:**
- Produces:
  - `enum ChallengeMethod { Otp }`
  - `class RegistrationChallenge { Guid Id; Guid UserId; ChallengeMethod Method; string SecretHash; DateTimeOffset ExpiresAt; int Attempts; DateTimeOffset LastSentAt; DateTimeOffset? ConsumedAt; }`
  - `static class OtpGenerator { string Generate(); }` — 6 random digits.
  - `class SecretHasher(string key) { string Hash(string code); bool Matches(string code, string hash); }` — HMAC-SHA256, `FixedTimeEquals`.

- [ ] **Step 1: Failing tests.** `SecretHasherTests`: `Hash` of the same code+key is stable and `Matches` true; different code → `Matches` false; `Hash` is not the code (HMAC). `OtpGeneratorTests`: output is exactly 6 ASCII digits; two generations differ with high probability (assert format, not inequality flakiness).

- [ ] **Step 2: Run to verify fail.**

- [ ] **Step 3: Implement** entities, `OtpGenerator` (`RandomNumberGenerator`), `SecretHasher` (`HMACSHA256` + `CryptographicOperations.FixedTimeEquals`). Add `DbSet` and index on `SecretHash`.

- [ ] **Step 4: Create migration** — `dotnet ef migrations add RegistrationChallenges …`. Run to verify pass.

- [ ] **Step 5: Commit** — `feat: add registration_challenges, OTP and HMAC helpers`

---

### Task 5: Confirmation-on register path + `POST /auth/register/confirm`

**Files:**
- Modify: `RegistrationService.cs` (pending path + `ConfirmAsync`)
- Modify: `RegistrationController.cs` (`confirm` action)
- Create: `src/…Api/Contracts/ConfirmRequest.cs`, `ConfirmedResponse.cs`
- Create: `src/…Infrastructure/Registration/IEmailSender.cs` + a `NullEmailSender` (real SMTP in Task 7)
- Test: `tests/…Tests/ConfirmEndpointTests.cs`

**Interfaces:**
- Consumes: Task 4 entities + helpers; Task 3 service/options.
- Produces:
  - `record ConfirmRequest(Guid AttemptId, string Code)`.
  - `record ConfirmedResponse(Guid Id, string Email, string Status)`.
  - `interface IEmailSender { Task SendOtpAsync(string email, string code, CancellationToken ct); }`.
  - `RegistrationService.ConfirmAsync(Guid attemptId, string code, CancellationToken ct) → ConfirmResult` (`Success(user)`, `Invalid`, `Exhausted`).

- [ ] **Step 1: Failing tests** `ConfirmEndpointTests` (confirmation **on**; capture the code via a test `IEmailSender`):
  - register-on → 202, then confirm with the captured code → **200** `status active`; user row now `Active`.
  - wrong code → **400**, `attempts` incremented.
  - 5 wrong then the correct code → **429** exhausted; attempt consumed on the 5th wrong. (Review Focus.)
  - expired attempt (fast-forward `ExpiresAt`) → **400**, `attempts` not incremented. (Review Focus.)
  - unknown/consumed `attemptId` → **400** (same as wrong code).

- [ ] **Step 2: Run to verify fail.**

- [ ] **Step 3: Implement.** Pending path in `RegisterAsync`: insert `pending` user + one `RegistrationChallenge` (method `Otp`, `SecretHash` of a generated code, `ExpiresAt = now+600s`, `Attempts=0`, `LastSentAt=now`), call `IEmailSender.SendOtpAsync`, return `ConfirmationRequired(attemptId)`. `ConfirmAsync`: load attempt; missing/consumed → `Invalid`; expired → `Invalid` (no counter bump); compare HMAC — mismatch → bump `attempts`, if now ≥5 set `ConsumedAt` and return `Exhausted` else `Invalid`; match → in one transaction set user `Active`, set `ConsumedAt`, (RBAC role seam: no-op while absent — `// shortcut: assign user role here once RBAC module exists`), return `Success`. Controller maps `Invalid→400`, `Exhausted→429`, `Success→200`.

- [ ] **Step 4: Run to verify pass.**

- [ ] **Step 5: Commit** — `feat: confirmation-on register and POST /auth/register/confirm`

---

### Task 6: Neutral response survives confirm — decoy challenge

**Files:**
- Modify: `RegistrationService.cs` (decoy on taken/unknown in register; real-OTP for pending)
- Test: `tests/…Tests/NeutralResponseTests.cs`

**Interfaces:**
- Consumes: Tasks 3–5.
- Produces: no new types; the taken-email branch now always returns a real persisted `attemptId`.

- [ ] **Step 1: Failing tests** `NeutralResponseTests`:
  - register active email again → neutral 202 with an `attemptId`; confirming that id with any code → **400**, identical to a genuine wrong code (no distinguishing status/body). (Review Focus: decoy vs genuine.)
  - register on an **active** email creates a decoy challenge that is never emailed (assert the test `IEmailSender` received nothing for that address).
  - register on a **pending** email → a real OTP is sent to that owner and the returned `attemptId` confirms successfully with the emailed code. (Review Focus: pending owner.)

- [ ] **Step 2: Run to verify fail.**

- [ ] **Step 3: Implement** the taken-email branch: if existing user is `Active` or unknown-but-conflict → insert a decoy `RegistrationChallenge` (random `SecretHash` matching no derivable code, normal `ExpiresAt`), **no email**, return its id. If existing user is `Pending` → treat as resend: regenerate code, restart TTL, zero `Attempts`, replace `SecretHash` in one `UPDATE`, send email, return the real id.

- [ ] **Step 4: Run to verify pass.**

- [ ] **Step 5: Commit** — `feat: decoy challenge keeps taken-email neutral through confirm`

---

### Task 7: `POST /auth/register/resend` + MailKit SMTP + 503

**Files:**
- Modify: `RegistrationService.cs` (`ResendAsync`)
- Modify: `RegistrationController.cs` (`resend` action)
- Create: `src/…Api/Contracts/ResendRequest.cs`
- Create: `src/…Infrastructure/Registration/SmtpEmailSender.cs` + `SmtpOptions.cs`
- Modify: `Program.cs` (bind SMTP options; register `SmtpEmailSender` as `IEmailSender`)
- Modify: appsettings (SMTP section; Mailpit for Development)
- Test: `tests/…Tests/ResendEndpointTests.cs`

**Interfaces:**
- Consumes: Tasks 5–6.
- Produces:
  - `record ResendRequest(string Email)`.
  - `class SmtpOptions { string Host; int Port; string From; }`.
  - `SmtpEmailSender : IEmailSender` (MailKit `SmtpClient`).
  - `RegistrationService.ResendAsync(string email, CancellationToken ct) → ResendResult` (`Sent(attemptId)`, `TooSoon`, `Neutral(attemptId)`).

- [ ] **Step 1: Failing tests** `ResendEndpointTests`:
  - resend for a pending email (with a test sender) → **202**, a new code sent, old code no longer confirms, TTL/counter reset.
  - two resends within 60 s → second is **429** (`LastSentAt` floor). (Spec resend floor.)
  - resend for an unknown/active email → neutral **202**, same shape, no email sent. (Enumeration parity with register.)
  - SMTP failure (sender throws) during register-on → **503**; the `pending` user and challenge persist (assert rows exist). (Review Focus: 503 keeps pending.)

- [ ] **Step 2: Run to verify fail.**

- [ ] **Step 3: Implement.** `ResendAsync`: normalize; if pending → enforce `LastSentAt + 60s` (`TooSoon`→429), else regenerate+restart+send, return `Sent`; if active/unknown → decoy/neutral `202` (reuse Task 6), no email. `SmtpEmailSender` via MailKit; register it in `Program.cs`. Make SMTP-send failures surface as a `503` from both register-on and resend while leaving the `pending` row + challenge committed (send email **after** the DB commit, map send failure to 503).

- [ ] **Step 4: Run to verify pass.**

- [ ] **Step 5: Commit** — `feat: POST /auth/register/resend, MailKit SMTP, 503 on send failure`

---

### Task 8: Rate limiting, audit logging, OpenAPI

**Files:**
- Modify: `Program.cs` (rate limiter policy, `UseForwardedHeaders`, `UseRateLimiter`)
- Modify: `RegistrationController.cs` (`[EnableRateLimiting("registration")]`; OpenAPI annotations)
- Create: `src/…Infrastructure/Registration/RegistrationAudit.cs` (logging helper)
- Test: `tests/…Tests/RateLimitTests.cs`, `tests/…Tests/AuditLoggingTests.cs`

**Interfaces:**
- Consumes: all prior.
- Produces: named rate-limit policy `"registration"`; audit log events.

- [ ] **Step 1: Failing tests.**
  - `RateLimitTests`: exceeding `Registration:RateLimitPermitPerWindow` register calls from one client → **429**. (Threshold from config.)
  - `AuditLoggingTests` (capture logs): register success/failure, code send, confirm success/failure each log one event; **no** log entry contains the password, hash, code, or full body. (Anti-goal.)

- [ ] **Step 2: Run to verify fail.**

- [ ] **Step 3: Implement.** `AddRateLimiter` with a fixed-window policy `"registration"` partitioned by client IP (`RemoteIpAddress`), permit = `RegistrationOptions.RateLimitPermitPerWindow`; `UseForwardedHeaders` (known-proxy restricted) before `UseRateLimiter`. Apply `[EnableRateLimiting("registration")]` to register + resend. Add structured audit logs at the service boundary (event name + email + outcome only — never secret fields). Add Swashbuckle/OpenApi annotations to the three operations.

- [ ] **Step 4: Run to verify pass.** Also run full `dotnet test` + `dotnet format … --verify-no-changes`.

- [ ] **Step 5: Commit** — `feat: rate limiting, audit logging, OpenAPI for registration`
