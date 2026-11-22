# Registration — Design

**Status:** Draft for approval
**Date:** 2026-11-22
**Source task:** `courses-content/backend/A/1/ru/1.1.0 Регистрация.md` (inno-fe-be-a1)

## Intent and why

Let a guest create an account with email and password. When email
confirmation is off, the account becomes `active` immediately and is
ready for later login. When confirmation is on, the account is created
as `pending` and is activated only after the guest enters a one-time
code (OTP) delivered by email. The server — never the client — decides
whether confirmation happens.

Registration itself issues no session and no JWT; a later authentication
module does that. A later RBAC module assigns the `user` role in the same
transaction that activates the account. This spec builds registration so
those modules can slot in without reworking it.

Why it is shaped this way: the password is kept only as a slow,
per-password-salted hash so a database leak does not cheaply yield
passwords. The email is the uniqueness key and is taken the moment a
`pending` account exists, so a second registration on it cannot bypass
confirmation. The OTP secret is never stored in reversible form and
never returned in an API response or log — only the email carries it.

## Goals

- `POST /auth/register` — create an account from email + password.
  - Confirmation off → `201`, account `active`.
  - Confirmation on → `202`, account `pending`, OTP emailed.
- `POST /auth/register/confirm` — activate a `pending` account with the
  OTP (attempt id + 6-digit code).
- `POST /auth/register/resend` — send a fresh OTP, reset its TTL and
  wrong-input counter, invalidate the old code.
- Full contract from task §1.3–§1.6: validation, neutral taken-email
  response, error codes, audit logging, rate limiting.
- Real PostgreSQL with EF Core migrations.
- Controllers (not minimal API).
- Built walking-skeleton style: thin vertical slices, each runnable and
  tested, grown in the order below.

## Non-goals

- **Magic link.** The contract allows OTP *or* magic link; the server
  picks. This build supports **OTP only**; `method` is always `otp`.
  Magic link is a later slice, out of scope here.
- Login / JWT issuance / sessions — separate auth module.
- RBAC and role assignment — separate module. Registration leaves a
  seam (a role-assignment call inside the activation transaction) but
  assigns no role while RBAC is absent, matching task §1.1: already-active
  users get the role later from empty RBAC config.
- A frontend. Requests are driven from an HTTP client (Bruno/Postman/
  `.http`). CORS trusted-origin config is deferred until a page exists.
- A settings module. The confirmation flag lives in app configuration.

## Anti-goals (failure even if it "works")

- Password, password hash, OTP, or full request body appearing in any
  response or log.
- Email stored or indexed without normalization (a second
  `User@Example.com` must not create a second account).
- OTP recoverable from the database (must be HMAC, not plaintext/reversible).
- A correct code accepted after the attempt is consumed (5th wrong input,
  expiry, or success must consume it).
- A concurrent same-email registration surfacing an unhandled 500 instead
  of the taken-email response.
- The taken-email response differing between `register` and `resend`
  (would leak account existence — see decision below).

## Constraints

- .NET 10 SDK (`global.json` pins `10.0.402`, `latestFeature`).
- Solution/namespace root: `FEDept.BackendCourse.GroupA1.Api.Template`.
- Tests: xUnit via `WebApplicationFactory<Program>`; `Program` stays a
  public partial class.
- PostgreSQL via Npgsql EF Core provider `10.0.3`.
- Password hash: `BCrypt.Net-Next`, work factor **12** (task's minimum).
  Argon2id is the task's preferred algorithm; bcrypt is the chosen
  fallback here for reliable build on any dev machine. Long passwords
  are rejected by validation *before* hashing, because bcrypt silently
  truncates after 72 bytes.
- OTP secret: HMAC-SHA256 with a configured key (not the password salt),
  compared with `CryptographicOperations.FixedTimeEquals`.
- SMTP via MailKit; local stand uses Mailpit. The app performs only SMTP
  submission (step 1 of delivery). IMAP/POP3 not used.

## Approaches considered

**A — Single layered API project.** Controllers, services, `DbContext`,
entities, migrations all inside the existing `.Api` project, foldered by
concern. Fastest to walk, least ceremony, matches the current one-project
repo. But the user has confirmed upcoming user-CRUD, RBAC, and full
authorization modules that all share the `users` table and the
activation transaction. Burying the `DbContext` and user entity in the
API project forces those later modules to reach into registration's
internals or duplicate them, and the refactor lands mid-RBAC.

**B — Full Clean Architecture** (`.Api` / `.Application` / `.Infrastructure`
/ `.Domain`, ports & adapters). Clean boundaries and teaches the pattern,
but four projects and interface indirection are too much scaffolding for
a walking skeleton and an internship exercise; each thin slice becomes
many files.

**B-lite — chosen.** Two projects, seamed by module (not by technical
layer):

- `…Api` — controllers, DI, pipeline, configuration, OpenAPI (the
  existing project).
- `…Infrastructure` — one shared EF Core `AppDbContext`, entities, and
  migrations, which every future module (users, RBAC, auth) reuses.
  Inside, folders are per module (`Users/`, `Registration/`, later
  `Rbac/`, `Auth/`), not per layer.

Rationale: draws exactly one seam now — the shared data layer and the
single migrations home — so user-CRUD/RBAC/auth build on `AppDbContext`
and the activation transaction instead of reworking registration. It
avoids B's ceremony; if a module later demands a deeper split, it is
cheap from here. **The user picked B-lite.**

## Decided design

### Projects and layout

```
src/
  FEDept.BackendCourse.GroupA1.Api.Template/            (.Api — exists)
    Controllers/RegistrationController.cs
    Program.cs                                          (DI, pipeline, config)
  FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure/
    AppDbContext.cs
    Users/User.cs
    Registration/
      RegistrationChallenge.cs
      RegistrationService.cs      (domain logic: hash, normalize, OTP, transaction)
      IEmailSender.cs  +  SmtpEmailSender.cs  (MailKit)
    Migrations/
tests/
  FEDept.BackendCourse.GroupA1.Api.Template.Tests/
```

`.Api` references `.Infrastructure`. The solution gains the new project.
Controllers are thin: validate, call `RegistrationService`, map result to
status code. Business rules and the transaction live in the service.

### Data model (task §Модель, §1.3)

`users`: `id`, `email` (normalized, unique index), `password_hash`,
`status` (`pending` | `active`), `created_at`, `updated_at`.

`registration_challenges`: `id` (returned by register, used by confirm to
locate the attempt), `user_id` → `users.id`, `method` (`otp` only here),
`secret_hash` (HMAC-SHA256 of the code), `expires_at`, `attempts`,
`last_sent_at`, `consumed_at`.

- `expires_at` and `last_sent_at` are updated in **one** `UPDATE` on
  resend (task §Нормальная форма: avoids the update anomaly from storing
  the derived `expires_at`). Storing both is the accepted denormalization.
- Email uniqueness is enforced by a DB unique index on normalized
  `email`. A unique-violation on concurrent insert is caught and mapped
  to the taken-email response — never an unhandled 500.

### Endpoints and contract

All three under `RegistrationController`.

`POST /auth/register` (body `email`, `password`):
1. Normalize email (trim, lowercase); keep password's edge spaces.
2. Validate: email format required; password ≥ 8 chars, ≥ 1 letter (any
   alphabet) and ≥ 1 digit, and not longer than the bcrypt 72-byte limit.
3. Compute bcrypt hash (work factor 12).
4. Confirmation **off** → create `active` user (role assigned in the
   activation transaction *if* RBAC present; absent now). Respond
   **201**: `id`, normalized `email`, `status: active`. No password/hash/
   token.
5. Confirmation **on** → create `pending` user + one open challenge,
   send OTP email. Respond **202**: `confirmationRequired: true`,
   `method: otp`, `attemptId`, `expiresInSeconds: 600`,
   `resendAfterSeconds: 60`. Code is only in the email.
6. Taken email → neutral response (see decision). If SMTP rejects the
   mail, the `pending` row and challenge persist and the client gets
   **503**; a new mail is obtained via resend.

`POST /auth/register/confirm` (OTP: attempt id + `code`):
1. Find the attempt; if missing or already consumed, respond as for a
   wrong code. A decoy challenge (neutral-response case) is a normal
   attempt whose code never matches, so it falls out here with the same
   `400` — no special-casing, which is what keeps decoy and genuine
   indistinguishable.
2. Reject an expired attempt without incrementing the counter.
3. Compare the code's HMAC with `FixedTimeEquals`. On mismatch increment
   `attempts`; the 5th wrong input consumes the attempt (a later correct
   code is then rejected as exhausted).
4. On success: set user `active`, assign `user` role if RBAC present and
   not yet assigned, consume the attempt — all in one transaction.
   Respond **200**: `id`, `email`, `status: active`.

After an attempt is consumed or expired, `confirm` does **not** auto-issue
a new challenge (my call, builder #5); the user is pending with no open
challenge and recovers via `resend`. This matches the task: resend is the
path that restarts TTL and the counter.

`POST /auth/register/resend` (body `email`):
- At most once per 60 s. Issues a new code, restarts TTL, zeroes
  `attempts`, invalidates the old code (one `UPDATE` of `last_sent_at` +
  `expires_at` + `secret_hash` + `attempts`). Respond **202** (same body
  shape as register-on), secret only in email. For a non-existent/taken
  email it returns the **same neutral response** as register (decision).

### Errors (task §1.4)

- `400` invalid email; `400` password fails policy.
- Taken email → **neutral response** (decision below), not a bare `409`.
- `400` wrong/expired code, or attempt not found / already consumed.
- `429` code attempts exhausted, resend sooner than 60 s, or registration
  too frequent (rate limit).
- `503` email not sent (`pending` row + challenge kept).

### Decision: neutral taken-email response (user choice)

Instead of an explicit `409`, register returns a neutral `202`
confirmation-required response from which the caller cannot tell whether
the email is taken. Resend returns the **identical** shape for the same
case. The response carries no existing-account signal: a real
`attemptId`, `method: otp`, `expiresInSeconds: 600`, `resendAfterSeconds:
60`, and never an existing account's identity or the `201` active body.

The neutrality must survive the `confirm` path, not just the register
response (builder finding #1): a placeholder id that dies at `confirm`
would re-leak existence. So the `attemptId` returned is **always a real,
persisted challenge**, and `confirm` cannot tell the cases apart:

- **Unknown email, or active account:** create/return a **persisted
  decoy** `registration_challenges` row whose `secret_hash` matches no
  derivable code, so `confirm` with its id fails **identically to a
  wrong code** (`400`, counter behaves the same). No email is sent for
  an active account. (User decision: persisted dummy challenge.)
- **Pending account:** this is the real owner mid-confirmation. Register
  and resend **send a fresh, working OTP** to that owner — restart TTL,
  zero `attempts`, replace `secret_hash` on the existing challenge — and
  return that account's **real** `attemptId`. The owner can confirm.
  (User decision: send a real working OTP.)

Result: every neutral response points at a real challenge; `confirm`
behaves identically for decoy and genuine-but-wrong-code attempts; the
legitimate pending owner is never starved. Anti-goal ("taken-email
response differing ... would leak account existence") holds across
register, resend, **and** confirm.

Decoy rows are a write-amplification/spam vector: capped behind the
registration + resend rate limiter (below) and reaped by the challenge
TTL (`expires_at`), same as any other challenge.

### Rate limiting (task §1.6)

ASP.NET Core rate limiting middleware (`AddFixedWindowLimiter` +
`UseRateLimiter`), a named policy applied to the registration and resend
endpoints via `[EnableRateLimiting]` / `RequireRateLimiting`. The
registration threshold is read from configuration. Resend's 60-second
floor is enforced in the service via `last_sent_at` (not only the
limiter), because it is per-email, not per-caller.

Partition key (my call, builder #4): there is no auth, so partition the
fixed window by **client IP** (`HttpContext.Connection.RemoteIpAddress`).
Configure `UseForwardedHeaders` (`X-Forwarded-For`) ahead of the limiter
so a reverse proxy / Mailpit-stand setup keys off the real client, not
one NAT'd address — with known-proxy restriction so the header is not
caller-spoofable. `.editorconfig`/stand docs note this is an exercise-
grade limiter, not abuse-proof.

### Audit logging (task §1.5)

Log: registration attempts (success + failure), code send, confirm
success + failure. Never log password, password hash, code, link token,
or the full request body.

### Configuration

- Registration confirmation flag (on/off) — bound to a typed options
  object injected into `RegistrationService` (my call, builder #3), not
  read as raw `IConfiguration` inside the service. This lets
  `WebApplicationFactory<Program>` override the flag per test and exercise
  both the `201` and `202` branches. Source is app config / environment.
- HMAC key for OTP secrets — config (same options object).
- SMTP host/port/from — config; Mailpit on the stand.
- Registration rate-limit threshold — config.

### Walking-skeleton slice order

1. Add `.Infrastructure` project + reference; `AppDbContext` + `User`
   entity + `users` migration; connection string + `UseNpgsql`
   registration. (Test: migration applies; app boots against Postgres.)
2. `POST /auth/register`, confirmation **off** path → `201 active`:
   normalize + validate + bcrypt hash + unique index; `400`s;
   neutral taken-email response; concurrent-insert maps to it, not 500.
3. Confirmation flag + `pending` + `registration_challenges` + OTP
   `confirm`: HMAC secret, TTL, 5-attempt consume, `FixedTimeEquals`.
4. `resend`: 60 s floor, TTL/counter reset, old-code invalidation;
   MailKit `SmtpEmailSender` + Mailpit + `503` on SMTP failure.
5. Harden: rate limiting (config threshold), audit logging, OpenAPI
   docs for the operations.

Each slice follows the project's TDD + verification workflow and lands
green (`dotnet build`, `dotnet test`, `dotnet format --verify-no-changes`).

## Left to the builder

- Exact DTO/field names in request and response bodies (within the
  contract's required fields).
- Service method signatures and internal decomposition.
- Migration/entity-configuration details (column types, index names).
- Test case list per slice (names, fixtures) — follow the repo's
  `WebApplicationFactory<Program>` pattern; a Postgres test database or
  Testcontainers is the builder's call.
- Whether the `user` role-assignment seam is an injected no-op interface
  now or a `// shortcut:` comment — builder's call, must not assign a
  role while RBAC is absent.
