# Registration confirmation by magic link — design

Source: course assignment `1.1.0 Регистрация` (backend A/1), sections 1.3.1, 1.3.2, 1.4, 1.5.

## Goal

Add the second registration confirmation method, `magic_link`, next to the existing OTP flow. When registration confirmation is on, a server setting selects OTP or magic link. With magic link, the user receives an email with a link containing a one-time token; a `POST /auth/register/confirm` with that token activates the account. Opening the link by itself never changes the account status.

## Current state

- `RegistrationService` implements register, resend and OTP confirm. `ChallengeMethod` has only `Otp`.
- `registration_challenges.method` is a string column; `secret_hash` already has a non-unique index.
- `RegistrationController` hardcodes `"otp"` in 202 responses.
- `IEmailSender` has only `SendOtpAsync`; implementations: `SmtpEmailSender`, `NullEmailSender`, and test fakes in `AuditLoggingTests`, `ResendEndpointTests`, `RegisterEndpointTests`, `ConfirmEndpointTests`.

## Decisions

| Topic | Decision |
| --- | --- |
| Link target | Configurable `Registration:MagicLinkBaseUrl`; link is `{base}?token={token}`. A future frontend reads the token and POSTs it. Until then the token is copied from Mailpit into an HTTP client. |
| Confirm endpoint | Same `POST /auth/register/confirm`, body is either `{attemptId, code}` or `{token}`. |
| Link lookup | By HMAC of the token only (course spec). The attempt id is not part of the link or the token. |
| Wrong tokens | No per-challenge counter (a wrong token matches no row). Brute force is bounded by 32-byte entropy and the existing `registration` rate limiter. |
| Method selection | `Registration:ConfirmationMethod` (`Otp` \| `MagicLink`, default `Otp`), read at registration time only. |
| Issued challenges | Resend and confirm follow the challenge's stored method, not the current config. |
| Structure | Extend `RegistrationService` in place; no strategy abstraction, no separate service. |

## Configuration

`RegistrationOptions` gains:

- `ChallengeMethod ConfirmationMethod { get; set; } = ChallengeMethod.Otp;`
- `string MagicLinkBaseUrl { get; set; } = string.Empty;`

Startup validation in `Program.cs` (next to the existing `HmacKey` rule, `ValidateOnStart`): if `ConfirmationEnabled` and `ConfirmationMethod == MagicLink`, `MagicLinkBaseUrl` must be an absolute URI. Message: `Registration:MagicLinkBaseUrl must be an absolute URL when the magic link method is enabled.`

`appsettings.Development.json` gets `"MagicLinkBaseUrl": "http://localhost:3000/register/confirm"`; `ConfirmationMethod` stays at its default (`Otp`) there.

## Data

- `ChallengeMethod` gains `MagicLink`; the existing string conversion stores `"MagicLink"`.
- No migration: column type and index are unchanged. The `secret_hash` index stays non-unique, because HMACs of 6-digit codes can collide across rows.
- The token itself is never stored; `secret_hash` holds `SecretHasher.Hash(token)` with the existing HMAC key.

## Token

New `MagicLinkTokenGenerator.Generate()` in `Infrastructure/Registration`:

```csharp
public static string Generate() => Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(32));
```

Output: 43 URL-safe characters, no padding.

## Register (confirmation on)

1. Method = `options.ConfirmationMethod`.
2. Secret = `OtpGenerator.Generate()` for `Otp`, `MagicLinkTokenGenerator.Generate()` for `MagicLink`.
3. Challenge row stores `Method` and `SecretHash = HMAC(secret)`; TTL 600 s, `Attempts = 0`, `LastSentAt = now`, as today.
4. After commit, send via `SendOtpAsync(email, code)` or `SendMagicLinkAsync(email, link)`. SMTP failure keeps the user and challenge and surfaces as 503, as today.
5. `RegisterResult.ConfirmationRequired` becomes `ConfirmationRequired(Guid AttemptId, ChallengeMethod Method)`.
6. Controller maps `Otp → "otp"`, `MagicLink → "magic_link"` in `ConfirmationRequiredResponse`. The 202 body still contains `attemptId`, `expiresInSeconds: 600`, `resendAfterSeconds: 60`, and never the token or link.

## Resend

- Unchanged locking, 60-second throttle and 404 for unknown/non-pending email.
- New secret is generated according to `challenge.Method`.
- Overwriting `secret_hash` makes the old token unfindable, so the old link is consumed. `ExpiresAt`, `Attempts`, `LastSentAt`, `ConsumedAt` reset in the same `SaveChanges`, as today.
- `ResendResult.Sent` carries the method; the response `method` comes from the challenge.

## Confirm

### Request

`ConfirmRequest(Guid? AttemptId, string? Code, string? Token)` implements `IValidatableObject`. Exactly one shape is valid:

- OTP: `attemptId` and non-empty `code`, `token` absent (code format is not validated here, so a malformed code still counts as a wrong attempt, as today);
- link: `token` only.

Any other combination (both shapes, neither, partial OTP body) → 400 `ValidationProblem` via `[ApiController]`.

### Service

`ConfirmAsync` splits into `ConfirmOtpAsync(Guid attemptId, string code, ct)` and `ConfirmTokenAsync(string token, ct)`. Both call a private `ActivateAsync` that sets the user `Active`, updates `UpdatedAt`, sets `ConsumedAt`, saves, commits, and keeps the existing `shortcut:` RBAC comment.

Token path, inside a transaction:

1. `hash = SecretHasher.Hash(token)`.
2. `SELECT * FROM "registration_challenges" WHERE "secret_hash" = {hash} AND "method" = 'MagicLink' FOR UPDATE`. The row lock makes a concurrent double submit yield one 200 and one 400.
3. Not found, consumed, expired, or user missing → `Invalid`. No counter changes.
4. Otherwise → `ActivateAsync` → `Success`.

The lookup by exact HMAC equality replaces the explicit constant-time compare; the caller never gets a per-row comparison to time.

OTP path: unchanged, plus: if `challenge.Method != Otp` → `Invalid` without incrementing `Attempts`.

### Controller

`Confirm` dispatches on `request.Token is not null`. Mapping unchanged: `Success` → 200 `{id, email, status: "active"}`, `Invalid` → 400, `Exhausted` → 429. `[EnableRateLimiting("registration")]` stays.

## Email

- `IEmailSender.SendMagicLinkAsync(string email, string link, CancellationToken ct)`.
- `SmtpEmailSender`: subject `Confirm your registration`, plain-text body `Open this link to confirm your registration: {link}`.
- Link built in `RegistrationService` as `MagicLinkBaseUrl + (MagicLinkBaseUrl.Contains('?') ? "&" : "?") + "token=" + token`, so a query string already present in the base URL is preserved. The base64url token needs no escaping. (`QueryHelpers` is not used: the Infrastructure project has no ASP.NET Core reference.)
- `NullEmailSender` and every test fake implement the new method.

## Audit and logs

- `RegistrationCodeSent` gains a `Method` field (`otp` / `magic_link`); the event covers both code and link sending.
- Confirm success/failure keeps using `RegistrationConfirm`.
- The token, the link URL and the request body are never logged.

## Errors

No new status codes.

| Status | Magic link cases |
| --- | --- |
| 400 | invalid body shape; token unknown, already used, expired, replaced by resend, or sent to an OTP challenge; code sent to a link challenge |
| 429 | `registration` rate limit; resend earlier than 60 s |
| 503 | SMTP failure on register or resend (pending user and challenge kept) |

## Tests

Integration tests via `RegistrationTestFactory`, with a capturing email sender that records the link. The `MagicLink` method is set through configuration overrides in the test host.

1. Register with `MagicLink` → 202, `method: "magic_link"`, body has no token; captured link starts with `MagicLinkBaseUrl` and carries a 43-char token.
2. Confirm `{token}` → 200, user `active`, challenge consumed.
3. Same token again → 400.
4. Expired token (challenge `ExpiresAt` moved into the past) → 400, user stays `pending`.
5. Resend → old token 400, new token 200.
6. Token against an OTP challenge → 400; code against a link challenge → 400 with `attempts` unchanged.
7. Mixed body (`attemptId` + `code` + `token`) and empty body → 400.
8. Host start fails when `ConfirmationEnabled` + `MagicLink` and `MagicLinkBaseUrl` is empty or relative.
9. Audit: link send logs `Method=magic_link` and never the token.
10. Unit: `MagicLinkTokenGenerator` output is 43 chars, base64url alphabet only, distinct across draws.

Existing OTP tests stay green unchanged, apart from the new interface member on their fakes.

## Docs

- `docs/openapi.yaml`: confirm request body as `oneOf` OTP / token; `method` enum `otp`, `magic_link` on 202 responses.
- `.http` file: sample `POST /auth/register/confirm` with `{ "token": "..." }`.

## Out of scope

- GET landing page for the link (no frontend yet).
- Magic link sign-in (belongs to the authentication module).
- CORS policy.
- Per-challenge counting of wrong tokens.
