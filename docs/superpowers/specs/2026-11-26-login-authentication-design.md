# Login authentication design

Source task: [1.1.1 Authentication — Practical assignment](https://github.com/pavel-skripko-innowise/inno-fe-be-a1/blob/main/courses-content/backend/A/1/en/1.1.1%20%D0%90%D1%83%D1%82%D0%B5%D0%BD%D1%82%D0%B8%D1%84%D0%B8%D0%BA%D0%B0%D1%86%D0%B8%D1%8F.md), sections 1.1–1.6.

## Goal

A guest signs in with email and password. The server either sets the access and refresh cookies at once or first requires an email challenge (OTP or magic link). A user with a refresh cookie gets a new pair without a password. Logout clears both cookies. Every token is accepted only for an existing user in the `active` state. Refresh sessions are not stored on the server.

## Decisions

| Topic | Decision |
| --- | --- |
| Scope | One spec for all of 1.1–1.6. The implementation plan is phased (see the end of this document). |
| Configuration | Sections in `appsettings`, environment variables via `__` (for example `Jwt__AccessSecret`). This matches the existing `Registration` and `Smtp` style. |
| Local secrets | `dotnet user-secrets`. Nothing is committed. Without the keys the application exits at startup. Tests inject their own random keys. |
| JWT | Hybrid: one `JwtTokenService` issues and validates both token types. A custom `AuthenticationHandler` uses it for access. The refresh endpoint uses it for refresh. Package: `Microsoft.IdentityModel.JsonWebTokens`. |
| Protected endpoint | No production endpoint is added. Tests register a test-only `[Authorize]` controller. |
| Registration | Unchanged. `registration_challenges` and `RegistrationService` keep their current behavior. |

## 1. Architecture and components

### Infrastructure project, new folder `Authentication/`

- **`LoginChallenge`** — entity for the `login_challenges` table:

  | Column | Type | Notes |
  | --- | --- | --- |
  | `id` | uuid, PK | `attemptId`; part of the magic-link token |
  | `user_id` | uuid, FK `users` | partial unique index `WHERE consumed_at IS NULL` |
  | `method` | text | `Otp` or `MagicLink`, chosen by the server |
  | `secret_hash` | text | HMAC-SHA256 of the OTP or link secret, key `Login:ChallengeHmacKey` |
  | `last_sent_at` | timestamptz | TTL (10 min) and resend pause (60 s) count from it |
  | `attempts` | int | incorrect OTP entries |
  | `consumed_at` | timestamptz, null | set on any consumption |
  | `consumed_reason` | text, null | `Confirmed`, `Replaced`, `AttemptsExhausted`, `UserInactive` |
  | `created_at` | timestamptz | |

  There is no `expires_at` column. Expiry is computed as `last_sent_at + 10 minutes`, which keeps the table in BCNF.
- **`ConsumedReason`** — enum for `consumed_reason`, stored as a string.
- **`LoginService`** — login, confirm, resend. Reuses `PasswordHasher`, `SecretHasher`, `OtpGenerator`, `MagicLinkTokenGenerator`, `EmailNormalizer`, `ChallengeMethod`. Holds a dummy BCrypt hash, computed once at startup, for the missing-user path.
- **`JwtTokenService`** — `Issue(userId) → TokenPair` and `Validate(token, TokenUse) → Ok(userId) | Fail(category)`.
- **`FailedLoginLimiter`** — counts failed checks per `(HMAC(email), IP)` in `IMemoryCache`. Carries the comment `shortcut: in-memory, per instance; move to a shared store when the API scales out`.
- **`AuthAudit`** — structured log helpers (section 4).
- **Options** — `JwtOptions`, `LoginOptions`, `FrontendOptions`, all validated at startup (section 4).

### API project

- **`LoginController`** (route `auth`) — `POST login`, `POST login/confirm`, `POST login/resend`, `POST refresh`, `POST logout`.
- **Contracts** — `LoginRequest`, `LoginConfirmRequest`, `LoginResendRequest`, `LoginChallengeResponse`, `LoginResendResponse`, `ErrorResponse`.
- **`AuthCookies`** — sets and clears both cookies with one set of attributes.
- **`AccessCookieAuthenticationHandler`** — default authentication scheme `AccessCookie`.
- **`CsrfMiddleware`** — the Origin and header check for every POST.
- **`HttpsOnlyMiddleware`** — rejects plain HTTP on `/auth/*`.
- **Rate limiter policies** — `login` and `refresh`.

### Changes to existing code

- `UserStatus` gains `Blocked`, `Deleting`, `Deleted`. Status is stored as a string, so no data migration is needed.
- `IEmailSender` gains `SendLoginOtpAsync` and `SendLoginMagicLinkAsync`, so sign-in emails do not say "registration". `NullEmailSender` and `SmtpEmailSender` implement them.
- The API `.csproj` gets a `UserSecretsId`.
- `Program.cs` registers the new options, services, authentication, CORS, middleware, rate limiter policies, exception handler and JSON console logging.

## 2. Login, confirmation and resend

### Shared response rules

- Error body: `ErrorResponse { code, message }`. Codes: `invalid_credentials`, `invalid_session`, `invalid_challenge`, `too_many_requests`, `csrf_rejected`, `https_required`, `service_unavailable`. Each code has one fixed message.
- Invalid request format returns the framework's 400 `ValidationProblemDetails`.
- Every 429 sends a `Retry-After` header and `retryAfterSeconds` in the body.
- No response contains a password, hash, JWT, OTP, link token, HMAC, key, role, or a hint about whether the account exists.

### `POST /auth/login`

Request: `email` (required, valid format, trimmed and lowercased), `password` (required, kept exactly as sent).

1. Model validation runs. Then the `login` limiter (30 per IP per minute) returns 429 when exceeded. Then `FailedLoginLimiter` returns 429 if the email-and-IP pair already has 5 failures within 15 minutes. All of this happens before BCrypt.
2. The user is loaded by the normalized email. If no user exists, the password is verified against the dummy hash.
3. A missing user, a wrong password, and any status other than `Active` record one failure and return `401 invalid_credentials`. The body is identical for all of them.
4. **Confirmation disabled:** `Issue(userId)` signs both tokens, then the response is **204** with both cookies and no body. If signing fails, the response is **503** with no `Set-Cookie`.
5. **Confirmation enabled:** the service reads the user's unconsumed challenge without a lock. If less than 60 seconds have passed since its `last_sent_at`, the response is **429** with the remaining seconds. No attempt is created and no email is sent.
6. One transaction:
   1. `SELECT … FROM users WHERE id = … FOR UPDATE`.
   2. `SELECT … FROM login_challenges WHERE user_id = … AND consumed_at IS NULL FOR UPDATE`.
   3. Re-check `Active`. If it changed, return `401 invalid_credentials` without an email.
   4. Re-check the 60-second pause. If it fails, return 429.
   5. Consume the previous challenge with `Replaced`.
   6. Insert a new challenge with the method from the current configuration.
   7. Commit. If the commit fails, return **503**, send no email; the client can repeat login.
7. After the commit, send the email:
   - OTP: the six digits.
   - Magic link: `{Login:MagicLinkBaseUrl}#token={attemptId}.{secret}`. The secret is 32 random bytes, base64url-encoded. The HMAC covers the secret only.
8. Success: **202** `{ confirmationRequired: true, method, attemptId, expiresInSeconds: 600, resendAfterSeconds: 60 }`. No cookies, no JWT.
9. SMTP failure after the commit: the attempt is kept. The response is **503** `{ confirmationRequired: true, method, attemptId, retryAfterSeconds }` without the secret. A retry goes through resend or a new login after the 60-second pause.

`method` uses the contract names `otp` and `magic_link`.

### `POST /auth/login/confirm`

Request is exactly one of:

- OTP: `attemptId` (Guid) and `code` matching `^\d{6}$`;
- magic link: `token` matching `{guid}.{43 base64url characters}`, split into `attemptId` and `secret`.

Any other shape returns 400.

1. Load `user_id` by `attemptId` without a lock. Not found: **400 `invalid_challenge`**.
2. Transaction: lock the user, then the challenge, in that order, and re-read both.
3. Checks, in order:
   1. `consumed_reason = AttemptsExhausted` → **429**.
   2. Any other consumed reason (`Confirmed`, `Replaced`, `UserInactive`) → **400**.
   3. Expired (`last_sent_at + 10 min <= now`) → **400**. `attempts` does not change.
   4. The request shape does not match the challenge method → **400**.
4. The user is missing or not `Active`: consume with `UserInactive`, commit, return **401 `invalid_credentials`**.
5. Compute the HMAC of the submitted secret and compare it with `secret_hash` using `CryptographicOperations.FixedTimeEquals`.
6. Wrong OTP: increment `attempts`. When it reaches 5, consume with `AttemptsExhausted`. Commit and return **400**. The fifth entry is still checked, so a correct fifth entry succeeds. The next entry after exhaustion returns 429.
7. Wrong magic-link secret: **400**. No counter.
8. Match: sign both tokens (failure → roll back, **503**), consume with `Confirmed`, commit (failure → **503**, the attempt can be confirmed again), then **204** with both cookies and no body.

### `POST /auth/login/resend`

Request: `attemptId` (Guid).

1. Load `user_id` by `attemptId`. Not found: **400**. Lock the user, then the challenge.
2. `AttemptsExhausted` → **429**. `Confirmed`, `Replaced`, `UserInactive` → **400**.
3. The user is not `Active`: consume with `UserInactive`, commit, return **401 `invalid_credentials`**. The task does not define this branch; it reuses the confirm behavior.
4. Less than 60 seconds since `last_sent_at` → **429** with the remaining seconds. An expired TTL does not block resend.
5. Generate a new secret of the stored method. Replace `secret_hash`, set `last_sent_at = now`, reset `attempts = 0`. Commit.
6. Send the email. On SMTP failure return **503 `service_unavailable`**. The new hash stays, the old secret is not restored, the next send is possible after 60 seconds.
7. Success: **202** `{ method, attemptId, expiresInSeconds: 600, resendAfterSeconds: 60 }`.

## 3. Tokens, session endpoints, access check, CSRF

### `JwtTokenService`

- Signing: `JsonWebTokenHandler`, HS256, header `typ: JWT`. `SetDefaultTimesOnTokenCreation = false`, so the token has no `nbf`.
- Claims:

  | Claim | Access | Refresh |
  | --- | --- | --- |
  | `sub` | user id (Guid) | same user id |
  | `iss` | `Jwt:Issuer` | `Jwt:Issuer` |
  | `aud` | `Jwt:Audience` | `Jwt:Audience` |
  | `iat` | issue time | issue time |
  | `exp` | `iat + 15 min` | `iat + 30 days` |
  | `token_use` | `access` | `refresh` |

  No `jti`, roles, email or other personal data.
- Keys: access is signed with `Jwt:AccessSecret`, refresh with `Jwt:RefreshSecret`. Key bytes are the UTF-8 bytes of the configured value.
- Any signing error is wrapped in `TokenSigningException`.
- Validation: `ValidAlgorithms = [HS256]`, issuer, audience, signed token required, expiration required, lifetime validated, `ClockSkew = 30 s`. Then the service checks that `iat` is present, `sub` is a non-empty Guid, and `token_use` equals the expected type.
- Failure categories: `missing`, `malformed`, `signature` (bad signature, unknown key or wrong algorithm), `expired`, `claims` (issuer, audience, `iat`, `sub`), `token_use`. Callers add `user_inactive` after the user check.

### `AuthCookies`

| Cookie | Attributes |
| --- | --- |
| `access_token` | `HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=900` |
| `refresh_token` | `HttpOnly; Secure; SameSite=Strict; Path=/auth/refresh; Max-Age=2592000` |

- No `Domain`, so both cookies are host-only.
- `Frontend:CrossSite = true` switches both to `SameSite=None; Secure`.
- Clearing sends the same name, `Path`, `Secure`, `SameSite`, and no `Domain`, with `Max-Age=0`.
- Tokens never appear in a body, a readable header or a URL.

### `POST /auth/refresh`

1. The `refresh` limiter allows 30 requests per IP per minute.
2. The token is read only from the `refresh_token` cookie. Body, query and other headers are ignored.
3. `Validate(token, Refresh)`. Failure → **401 `invalid_session`**.
4. Load the user by `sub`. Missing or not `Active` → **401 `invalid_session`**, no cookies.
5. `Issue(userId)` → **204** with both cookies, new lifetimes from now.
6. The previous refresh token is not stored and not denylisted. It stays valid until its own `exp`; this is an accepted limit of the stateless scheme.
7. Database unavailable → **503**. Signing failure → **503** without `Set-Cookie`.

### `POST /auth/logout`

No body. Requires no valid token. Always returns **204** and clears both cookies, whether they are present, invalid or missing. Nothing is written to the database.

### Access check: `AccessCookieAuthenticationHandler`

1. Read the `access_token` cookie and call `Validate(token, Access)`.
2. Load only `{ Id, Status }` by `sub`, with `AsNoTracking`.
3. Only an existing `Active` user passes. The principal carries only the `sub` claim, no roles.
4. `HandleChallengeAsync` returns **401 `invalid_session`** and logs the category. The response does not reveal which check failed.
5. `HandleForbiddenAsync` keeps the default 403 for future RBAC.
6. Protected routes use `[Authorize]`.

### 503 mapping

`UseExceptionHandler` maps these to **503 `service_unavailable`** and logs `DependencyUnavailable`:

- `NpgsqlException` — database unavailable;
- `TokenSigningException`;
- `EmailDeliveryException` — only where the endpoint does not return its own partial-failure body (login catches it itself, see section 2).

Other exceptions stay 500.

### CORS and CSRF

- `Frontend:Origin` is optional. When set, CORS allows exactly that origin with credentials, the headers `Content-Type` and `X-CSRF-Protection`, and the methods GET and POST. `*` is never used.
- `CsrfMiddleware` checks every POST:

  | `Origin` header | Result |
  | --- | --- |
  | absent (non-browser client) | pass |
  | the API's own origin | pass |
  | equals `Frontend:Origin` and `X-CSRF-Protection: 1` is present | pass |
  | anything else | **403 `csrf_rejected`** |

- The middleware is global, so registration POSTs get the same protection.
- GET does not change state anywhere.

### HTTPS

- `/auth/*` over plain HTTP returns **400 `https_required`** without reading the body. It is not redirected, so the password is not sent twice.
- `UseHsts` runs outside Development.
- Cookies are always `Secure`.

## 4. Configuration, rate limits, audit

### Configuration

| Task name | .NET key |
| --- | --- |
| `LOGIN_EMAIL_CONFIRMATION_ENABLED` | `Login:ConfirmationEnabled` |
| `LOGIN_EMAIL_CONFIRMATION_METHOD` | `Login:ConfirmationMethod` (`Otp` or `MagicLink`) |
| `LOGIN_CHALLENGE_HMAC_KEY` | `Login:ChallengeHmacKey` |
| audit identifier key (task 1.5) | `Login:AuditHmacKey` |
| magic-link page address | `Login:MagicLinkBaseUrl` |
| `JWT_ACCESS_SECRET` | `Jwt:AccessSecret` |
| `JWT_REFRESH_SECRET` | `Jwt:RefreshSecret` |
| `JWT_ISSUER` | `Jwt:Issuer` |
| `JWT_AUDIENCE` | `Jwt:Audience` |
| trusted frontend address | `Frontend:Origin`, `Frontend:CrossSite` |

Startup validation (`ValidateOnStart`; any failure stops the application, so readiness never passes):

- `Jwt:AccessSecret`, `Jwt:RefreshSecret`, `Login:ChallengeHmacKey` and `Login:AuditHmacKey` are each at least 32 UTF-8 bytes and pairwise different. They are required whether or not confirmation is enabled, so the flag can change without a restart.
- `Jwt:Issuer` and `Jwt:Audience` are non-empty.
- When `Login:ConfirmationMethod = MagicLink`, `Login:MagicLinkBaseUrl` is an absolute https URL (http allowed in Development).
- `Frontend:Origin`, when set, is an exact origin: scheme, host and optional port, no path.
- No code default, no generated key, no shared key.

`LoginService` reads `IOptionsSnapshot<LoginOptions>`. A configuration reload changes the flag and the method for new logins only. An existing challenge keeps its stored `method` for confirm and resend.

Local development: `dotnet user-secrets set "Jwt:AccessSecret" "$(openssl rand -base64 32)"`, and the same for the other three keys. The README documents this.

### Rate limits

| Limit | Value | Mechanism |
| --- | --- | --- |
| login per IP | 30 per minute | rate limiter policy `login`, fixed window |
| failed login per email and IP | 5 per 15 minutes | `FailedLoginLimiter`, counts failures only, success does not reset it |
| refresh per IP | 30 per minute | rate limiter policy `refresh`, fixed window |
| OTP entries | 5 per attempt | `login_challenges.attempts` |
| new email (login or resend) | one per 60 seconds | `login_challenges.last_sent_at` |

Rejections return 429 through `OnRejected`, which also writes the audit entry.

### Audit

One structured line per event with `EventName`, `Outcome`, `UserId` or `EmailRef`, `Method`, `AttemptId`, `Category` and `RequestId` (`HttpContext.TraceIdentifier`, through the logging scope). Logging switches to `AddJsonConsole` with `IncludeScopes`.

| Event | Outcomes |
| --- | --- |
| `Login` | `success`, `invalid_credentials`, `rate_limited_ip`, `rate_limited_pair`, `cooldown` |
| `LoginChallenge` | `created`, `resent`, `confirmed`, `wrong_entry`, `expired`, `exhausted`, `user_inactive`, `send_failed` |
| `Refresh` | `success`, `failure` with category |
| `Logout` | `success` |
| `AccessRejected` | category |
| `DependencyUnavailable` | `db`, `smtp`, `signing` |
| `CsrfRejected` | `origin`, `header` |

- `EmailRef` is the base64url HMAC-SHA256 of the normalized email with `Login:AuditHmacKey`. It is used for unknown emails, so attacks can be correlated without storing the address.
- Never logged: plaintext email, password, password hash, OTP, magic-link token, HMAC of a secret, JWT, `Cookie`, `Set-Cookie`, keys, full URL, full body, full headers.

Known gap, out of scope: `RegistrationAudit` logs the plaintext email today. This spec does not change it; it is follow-up debt.

## 5. Testing, docs, phases

### Test infrastructure

- `AuthTestFactory` builds on the existing Testcontainers Postgres setup and injects fresh random keys per run.
- A capturing `IEmailSender` records each OTP and link, and can be switched to fail for the SMTP 503 tests.
- Time-based branches (60-second pause, 10-minute TTL) are tested by moving `last_sent_at` back in the database. Expired and forged JWTs are signed in the test with the configured or wrong keys.
- The protected route is a `[Authorize]` controller in the test assembly, added with `AddApplicationPart` in `ConfigureTestServices`.

### Test cases

- **Startup:** a missing, short or duplicate key makes the host fail to start.
- **Direct login:** 204, exact `Set-Cookie` attributes for both cookies, no body.
- **Neutral 401:** unknown email, wrong password, `pending`, `blocked`, `deleting`, `deleted` return a byte-identical body.
- **Rate limits:** the 31st login per IP returns 429; the 6th failed check for an email-and-IP pair returns 429 even with the correct password; the 31st refresh per IP returns 429.
- **OTP:** 202 shape; confirm 204 with cookies; wrong code 400; 5th wrong code 400 and consumed; 6th entry 429; correct 5th entry succeeds; expired 400 with `attempts` unchanged; second login within 60 s 429; login after 60 s replaces the attempt and the old code returns 400; user blocked mid-challenge returns 401 and consumes as `UserInactive`.
- **Magic link:** the email link carries `#token=`; valid token 204; wrong secret 400 without a counter; malformed token 400.
- **Resend:** within 60 s 429; after 60 s the old secret 400 and the new one 204; exhausted 429; SMTP failure 503 with the new hash kept.
- **SMTP failure at login:** 503 with `attemptId` and no secret.
- **Refresh:** success returns a new pair; access token in the refresh cookie 401; wrong key, `alg: none`, expired token and blocked user 401 `invalid_session`.
- **Logout:** 204 and both cookies cleared, with and without cookies on the request.
- **Access check:** valid 200; missing cookie, refresh-as-access, inactive user, expired token 401.
- **CSRF and HTTPS:** foreign `Origin` 403; trusted origin without the header 403; trusted origin with the header passes; no `Origin` passes; preflight for the trusted origin succeeds; plain HTTP 400 `https_required`.
- **Audit:** captured logs contain no email, OTP, token, JWT or cookie value.
- **Unit:** `JwtTokenService` failure categories; options validation.

Coverage target: at least 80%, measured with the existing `coverlet.collector`.

### Docs

- `docs/openapi.yaml`: the five endpoints with every response branch.
- `README.md`: user-secrets setup and the new configuration keys.
- `.http` file: login, confirm, resend, refresh and logout samples.
- `CLAUDE.md`: refresh the architecture section.

### Implementation phases

1. **Foundation:** new `UserStatus` values, options and startup validation, `UserSecretsId`, `JwtTokenService`, `AuthCookies`, exception handler.
2. **Direct login and session:** login without confirmation, both limiters, refresh, logout, access handler.
3. **Email challenge:** `login_challenges` migration, OTP, magic link, confirm, resend.
4. **Browser protection:** CSRF, CORS, HTTPS guard.
5. **Audit and docs:** `AuthAudit` events, OpenAPI, README, `.http`, `CLAUDE.md`.
