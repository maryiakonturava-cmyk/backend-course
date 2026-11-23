# Authentication Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Добавить stateless cookie-аутентификацию, опциональное email-подтверждение входа и безопасную проверку access без изменения HTTP-контракта регистрации.

**Architecture:** Продолжить B-lite: контроллеры, HTTP-защита и cookies в API; сценарии, JWT и отдельные login challenges в Infrastructure; общий AppDbContext и PostgreSQL. Существующие registration challenges не обобщать. Для access использовать стандартную authentication/authorization pipeline с собственным cookie-only handler и общим JWT-validator.

**Tech Stack:** .NET 10, ASP.NET Core, EF Core/Npgsql, PostgreSQL 16, BCrypt.Net-Next, MailKit, System.IdentityModel.Tokens.Jwt, xUnit, WebApplicationFactory, Testcontainers, coverlet.collector.

**Spec:** [Аутентификация — спецификация и дизайн](../specs/2026-11-22-authentication-design.md). Читать вместе с планом; точные HTTP-таблицы и acceptance criteria spec не заменяются сокращениями ниже.

## Global Constraints

- Access TTL — `900` секунд; refresh TTL — `2592000`; challenge TTL — `600`; cooldown — `60`; clock skew — `30` секунд.
- Только HS256. Claims: `sub`, `iss`, `aud`, `iat`, `exp`, `token_use`. Без `jti`, ролей, email и серверных refresh-сессий.
- JWT только в host-only HttpOnly Secure cookies: `access_token`, Path `/`; `refresh_token`, Path `/auth/refresh`. Strict по умолчанию; None только при явно включённом cross-site режиме.
- Обе подписи и оба cookie-заголовка подготовить до изменения ответа. Ошибки login/confirm/refresh не изменяют cookies.
- Только существующий Active-пользователь допускается к login, confirm, refresh и access. Новый enum не меняет сохранённые Pending/Active.
- Login — 30/IP/60 секунд; refresh — 30/IP/60 секунд; credential failures — 5/email+IP/900 секунд. Строгое скользящее окно, не fixed window.
- Пароль не нормализовать; максимум 72 байта UTF-8. Dummy bcrypt hash имеет work factor 12. Не применять registration PasswordPolicy ко входу.
- PostgreSQL lock order: user, затем login challenge; повторная проверка после блокировок. SMTP только после commit.
- Пятый неверный login OTP: `400`, следующий запрос: `429`. Существующий registration confirm сохраняет своё поведение пятого отказа.
- Не журналировать открытый email, пароль, хеш пароля, OTP, magic-link token, HMAC/secret hash, JWT, Cookie, Set-Cookie, ключи, полный URL, тела и заголовки запросов. Разрешён только отдельный audit HMAC email.
- Новые ключи Base64, минимум 32 декодированных байта, попарно различны; login challenge key отличен от registration key. Ошибка конфигурации останавливает host и при отключённом втором шаге.
- Без UI, RBAC, Redis, outbox, repository/UoW, нового production profile endpoint и автоматической генерации рабочих ключей.
- Сохранить public partial Program, историю миграций, регистрацию `201`/`202`/`409`, существующие данные и пользовательские изменения README/compose/appsettings.
- Production line coverage обоих проектов вместе — не ниже 80%; auth-код не исключать.
- Этот документ не разрешает реализацию, commit или push. После отдельного разрешения реализации сначала создать feature branch. Каждый commit checkpoint ниже выполняется только при отдельном разрешении коммитов; иначе оставить проверенный diff.

## Review Focus

1. Многобайтный пароль на границе 72 UTF-8 bytes и пробелы: проверять байты, не менять строку — Task 4.
2. Подписанный JWT с дубликатами/неверными JSON-типами claims и задержка ответа после подписи: отказ без частичной cookie — Task 2.
3. Конкурентные credential checks, отмена ожидающего запроса и очистка limiter: не обходят cap и не оставляют вечный lock — Task 4.
4. Удаление пользователя между discovery и row lock; resend одновременно с confirm: ни повторного входа, ни двух писем — Tasks 5, 7, 8.
5. Исключение SMTP/JWT, текст которого содержит секрет, и URL с секретом: клиент и framework logs не получают исходный текст — Tasks 3, 10.

---

## Карта файлов и решений

Пути ниже относительно корня репозитория. Для компактности в задачах используются **строгие префиксы**:

- `API/` = `src/FEDept.BackendCourse.GroupA1.Api.Template/`.
- `INF/` = `src/FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure/`.
- `TEST/` = `tests/FEDept.BackendCourse.GroupA1.Api.Template.Tests/`.

Это обозначения путей документа, не новые каталоги. Все названные далее Create/Modify/Test файлы входят в карту:

- `INF/Authentication/AuthenticationOptions.cs`, `AuthenticationOptionsValidator.cs`: типизированные значения и startup validation.
- `API/Authentication/AuthenticationConfiguration.cs`: явное отображение внешних ключей конфигурации и DI.
- `INF/Authentication/JwtTokens.cs`: TokenPair, TokenValidationResult, IJwtTokens и реализация подписи/проверки.
- `API/Authentication/AuthCookies.cs`, `AuthResponses.cs`: атрибуты cookies, безопасное отображение результатов в ProblemDetails/JSON/204.
- `INF/Authentication/AuthResult.cs`: общий закрытый набор исходов сценариев; не содержит HTTP-объектов.
- `INF/Authentication/AuthAudit.cs`: безопасные structured events и HMAC-псевдоним email.
- `API/Authentication/AuthRequestGuard.cs`, `AuthExceptionHandler.cs`: Origin/CSRF/HTTPS и санитизированные ошибки.
- `INF/Authentication/AuthRateLimiter.cs`, `CredentialVerifier.cs`, `LoginService.cs`: строгие лимиты, bcrypt и вход.
- `INF/Authentication/LoginChallenge.cs`, `LoginChallengeLocks.cs`, `LoginChallengeService.cs`: модель, единый порядок DB locks, создание/confirm/resend.
- `INF/Authentication/SessionService.cs`, `API/Authentication/AccessCookieHandler.cs`: refresh и общий access handler.
- `API/Controllers/AuthenticationController.cs`, `API/Contracts/LoginRequest.cs`, `LoginConfirmRequest.cs`, `LoginResendRequest.cs`: только новый HTTP-контракт.
- `API/Authentication/AuthenticationOpenApiTransformer.cs`: обе формы confirm, cookie security, ответы и заголовки.
- Изменяемые существующие файлы: `API/Program.cs`, API/Infrastructure `.csproj`, `INF/AppDbContext.cs`, `INF/Users/UserStatus.cs`, `INF/Registration/SecretHasher.cs`, `IEmailSender.cs`, `SmtpEmailSender.cs`, `RegistrationAudit.cs`, `RegistrationService.cs`.
- Миграция `AddLoginChallenges` создаётся в `INF/Migrations/` с генерируемым EF timestamp; её Designer и существующий `AppDbContextModelSnapshot.cs` обновляются инструментом, не вручную.
- Общие тестовые файлы: `TEST/TestAuthConfiguration.cs`, `MutableTimeProvider.cs`, `AuthenticationTestHost.cs`, `AuthenticationTestDoubles.cs`; существующие `RegistrationTestFactory.cs`, `HealthEndpointTests.cs` и email doubles обновляются без ослабления assertions.
- Отдельные suites: `AuthenticationConfigurationTests.cs`, `JwtTokensTests.cs`, `AuthCookieTests.cs`, `AuthRequestGuardTests.cs`, `AuthRateLimiterTests.cs`, `LoginEndpointTests.cs`, `LoginChallengeMigrationTests.cs`, `LoginChallengeCreationTests.cs`, `LoginConfirmEndpointTests.cs`, `LoginResendEndpointTests.cs`, `SessionEndpointTests.cs`, `AccessCookieTests.cs`, `AuthenticationAuditTests.cs`, `ReadinessTests.cs`, `AuthenticationOpenApiTests.cs`, `SmtpLoginEmailTests.cs` в `TEST/`.
- Эксплуатация: `compose.yaml`, `.gitignore`, `README.md`, `API/Dockerfile`, `API/Properties/launchSettings.json`, `API/appsettings.json`, `API/appsettings.Development.json`, `API/FEDept.BackendCourse.GroupA1.Api.Template.http`, `coverage.runsettings`, `scripts/check-coverage.py`.

**Выбор JWT:** добавить `System.IdentityModel.Tokens.Jwt` версии `8.14.0` в Infrastructure; ASP.NET handler использует framework reference API-проекта, JwtBearer-пакет не нужен. Перед добавлением проверить совместимость/известные уязвимости; при advisory взять исправленную стабильную 8.x и зафиксировать точную версию. Context7 library lookup дал `/dotnet/aspnetcore.docs`, но чтение docs было заблокировано разрешениями. До реализации JWT/handler получить разрешение на `npx ctx7@latest docs /dotnet/aspnetcore.docs "ASP.NET Core custom AuthenticationHandler cookie authentication JWT validation"`; конкретные библиотечные вызовы этим планом не считаются проверенными.

**Время и fault injection:** singleton TimeProvider.System в production; собственный MutableTimeProvider в тестах. IJwtTokens заменяется double, выбрасывающим исключение после создания access, до возврата пары. Сбой до DB commit воспроизводится тестовым DbTransactionInterceptor.TransactionCommittingAsync; production transaction-wrapper ради тестов не добавлять. Сетевой разрыв с неоднозначным результатом commit не обещает rollback: подтвердить состояние новой DB-сессией; retry не должен повторно использовать уже consumed challenge.

**Email:** сохранить SendOtpAsync регистрации, добавить два login-метода в тот же IEmailSender. Все существующие реализации и doubles должны компилироваться; общий template engine не вводить.

## Task 1: Валидная конфигурация и общая тестовая база

**Files:** Create `INF/Authentication/AuthenticationOptions.cs`, `AuthenticationOptionsValidator.cs`, `AuthResult.cs`, `AuthAudit.cs`, `API/Authentication/AuthenticationConfiguration.cs`, `TEST/TestAuthConfiguration.cs`, `MutableTimeProvider.cs`, `AuthenticationConfigurationTests.cs`; Modify `API/Program.cs`, `TEST/RegistrationTestFactory.cs`, `TEST/HealthEndpointTests.cs`.

**Interfaces:**
- `AuthenticationOptions`: bool ConfirmationEnabled; string ConfirmationMethod, AccessSecret, RefreshSecret, ChallengeHmacKey, AuditHmacKey, Issuer, Audience, PublicApiOrigin, FrontendOrigin, ConfirmationUrl; bool CrossSiteCookies; string[] TrustedProxies. Секреты здесь — Base64 strings; декодирование после успешной валидации в потребителях.
- `AuthenticationConfiguration.AddAuthenticationConfiguration(IServiceCollection services, IConfiguration configuration) : IServiceCollection`.
- `enum AuthOutcome { Success, ChallengeRequired, ChallengeResent, InvalidRequest, InvalidCredentials, InvalidSession, Throttled, Unavailable }`.
- `record ChallengeInfo(Guid AttemptId, string Method)`; `record AuthResult(AuthOutcome Outcome, TokenPair? Tokens = null, ChallengeInfo? Challenge = null, int? RetryAfterSeconds = null)`; TokenPair определяется Task 2, до неё временно создать сам record с указанной там сигнатурой.
- `AuthAudit.EmailId(string normalizedEmail) : string`; `AuthAudit.Write(string eventName, string outcome, Guid? userId = null, string? method = null, Guid? attemptId = null, string? emailId = null, string? rejection = null) : void`. Конструктор получает IOptions<AuthenticationOptions>, TimeProvider, ILogger<AuthAudit>; request ID приходит из logging scope Task 3.
- `TestAuthConfiguration.Values() : Dictionary<string,string?>`; `MutableTimeProvider(DateTimeOffset initial)`, `Advance(TimeSpan delta) : void`, override `GetUtcNow() : DateTimeOffset`.

- [ ] **1. Написать тесты startup validation.** Таблица Missing/Empty/Malformed/31Bytes/ReusedKeys, confirmation true/false; отдельные пустые issuer/audience, неверный method, origin с path/userinfo/query, URL с чужим origin/fragment, CrossSiteCookies без FrontendOrigin. Проверять отказ host, не HTTP 500. Позитивный smoke:
  ```csharp
  Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/health")).StatusCode);
  Assert.NotEqual(audit.EmailId("a@example.com"), audit.EmailId("b@example.com"));
  Assert.Equal(audit.EmailId("a@example.com"), audit.EmailId("a@example.com"));
  ```
- [ ] **2. Запустить RED:** `dotnet test FEDept.BackendCourse.GroupA1.Api.Template.sln --filter FullyQualifiedName~AuthenticationConfigurationTests`. Ожидается отсутствие новых типов/отсутствие startup rejection.
- [ ] **3. Реализовать options/binder/validator и fixtures.** Сначала bind `Authentication`, затем явно наложить значения присутствующих внешних ключей `LOGIN_EMAIL_CONFIRMATION_ENABLED`, `LOGIN_EMAIL_CONFIRMATION_METHOD`, `JWT_ACCESS_SECRET`, `JWT_REFRESH_SECRET`, `LOGIN_CHALLENGE_HMAC_KEY`, `LOGIN_AUDIT_HMAC_KEY`, `JWT_ISSUER`, `JWT_AUDIENCE`; заданное пустое значение тоже должно наложиться и провалить validation. Не использовать проверку «непустой» для выбора override. Остальные имена — `Authentication:PublicApiOrigin`, `FrontendOrigin`, `ConfirmationUrl`, `CrossSiteCookies`, `TrustedProxies` с обычным `__` environment mapping. Origin — HTTPS authority без path; ConfirmationUrl — HTTPS URL этого frontend origin, без query/fragment/userinfo. Если FrontendOrigin отсутствует, ConfirmationUrl использует PublicApiOrigin; method/URL валидируются и при выключенном confirmation. Декодировать все 4 новых ключа, сравнить байты попарно; challenge key сравнить также с UTF-8 bytes registration key и с её Base64-decoded представлением, если оно допустимо. ValidateOnStart без ослабления Development.
- [ ] **4. Подключить TimeProvider/AuthAudit и тестовую конфигурацию.** В fixtures передавать 4 независимых test-only ключа, origins, issuer/audience, registration key; включать их до запуска host. HealthEndpointTests с plain WebApplicationFactory тоже получают TestAuthConfiguration, но не требуют доступной БД. Не хранить operational defaults. AuthAudit пишет только разрешённые поля/время. Запустить команду шага 2 и весь существующий suite: ожидается PASS.
- [ ] **5. Commit checkpoint:** только с разрешением, `feat(auth): validate configuration and initialize test hosts`; stage только файлы этой задачи.

## Task 2: JWT и атомарное формирование cookies

**Files:** Create `INF/Authentication/JwtTokens.cs`, `API/Authentication/AuthCookies.cs`, `AuthResponses.cs`, `TEST/JwtTokensTests.cs`, `AuthCookieTests.cs`; Modify `INF/FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.csproj`, `INF/Authentication/AuthResult.cs`.

**Interfaces:**
- `enum TokenUse { Access, Refresh }`; `record TokenPair(string AccessToken, string RefreshToken, DateTimeOffset AccessExpiresAt, DateTimeOffset RefreshExpiresAt)`.
- `record TokenValidationResult(Guid? UserId, string? Rejection)`; ровно одно из UserId/Rejection задано.
- `IJwtTokens.Issue(Guid userId) : TokenPair`; `IJwtTokens.Validate(string? token, TokenUse expectedUse) : TokenValidationResult`; production `JwtTokens` получает options и TimeProvider.
- `AuthCookies.Prepare(TokenPair pair) : string[]` возвращает ровно два готовых Set-Cookie; `PrepareDeletion() : string[]`; `Apply(HttpResponse response, string[] headers) : void` делает одну append-операцию массива. Prepare при истёкшей паре выбрасывает безопасную ошибку до изменения response.
- `AuthResponses.Map(ControllerBase controller, AuthResult result, AuthCookies cookies, bool isLogin) : IActionResult`; выдаёт 204/202/400/401/429/503. ProblemDetails extensions: code; retryAfterSeconds, если задан; для challenge SMTP failure ещё confirmationRequired=true/method/attemptId. Resend success не содержит confirmationRequired. Новые коды: invalid_request, invalid_credentials, invalid_session, rate_limited, service_unavailable. Guard использует csrf_rejected/https_required.

- [ ] **1. Написать тесты подписи и cookie contract:**
  ```csharp
  Assert.Equal(900, accessExp - issuedAt);
  Assert.Equal(2592000, refreshExp - issuedAt);
  Assert.Equal(new[] { "aud", "exp", "iat", "iss", "sub", "token_use" }, claimNames.Order().ToArray());
  Assert.Equal("token_use", tokens.Validate(refreshSignedWithAccessKey, TokenUse.Access).Rejection);
  Assert.DoesNotContain("Domain=", string.Join(";", cookies.Prepare(pair)), StringComparison.OrdinalIgnoreCase);
  Assert.Empty(response.Headers.SetCookie); // second-signature exception before Apply
  ```
  Для последнего теста access-key token имеет token_use=refresh, остальные claims корректны. Добавить theory для none/HS384/чужой ключ, missing/duplicate claim, sub не Guid/JSON number, iat/exp strings/null/arrays, aud array вместо строки, exp<=iat, iat>now+30. Проверить expiry в exp+29 и exp+31, границу библиотечного допуска явно закрепить. Проверить Strict/None, HttpOnly/Secure/Paths; отсутствие nbf и auto-added claims. Задержка 2 секунды уменьшает Max-Age, не сдвигает Expires; задержка за exp не эмитит cookies. Logout: оба исходных Path, Max-Age=0, прошлый Expires.
- [ ] **2. RED:** `dotnet test FEDept.BackendCourse.GroupA1.Api.Template.sln --filter 'FullyQualifiedName~JwtTokensTests|FullyQualifiedName~AuthCookieTests'`. Ожидается отсутствие JWT/cookie реализации.
- [ ] **3. Реализовать IJwtTokens и AuthCookies.** Использовать JWT-библиотеку для криптографической проверки, не писать HS256 самостоятельно. Issuance — целые Unix seconds от одного TimeProvider чтения, явный payload без лишних claims. Validation — allowlist HS256, отдельный ключ, точные issuer/audience/use, lifetime/skew30; отдельно проверить JSON-типы, уникальность и обязательность claims из подписанного payload. Отключить claims mapping. Категории отказа: missing/malformed/signature/expired/claims/token_use; не выпускать exception с token. Оба токена подготовить в локальных переменных до TokenPair. Не требовать различия строк при выпуске в ту же секунду. Max-Age округлять вниз от exp-now, Expires=exp, Domain не задавать; не использовать default cookie deletion, если оно не выдаёт Max-Age=0.
- [ ] **4. Реализовать Map и выполнить команду шага 2:** PASS. Добавить assertions на пустое тело 204 и отсутствие token-свойств/альтернативных token-заголовков. При malformed/expired старые cookies не удалять.
- [ ] **5. Commit checkpoint:** `feat(auth): issue and validate JWT cookie pairs`, только с разрешением.

## Task 3: HTTPS/Origin/CSRF и безопасная обработка исключений

**Files:** Create `API/Authentication/AuthRequestGuard.cs`, `AuthExceptionHandler.cs`, `TEST/AuthRequestGuardTests.cs`; Modify `API/Program.cs`, `API/Authentication/AuthenticationConfiguration.cs`, `API/appsettings.json`.

**Interfaces:** `AuthRequestGuard.InvokeAsync(HttpContext context) : Task`; `AuthExceptionHandler.TryHandleAsync(HttpContext context, Exception exception, CancellationToken ct) : ValueTask<bool>` через ASP.NET IExceptionHandler. Guard и handler используют AuthAudit. Новые auth маршруты пока проверять через test-only endpoints в host.

- [ ] **1. Написать guard theories:** same-origin без CSRF разрешён; missing Origin по HTTPS разрешён; trusted same-site cross-origin и cross-site требуют ровно X-CSRF-Protection:1; null/untrusted/multiple Origin, отсутствующий/неверный/множественный header дают403. Проверять отказ до вызова delegate:
  ```csharp
  Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
  Assert.Equal("csrf_rejected", body.GetProperty("code").GetString());
  Assert.Equal(0, sideEffects);
  Assert.Empty(response.Headers.SetCookie);
  ```
  HTTP auth POST даёт400 https_required без redirect и побочных эффектов. Чужой Host не определяет same-origin; spoofed X-Forwarded-Proto/For без trusted peer не меняет scheme/IP. Preflight возвращает точный Allow-Origin, Credentials=true, нужные headers/methods, без wildcard. GET не изменяет challenge.
- [ ] **2. RED:** `dotnet test FEDept.BackendCourse.GroupA1.Api.Template.sln --filter FullyQualifiedName~AuthRequestGuardTests`. Ожидается отсутствие guard/403.
- [ ] **3. Реализовать middleware и CORS.** Проверять HTTPS для всех `/auth` POST, включая регистрацию, до UseHttpsRedirection согласно spec §7.1; Origin/CSRF для изменяющих состояние POST, включая существующие registration endpoints. Совместимость регистрации означает прежние DTO/status/body для допустимых HTTPS-запросов; HTTP теперь получает400 https_required вместо redirect. Добавить theory `AuthPost_OverHttp_RejectsBeforeSideEffects` для пяти новых и трёх registration routes; существующие HTTPS registration tests сохраняют assertions. PublicApiOrigin брать только из валидной конфигурации, не из Host. ForwardedHeaders принимать только от явно заданных TrustedProxies; очистить неявные trust lists, при пустом списке не подключать обработку forwarded headers. Доверять XForwardedFor/XForwardedProto, не произвольному forwarded host. Отдельный CORS policy только для configured FrontendOrigin с credentials, POST/OPTIONS и Content-Type/X-CSRF-Protection; expose Retry-After. Same-site cross-origin не означает освобождение от CSRF.
- [ ] **4. Подключить sanitized error handling/logging.** Pipeline: безопасный request-ID scope и exception handler; trusted forwarded headers; guard; HTTPS redirect для остальных маршрутов; routing; CORS; existing registration rate limiter; authentication/authorization после Task 9; controllers. Неизвестное исключение нового auth пути превращать в503 service_unavailable без exception.Message/ToString и без Set-Cookie. Исключить дублирующее framework exception logging для уже обработанного исключения; не включать HTTP body/header logging и EF sensitive-data logging. Проверить исключение с текстом `sentinel-secret` и URL/query с ним: sentinel отсутствует в теле и во всех собранных logs. Выполнить команду шага 2: PASS.
- [ ] **5. Commit checkpoint:** `feat(auth): enforce HTTPS origins and CSRF`, только с разрешением.

## Task 4: Строгие лимиты и прямой login

**Files:** Create `INF/Authentication/AuthRateLimiter.cs`, `CredentialVerifier.cs`, `LoginService.cs`, `API/Controllers/AuthenticationController.cs`, `API/Contracts/LoginRequest.cs`, `TEST/AuthRateLimiterTests.cs`, `LoginEndpointTests.cs`, `AuthenticationTestHost.cs`, `AuthenticationTestDoubles.cs`; Modify `API/Program.cs`, `API/Authentication/AuthenticationConfiguration.cs`.

**Interfaces:**
- `AuthRateLimiter.TryRequest(string operation, string clientIp) : int?` — null при допуске, иначе ceiling Retry-After; operation только login/refresh, отдельные очереди.
- `AuthRateLimiter.CheckCredentialsAsync(string normalizedEmail, string clientIp, Func<CancellationToken, Task<AuthResult>> check, CancellationToken ct) : Task<AuthResult>` — сериализует check для пары и считает только InvalidCredentials.
- `ICredentialVerifier.Verify(string password, string? storedHash) : bool`; `CredentialVerifier` использует PasswordHasher.Verify; null hash выбирает статический заранее вычисленный dummy bcrypt work factor12.
- `LoginService.LoginAsync(string email, string password, string clientIp, CancellationToken ct) : Task<AuthResult>`.
- `LoginRequest(string Email, string Password)`; `AuthenticationController.Login(LoginRequest request, CancellationToken ct) : Task<IActionResult>`, route POST /auth/login.
- `AuthenticationTestHost` оборачивает factory.WithWebHostBuilder, регистрирует MutableTimeProvider, email/signing doubles, optional DB interceptors; создаёт HTTPS client с HandleCookies=false и AllowAutoRedirect=false. Никаких production test-only routes/config switches.

- [ ] **1. Написать тесты прямого входа и лимитов.** Нормализация email; пароль `" abc123 "`; 72-byte ASCII/многобайтные строки допускаются, 73 bytes дают400; пустой/отсутствующий пароль и invalid email дают400 без verify. Для неизвестного email и Pending/Blocked/Deleting/Deleted проверять ровно один Verify, одинаковые401/code/body без cookie; Active выдаёт204 и пару. Использовать spy ICredentialVerifier для вызовов и хотя бы один настоящий bcrypt roundtrip с пользователем, созданным через /auth/register.
  ```csharp
  Assert.Equal(30, acceptedInRollingMinute);
  Assert.Equal(429, thirtyFirstStatus);
  Assert.Equal(5, verifierCallsForSixConcurrentFailures);
  Assert.Equal(429, sixthStatus);
  Assert.Equal(new[] { 401, 401, 401, 401, 204, 401, 429 }, statusesAfterFourFailuresThenSuccessThenTwoFailures);
  Assert.Empty(response.Headers.SetCookie); // signing failure
  ```
  Отдельно: успех не сбрасывает failures; invalid JSON/503 не увеличивают их; граница60/900 секунд освобождает только истёкшие записи; всплеск через границу минуты не удваивает cap. Отмена ожидающего pair check освобождает ссылку/lease; cleanup не удаляет active lock; после завершения/TTL записи удаляются. IP spoofing не создаёт новый bucket.
- [ ] **2. RED:** `dotnet test FEDept.BackendCourse.GroupA1.Api.Template.sln --filter 'FullyQualifiedName~AuthRateLimiterTests|FullyQualifiedName~LoginEndpointTests'`. Ожидается404/отсутствие новых сервисов.
- [ ] **3. Реализовать limiter.** Singleton, timestamp queues; удалять записи с timestamp<=now-window перед допуском. Для pair — reference-counted per-key SemaphoreSlim, очередь только отказов, HMAC email+canonical IP key без plaintext email. Acquire/проверка cap до bcrypt, release в finally. Очистка простаивающих buckets при обращениях и периодическом sweep с TimeProvider; проверять refcount под тем же dictionary lock, не создавать два lock одного ключа. Request buckets живут не меньше60 секунд, pair buckets900; успех/503 не записывать как failure. Audit обоих limit triggers без email.
- [ ] **4. Реализовать LoginService/DTO/controller.** Guard, model validation, login-IP limit, pair admission, DB lookup, реальный/dummy verify, Active check. ICredentialVerifier не должен пропускаться для known inactive. Существующий registration PasswordHasher не менять. При confirmation=false вернуть TokenPair; Map ставит cookies после обеих подписей. Подписную ошибку/DB exception санитизировать в503. До Task 6 при confirmation=true и верных Active credentials явно вернуть Unavailable без JWT/cookies/письма; закрепить тестом `Login_ConfirmationEnabledBeforeChallengeIntegration_Returns503WithoutCookies`. Это временное fail-closed поведение незавершённой ветки, не конечный контракт; Task 6 заменяет его реальным StartAsync и заменяет этот тест assertions на202. Запустить команду шага 2 и RegisterEndpointTests/RegisterValidationTests: PASS.
- [ ] **5. Commit checkpoint:** `feat(auth): add limited password login`, только с разрешением.

## Task 5: Login challenges, миграция и единый lock order

**Files:** Create `INF/Authentication/LoginChallenge.cs`, `LoginChallengeLocks.cs`, `TEST/LoginChallengeMigrationTests.cs`; Modify `INF/AppDbContext.cs`, `INF/Users/UserStatus.cs`, `INF/Migrations/AppDbContextModelSnapshot.cs`; Generate `INF/Migrations/<timestamp>_AddLoginChallenges.cs` и `.Designer.cs`.

**Interfaces:**
- `LoginChallenge`: Guid Id/UserId; string Method/SecretHash; int Attempts; DateTimeOffset LastSentAt; DateTimeOffset? ConsumedAt; string? ConsumedReason. Method только otp/magic_link, причины только confirmed/replaced/attempts_exhausted/user_inactive.
- `AppDbContext.LoginChallenges : DbSet<LoginChallenge>`.
- `LoginChallengeLocks.LockUserAsync(Guid userId, CancellationToken ct) : Task<User?>`; `LockChallengeAsync(Guid attemptId, CancellationToken ct) : Task<LoginChallenge?>`; `LockLiveChallengeAsync(Guid userId, CancellationToken ct) : Task<LoginChallenge?>`. Все вызываются внутри caller transaction, используют параметризованный SELECT FOR UPDATE и перечитывание без stale tracked entity.

- [ ] **1. Написать PostgreSQL migration tests.** Создать БД со старыми миграциями/пользователями/registration challenge, применить новую. Проверить сохранение id/hash/status и старых таблиц; отсутствие expires_at/JWT/refresh columns. Два live challenge одного user нарушают named unique index; consumed+live разрешены. Attempts -1/6, invalid method/reason и несовпадающая nullable pair нарушают CHECK. Физическое удаление user каскадно удаляет login challenges; registration FK не менять.
  ```csharp
  Assert.Equal(originalHash, persistedUser.PasswordHash);
  Assert.Equal(PostgresErrorCodes.UniqueViolation, uniqueViolation.SqlState);
  Assert.Empty(await db.LoginChallenges.Where(x => x.UserId == removedId).ToListAsync());
  ```
- [ ] **2. RED:** `dotnet test FEDept.BackendCourse.GroupA1.Api.Template.sln --filter FullyQualifiedName~LoginChallengeMigrationTests`. Ожидается отсутствие DbSet/таблицы/constraint.
- [ ] **3. Реализовать mapping и миграцию AddLoginChallenges.** Строковые snake_case columns, named `ux_login_challenges_live_user` с filter consumed_at IS NULL; CHECK attempts BETWEEN0AND5, допустимые method/reason, согласованность consumed pair; FK ON DELETE CASCADE. UserStatus добавить Blocked/Deleting/Deleted без перенумерации старых значений и без data rewrite. Lock users по фактической существующей таблице `Users`/колонке `Id`, login_challenges — snake_case. Для discovery использовать AsNoTracking projection только UserId; после locks не доверять первоначальному чтению. Исчезнувшая строка даёт отсутствие, а не исключение/успех.
- [ ] **4. Запустить команду шага 2 и `dotnet test FEDept.BackendCourse.GroupA1.Api.Template.sln --filter FullyQualifiedName~MigrationTests`: PASS на PostgreSQL. Проверить SQL миграции: нет DROP старых таблиц/очистки пользователей. Тестировать locks двумя независимыми DbContext/соединениями, не одним tracked context.
- [ ] **5. Commit checkpoint:** `feat(auth): persist serialized login challenges`, только с разрешением.

## Task 6: Создание challenge и письма OTP/magic link

**Files:** Create `INF/Authentication/LoginChallengeService.cs`, `TEST/LoginChallengeCreationTests.cs`, `SmtpLoginEmailTests.cs`; Modify `INF/Authentication/LoginService.cs`, `INF/Registration/SecretHasher.cs`, `IEmailSender.cs`, `SmtpEmailSender.cs`, `TEST/ConfirmEndpointTests.cs`, `RegisterEndpointTests.cs`, `AuditLoggingTests.cs`, `ResendEndpointTests.cs`, `AuthenticationTestDoubles.cs`.

**Interfaces:**
- Добавить `SecretHasher(byte[] key)` без изменения семантики существующего `SecretHasher(string key)`; Hash/Matches остаются прежними. Новая перегрузка копирует bytes; регистрация продолжает UTF-8 text key.
- `IEmailSender.SendLoginOtpAsync(string email, string code, CancellationToken ct) : Task`; `SendLoginLinkAsync(string email, Uri link, CancellationToken ct) : Task`; SendOtpAsync не менять.
- `LoginChallengeService.StartAsync(Guid userId, CancellationToken ct) : Task<AuthResult>`; service получает DbContext, locks, IOptionsMonitor<AuthenticationOptions>, IEmailSender, IJwtTokens, TimeProvider, AuthAudit.
- Новая попытка читает текущие ConfirmationEnabled/Method через IOptionsMonitor; LoginService передаёт управление StartAsync только после верных credentials. Старые попытки всегда используют сохранённый Method.

- [ ] **1. Написать tests:** 202 с точными пятью полями; нет cookies/JWT; в БД только HMAC. OTP шесть ASCII digits, leading zero допускается; magic secret декодируется в32 bytes, URL fragment `token=<attemptId>.<secret>`, доверенный configured origin/path. Host/Origin не меняют destination. SMTP вызывается после commit — capturing sender читает challenge отдельным соединением. Concurrent login даёт один202 и один429, одно письмо. До60 возвращается ceiling Retry-After; ровно60 создаётся новая попытка, старая replaced.
  ```csharp
  Assert.True(body.GetProperty("confirmationRequired").GetBoolean());
  Assert.Equal(600, body.GetProperty("expiresInSeconds").GetInt32());
  Assert.Equal(60, body.GetProperty("resendAfterSeconds").GetInt32());
  Assert.Empty(response.Headers.SetCookie);
  Assert.Equal("replaced", previous.ConsumedReason);
  Assert.Equal(32, decodedMagicSecret.Length);
  ```
  SMTP failure:503 с continuation, challenge сохранён, повтор ранее60 не отправляет письмо. Pre-commit interceptor failure:503, нет письма/новой попытки, старый live challenge не заменён. SMTP delay уменьшает retryAfterSeconds от сохранённого времени.
- [ ] **2. RED:** `dotnet test FEDept.BackendCourse.GroupA1.Api.Template.sln --filter 'FullyQualifiedName~LoginChallengeCreationTests|FullyQualifiedName~SmtpLoginEmailTests|FullyQualifiedName~SecretHasherTests'`.
- [ ] **3. Реализовать StartAsync.** Транзакция; lock user, live challenge; Active и cooldown recheck; consume previous=replaced, SaveChanges до INSERT новой строки, чтобы EF ordering не нарушил partial unique index; всё в одной транзакции. OTP через существующий generator, magic через RandomNumberGenerator32 bytes и base64url. SecretHasher получает decoded login key. Save/commit; только затем email. SMTP исключение превращать в AuthResult.Unavailable с ChallengeInfo и ceiling max(0,60-elapsed), без секрета/inner exception в audit. Нет JWT на этом шаге. Если user стал inactive,401, без письма.
- [ ] **4. Расширить SmtpEmailSender/NullEmailSender и все существующие doubles.** Login OTP subject `Login verification code`; magic subject `Confirm your login`; registration subject/body не менять. Только общий SMTP transport вынести в private helper этого класса; не создавать notification framework. Старые registration-only doubles явно throw NotSupportedException на неожиданный login вызов; новый double захватывает оба login метода. Добавить test SMTP server на loopback ephemeral port для проверки реальных MimeMessage/команд MailKit и сценария 4xx/5xx, не внешнюю почту. Выполнить команду шага 2 и весь registration suite: PASS.
- [ ] **5. Commit checkpoint:** `feat(auth): start email login challenges`, только с разрешением.

## Task 7: Подтверждение обоими методами и атомарная выдача

**Files:** Create `API/Contracts/LoginConfirmRequest.cs`, `TEST/LoginConfirmEndpointTests.cs`; Modify `INF/Authentication/LoginChallengeService.cs`, `API/Controllers/AuthenticationController.cs`, `TEST/AuthenticationTestDoubles.cs`.

**Interfaces:** `LoginConfirmRequest(Guid? AttemptId, string? Code, string? Token)` с IValidatableObject для ровно одной формы; `LoginChallengeService.ConfirmAsync(Guid attemptId, string secret, string method, CancellationToken ct) : Task<AuthResult>`; `AuthenticationController.Confirm(LoginConfirmRequest request, CancellationToken ct) : Task<IActionResult>` на POST /auth/login/confirm. Парсинг token в controller/DTO: Guid + точка + canonical base64url secret32 bytes; неправильная форма не вызывает service.

- [ ] **1. Написать таблицу OTP/magic подтверждений:** mixed/incomplete/unicode digits/wrong method дают400 без attempts; missing challenge400; consumed reason exhaustion429, остальные400; now=last_sent_at+600 даёт400 без increment; wrong magic400 без increment. Для попытки с Attempts=4:
  ```csharp
  Assert.Equal(HttpStatusCode.NoContent, correctFifth.StatusCode);
  Assert.Equal(HttpStatusCode.BadRequest, wrongFifth.StatusCode);
  Assert.Equal(HttpStatusCode.TooManyRequests, afterWrongFifth.StatusCode);
  Assert.Equal(5, exhausted.Attempts);
  Assert.Equal("attempts_exhausted", exhausted.ConsumedReason);
  ```
  Это разные fixtures/challenges, не последовательность на одном consumed challenge. Добавить leading-zero OTP, replay, replacement, настройка method изменена/confirmation выключен. Все inactive статусы: первый live valid request401+user_inactive, повтор400, без JWT. Physical delete между discovery/lock400, не500. Подпись №2 и pre-commit failure:503, нет Set-Cookie, challenge не consumed, retry успешен. Два concurrent correct confirm: ровно один204. Шесть parallel wrong: attempts5 и ни одного успешного входа. Статус, изменённый под user row lock до confirm, запрещает вход.
- [ ] **2. RED:** `dotnet test FEDept.BackendCourse.GroupA1.Api.Template.sln --filter FullyQualifiedName~LoginConfirmEndpointTests`. Ожидается404/отсутствие ConfirmAsync.
- [ ] **3. Реализовать ConfirmAsync.** Discovery UserId; begin transaction; LockUser, LockChallenge; проверить method, consumption, TTL, затем Active по порядку spec. Wrong OTP атомарно увеличивает attempts, пятый гасит и всё равно InvalidRequest; следующая попытка Throttled. Wrong magic не меняет attempts. Верный секрет: Issue обоих JWT до consumed update/commit, затем consumed=confirmed, Save/commit; только наружный mapper пишет cookies. Если commit завершился, но задержка до Prepare уже исчерпала TTL access, вернуть503 без cookies, не восстанавливать consumed challenge: это post-commit потеря результата, требуется новый login. Тест `Confirm_TokensExpireDuringCommit_Returns503AndKeepsChallengeConsumed` продвигает MutableTimeProvider на901 секунду в commit interceptor и проверяет503/пустой Set-Cookie/confirmed в новой DB-сессии. Гарантия retry относится только к доказанному rollback до commit. Ошибку до commit откатить; не маскировать отмену запроса как invalid_credentials. GET никогда не вызывает ConfirmAsync. Не переиспользовать регистрацию и её ConfirmResult.
- [ ] **4. Выполнить команду шага 2 и существующие ConfirmEndpointTests:** PASS. Для конкурентных tests использовать PostgreSQL и barriers/TaskCompletionSource вместо задержек sleep; lost-response сценарий повторяет уже committed challenge и получает400.
- [ ] **5. Commit checkpoint:** `feat(auth): confirm OTP and magic-link login`, только с разрешением.

## Task 8: Resend со старым методом, общей паузой и сбоями

**Files:** Create `API/Contracts/LoginResendRequest.cs`, `TEST/LoginResendEndpointTests.cs`; Modify `INF/Authentication/LoginChallengeService.cs`, `API/Controllers/AuthenticationController.cs`.

**Interfaces:** `LoginResendRequest(Guid AttemptId)`; `LoginChallengeService.ResendAsync(Guid attemptId, CancellationToken ct) : Task<AuthResult>`; `AuthenticationController.Resend(LoginResendRequest request, CancellationToken ct) : Task<IActionResult>` на POST /auth/login/resend.

- [ ] **1. Написать тесты обоих методов:** before60 ->429+ceiling/body/header; exactly60 и expired live ->202; сохраняются id/method, attempts0, новый LastSentAt и HMAC; старая secret invalid. Method/flag изменены между login/resend — старый метод работает. Missing/confirmed/replaced/user_inactive400; exhausted429; первый inactive401 и consume, повтор400. Success JSON не содержит confirmationRequired:
  ```csharp
  Assert.Equal(original.Id, resent.Id);
  Assert.Equal(original.Method, resent.Method);
  Assert.Equal(0, resent.Attempts);
  Assert.False(body.TryGetProperty("confirmationRequired", out _));
  Assert.Empty(response.Headers.SetCookie);
  ```
  Pre-commit failure сохраняет прежний secret/time и не отправляет mail; SMTP failure сохраняет новый hash/cooldown. Concurrent login/resend либо confirm/resend: сериализованные результаты, не два письма за60, не повторный вход; при confirm first resend400, при resend first старый secret400. Пользователь удалён/статус изменён до lock — JWT/mail не выдаются.
- [ ] **2. RED:** `dotnet test FEDept.BackendCourse.GroupA1.Api.Template.sln --filter FullyQualifiedName~LoginResendEndpointTests`.
- [ ] **3. Реализовать ResendAsync с тем же lock helper.** После locks: consumption/status, cooldown; expiry не запрещает resend. Генерировать secret только по сохранённому method; заменить HMAC/LastSentAt/Attempts, commit, SMTP. Считать retry от committed LastSentAt. Новую строку/attemptId не создавать; при SMTP failure не восстанавливать старый hash. Смена конфигурации не отключает старый challenge.
- [ ] **4. Запустить команду шага 2 и LoginChallengeCreationTests/LoginConfirmEndpointTests:** PASS; проверить строки БД после каждого injected failure отдельным DbContext.
- [ ] **5. Commit checkpoint:** `feat(auth): resend existing login challenges`, только с разрешением.

## Task 9: Refresh, logout и общий access handler

**Files:** Create `INF/Authentication/SessionService.cs`, `API/Authentication/AccessCookieHandler.cs`, `TEST/SessionEndpointTests.cs`, `AccessCookieTests.cs`; Modify `API/Controllers/AuthenticationController.cs`, `API/Program.cs`, `API/Authentication/AuthenticationConfiguration.cs`, `TEST/AuthenticationTestHost.cs`.

**Interfaces:**
- `SessionService.RefreshAsync(string? refreshToken, CancellationToken ct) : Task<AuthResult>`.
- `SessionService.ValidateAccessAsync(string? accessToken, CancellationToken ct) : Task<TokenValidationResult>`; DB failures выбрасываются в safe503 handler, не превращаются в token rejection.
- `AccessCookieHandler : AuthenticationHandler<AuthenticationSchemeOptions>`, scheme `AccessCookie`; HandleAuthenticateAsync вызывает ValidateAccessAsync, создаёт ClaimsPrincipal только с ClaimTypes.NameIdentifier=userId. HandleChallengeAsync пишет401 invalid_session. Никакого fallback к Authorization/query/body.
- `AuthenticationController.Refresh(CancellationToken ct) : Task<IActionResult>`; `Logout() : IActionResult`; endpoints POST /auth/refresh и /auth/logout. Logout не вызывает SessionService/JWT/БД.

- [ ] **1. Написать refresh/logout/access tests:** refresh только cookie; body/query/Authorization без cookie401; access нельзя refresh и наоборот. Active + валидный JWT204, TTL от нового now; old refresh остаётся пригодным после refresh и logout. Same-second issuance проверяет сроки/claims, не неравенство строк. Все статусы/отсутствующий пользователь401, DB outage503, подпись №2 failure503 — cookies неизменны. Access тестовый protected controller добавляется только через test host ApplicationPart, возвращает verified userId и набор переданных claims:
  ```csharp
  Assert.Equal(user.Id.ToString(), principal.FindFirstValue(ClaimTypes.NameIdentifier));
  Assert.Single(principal.Claims);
  Assert.Equal(HttpStatusCode.Unauthorized, responseWithoutCookie.StatusCode);
  Assert.Equal(HttpStatusCode.ServiceUnavailable, responseDuringDbFailure.StatusCode);
  ```
  Logout без/с malformed/валидными cookies204, обе deletion cookies с Max-Age0 и matching Path, без запроса БД. CSRF rejected logout403 без удаления. Theory `AnonymousRoute_WithAccessCookie_DoesNotValidateAccess` проверяет malformed и валидную access cookie на health/OpenAPI/auth routes с IJwtTokens spy: вызовов Validate с TokenUse.Access ровно0. При недоступной БД /health остаётся200, logout204; login/refresh могут дать503 из собственного сценария, но не из access handler.
- [ ] **2. RED:** `dotnet test FEDept.BackendCourse.GroupA1.Api.Template.sln --filter 'FullyQualifiedName~SessionEndpointTests|FullyQualifiedName~AccessCookieTests'`.
- [ ] **3. Реализовать SessionService и handler.** Refresh-IP limit до проверки JWT/DB; Validate нужным key/use, query только id/status, Active, затем Issue. Access query AsNoTracking projection id/status на каждом запросе; user absence/inactive -> user_inactive audit, public invalid_session. Handler не копирует исходный JWT principal/roles; исключение DB проходит safe503 путь, не AuthenticateResult.Fail401. AddAuthentication/Authorization и middleware перед MapControllers; [Authorize(AuthenticationSchemes="AccessCookie")] подключает будущие protected endpoints. Не задавать DefaultScheme/DefaultAuthenticateScheme; отключить автоматический default для единственной схемы через framework switch `Microsoft.AspNetCore.Authentication.SuppressAutoDefaultScheme` до регистрации схемы, сверив API по docs. FallbackPolicy=null. Это исключает eager access validation на anonymous routes, а не только обязательность авторизации. Logout проходит guard, пишет deletion headers и204, даже если refresh cookie не пришла из-за её Path.
- [ ] **4. Выполнить команду шага 2 и JWT/guard suites:** PASS. Добавить параллельный refresh одной копией: оба допускаются stateless контрактом. Не добавлять jti/refresh storage ради различия строк.
- [ ] **5. Commit checkpoint:** `feat(auth): refresh logout and validate access cookies`, только с разрешением.

## Task 10: Сквозной безопасный аудит, readiness и OpenAPI

**Files:** Create `TEST/AuthenticationAuditTests.cs`, `ReadinessTests.cs`, `AuthenticationOpenApiTests.cs`, `API/Authentication/AuthenticationOpenApiTransformer.cs`; Modify `INF/Registration/RegistrationAudit.cs`, `RegistrationService.cs`, `TEST/AuditLoggingTests.cs`, `API/Program.cs`, `INF/Authentication/AuthAudit.cs`, `LoginService.cs`, `LoginChallengeService.cs`, `SessionService.cs`, `API/Authentication/AuthRequestGuard.cs`, `AccessCookieHandler.cs`.

**Interfaces:** RegistrationAudit становится injectable instance с AuthAudit; существующие три метода сохраняют имена/параметры email/outcome, но внутри вычисляют EmailId, а не логируют email. RegistrationService получает RegistrationAudit через DI. Readiness — GET /health/ready, без credentials; DB CanConnectAsync с ограничением5 секунд, failure503; не проверяет SMTP. OpenAPI transformer реализует framework IOpenApiDocumentTransformer.TransformAsync для текущего установленного OpenAPI пакета.

- [ ] **1. Написать audit scenario matrix:** login success/failure, оба лимита, creation/replacement/resend, confirm wrong/expired/exhausted/success, refresh/logout/access, guard и DB/commit/SMTP/signing failures. Каждое событие содержит EventName/Outcome/Time/RequestId и известные UserId/Method/AttemptId; unknown email только EmailId. JWT rejection theory покрывает missing/malformed/signature/expired/claims/token_use/user_inactive. Capture logger собирает все категории, включая framework, не только RegistrationService.
  ```csharp
  Assert.DoesNotContain(email, logs, StringComparison.OrdinalIgnoreCase);
  Assert.DoesNotContain(password, logs, StringComparison.Ordinal);
  Assert.DoesNotContain(smtpExceptionSecret, logs, StringComparison.Ordinal);
  Assert.Contains("RequestId=", logs);
  Assert.Contains("EmailId=", unknownLoginLog);
  Assert.DoesNotContain("Email=", logs, StringComparison.Ordinal);
  ```
  Assert каждого реального OTP/magic/JWT/hash/key/cookie и полного URI отсутствует; не ограничиваться именем поля. Обновить старые assertions, требовавшие plaintext emails, но сохранить проверку всех registration outcomes.
- [ ] **2. RED:** `dotnet test FEDept.BackendCourse.GroupA1.Api.Template.sln --filter 'FullyQualifiedName~AuthenticationAuditTests|FullyQualifiedName~AuditLoggingTests|FullyQualifiedName~ReadinessTests|FullyQualifiedName~AuthenticationOpenApiTests'`.
- [ ] **3. Закрыть audit gaps и добавить readiness.** Использовать только AuthAudit.Write и logging scope RequestId; correlation создавать сервером либо ограничивать/санитизировать внешний request ID. Не передавать raw Exception в ILogger и не включать SQL parameter logging. RegistrationAudit хеширует email независимым audit key; response registration не менять. Readiness200 при доступной БД,503 при недоступной, health200 в обоих случаях; timeout/cancellation не оставляют зависший запрос. Invalid mandatory config не даёт host стартовать.
- [ ] **4. Добавить OpenAPI assertions и transformer.** Документ содержит пять POST, oneOf двух confirm forms с запретом смешивания, все исходы/continuation503, отсутствие body у204, Set-Cookie/Retry-After, cookie security schemes с разными именами, CSRF и exact-origin правила. Примеры только placeholders, не valid JWT/OTP/ключи. Проверить dev /openapi/v1.json; в другом окружении сохранить прежнее отсутствие документа. Выполнить команду шага 2 и все tests: PASS.
- [ ] **5. Commit checkpoint:** `feat(auth): document and audit authentication safely`, только с разрешением.

## Task 11: Реальный локальный HTTPS и инструкции без встроенных секретов

**Files:** Modify `compose.yaml`, `.gitignore`, `README.md`, `API/Dockerfile`, `API/Properties/launchSettings.json`, `API/appsettings.json`, `API/appsettings.Development.json`, `API/FEDept.BackendCourse.GroupA1.Api.Template.http`.

**Interfaces:** TLS заканчивается непосредственно в Kestrel, не новый proxy. Compose API публикует только `127.0.0.1:${API_HTTPS_PORT:-7135}:8443`; HTTPS listener8443 с read-only mounted developer certificate; PublicApiOrigin совпадает с выбранным host port. Настройки Mailpit/Postgres и несвязанные пользовательские изменения сохраняются; pgAdmin в Compose отсутствует.

- [ ] **1. Зафиксировать RED smoke до изменения compose.** `docker compose config --quiet`; проверить текущий HTTPS URL отдельным клиентом: без TLS listener handshake не проходит. Команды запуска/deploy выполнять только на этапе реализации с разрешением; не останавливать чужие контейнеры и не удалять volume. Не выводить rendered environment/secrets через docker compose config без --quiet.
- [ ] **2. Настроить HTTPS listener и secret forwarding.** Compose env `ASPNETCORE_URLS=https://+:8443`, certificate Path `/https/api.pfx`, password из `${HTTPS_CERT_PASSWORD:?required}`; mount `${HTTPS_CERT_PATH:?required}:/https/api.pfx:ro`. Передавать все восемь внешних auth parameters явно через `${NAME:?required}`, включая bool/method и audit key; JWT issuer/audience также обязательны. Передавать PublicApiOrigin/FrontendOrigin/ConfirmationUrl/CrossSiteCookies, registration key, SMTP. TrustedProxies пустой для direct TLS. EXPOSE8443; HTTP profile оставить для health/старых упражнений, явно указав, что все `/auth` POST, включая регистрацию, по нему запрещены. Не добавлять ключи/пароль PFX в appsettings/launchSettings. Добавить .env, .certs/, *.pfx в gitignore; не перезаписывать существующий .env и не коммитить сертификат.
- [ ] **3. Обновить README/.http.** Исправить устаревшее описание starter, таблицу endpoints, host/Docker HTTPS URL и OpenAPI, prerequisites Docker для tests, явный setup environment/User Secrets, генерацию независимых random32-byte Base64 ключей разработчиком до запуска, export/trust dev certificate и права чтения mounted PFX непривилегированным пользователем контейнера. Примеры содержат имена переменных, не значения ключей. Не печатать secrets в logs/shell history. Документировать flat mapping, cookie Path, CSRF/credentials, fragment-only magic link, отсутствие UI, stateless logout limitation, in-memory single-replica limits. Показать HTTPS сразу, не советовать отправлять пароль по HTTP и ждать redirect. Проверить команды сертификата по актуальным .NET docs на этапе реализации.
- [ ] **4. GREEN smoke реального стенда.** `docker compose config --quiet`, затем `docker compose up --build -d api` с локальными env. Без `-k` доверенный клиент открывает https://localhost:7135/health и /health/ready ->200; OpenAPI доступен. Зарегистрировать тестового active user, login204, проверить cookie flags/path без публикации значений; refresh204, logout204/deletions. Включить OTP/magic в отдельном запуске, проверить доставку Mailpit и POST confirm; GET не подтверждает. В браузере same-origin cookies сохраняются/удаляются; trusted cross-origin запрос с credentials+header работает, без header403; cross-site None проверять на двух действительно разных site, не двух localhost ports. Если доверенного второго site нет, отметить этот browser case непроверенным, а не считать integration test заменой. Не сохранять JWT/OTP/cookie jar в репозиторий; очистить временные локальные файлы. `dotnet` in-memory tests не являются доказательством TLS.
- [ ] **5. Commit checkpoint:** `docs(dev): configure HTTPS authentication workflow`, только с разрешением и без секретов.

## Task 12: Coverage gate и финальная проверка совместимости

**Files:** Create `coverage.runsettings`, `scripts/check-coverage.py`; Modify `TEST/FEDept.BackendCourse.GroupA1.Api.Template.Tests.csproj` только если требуется настройка уже установленного coverlet.collector; добавить недостающие tests в suites задач-владельцев, не отдельную вторую реализацию сценариев.

**Interfaces:** `python3 -I scripts/check-coverage.py <results-directory>` читает все Cobertura XML рекурсивно, объединяет покрытые production source lines по file+line, печатает процент и возвращает0 при coverage>=80%, иначе1. Отсутствие отчётов/production lines — ошибка, не100%. Не усреднять проценты проектов/дублирующихся отчётов.

- [ ] **1. Написать assert-based self-test coverage checker.** Временные minimal XML:79/100 ->exit1;80/100 ->0; два отчёта с пересекающимися строками не удваивают denominator;0/0 и missing reports ->1. Добавить `--self-test` режим checker, не внешний Python package.
- [ ] **2. RED:** `python3 -I scripts/check-coverage.py --self-test`; ожидается отсутствие checker. Затем реализовать checker и runsettings: collector XPlat Code Coverage, Cobertura; включить оба production assemblies, исключить tests/generated code/EF generated migrations и snapshots, не Authentication/Program/controller/exception handlers. Production line counts по нормализованному source path, не имени assembly test report.
- [ ] **3. Выполнить весь acceptance matrix spec §15.** У каждого требования есть suite в Tasks1–10; недостающее assertion добавить в соответствующий suite. Отдельно сверить реальную совместимость регистрации201/202/409, пятого registration OTP, отсутствия session у регистрации, readiness, method toggle, rollback и concurrent row locks. Никаких broad exclusions ради80%.
- [ ] **4. Финальные команды:**
  ```bash
  python3 -I scripts/check-coverage.py --self-test
  dotnet build FEDept.BackendCourse.GroupA1.Api.Template.sln
  dotnet test FEDept.BackendCourse.GroupA1.Api.Template.sln
  dotnet test FEDept.BackendCourse.GroupA1.Api.Template.sln --collect:"XPlat Code Coverage" --settings coverage.runsettings --results-directory TestResults/authentication-coverage
  python3 -I scripts/check-coverage.py TestResults/authentication-coverage
  dotnet format FEDept.BackendCourse.GroupA1.Api.Template.sln --verify-no-changes
  git diff --check
  ```
  Coverage directory должен быть новым для этого прогона; не смешивать старые reports. Все команды exit0, production line coverage>=80%; плюс отдельно evidence HTTPS/browser/SMTP из Task11. Если Docker/документация/браузер недоступны, явно назвать непроверенное; не объявлять все acceptance criteria выполненными.
- [ ] **5. Commit checkpoint:** `test(auth): enforce coverage and regression gates`, только с разрешением. Перед staging проверить diff и список файлов; не включать .DS_Store, .idea, .claude, .postman, чужие изменения и operational secrets. Push/PR не выполнять без запроса.

## Проверка полноты перед передачей реализации

- Конфигурация/ключи/fixtures — Task1; JWT/cookies — Task2; HTTPS/Origin/CSRF/proxy/error hygiene — Task3.
- Login/валидация/строгие лимиты — Task4; PostgreSQL constraints/удаление/locks — Task5.
- Challenge/mail/commit-before-SMTP — Task6; confirm/fifth failure/rollback/replay — Task7; resend/toggle/races — Task8.
- Refresh/logout/access/stateless limitations — Task9; аудит старой регистрации, health/readiness, OpenAPI — Task10.
- Реальный Docker/browser TLS и безопасные инструкции — Task11; coverage/весь regression suite — Task12.
- Пять Review Focus привязаны к конкретным тестовым шагам. Общие типы/сигнатуры определены до использования; единственная forward declaration TokenPair создаётся Task1 с окончательной сигнатурой Task2.

**Граница готовности этого плана:** план не является evidence работающего auth. До реализации остаются разрешение на чтение актуальных библиотечных docs, утверждение плана и выбор способа исполнения. Runtime-проверки, миграции, HTTPS smoke и coverage выполняются только при реализации.
