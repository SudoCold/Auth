# .NET 10 Authentication and Authorization API

An ASP.NET Core controller-based Web API with ASP.NET Core Identity, EF Core 10, SQLite, JWT bearer authentication, and role-based authorization. The database and initial roles are created automatically in Development. No database server is required.

## Run locally

Install the .NET 10 SDK. From this directory, run these PowerShell commands once:

```powershell
dotnet restore
dotnet dev-certs https --trust
```

Then start the API with the development launcher (Windows PowerShell 5.1 or PowerShell 7):

```powershell
.\scripts\Start-Dev.ps1
```

- HTTPS: `https://localhost:7080`
- Swagger UI, available in Development: `https://localhost:7080/swagger`
- Health: `GET https://localhost:7080/health`
- Swagger JSON, available in Development: `https://localhost:7080/swagger/v1/swagger.json` (also available at `/openapi/v1.json`)
- Example requests: `src/Auth.Api/Auth.Api.http`

The launcher uses a valid `Jwt__SigningKey` environment variable, otherwise loads the key from your current user's secret store. If no valid key exists, it generates and saves a random key. It explicitly launches in Development and supplies the key to the API process without displaying it. Production still requires an explicitly configured key.

After setup, `dotnet run --project src/Auth.Api` also works with the supplied HTTPS launch profile. If that command reports a missing `SigningKey`, run `.\scripts\Start-Dev.ps1` from this directory to configure the current user's key and start the API. An empty environment variable can override a valid user-secret; the launcher handles this case too.

Saved keys stay in your local ASP.NET Core user-secrets store, outside this repository. Keep the key between runs to retain valid sessions. Changing it invalidates existing access tokens; existing refresh tokens remain usable unless you also revoke their sessions. User-secrets are a development convenience, not an encrypted production vault.

## Try the API

Open `https://localhost:7080/` to go to Swagger UI. Documentation is public in Development; API routes still enforce their authentication and role requirements.

1. Expand `POST /api/auth/register`, click **Try it out**, and enter your email, display name, and a password such as `Example-password-123!`. Execute the request once to create the account.
2. Execute `POST /api/auth/login` with the same email and password.
3. Copy the `accessToken` value from the login response.
4. Click **Authorize** at the top, paste only the token (without `Bearer ` or quotes), and click **Authorize**, then **Close**.
5. Execute `GET /api/auth/me` to retrieve your profile. Swagger sends the Authorization header automatically.

Logging in returns a token; you must still paste it into **Authorize**. A regular user receives `403` on administrator endpoints. Log in again and update the token in **Authorize** when it expires or after logout/password changes.

In another PowerShell terminal:

```powershell
$baseUrl = "https://localhost:7080"
$registration = @{
    email = "you@example.com"
    password = "Example-password-123!"
    displayName = "Your Name"
} | ConvertTo-Json
Invoke-RestMethod "$baseUrl/api/auth/register" -Method Post -ContentType "application/json" -Body $registration

$login = @{ email = "you@example.com"; password = "Example-password-123!" } | ConvertTo-Json
$tokens = Invoke-RestMethod "$baseUrl/api/auth/login" -Method Post -ContentType "application/json" -Body $login
$headers = @{ Authorization = "Bearer $($tokens.accessToken)" }
Invoke-RestMethod "$baseUrl/api/auth/me" -Headers $headers
```

Registration creates a `User` account and returns its profile with status `201`. Log in separately to obtain tokens. Passwords must have 12–128 characters, uppercase and lowercase letters, a digit, a symbol, and at least four distinct characters. Public registration cannot assign administrator roles.

## Endpoints

Public:

- `POST /api/auth/register` — `{ "email", "password", "displayName" }`; creates a regular user.
- `POST /api/auth/login` — `{ "email", "password" }`; returns access/refresh tokens, expiration times, and the user's profile.
- `POST /api/auth/refresh` — `{ "refreshToken" }`; rotates the refresh token and issues a new access token.
- `GET /health` — process liveness.

Authenticated, using `Authorization: Bearer <accessToken>`:

- `GET /api/auth/me` — current profile and roles.
- `POST /api/auth/logout` — revokes the current session and both of its token types.
- `POST /api/auth/logout-all` — revokes every session for the current user.
- `POST /api/auth/change-password` — `{ "currentPassword", "newPassword" }`; changes the password and invalidates every existing session. Log in again afterward.

Administrator only:

- `GET /api/admin/users?page=1&pageSize=20` — paginated user profiles; maximum page size 100.
- `PUT /api/admin/users/{userId}/roles/{role}` — grants `User` or `Admin`. Role names are case sensitive; repeated assignments return `204`.

Invalid input returns `400` with Problem Details. Missing, invalid, expired, or revoked credentials return `401`; insufficient permissions return `403`; throttled requests return `429` with `Retry-After`.

## Create an administrator

There is no default administrator or default administrator password. To bootstrap a new administrator, set these user-secrets with a new email address and your own strong password, then restart the API:

```powershell
dotnet user-secrets set "BootstrapAdmin:Email" "admin@example.com" --project src/Auth.Api
dotnet user-secrets set "BootstrapAdmin:Password" "<your-strong-password>" --project src/Auth.Api
dotnet run --project src/Auth.Api
```

The bootstrap process refuses to promote an existing regular account. Once the administrator exists, stop the server and remove the bootstrap secrets:

```powershell
dotnet user-secrets remove "BootstrapAdmin:Email" --project src/Auth.Api
dotnet user-secrets remove "BootstrapAdmin:Password" --project src/Auth.Api
```

Log in as that administrator to grant roles to other accounts through the protected API. Bootstrap settings never reset an existing administrator's password.

## Authentication behavior

- Identity hashes and salts passwords using its built-in password hasher.
- JWT validation requires the configured issuer, audience, expiration, signature, and HS256 algorithm. Unsigned tokens are rejected.
- Access tokens last 15 minutes by default. Sessions last seven days with an absolute expiration; refreshing does not extend it.
- Refresh tokens contain 64 cryptographically random bytes. Only their SHA-256 hashes are stored. A transaction and conditional database update enforce single use.
- Reusing a consumed refresh token revokes its entire session, including the latest access and refresh tokens. Clients must serialize refresh requests and replace the stored refresh token after each successful refresh. Retrying an already consumed token also revokes the session.
- Every authenticated request checks the session, Identity security stamp, lockout state, and current roles in SQLite. Logout, password changes, and role changes take effect on the next request; this adds database reads to authenticated requests.
- Five failed passwords lock an account for 15 minutes. Authentication endpoints share a limit of ten requests per IP address per minute, per application process; configure `RateLimiting:AuthPermitLimit` to adjust it.
- Authorization is required by default. Only endpoints explicitly marked anonymous are public. No cookie authentication or cross-origin access is enabled.
- Authentication responses use `Cache-Control: no-store`. Passwords, signing keys, and raw tokens are not logged by application code.

This implementation supports accounts for a single application. It does not implement an OAuth/OIDC identity provider, external login, email verification, password recovery, or MFA. For federated or third-party clients, use a standards-based identity provider and configure its issuer/audience for JWT validation; see [Microsoft's JWT bearer guidance](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/configure-jwt-bearer-authentication?view=aspnetcore-10.0).

## Configuration and deployment

Configuration uses normal ASP.NET Core providers: JSON, Development user-secrets, and environment variables. Supply these environment variables through your deployment's secret/configuration store:

```text
ASPNETCORE_ENVIRONMENT=Production
Jwt__SigningKey=<random secret of at least 32 UTF-8 bytes>
Jwt__Issuer=<your issuer>
Jwt__Audience=<your API audience>
ConnectionStrings__Auth=Data Source=/absolute/persistent/path/auth.db
AllowedHosts=api.example.com
```

Terminate HTTPS at a correctly configured hosting layer or configure Kestrel with a certificate. If using a reverse proxy, explicitly configure trusted proxies/networks and forwarded headers before HTTPS redirection and rate limiting so requests use the correct scheme and client IP. Match the allowed host name to your deployment. The supplied launch profile is for local development.

SQLite files must be stored on a persistent writable volume. For multiple instances or higher write concurrency, adapt the EF provider and migrations to a shared database and use a distributed rate limiter. Periodically delete expired/revoked sessions according to your retention policy; refresh-token rows cascade on session deletion. Keep consumed refresh tokens until their session expires so replay detection continues to work.

Production does not apply schema migrations on startup. Apply the included migration before starting the API, using the same absolute database connection string:

```powershell
dotnet tool restore
$env:ConnectionStrings__Auth = "Data Source=C:\your\persistent\path\auth.db"
dotnet ef database update --project src/Auth.Api
```

Development applies migrations automatically. To add future schema changes:

```powershell
dotnet tool restore
dotnet ef migrations add YourChange --project src/Auth.Api --output-dir Data/Migrations
```

`Database:MigrateOnStartup=true` enables automatic migrations explicitly in other environments. The design-time factory supports EF commands without runtime signing or bootstrap secrets. Runtime startup still validates the signing key before database initialization.

## Verify

```powershell
dotnet test Auth.slnx
dotnet build Auth.slnx -c Release
```

Integration tests use the real HTTP pipeline, Identity, migrations, and isolated temporary SQLite databases. They cover registration validation, hashing, login, lockout, JWT validation, authorization, role assignment, refresh rotation and replay, concurrent refreshes, logout, password changes, expired sessions, throttling, OpenAPI visibility, and startup secret validation. Test-only credentials are confined to the test project.

## Structure

- `src/Auth.Api/Controllers` — public auth and protected admin endpoints.
- `src/Auth.Api/Security` — token issuance, rotation, session validation, and role policies.
- `src/Auth.Api/Data` — Identity model, SQLite context, migrations, and administrator bootstrap.
- `src/Auth.Api/Contracts` — validated request DTOs and response models.
- `tests/Auth.Api.Tests` — integration tests.

The Identity/role setup follows the [ASP.NET Core role authorization documentation](https://learn.microsoft.com/en-us/aspnet/core/security/authorization/roles?view=aspnetcore-10.0).
