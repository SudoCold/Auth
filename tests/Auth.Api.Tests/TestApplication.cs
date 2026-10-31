using Auth.Api.Contracts;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;

namespace Auth.Api.Tests;

public sealed class TestApplication(int permitLimit = 1000, bool development = false,
    string? signingKey = TestApplication.SigningKey) : WebApplicationFactory<Program>
{
    public const string SigningKey = "integration-test-key-only-32-bytes-minimum-8e93a104";
    public const string Password = "Test-password-123!";
    public const string AdminEmail = "admin@example.test";
    private readonly string databasePath = Path.Combine(Path.GetTempPath(), $"auth-tests-{Guid.NewGuid():N}.db");

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment(development ? "Development" : "Testing");
        builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(
            new Dictionary<string, string?>
            {
                ["ConnectionStrings:Auth"] = $"Data Source={databasePath};Pooling=False",
                ["Database:MigrateOnStartup"] = "true",
                ["Jwt:SigningKey"] = signingKey,
                ["Jwt:Issuer"] = "Auth.Api",
                ["Jwt:Audience"] = "Auth.Api.Client",
                ["BootstrapAdmin:Email"] = AdminEmail,
                ["BootstrapAdmin:Password"] = Password,
                ["RateLimiting:AuthPermitLimit"] = permitLimit.ToString(),
                ["Logging:LogLevel:Default"] = "Warning"
            }));
    }

    public HttpClient Client() => CreateClient(new WebApplicationFactoryClientOptions
    {
        BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false
    });

    public static async Task<UserResponse> RegisterAsync(HttpClient client, string email = "user@example.test")
    {
        using var response = await client.PostAsJsonAsync("/api/auth/register",
            new RegisterRequest(email, Password, "Test User"));
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<UserResponse>())!;
    }

    public static async Task<TokenResponse> LoginAsync(HttpClient client, string email = "user@example.test",
        string password = Password)
    {
        using var response = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest(email, password));
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<TokenResponse>())!;
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (disposing)
            foreach (var suffix in new[] { "", "-shm", "-wal" }) File.Delete(databasePath + suffix);
    }
}
