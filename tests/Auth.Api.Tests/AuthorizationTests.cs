using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Auth.Api.Contracts;
using Microsoft.IdentityModel.Tokens;

namespace Auth.Api.Tests;

public sealed class AuthorizationTests
{
    [Fact]
    public async Task AnonymousGets401UserGets403AndAdminCanGrantRolesImmediately()
    {
        using var app = new TestApplication();
        using var client = app.Client();
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/auth/me")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/admin/users")).StatusCode);
        
        var registration = await client.PostAsJsonAsync("/api/auth/register", new
        {
            email = "user@example.test", password = TestApplication.Password, displayName = "Test",
            roles = new[] { "Admin" }
        });
        registration.EnsureSuccessStatusCode();
        var user = (await registration.Content.ReadFromJsonAsync<UserResponse>())!;
        var regularTokens = await TestApplication.LoginAsync(client);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", regularTokens.AccessToken);
        Assert.Equal(HttpStatusCode.Forbidden, (await client.GetAsync("/api/admin/users")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden,
            (await client.PutAsync($"/api/admin/users/{user.Id}/roles/Admin", null)).StatusCode);
        var admin = await TestApplication.LoginAsync(client, TestApplication.AdminEmail);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", admin.AccessToken);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/api/admin/users")).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent,
            (await client.PutAsync($"/api/admin/users/{user.Id}/roles/Admin", null)).StatusCode);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", regularTokens.AccessToken);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/api/admin/users")).StatusCode);
    }

    [Fact]
    public async Task AdminEndpointsValidateRolesUsersAndPagination()
    {
        using var app = new TestApplication();
        using var client = app.Client();
        var admin = await TestApplication.LoginAsync(client, TestApplication.AdminEmail);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", admin.AccessToken);
        Assert.Equal(HttpStatusCode.BadRequest,
            (await client.PutAsync($"/api/admin/users/{admin.User.Id}/roles/SuperUser", null)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound,
            (await client.PutAsync("/api/admin/users/missing/roles/Admin", null)).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await client.GetAsync("/api/admin/users?page=0")).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await client.GetAsync("/api/admin/users?pageSize=101")).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent,
            (await client.PutAsync($"/api/admin/users/{admin.User.Id}/roles/Admin", null)).StatusCode);
    }

    [Theory]
    [InlineData("issuer")]
    [InlineData("audience")]
    [InlineData("signature")]
    [InlineData("expired")]
    [InlineData("unsigned")]
    public async Task JwtValidationRejectsInvalidTokens(string invalidPart)
    {
        using var app = new TestApplication();
        using var client = app.Client();
        await TestApplication.RegisterAsync(client);
        var tokens = await TestApplication.LoginAsync(client);
        var original = new JwtSecurityTokenHandler().ReadJwtToken(tokens.AccessToken);
        var signingKey = invalidPart == "signature" ? new string('x', 48) : TestApplication.SigningKey;
        var jwt = new JwtSecurityToken(
            invalidPart == "issuer" ? "wrong" : "Auth.Api",
            invalidPart == "audience" ? "wrong" : "Auth.Api.Client",
            original.Claims.Where(x => x.Type is "sub" or "sid" or "email" or "role"),
            DateTime.UtcNow.AddMinutes(-30),
            invalidPart == "expired" ? DateTime.UtcNow.AddMinutes(-1) : DateTime.UtcNow.AddMinutes(5),
            invalidPart == "unsigned" ? null : new SigningCredentials(
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signingKey)), SecurityAlgorithms.HmacSha256));
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer",
            new JwtSecurityTokenHandler().WriteToken(jwt));
        var response = await client.GetAsync("/api/auth/me");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains(response.Headers.WwwAuthenticate, x => x.Scheme == "Bearer");
    }

    [Fact]
    public async Task LoginRateLimitReturns429AndRetryAfter()
    {
        using var app = new TestApplication(permitLimit: 2);
        using var client = app.Client();
        for (var i = 0; i < 2; i++)
            await client.PostAsJsonAsync("/api/auth/login", new LoginRequest("unknown@example.test", TestApplication.Password));
        var response = await client.PostAsJsonAsync("/api/auth/login",
            new LoginRequest("unknown@example.test", TestApplication.Password));
        Assert.Equal(HttpStatusCode.TooManyRequests, response.StatusCode);
        Assert.NotNull(response.Headers.RetryAfter);
    }

    [Fact]
    public async Task HealthIsPublicAndOpenApiIsDevelopmentOnly()
    {
        using var app = new TestApplication();
        using var client = app.Client();
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/health")).StatusCode);
        Assert.NotEqual(HttpStatusCode.OK, (await client.GetAsync("/openapi/v1.json")).StatusCode);
        Assert.NotEqual(HttpStatusCode.OK, (await client.GetAsync("/swagger/index.html")).StatusCode);
        Assert.NotEqual(HttpStatusCode.OK, (await client.GetAsync("/swagger/v1/swagger.json")).StatusCode);
        using var development = new TestApplication(development: true);
        using var devClient = development.Client();
        var schema = await devClient.GetAsync("/openapi/v1.json");
        schema.EnsureSuccessStatusCode();
        Assert.Contains("Bearer", await schema.Content.ReadAsStringAsync());
    }

    [Theory]
    [InlineData(null)]
    [InlineData("short-key")]
    public void MissingOrWeakSigningKeyFailsStartup(string? key)
    {
        using var app = new TestApplication(signingKey: key);
        Assert.Throws<Microsoft.Extensions.Options.OptionsValidationException>(() => app.Client());
    }
}
