using System.Net;
using System.Net.Http.Headers;
using Auth.Api.Contracts;
using Auth.Api.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Auth.Api.Tests;

public sealed class AuthFlowTests
{
    [Fact]
    public async Task RegisterLoginAndProfileUsePersistedIdentityAndHashedSecrets()
    {
        using var app = new TestApplication();
        using var client = app.Client();
        var user = await TestApplication.RegisterAsync(client);
        Assert.Equal(["User"], user.Roles);
        var tokens = await TestApplication.LoginAsync(client);
        Assert.Equal("Bearer", tokens.TokenType);
        Assert.True(tokens.ExpiresAt > DateTimeOffset.UtcNow);
        Assert.True(tokens.RefreshTokenExpiresAt > tokens.ExpiresAt);
        Assert.Contains("no-store", (await client.PostAsJsonAsync("/api/auth/login",
            new LoginRequest(user.Email, TestApplication.Password))).Headers.CacheControl!.ToString());
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens.AccessToken);
        var profile = await client.GetFromJsonAsync<UserResponse>("/api/auth/me");
        Assert.Equal(user.Id, profile!.Id);
        using var scope = app.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        var stored = await db.Users.SingleAsync(x => x.Id == user.Id);
        Assert.NotEqual(TestApplication.Password, stored.PasswordHash);
        var refresh = await db.RefreshTokens.FirstAsync(x => x.Session.UserId == user.Id);
        Assert.Equal(64, refresh.Hash.Length);
        Assert.NotEqual(tokens.RefreshToken, refresh.Hash);
    }

    [Theory]
    [InlineData("invalid-email", TestApplication.Password, "Name")]
    [InlineData("person@example.test", "short", "Name")]
    [InlineData("person@example.test", "onlylowercaseletters", "Name")]
    [InlineData("person@example.test", TestApplication.Password, "   ")]
    public async Task RegistrationRejectsInvalidInput(string email, string password, string name)
    {
        using var app = new TestApplication();
        using var client = app.Client();
        var response = await client.PostAsJsonAsync("/api/auth/register", new RegisterRequest(email, password, name));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType!.MediaType);
    }

    [Fact]
    public async Task DuplicateEmailIsRejectedIgnoringCase()
    {
        using var app = new TestApplication();
        using var client = app.Client();
        await TestApplication.RegisterAsync(client);
        var response = await client.PostAsJsonAsync("/api/auth/register",
            new RegisterRequest("USER@example.test", TestApplication.Password, "Duplicate"));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task WrongAndUnknownCredentialsReturnUnauthorizedAndFiveFailuresLockTheAccount()
    {
        using var app = new TestApplication();
        using var client = app.Client();
        await TestApplication.RegisterAsync(client);
        var unknown = await client.PostAsJsonAsync("/api/auth/login",
            new LoginRequest("unknown@example.test", TestApplication.Password));
        Assert.Equal(HttpStatusCode.Unauthorized, unknown.StatusCode);
        for (var i = 0; i < 5; i++)
        {
            var wrong = await client.PostAsJsonAsync("/api/auth/login",
                new LoginRequest("user@example.test", "Wrong-password-123!"));
            Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
        }
        var locked = await client.PostAsJsonAsync("/api/auth/login",
            new LoginRequest("user@example.test", TestApplication.Password));
        Assert.Equal(HttpStatusCode.Unauthorized, locked.StatusCode);
    }

    [Fact]
    public async Task RefreshRotatesAndReplayRevokesTheSession()
    {
        using var app = new TestApplication();
        using var client = app.Client();
        await TestApplication.RegisterAsync(client);
        var first = await TestApplication.LoginAsync(client);
        var rotated = await client.PostAsJsonAsync("/api/auth/refresh", new RefreshRequest(first.RefreshToken));
        rotated.EnsureSuccessStatusCode();
        var second = (await rotated.Content.ReadFromJsonAsync<TokenResponse>())!;
        Assert.NotEqual(first.RefreshToken, second.RefreshToken);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", second.AccessToken);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/api/auth/me")).StatusCode);
        var replay = await client.PostAsJsonAsync("/api/auth/refresh", new RefreshRequest(first.RefreshToken));
        Assert.Equal(HttpStatusCode.Unauthorized, replay.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/auth/me")).StatusCode);
        var newRefresh = await client.PostAsJsonAsync("/api/auth/refresh", new RefreshRequest(second.RefreshToken));
        Assert.Equal(HttpStatusCode.Unauthorized, newRefresh.StatusCode);
    }

    [Fact]
    public async Task ConcurrentRefreshHasOnlyOneSuccessfulRotation()
    {
        using var app = new TestApplication();
        using var client = app.Client();
        await TestApplication.RegisterAsync(client);
        var tokens = await TestApplication.LoginAsync(client);
        var responses = await Task.WhenAll(Enumerable.Range(0, 2).Select(_ =>
            client.PostAsJsonAsync("/api/auth/refresh", new RefreshRequest(tokens.RefreshToken))));
        Assert.Single(responses, x => x.StatusCode == HttpStatusCode.OK);
        Assert.Single(responses, x => x.StatusCode == HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task LogoutRevokesOnlyCurrentSessionAndLogoutAllRevokesOtherSessions()
    {
        using var app = new TestApplication();
        using var client = app.Client();
        await TestApplication.RegisterAsync(client);
        var first = await TestApplication.LoginAsync(client);
        var second = await TestApplication.LoginAsync(client);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", first.AccessToken);
        Assert.Equal(HttpStatusCode.NoContent, (await client.PostAsync("/api/auth/logout", null)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/auth/me")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.PostAsJsonAsync("/api/auth/refresh",
            new RefreshRequest(first.RefreshToken))).StatusCode);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", second.AccessToken);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/api/auth/me")).StatusCode);
        var third = await TestApplication.LoginAsync(client);
        Assert.Equal(HttpStatusCode.NoContent, (await client.PostAsync("/api/auth/logout-all", null)).StatusCode);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", third.AccessToken);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/auth/me")).StatusCode);
    }

    [Fact]
    public async Task PasswordChangeInvalidatesEverySessionAndOldPassword()
    {
        using var app = new TestApplication();
        using var client = app.Client();
        await TestApplication.RegisterAsync(client);
        var tokens = await TestApplication.LoginAsync(client);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens.AccessToken);
        var wrong = await client.PostAsJsonAsync("/api/auth/change-password",
            new ChangePasswordRequest("Wrong-password-123!", "New-password-456!"));
        Assert.Equal(HttpStatusCode.BadRequest, wrong.StatusCode);
        var changed = await client.PostAsJsonAsync("/api/auth/change-password",
            new ChangePasswordRequest(TestApplication.Password, "New-password-456!"));
        Assert.Equal(HttpStatusCode.NoContent, changed.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/auth/me")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.PostAsJsonAsync("/api/auth/refresh",
            new RefreshRequest(tokens.RefreshToken))).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.PostAsJsonAsync("/api/auth/login",
            new LoginRequest("user@example.test", TestApplication.Password))).StatusCode);
        await TestApplication.LoginAsync(client, password: "New-password-456!");
    }

    [Fact]
    public async Task ExpiredSessionsRejectBothAccessAndRefreshTokens()
    {
        using var app = new TestApplication();
        using var client = app.Client();
        var user = await TestApplication.RegisterAsync(client);
        var tokens = await TestApplication.LoginAsync(client);
        using (var scope = app.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
            await db.Sessions.Where(x => x.UserId == user.Id).ExecuteUpdateAsync(update =>
                update.SetProperty(x => x.ExpiresAt, DateTimeOffset.UtcNow.AddDays(-1).ToUnixTimeSeconds()));
        }
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens.AccessToken);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/auth/me")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.PostAsJsonAsync("/api/auth/refresh",
            new RefreshRequest(tokens.RefreshToken))).StatusCode);
    }
}
