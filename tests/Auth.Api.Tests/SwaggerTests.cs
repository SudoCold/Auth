using System.Net;
using System.Text.Json;

namespace Auth.Api.Tests;

public sealed class SwaggerTests
{
    [Fact]
    public async Task DevelopmentRootRedirectsToPublicSwaggerUiWithLocallyServedAssets()
    {
        using var app = new TestApplication(development: true);
        using var client = app.Client();
        var root = await client.GetAsync("/");
        Assert.Equal(HttpStatusCode.Redirect, root.StatusCode);
        Assert.Equal("swagger/index.html", root.Headers.Location!.ToString());

        var ui = await client.GetAsync("/swagger/index.html");
        ui.EnsureSuccessStatusCode();
        Assert.Equal("text/html", ui.Content.Headers.ContentType!.MediaType);
        Assert.Contains("swagger-ui-bundle.js", await ui.Content.ReadAsStringAsync());
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/swagger/swagger-ui-bundle.js")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/swagger/swagger-ui.css")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/auth/me")).StatusCode);
    }

    [Fact]
    public async Task SwaggerSchemaDescribesBearerAuthenticationOnlyForProtectedEndpoints()
    {
        using var app = new TestApplication(development: true);
        using var client = app.Client();
        using var schema = JsonDocument.Parse(await client.GetStringAsync("/swagger/v1/swagger.json"));
        var document = schema.RootElement;
        var scheme = document.GetProperty("components").GetProperty("securitySchemes").GetProperty("Bearer");
        Assert.Equal("http", scheme.GetProperty("type").GetString());
        Assert.Equal("bearer", scheme.GetProperty("scheme").GetString());

        var paths = document.GetProperty("paths");
        foreach (var route in new[] { "/api/auth/register", "/api/auth/login", "/api/auth/refresh" })
        {
            var operation = paths.GetProperty(route).GetProperty("post");
            Assert.False(operation.TryGetProperty("security", out var security) && security.GetArrayLength() > 0);
        }
        Assert.False(paths.GetProperty("/health").GetProperty("get").TryGetProperty("security", out _));
        foreach (var route in new[] { "/api/auth/me", "/api/admin/users" })
        {
            var operation = paths.GetProperty(route).GetProperty("get");
            Assert.Equal(0, operation.GetProperty("security")[0].GetProperty("Bearer").GetArrayLength());
            Assert.True(operation.GetProperty("responses").TryGetProperty("401", out _));
            Assert.True(operation.GetProperty("responses").TryGetProperty("403", out _));
        }
        Assert.True(document.GetProperty("components").GetProperty("schemas").TryGetProperty("TokenResponse", out _));
        using var legacy = JsonDocument.Parse(await client.GetStringAsync("/openapi/v1.json"));
        Assert.Equal(document.GetProperty("info").GetProperty("title").GetString(),
            legacy.RootElement.GetProperty("info").GetProperty("title").GetString());
    }
}
