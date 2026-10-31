using System.Text;
using System.Threading.RateLimiting;
using Auth.Api.Configuration;
using Auth.Api.Data;
using Auth.Api.OpenApi;
using Auth.Api.Security;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddProblemDetails();
builder.Services.AddControllers();
builder.Services.AddOptions<JwtOptions>().BindConfiguration(JwtOptions.SectionName)
    .ValidateDataAnnotations()
    .Validate(x => x.HasStrongKey(), "Jwt:SigningKey must contain at least 32 UTF-8 bytes. Supply a random key through user-secrets or environment variables.")
    .ValidateOnStart();
builder.Services.AddDbContext<AuthDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("Auth")
        ?? throw new InvalidOperationException("ConnectionStrings:Auth is required.")));
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddIdentityCore<ApplicationUser>(options =>
    {
        options.User.RequireUniqueEmail = true;
        options.Password.RequiredLength = 12;
        options.Password.RequiredUniqueChars = 4;
        options.Lockout.MaxFailedAccessAttempts = 5;
        options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
        options.ClaimsIdentity.UserIdClaimType = "sub";
        options.ClaimsIdentity.UserNameClaimType = "email";
        options.ClaimsIdentity.RoleClaimType = "role";
    })
    .AddRoles<IdentityRole>()
    .AddEntityFrameworkStores<AuthDbContext>()
    .AddSignInManager();
builder.Services.AddScoped<TokenService>();
builder.Services.AddScoped<SessionValidationEvents>();
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer();
builder.Services.AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme)
    .Configure<IOptions<JwtOptions>>((options, configured) =>
    {
        var jwt = configured.Value;
        options.MapInboundClaims = false;
        options.IncludeErrorDetails = false;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true, ValidIssuer = jwt.Issuer,
            ValidateAudience = true, ValidAudience = jwt.Audience,
            ValidateLifetime = true, RequireExpirationTime = true,
            ValidateIssuerSigningKey = true, RequireSignedTokens = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwt.SigningKey)),
            ValidAlgorithms = [SecurityAlgorithms.HmacSha256],
            ClockSkew = TimeSpan.Zero,
            NameClaimType = "email", RoleClaimType = "role"
        };
        options.EventsType = typeof(SessionValidationEvents);
    });
builder.Services.AddAuthorization(options =>
{
    options.FallbackPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build();
    options.AddPolicy(Roles.AdminPolicy, policy => policy.RequireRole(Roles.Admin));
});
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.AddPolicy("auth", context => RateLimitPartition.GetFixedWindowLimiter(
        context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
        _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = builder.Configuration.GetValue("RateLimiting:AuthPermitLimit", 10),
            Window = TimeSpan.FromMinutes(1), QueueLimit = 0, AutoReplenishment = true
        }));
    options.OnRejected = async (context, ct) =>
    {
        context.HttpContext.Response.Headers.RetryAfter = "60";
        await Results.Problem(statusCode: 429, title: "Too many requests.",
            detail: "Wait before trying again.").ExecuteAsync(context.HttpContext);
    };
});
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "Authentication & Authorization API",
        Version = "v1",
        Description = "Register a user, then log in to obtain an accessToken. Click Authorize and paste " +
            "only the accessToken value to try protected endpoints. Admin endpoints require the Admin role. " +
            "Passwords require 12–128 characters including uppercase, lowercase, a digit, and a symbol."
    });
    options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Type = SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT",
        Description = "Paste the accessToken from POST /api/auth/login. Swagger adds the Bearer prefix automatically."
    });
    options.OperationFilter<BearerSecurityOperationFilter>();
});

var app = builder.Build();
_ = app.Services.GetRequiredService<IOptions<JwtOptions>>().Value;
app.UseExceptionHandler();
app.UseStatusCodePages();
if (!app.Environment.IsDevelopment()) app.UseHsts();
app.UseHttpsRedirection();
if (app.Environment.IsDevelopment())
{
    app.UseSwaggerUI(options =>
    {
        options.SwaggerEndpoint("v1/swagger.json", "Auth API v1");
        options.DocumentTitle = "Auth API — Swagger UI";
    });
}
app.UseRouting();
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();
if (app.Environment.IsDevelopment())
{
    app.MapSwagger().AllowAnonymous();
    app.MapSwagger("/openapi/{documentName}.json").AllowAnonymous();
    app.MapGet("/", () => Results.Redirect("swagger/index.html"))
        .AllowAnonymous().ExcludeFromDescription();
}
app.MapControllers();
app.MapGet("/health", () => Results.Ok(new { status = "healthy" })).AllowAnonymous();
await DatabaseInitializer.InitializeAsync(app.Services, app.Configuration);
app.Run();

public partial class Program;
