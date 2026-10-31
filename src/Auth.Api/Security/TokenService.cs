using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Auth.Api.Configuration;
using Auth.Api.Contracts;
using Auth.Api.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Auth.Api.Security;

public sealed class TokenService(
    AuthDbContext db,
    UserManager<ApplicationUser> users,
    IOptions<JwtOptions> options,
    TimeProvider clock)
{
    private readonly JwtOptions settings = options.Value;

    public async Task<TokenResponse> CreateSessionAsync(ApplicationUser user, CancellationToken ct)
    {
        var session = new AuthSession
        {
            UserId = user.Id,
            SecurityStamp = user.SecurityStamp!,
            ExpiresAt = clock.GetUtcNow().AddDays(settings.SessionDays).ToUnixTimeSeconds()
        };
        db.Sessions.Add(session);
        var response = await IssueAsync(user, session);
        await db.SaveChangesAsync(ct);
        return response;
    }

    public async Task<TokenResponse?> RefreshAsync(string rawToken, CancellationToken ct)
    {
        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        var hash = Hash(rawToken);
        var token = await db.RefreshTokens.Include(x => x.Session).ThenInclude(x => x.User)
            .SingleOrDefaultAsync(x => x.Hash == hash, ct);
        if (token is null) return null;

        var session = token.Session;
        var user = session.User;
        var now = clock.GetUtcNow().ToUnixTimeSeconds();
        if (session.RevokedAt is not null || session.ExpiresAt <= now ||
            session.SecurityStamp != user.SecurityStamp || await users.IsLockedOutAsync(user))
            return null;

        if (token.ConsumedAt is not null)
        {
            session.RevokedAt = now;
            await db.SaveChangesAsync(ct);
            await transaction.CommitAsync(ct);
            return null;
        }

        var consumed = await db.RefreshTokens.Where(x => x.Id == token.Id && x.ConsumedAt == null)
            .ExecuteUpdateAsync(update => update.SetProperty(x => x.ConsumedAt, now), ct);
        if (consumed != 1) return null;

        var response = await IssueAsync(user, session);
        await db.SaveChangesAsync(ct);
        await transaction.CommitAsync(ct);
        return response;
    }

    private async Task<TokenResponse> IssueAsync(ApplicationUser user, AuthSession session)
    {
        var now = clock.GetUtcNow();
        var expiry = now.AddMinutes(settings.AccessTokenMinutes);
        var sessionExpiry = DateTimeOffset.FromUnixTimeSeconds(session.ExpiresAt);
        if (expiry > sessionExpiry) expiry = sessionExpiry;
        var roles = await users.GetRolesAsync(user);
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new(JwtRegisteredClaimNames.Email, user.Email!),
            new("sid", session.Id.ToString())
        };
        claims.AddRange(roles.Select(role => new Claim("role", role)));
        var jwt = new JwtSecurityToken(settings.Issuer, settings.Audience, claims,
            now.UtcDateTime, expiry.UtcDateTime,
            new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(settings.SigningKey)),
                SecurityAlgorithms.HmacSha256));
        var rawRefresh = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(64));
        db.RefreshTokens.Add(new RefreshToken { Hash = Hash(rawRefresh), SessionId = session.Id });
        return new TokenResponse(new JwtSecurityTokenHandler().WriteToken(jwt), expiry, rawRefresh,
            sessionExpiry, new UserResponse(user.Id, user.Email!, user.DisplayName, roles));
    }

    private static string Hash(string rawToken) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(rawToken)));
}
