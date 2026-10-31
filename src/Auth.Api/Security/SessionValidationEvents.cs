using System.Security.Claims;
using Auth.Api.Data;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace Auth.Api.Security;

public sealed class SessionValidationEvents(
    AuthDbContext db,
    UserManager<ApplicationUser> users,
    TimeProvider clock) : JwtBearerEvents
{
    public override async Task TokenValidated(TokenValidatedContext context)
    {
        var principal = context.Principal!;
        if (!Guid.TryParse(principal.FindFirstValue("sid"), out var sessionId))
        {
            context.Fail("Invalid session.");
            return;
        }

        var session = await db.Sessions.AsNoTracking().Include(x => x.User)
            .SingleOrDefaultAsync(x => x.Id == sessionId, context.HttpContext.RequestAborted);
        if (session is null || session.UserId != principal.FindFirstValue("sub") ||
            session.RevokedAt is not null || session.ExpiresAt <= clock.GetUtcNow().ToUnixTimeSeconds() ||
            session.SecurityStamp != session.User.SecurityStamp || await users.IsLockedOutAsync(session.User))
        {
            context.Fail("Session expired or revoked.");
            return;
        }


        var identity = (ClaimsIdentity)principal.Identity!;
        foreach (var claim in identity.FindAll("role").ToArray()) identity.RemoveClaim(claim);
        identity.AddClaims((await users.GetRolesAsync(session.User)).Select(role => new Claim("role", role)));
    }
}
