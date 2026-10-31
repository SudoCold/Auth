using System.Security.Claims;
using Auth.Api.Contracts;
using Auth.Api.Data;
using Auth.Api.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;

namespace Auth.Api.Controllers;

[ApiController]
[Route("api/auth")]
[ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
public sealed class AuthController(
    UserManager<ApplicationUser> users,
    SignInManager<ApplicationUser> signIn,
    AuthDbContext db,
    TokenService tokens,
    TimeProvider clock) : ControllerBase
{
    [HttpPost("register")]
    [ProducesResponseType<UserResponse>(StatusCodes.Status201Created)]
    [AllowAnonymous]
    [EnableRateLimiting("auth")]
    public async Task<IActionResult> Register(RegisterRequest request, CancellationToken ct)
    {
        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        var user = new ApplicationUser
        {
            UserName = request.Email.Trim(), Email = request.Email.Trim(),
            DisplayName = request.DisplayName.Trim()
        };
        if (user.DisplayName.Length == 0)
            return ValidationProblem(new ValidationProblemDetails(
                new Dictionary<string, string[]> { ["displayName"] = ["Display name is required."] }));
        var result = await users.CreateAsync(user, request.Password);
        if (!result.Succeeded) return IdentityErrors(result);
        result = await users.AddToRoleAsync(user, Roles.User);
        if (!result.Succeeded) return IdentityErrors(result);
        await transaction.CommitAsync(ct);
        return Created("/api/auth/me", await ProfileAsync(user));
    }

    [HttpPost("login")]
    [ProducesResponseType<TokenResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [AllowAnonymous]
    [EnableRateLimiting("auth")]
    public async Task<IActionResult> Login(LoginRequest request, CancellationToken ct)
    {
        var user = await users.FindByEmailAsync(request.Email.Trim());
        if (user is null) return Challenge();
        var result = await signIn.CheckPasswordSignInAsync(user, request.Password, lockoutOnFailure: true);
        if (!result.Succeeded) return Challenge();
        return Ok(await tokens.CreateSessionAsync(user, ct));
    }

    [HttpPost("refresh")]
    [ProducesResponseType<TokenResponse>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [AllowAnonymous]
    [EnableRateLimiting("auth")]
    public async Task<IActionResult> Refresh(RefreshRequest request, CancellationToken ct)
    {
        var response = await tokens.RefreshAsync(request.RefreshToken, ct);
        return response is null ? Challenge() : Ok(response);
    }

    [HttpGet("me")]
    public async Task<ActionResult<UserResponse>> Me() =>
        Ok(await ProfileAsync((await users.GetUserAsync(User))!));

    [HttpPost("logout")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> Logout(CancellationToken ct)
    {
        var id = Guid.Parse(User.FindFirstValue("sid")!);
        var now = clock.GetUtcNow().ToUnixTimeSeconds();
        await db.Sessions.Where(x => x.Id == id && x.RevokedAt == null)
            .ExecuteUpdateAsync(update => update.SetProperty(x => x.RevokedAt, now), ct);
        return NoContent();
    }

    [HttpPost("logout-all")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> LogoutAll(CancellationToken ct)
    {
        var userId = User.FindFirstValue("sub")!;
        var now = clock.GetUtcNow().ToUnixTimeSeconds();
        await db.Sessions.Where(x => x.UserId == userId && x.RevokedAt == null)
            .ExecuteUpdateAsync(update => update.SetProperty(x => x.RevokedAt, now), ct);
        return NoContent();
    }

    [HttpPost("change-password")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [EnableRateLimiting("auth")]
    public async Task<IActionResult> ChangePassword(ChangePasswordRequest request)
    {
        var user = (await users.GetUserAsync(User))!;
        var result = await users.ChangePasswordAsync(user, request.CurrentPassword, request.NewPassword);
        return result.Succeeded ? NoContent() : IdentityErrors(result);
    }

    private async Task<UserResponse> ProfileAsync(ApplicationUser user) =>
        new(user.Id, user.Email!, user.DisplayName, await users.GetRolesAsync(user));

    private ActionResult IdentityErrors(IdentityResult result) => ValidationProblem(new ValidationProblemDetails(
        result.Errors.GroupBy(x => x.Code).ToDictionary(g => g.Key, g => g.Select(x => x.Description).ToArray())));
}
