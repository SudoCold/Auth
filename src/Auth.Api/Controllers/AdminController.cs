using Auth.Api.Contracts;
using Auth.Api.Data;
using Auth.Api.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace Auth.Api.Controllers;

[ApiController]
[Route("api/admin")]
[Authorize(Policy = Roles.AdminPolicy)]
public sealed class AdminController(UserManager<ApplicationUser> users) : ControllerBase
{
    [HttpGet("users")]
    [ProducesResponseType<UserPageResponse>(StatusCodes.Status200OK)]
    public async Task<IActionResult> ListUsers([FromQuery] int page = 1, [FromQuery] int pageSize = 20,
        CancellationToken ct = default)
    {
        if (page < 1 || page > 1_000_000 || pageSize is < 1 or > 100)
            return Problem(statusCode: 400, detail: "Page must be between 1 and 1000000; pageSize between 1 and 100.");
        var total = await users.Users.CountAsync(ct);
        var pageUsers = await users.Users.OrderBy(x => x.Id).Skip((page - 1) * pageSize).Take(pageSize).ToListAsync(ct);
        var items = new List<UserResponse>();
        foreach (var user in pageUsers)
            items.Add(new(user.Id, user.Email!, user.DisplayName, await users.GetRolesAsync(user)));
        return Ok(new UserPageResponse(items, total, page, pageSize));
    }

    [HttpPut("users/{userId}/roles/{role}")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> AddRole(string userId, string role)
    {
        if (!Roles.All.Contains(role, StringComparer.Ordinal))
            return Problem(statusCode: 400, detail: "Supported roles are User and Admin (case sensitive).");
        var user = await users.FindByIdAsync(userId);
        if (user is null) return NotFound();
        if (await users.IsInRoleAsync(user, role)) return NoContent();
        var result = await users.AddToRoleAsync(user, role);
        return result.Succeeded ? NoContent() : Problem(statusCode: 409, detail: "The role could not be assigned. Retry the request.");
    }
}
