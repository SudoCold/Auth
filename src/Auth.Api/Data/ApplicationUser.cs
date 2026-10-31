using Microsoft.AspNetCore.Identity;

namespace Auth.Api.Data;

public sealed class ApplicationUser : IdentityUser
{
    public string DisplayName { get; set; } = "";
}
