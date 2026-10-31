using System.ComponentModel.DataAnnotations;

namespace Auth.Api.Contracts;

public sealed record RegisterRequest(
    [Required, EmailAddress, StringLength(254)] string Email,
    [Required, StringLength(128, MinimumLength = 12)] string Password,
    [Required, StringLength(100)] string DisplayName);

public sealed record LoginRequest(
    [Required, EmailAddress, StringLength(254)] string Email,
    [Required, StringLength(128)] string Password);

public sealed record RefreshRequest([Required, StringLength(128)] string RefreshToken);

public sealed record ChangePasswordRequest(
    [Required, StringLength(128)] string CurrentPassword,
    [Required, StringLength(128, MinimumLength = 12)] string NewPassword);

public sealed record UserResponse(string Id, string Email, string DisplayName, IList<string> Roles);

public sealed record UserPageResponse(List<UserResponse> Items, int Total, int Page, int PageSize);

public sealed record TokenResponse(
    string AccessToken,
    DateTimeOffset ExpiresAt,
    string RefreshToken,
    DateTimeOffset RefreshTokenExpiresAt,
    UserResponse User,
    string TokenType = "Bearer");
