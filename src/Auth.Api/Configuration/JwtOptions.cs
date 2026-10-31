using System.ComponentModel.DataAnnotations;
using System.Text;

namespace Auth.Api.Configuration;

public sealed class JwtOptions
{
    public const string SectionName = "Jwt";

    [Required] public string Issuer { get; init; } = "";
    [Required] public string Audience { get; init; } = "";
    [Required] public string SigningKey { get; init; } = "";
    [Range(1, 60)] public int AccessTokenMinutes { get; init; } = 15;
    [Range(1, 30)] public int SessionDays { get; init; } = 7;

    public bool HasStrongKey() => !string.IsNullOrWhiteSpace(SigningKey) && Encoding.UTF8.GetByteCount(SigningKey) >= 32;
}
