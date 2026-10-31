namespace Auth.Api.Data;

public sealed class AuthSession
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string UserId { get; set; } = "";
    public ApplicationUser User { get; set; } = null!;
    public string SecurityStamp { get; set; } = "";
    public long ExpiresAt { get; set; }
    public long? RevokedAt { get; set; }
}

public sealed class RefreshToken
{
    public int Id { get; set; }
    public string Hash { get; set; } = "";
    public Guid SessionId { get; set; }
    public AuthSession Session { get; set; } = null!;
    public long? ConsumedAt { get; set; }
}
