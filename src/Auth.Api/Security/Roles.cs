namespace Auth.Api.Security;

public static class Roles
{
    public const string User = "User";
    public const string Admin = "Admin";
    public const string AdminPolicy = "AdministratorsOnly";
    public static readonly string[] All = [User, Admin];
}
