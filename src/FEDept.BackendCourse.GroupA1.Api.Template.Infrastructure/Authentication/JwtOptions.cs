namespace FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Authentication;

public sealed class JwtOptions
{
    public string AccessSecret { get; set; } = string.Empty;

    public string RefreshSecret { get; set; } = string.Empty;

    public string Issuer { get; set; } = string.Empty;

    public string Audience { get; set; } = string.Empty;
}
