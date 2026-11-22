namespace FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Registration;

public sealed class SmtpOptions
{
    public string Host { get; set; } = string.Empty;

    public int Port { get; set; }

    public string From { get; set; } = string.Empty;
}
