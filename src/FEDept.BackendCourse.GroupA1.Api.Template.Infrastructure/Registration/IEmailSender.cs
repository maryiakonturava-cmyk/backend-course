using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Authentication;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Registration;

public interface IEmailSender
{
    Task SendOtpAsync(string email, string code, CancellationToken ct);

    Task SendMagicLinkAsync(string email, string link, CancellationToken ct);
}

public sealed class NullEmailSender : IEmailSender, ILoginEmailSender
{
    public Task SendOtpAsync(string email, string code, CancellationToken ct) => Task.CompletedTask;

    public Task SendMagicLinkAsync(string email, string link, CancellationToken ct) => Task.CompletedTask;

    public Task SendLoginOtpAsync(string email, string code, CancellationToken ct) => Task.CompletedTask;

    public Task SendLoginMagicLinkAsync(string email, string link, CancellationToken ct) => Task.CompletedTask;
}
