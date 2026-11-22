namespace FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Registration;

public interface IEmailSender
{
    Task SendOtpAsync(string email, string code, CancellationToken ct);
}

public sealed class NullEmailSender : IEmailSender
{
    public Task SendOtpAsync(string email, string code, CancellationToken ct) => Task.CompletedTask;
}
