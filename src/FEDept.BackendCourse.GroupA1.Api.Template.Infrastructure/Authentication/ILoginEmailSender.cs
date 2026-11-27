namespace FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Authentication;

public interface ILoginEmailSender
{
    Task SendLoginOtpAsync(string email, string code, CancellationToken ct);

    Task SendLoginMagicLinkAsync(string email, string link, CancellationToken ct);
}
