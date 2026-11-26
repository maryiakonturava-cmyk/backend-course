using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.Extensions.Options;
using MimeKit;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Registration;

public sealed class SmtpEmailSender(IOptions<SmtpOptions> options) : IEmailSender
{
    public Task SendOtpAsync(string email, string code, CancellationToken ct) =>
        SendAsync(email, "Registration verification code", $"Your verification code is {code}.", ct);

    public Task SendMagicLinkAsync(string email, string link, CancellationToken ct) =>
        SendAsync(email, "Confirm your registration", $"Open this link to confirm your registration: {link}", ct);

    private async Task SendAsync(string email, string subject, string text, CancellationToken ct)
    {
        var message = new MimeMessage
        {
            Subject = subject,
            Body = new TextPart("plain") { Text = text }
        };
        message.From.Add(MailboxAddress.Parse(options.Value.From));
        message.To.Add(MailboxAddress.Parse(email));

        using var client = new SmtpClient();
        await client.ConnectAsync(options.Value.Host, options.Value.Port, SecureSocketOptions.Auto, ct);
        await client.SendAsync(FormatOptions.Default, new SmtpSendRequest(message), ct);
        await client.DisconnectAsync(true, ct);
    }
}
