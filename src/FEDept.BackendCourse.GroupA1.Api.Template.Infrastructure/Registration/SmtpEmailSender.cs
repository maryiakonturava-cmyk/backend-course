using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.Extensions.Options;
using MimeKit;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Registration;

public sealed class SmtpEmailSender(IOptions<SmtpOptions> options) : IEmailSender
{
    public async Task SendOtpAsync(string email, string code, CancellationToken ct)
    {
        var message = new MimeMessage
        {
            Subject = "Registration verification code",
            Body = new TextPart("plain") { Text = $"Your verification code is {code}." }
        };
        message.From.Add(MailboxAddress.Parse(options.Value.From));
        message.To.Add(MailboxAddress.Parse(email));

        using var client = new SmtpClient();
        await client.ConnectAsync(options.Value.Host, options.Value.Port, SecureSocketOptions.Auto, ct);
        await client.SendAsync(FormatOptions.Default, new SmtpSendRequest(message), ct);
        await client.DisconnectAsync(true, ct);
    }
}
