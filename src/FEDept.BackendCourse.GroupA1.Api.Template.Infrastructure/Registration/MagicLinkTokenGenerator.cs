using System.Buffers.Text;
using System.Security.Cryptography;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Registration;

public static class MagicLinkTokenGenerator
{
    public static string Generate() => Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(32));
}
