using System.Globalization;
using System.Security.Cryptography;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Registration;

public static class OtpGenerator
{
    public static string Generate() => RandomNumberGenerator.GetInt32(1_000_000).ToString("D6", CultureInfo.InvariantCulture);
}
