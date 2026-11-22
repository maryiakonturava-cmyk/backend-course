namespace FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Registration;

public static class EmailNormalizer
{
    public static string Normalize(string email) => email.Trim().ToLowerInvariant();
}
