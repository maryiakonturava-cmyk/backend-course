using System.ComponentModel.DataAnnotations;
using System.Text;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Contracts;

[AttributeUsage(AttributeTargets.Property | AttributeTargets.Field | AttributeTargets.Parameter)]
public sealed class PasswordPolicyAttribute : ValidationAttribute
{
    public PasswordPolicyAttribute()
        : base("Password must be at least 8 characters, include a letter and a digit, and use no more than 72 UTF-8 bytes.")
    {
    }

    public override bool IsValid(object? value)
    {
        if (value is null)
        {
            return true;
        }

        if (value is not string password || password.Length < 8 ||
            !password.Any(char.IsLetter) || !password.Any(char.IsDigit))
        {
            return false;
        }

        return Encoding.UTF8.GetByteCount(password) <= 72;
    }
}
