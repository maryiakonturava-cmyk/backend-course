using System.Security.Cryptography;
using System.Text;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Registration;

public class SecretHasher(string key)
{
    public string Hash(string code)
    {
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(key));
        return Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(code)));
    }

    public bool Matches(string code, string hash)
    {
        byte[] actualHash;
        try
        {
            actualHash = Convert.FromBase64String(hash);
        }
        catch (FormatException)
        {
            return false;
        }

        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(key));
        var expectedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(code));
        return CryptographicOperations.FixedTimeEquals(expectedHash, actualHash);
    }
}
