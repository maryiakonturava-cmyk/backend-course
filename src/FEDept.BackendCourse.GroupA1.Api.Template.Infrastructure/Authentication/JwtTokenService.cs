using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Authentication;

public enum TokenUse
{
    Access,
    Refresh
}

public sealed record TokenPair(string AccessToken, string RefreshToken);

public abstract record TokenValidation
{
    public sealed record Ok(Guid UserId) : TokenValidation;

    public sealed record Fail(string Category) : TokenValidation;
}

public sealed class TokenSigningException(Exception innerException) : Exception("Token signing failed.", innerException);

public sealed class JwtTokenService(IOptions<JwtOptions> options)
{
    public static readonly TimeSpan AccessLifetime = TimeSpan.FromMinutes(15);
    public static readonly TimeSpan RefreshLifetime = TimeSpan.FromDays(30);
    private static readonly TimeSpan ClockSkew = TimeSpan.FromSeconds(30);

    // no implicit nbf/iat/exp: the contract fixes the claim set
    private static readonly JsonWebTokenHandler Handler = new() { SetDefaultTimesOnTokenCreation = false };

    public TokenPair Issue(Guid userId) => Issue(userId, DateTimeOffset.UtcNow);

    public TokenPair Issue(Guid userId, DateTimeOffset issuedAt)
    {
        try
        {
            return new TokenPair(Create(userId, TokenUse.Access, issuedAt), Create(userId, TokenUse.Refresh, issuedAt));
        }
        catch (Exception exception)
        {
            throw new TokenSigningException(exception);
        }
    }

    public async Task<TokenValidation> ValidateAsync(string? token, TokenUse use)
    {
        if (string.IsNullOrEmpty(token))
        {
            return new TokenValidation.Fail("missing");
        }

        var result = await Handler.ValidateTokenAsync(token, Parameters(use));
        if (!result.IsValid)
        {
            return new TokenValidation.Fail(Categorize(result.Exception));
        }

        if (!result.Claims.ContainsKey(JwtRegisteredClaimNames.Iat)
            || !result.Claims.TryGetValue(JwtRegisteredClaimNames.Sub, out var sub)
            || !Guid.TryParse(sub as string, out var userId)
            || userId == Guid.Empty)
        {
            return new TokenValidation.Fail("claims");
        }

        return result.Claims.TryGetValue("token_use", out var tokenUse) && Equals(tokenUse, Name(use))
            ? new TokenValidation.Ok(userId)
            : new TokenValidation.Fail("token_use");
    }

    private string Create(Guid userId, TokenUse use, DateTimeOffset issuedAt) =>
        Handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = options.Value.Issuer,
            Audience = options.Value.Audience,
            IssuedAt = issuedAt.UtcDateTime,
            Expires = (issuedAt + (use == TokenUse.Access ? AccessLifetime : RefreshLifetime)).UtcDateTime,
            Claims = new Dictionary<string, object>
            {
                [JwtRegisteredClaimNames.Sub] = userId.ToString(),
                ["token_use"] = Name(use)
            },
            SigningCredentials = new SigningCredentials(Key(use), SecurityAlgorithms.HmacSha256)
        });

    private TokenValidationParameters Parameters(TokenUse use) => new()
    {
        ValidIssuer = options.Value.Issuer,
        ValidAudience = options.Value.Audience,
        IssuerSigningKey = Key(use),
        ValidAlgorithms = [SecurityAlgorithms.HmacSha256],
        RequireSignedTokens = true,
        RequireExpirationTime = true,
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ClockSkew = ClockSkew
    };

    private SymmetricSecurityKey Key(TokenUse use) => new(Encoding.UTF8.GetBytes(
        use == TokenUse.Access ? options.Value.AccessSecret : options.Value.RefreshSecret));

    private static string Name(TokenUse use) => use == TokenUse.Access ? "access" : "refresh";

    private static string Categorize(Exception? exception) => exception switch
    {
        SecurityTokenExpiredException => "expired",
        SecurityTokenInvalidSignatureException or SecurityTokenInvalidAlgorithmException => "signature",
        SecurityTokenInvalidIssuerException or SecurityTokenInvalidAudienceException
            or SecurityTokenNoExpirationException or SecurityTokenInvalidLifetimeException
            or SecurityTokenNotYetValidException => "claims",
        _ => "malformed"
    };
}
