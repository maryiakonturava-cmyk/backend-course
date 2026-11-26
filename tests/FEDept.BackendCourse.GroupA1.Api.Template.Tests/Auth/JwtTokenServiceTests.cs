using System.Text;
using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Authentication;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Tests.Auth;

public sealed class JwtTokenServiceTests
{
    private static readonly JwtOptions Options = new()
    {
        AccessSecret = new string('a', 32),
        RefreshSecret = new string('r', 32),
        Issuer = "api",
        Audience = "web"
    };

    private readonly JwtTokenService _service = new(Microsoft.Extensions.Options.Options.Create(Options));

    [Fact]
    public async Task Issue_ProducesAccessAndRefreshThatValidateForTheirOwnUse()
    {
        var userId = Guid.NewGuid();

        var pair = _service.Issue(userId);

        Assert.Equal(new TokenValidation.Ok(userId), await _service.ValidateAsync(pair.AccessToken, TokenUse.Access));
        Assert.Equal(new TokenValidation.Ok(userId), await _service.ValidateAsync(pair.RefreshToken, TokenUse.Refresh));
    }

    [Fact]
    public void Issue_WritesOnlyTheContractClaims()
    {
        var issuedAt = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds());

        var pair = _service.Issue(Guid.NewGuid(), issuedAt);

        var access = new JsonWebToken(pair.AccessToken);
        var refresh = new JsonWebToken(pair.RefreshToken);
        Assert.Equal("HS256", access.Alg);
        Assert.Equal("JWT", access.Typ);
        var expectedClaims = new[] { "aud", "exp", "iat", "iss", "sub", "token_use" };
        Assert.Equal(expectedClaims, access.Claims.Select(claim => claim.Type).Order().ToArray());
        Assert.Equal(expectedClaims, refresh.Claims.Select(claim => claim.Type).Order().ToArray());
        Assert.Equal("access", access.GetClaim("token_use").Value);
        Assert.Equal("refresh", refresh.GetClaim("token_use").Value);
        Assert.Equal(900, access.ValidTo.Subtract(access.IssuedAt).TotalSeconds);
        Assert.Equal(2592000, refresh.ValidTo.Subtract(refresh.IssuedAt).TotalSeconds);
    }

    [Fact]
    public async Task Validate_RefreshAsAccess_FailsWithSignature()
    {
        var pair = _service.Issue(Guid.NewGuid());

        Assert.Equal(new TokenValidation.Fail("signature"), await _service.ValidateAsync(pair.RefreshToken, TokenUse.Access));
    }

    [Theory]
    [InlineData(null, "missing")]
    [InlineData("", "missing")]
    [InlineData("not-a-jwt", "malformed")]
    public async Task Validate_BadInput_ReturnsCategory(string? token, string category)
    {
        Assert.Equal(new TokenValidation.Fail(category), await _service.ValidateAsync(token, TokenUse.Access));
    }

    [Fact]
    public async Task Validate_Expired_ReturnsExpired()
    {
        var pair = _service.Issue(Guid.NewGuid(), DateTimeOffset.UtcNow.AddMinutes(-16));

        Assert.Equal(new TokenValidation.Fail("expired"), await _service.ValidateAsync(pair.AccessToken, TokenUse.Access));
    }

    [Fact]
    public async Task Validate_BeyondClockSkew_ReturnsExpired()
    {
        var pair = _service.Issue(Guid.NewGuid(), DateTimeOffset.UtcNow.AddMinutes(-15).AddSeconds(-40));

        Assert.Equal(new TokenValidation.Fail("expired"), await _service.ValidateAsync(pair.AccessToken, TokenUse.Access));
    }

    [Fact]
    public async Task Validate_WithinClockSkew_IsAccepted()
    {
        var userId = Guid.NewGuid();
        var pair = _service.Issue(userId, DateTimeOffset.UtcNow.AddMinutes(-15).AddSeconds(-20));

        Assert.Equal(new TokenValidation.Ok(userId), await _service.ValidateAsync(pair.AccessToken, TokenUse.Access));
    }

    [Fact]
    public async Task Validate_OtherIssuer_ReturnsClaims()
    {
        var other = new JwtTokenService(Microsoft.Extensions.Options.Options.Create(new JwtOptions
        {
            AccessSecret = Options.AccessSecret,
            RefreshSecret = Options.RefreshSecret,
            Issuer = "someone-else",
            Audience = Options.Audience
        }));

        var pair = other.Issue(Guid.NewGuid());

        Assert.Equal(new TokenValidation.Fail("claims"), await _service.ValidateAsync(pair.AccessToken, TokenUse.Access));
    }

    [Fact]
    public async Task Validate_OtherAudience_ReturnsClaims()
    {
        var other = new JwtTokenService(Microsoft.Extensions.Options.Options.Create(new JwtOptions
        {
            AccessSecret = Options.AccessSecret,
            RefreshSecret = Options.RefreshSecret,
            Issuer = Options.Issuer,
            Audience = "someone-else"
        }));
        var pair = other.Issue(Guid.NewGuid());

        Assert.Equal(new TokenValidation.Fail("claims"), await _service.ValidateAsync(pair.AccessToken, TokenUse.Access));
    }

    [Fact]
    public async Task Validate_AccessKeyWithRefreshUse_ReturnsTokenUse()
    {
        var token = Sign(Options.AccessSecret, SecurityAlgorithms.HmacSha256, new Dictionary<string, object>
        {
            ["sub"] = Guid.NewGuid().ToString(),
            ["token_use"] = "refresh"
        });

        Assert.Equal(new TokenValidation.Fail("token_use"), await _service.ValidateAsync(token, TokenUse.Access));
    }

    [Fact]
    public async Task Validate_EmptyGuidSub_ReturnsClaims()
    {
        var token = Sign(Options.AccessSecret, SecurityAlgorithms.HmacSha256, new Dictionary<string, object>
        {
            ["sub"] = Guid.Empty.ToString(),
            ["token_use"] = "access"
        });

        Assert.Equal(new TokenValidation.Fail("claims"), await _service.ValidateAsync(token, TokenUse.Access));
    }

    [Fact]
    public async Task Validate_NonGuidSub_ReturnsClaims()
    {
        var token = Sign(Options.AccessSecret, SecurityAlgorithms.HmacSha256, new Dictionary<string, object>
        {
            ["sub"] = "user-42",
            ["token_use"] = "access"
        });

        Assert.Equal(new TokenValidation.Fail("claims"), await _service.ValidateAsync(token, TokenUse.Access));
    }

    [Fact]
    public async Task Validate_MissingIssuedAt_ReturnsClaims()
    {
        var handler = new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false };
        var token = handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = Options.Issuer,
            Audience = Options.Audience,
            Expires = DateTime.UtcNow.AddMinutes(5),
            Claims = new Dictionary<string, object>
            {
                ["sub"] = Guid.NewGuid().ToString(),
                ["token_use"] = "access"
            },
            SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Options.AccessSecret)),
                SecurityAlgorithms.HmacSha256)
        });

        Assert.Equal(new TokenValidation.Fail("claims"), await _service.ValidateAsync(token, TokenUse.Access));
    }

    [Fact]
    public async Task Validate_OtherAlgorithmOrUnsigned_ReturnsSignature()
    {
        var claims = new Dictionary<string, object> { ["sub"] = Guid.NewGuid().ToString(), ["token_use"] = "access" };
        var hs512 = Sign(Options.AccessSecret + Options.AccessSecret, SecurityAlgorithms.HmacSha512, claims);
        var unsigned = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = Options.Issuer,
            Audience = Options.Audience,
            Expires = DateTime.UtcNow.AddMinutes(5),
            Claims = claims
        });

        Assert.Equal(new TokenValidation.Fail("signature"), await _service.ValidateAsync(hs512, TokenUse.Access));
        Assert.Equal(new TokenValidation.Fail("signature"), await _service.ValidateAsync(unsigned, TokenUse.Access));
    }

    private static string Sign(string key, string algorithm, Dictionary<string, object> claims) =>
        new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = Options.Issuer,
            Audience = Options.Audience,
            IssuedAt = DateTime.UtcNow,
            Expires = DateTime.UtcNow.AddMinutes(5),
            Claims = claims,
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key)), algorithm)
        });
}
