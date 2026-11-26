using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Authentication;
using Microsoft.Extensions.Caching.Memory;
using Xunit;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Tests.Auth;

public sealed class FailedLoginLimiterTests
{
    private readonly FailedLoginLimiter _limiter = new(new MemoryCache(new MemoryCacheOptions()));

    [Fact]
    public void FourFailures_StillAllowed()
    {
        for (var i = 0; i < 4; i++)
        {
            _limiter.RecordFailure("ref", "10.0.0.1");
        }

        Assert.Null(_limiter.RetryAfterSeconds("ref", "10.0.0.1"));
    }

    [Fact]
    public void FiveFailures_BlockThePairOnly()
    {
        for (var i = 0; i < 5; i++)
        {
            _limiter.RecordFailure("ref", "10.0.0.1");
        }

        var retryAfter = _limiter.RetryAfterSeconds("ref", "10.0.0.1");
        Assert.NotNull(retryAfter);
        Assert.InRange(retryAfter.Value, 1, 900);
        Assert.Null(_limiter.RetryAfterSeconds("ref", "10.0.0.2"));
        Assert.Null(_limiter.RetryAfterSeconds("other", "10.0.0.1"));
    }
}
