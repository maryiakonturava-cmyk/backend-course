using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Authentication;
using Microsoft.Extensions.Caching.Memory;
using Xunit;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Tests.Auth;

public sealed class FailedLoginLimiterTests
{
    private readonly FailedLoginLimiter _limiter = new(new MemoryCache(new MemoryCacheOptions()));

    [Fact]
    public void FiveFailedAttempts_AllowedThenSixthBlocked()
    {
        for (var i = 0; i < 5; i++)
        {
            Assert.Null(_limiter.TryBeginAttempt("ref", "10.0.0.1"));
        }

        var retryAfter = _limiter.TryBeginAttempt("ref", "10.0.0.1");
        Assert.NotNull(retryAfter);
        Assert.InRange(retryAfter.Value, 1, 900);
    }

    [Fact]
    public void Block_AppliesToThePairOnly()
    {
        for (var i = 0; i < 5; i++)
        {
            _limiter.TryBeginAttempt("ref", "10.0.0.1");
        }

        Assert.Null(_limiter.TryBeginAttempt("ref", "10.0.0.2"));
        Assert.Null(_limiter.TryBeginAttempt("other", "10.0.0.1"));
    }

    [Fact]
    public void ReleasedAttempts_DoNotCount()
    {
        for (var i = 0; i < 10; i++)
        {
            Assert.Null(_limiter.TryBeginAttempt("ref", "10.0.0.1"));
            _limiter.Release("ref", "10.0.0.1");
        }

        Assert.Null(_limiter.TryBeginAttempt("ref", "10.0.0.1"));
    }

    [Fact]
    public void ConcurrentAttempts_NeverExceedTheLimit()
    {
        var allowed = 0;

        Parallel.For(0, 50, _ =>
        {
            if (_limiter.TryBeginAttempt("ref", "10.0.0.1") is null)
            {
                Interlocked.Increment(ref allowed);
            }
        });

        Assert.Equal(FailedLoginLimiter.MaxFailures, allowed);
    }
}
