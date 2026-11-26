using Microsoft.Extensions.Caching.Memory;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Authentication;

// shortcut: in-memory and per instance; move to a shared store when the API scales out
public sealed class FailedLoginLimiter(IMemoryCache cache)
{
    public const int MaxFailures = 5;
    public static readonly TimeSpan Window = TimeSpan.FromMinutes(15);

    // one gate for get-or-create, prune and count: IMemoryCache.GetOrCreate is not atomic
    private readonly Lock _gate = new();

    // reserves a slot that counts as a failure until Release; returns the seconds to wait when the pair is blocked
    public int? TryBeginAttempt(string emailRef, string clientIp)
    {
        var now = DateTimeOffset.UtcNow;
        lock (_gate)
        {
            var attempts = cache.GetOrCreate(Key(emailRef, clientIp), entry =>
            {
                entry.SlidingExpiration = Window;
                return new List<DateTimeOffset>();
            })!;
            attempts.RemoveAll(at => at + Window <= now);
            if (attempts.Count >= MaxFailures)
            {
                return (int)Math.Ceiling((attempts[0] + Window - now).TotalSeconds);
            }

            attempts.Add(now);
            return null;
        }
    }

    // a successful check (or an outage) gives the reserved slot back
    public void Release(string emailRef, string clientIp)
    {
        lock (_gate)
        {
            if (cache.TryGetValue(Key(emailRef, clientIp), out List<DateTimeOffset>? attempts) && attempts is { Count: > 0 })
            {
                attempts.RemoveAt(attempts.Count - 1);
            }
        }
    }

    private static string Key(string emailRef, string clientIp) => $"failed-login:{emailRef}:{clientIp}";
}
