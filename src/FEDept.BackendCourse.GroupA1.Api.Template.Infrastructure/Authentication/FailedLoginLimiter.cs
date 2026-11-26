using Microsoft.Extensions.Caching.Memory;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Authentication;

// shortcut: in-memory and per instance; move to a shared store when the API scales out
public sealed class FailedLoginLimiter(IMemoryCache cache)
{
    public const int MaxFailures = 5;
    public static readonly TimeSpan Window = TimeSpan.FromMinutes(15);

    public int? RetryAfterSeconds(string emailRef, string clientIp)
    {
        if (!cache.TryGetValue(Key(emailRef, clientIp), out Queue<DateTimeOffset>? failures) || failures is null)
        {
            return null;
        }

        var now = DateTimeOffset.UtcNow;
        lock (failures)
        {
            while (failures.Count > 0 && failures.Peek() + Window <= now)
            {
                failures.Dequeue();
            }

            return failures.Count < MaxFailures
                ? null
                : (int)Math.Ceiling((failures.Peek() + Window - now).TotalSeconds);
        }
    }

    public void RecordFailure(string emailRef, string clientIp)
    {
        var failures = cache.GetOrCreate(Key(emailRef, clientIp), entry =>
        {
            entry.SlidingExpiration = Window;
            return new Queue<DateTimeOffset>();
        })!;
        lock (failures)
        {
            failures.Enqueue(DateTimeOffset.UtcNow);
        }
    }

    private static string Key(string emailRef, string clientIp) => $"failed-login:{emailRef}:{clientIp}";
}
