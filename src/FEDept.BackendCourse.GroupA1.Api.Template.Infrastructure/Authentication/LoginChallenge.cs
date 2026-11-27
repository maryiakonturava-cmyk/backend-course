using FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Registration;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Authentication;

// no expires_at column: expiry is last_sent_at + 10 minutes (keeps the table in BCNF)
public class LoginChallenge
{
    public Guid Id { get; set; }

    public Guid UserId { get; set; }

    public ChallengeMethod Method { get; set; }

    public string SecretHash { get; set; } = string.Empty;

    public DateTimeOffset LastSentAt { get; set; }

    public int Attempts { get; set; }

    public DateTimeOffset? ConsumedAt { get; set; }

    public ConsumedReason? ConsumedReason { get; set; }

    public DateTimeOffset CreatedAt { get; set; }
}

public enum ConsumedReason
{
    Confirmed,
    Replaced,
    AttemptsExhausted,
    UserInactive
}
