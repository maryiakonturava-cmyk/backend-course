namespace FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Registration;

public class RegistrationChallenge
{
    public Guid Id { get; set; }

    public Guid UserId { get; set; }

    public ChallengeMethod Method { get; set; }

    public string SecretHash { get; set; } = string.Empty;

    public DateTimeOffset ExpiresAt { get; set; }

    public int Attempts { get; set; }

    public DateTimeOffset LastSentAt { get; set; }

    public DateTimeOffset? ConsumedAt { get; set; }
}
