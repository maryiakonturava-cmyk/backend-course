namespace FEDept.BackendCourse.GroupA1.Api.Template.Infrastructure.Registration;

public enum ChallengeMethod
{
    Otp,
    MagicLink
}

public static class ChallengeMethodExtensions
{
    public static string ToContractName(this ChallengeMethod method) => method switch
    {
        ChallengeMethod.Otp => "otp",
        ChallengeMethod.MagicLink => "magic_link",
        _ => throw new ArgumentOutOfRangeException(nameof(method), method, null)
    };
}
