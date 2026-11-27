using System.ComponentModel.DataAnnotations;

namespace FEDept.BackendCourse.GroupA1.Api.Template.Contracts;

// parameter target: MVC throws on validation attributes put on primary-constructor record properties
public sealed record LoginResendRequest([Required] Guid? AttemptId);
