using Haley.Abstractions;

namespace Haley.Utils;

public static class MinimalApiFeedbackExtensions
{
    public static IResult ToMinimalApiResult<T>(this IFeedback<T> feedback)
    {
        ArgumentNullException.ThrowIfNull(feedback);
        if (feedback.Status && feedback.Result is not null)
            return Results.Ok(feedback.Result);

        return Problem(feedback);
    }

    public static IResult ToMinimalApiResult(this IFeedback feedback)
    {
        ArgumentNullException.ThrowIfNull(feedback);
        return feedback.Status ? Results.NoContent() : Problem(feedback);
    }

    private static IResult Problem(IFeedbackBase feedback) =>
        Results.Problem(
            detail: feedback.Message,
            statusCode: NormalizeStatus(feedback.Code),
            extensions: string.IsNullOrWhiteSpace(feedback.Key)
                ? null
                : new Dictionary<string, object?> { ["code"] = feedback.Key });

    private static int NormalizeStatus(int code) =>
        code is >= 400 and <= 599 ? code : StatusCodes.Status400BadRequest;
}
