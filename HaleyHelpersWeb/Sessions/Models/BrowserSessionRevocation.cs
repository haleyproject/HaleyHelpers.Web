namespace Haley.Models;

public sealed record BrowserSessionRevocation(Guid SessionId, Guid SubjectId);
