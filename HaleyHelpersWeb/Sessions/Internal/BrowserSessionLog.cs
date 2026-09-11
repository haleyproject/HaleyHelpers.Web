namespace Haley.Internal;

internal static partial class BrowserSessionLog
{
    [LoggerMessage(
        EventId = 1,
        Level = LogLevel.Error,
        Message = "The browser session could not be persisted.")]
    internal static partial void PersistenceFailed(ILogger logger, Exception exception);

    [LoggerMessage(
        EventId = 2,
        Level = LogLevel.Warning,
        Message = "A browser refresh payload was invalid.")]
    internal static partial void RefreshPayloadInvalid(ILogger logger, Exception exception);
}
