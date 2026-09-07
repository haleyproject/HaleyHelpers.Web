namespace Haley.Models;

public sealed record BrowserAccessTicket(byte[] Payload, DateTimeOffset ExpiresAt);
