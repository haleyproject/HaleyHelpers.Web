using System.Net;
using System.Text.Json;
using Haley.Models;
using Haley.Services;
using Haley.Utils;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace Haley.Tests;

public sealed class RequestRateLimitTests
{
    [Fact]
    public void MissingSettingsRetainCSharpDefaults()
    {
        using var provider = Services(new ConfigurationBuilder().Build());
        var options = provider.GetRequiredService<IOptionsMonitor<RequestRateLimitOptions>>().Get("test");
        Assert.True(options.Enabled);
        Assert.Equal(RequestRateLimitOptions.DefaultPermitLimit, options.PermitLimit);
        Assert.Equal(RequestRateLimitOptions.DefaultWindowSeconds, options.WindowSeconds);
        Assert.Equal(RequestRateLimitOptions.IpUserScope, options.Scope);
    }

    [Fact]
    public void PartialSettingsRetainTheOtherDefaults()
    {
        var configuration = Configuration(("PermitLimit", "7"));
        using var provider = Services(configuration);
        var options = provider.GetRequiredService<IOptionsMonitor<RequestRateLimitOptions>>().Get("test");
        Assert.Equal(7, options.PermitLimit);
        Assert.Equal(60, options.WindowSeconds);
        Assert.Equal("ip-user", options.Scope);
        Assert.True(options.Enabled);
    }

    [Fact]
    public void OneHundredUsersAtOneAddressHaveIndependentAllowances()
    {
        using var provider = Services(Configuration(("PermitLimit", "1")));
        var limiter = provider.GetRequiredService<FixedWindowRequestRateLimiter>();
        var context = Context(provider);
        for (var i = 0; i < 100; i++)
        {
            using var lease = limiter.AttemptAcquire(context, "test", "account:" + i);
            Assert.True(lease.IsAcquired);
        }
        using var repeat = limiter.AttemptAcquire(context, "test", "account:0");
        Assert.False(repeat.IsAcquired);
        using var differentIp = limiter.AttemptAcquire(Context(provider, "192.0.2.2"), "test", "account:0");
        Assert.True(differentIp.IsAcquired);
    }

    [Fact]
    public void IpScopeSharesTheBudgetAcrossUsers()
    {
        using var provider = Services(Configuration(("PermitLimit", "1"), ("Scope", "ip")));
        var limiter = provider.GetRequiredService<FixedWindowRequestRateLimiter>();
        using var first = limiter.AttemptAcquire(Context(provider), "test", "alice");
        using var second = limiter.AttemptAcquire(Context(provider), "test", "bob");
        Assert.True(first.IsAcquired);
        Assert.False(second.IsAcquired);
    }

    [Fact]
    public void MissingSubjectsUseOneAnonymousBudgetAndIpv4MappedAddressesAreEquivalent()
    {
        using var provider = Services(Configuration(("PermitLimit", "1")));
        var limiter = provider.GetRequiredService<FixedWindowRequestRateLimiter>();
        using var first = limiter.AttemptAcquire(Context(provider), "test");
        using var second = limiter.AttemptAcquire(Context(provider, "::ffff:192.0.2.1"), "test");
        Assert.True(first.IsAcquired);
        Assert.False(second.IsAcquired);
    }

    [Fact]
    public void ConfigurationReloadChangesTheActiveAllowance()
    {
        var configuration = Configuration(("PermitLimit", "1"));
        using var provider = Services(configuration);
        var limiter = provider.GetRequiredService<FixedWindowRequestRateLimiter>();
        using var first = limiter.AttemptAcquire(Context(provider), "test", "alice");
        using var rejected = limiter.AttemptAcquire(Context(provider), "test", "alice");
        Assert.False(rejected.IsAcquired);
        configuration["Limits:PermitLimit"] = "2";
        configuration.Reload();
        using var afterReload = limiter.AttemptAcquire(Context(provider), "test", "alice");
        using var secondAfterReload = limiter.AttemptAcquire(Context(provider), "test", "alice");
        using var exhausted = limiter.AttemptAcquire(Context(provider), "test", "alice");
        Assert.True(afterReload.IsAcquired);
        Assert.True(secondAfterReload.IsAcquired);
        Assert.False(exhausted.IsAcquired);
    }

    [Fact]
    public void DisabledPolicyDoesNotReject()
    {
        using var provider = Services(Configuration(("Enabled", "false"), ("PermitLimit", "1")));
        var limiter = provider.GetRequiredService<FixedWindowRequestRateLimiter>();
        for (var i = 0; i < 5; i++)
        {
            using var lease = limiter.AttemptAcquire(Context(provider), "test", "alice");
            Assert.True(lease.IsAcquired);
        }
    }

    [Theory]
    [InlineData("Scope", "user")]
    [InlineData("Scope", "")]
    [InlineData("PermitLimit", "0")]
    [InlineData("WindowSeconds", "0")]
    public void InvalidSettingsFailStartupValidation(string field, string value)
    {
        using var provider = Services(Configuration((field, value)));
        Assert.Throws<OptionsValidationException>(() => provider.GetRequiredService<IStartupValidator>().Validate());
    }

    [Fact]
    public async Task RejectionContainsRetryAfterAndStableProblemDetails()
    {
        using var provider = Services(Configuration(("PermitLimit", "1"), ("WindowSeconds", "17")));
        var limiter = provider.GetRequiredService<FixedWindowRequestRateLimiter>();
        var context = Context(provider);
        using var first = limiter.AttemptAcquire(context, "test", "alice");
        using var rejected = limiter.AttemptAcquire(context, "test", "alice");
        context.Response.Body = new MemoryStream();
        await FixedWindowRequestRateLimiter.Rejection(context, rejected).ExecuteAsync(context);
        Assert.Equal(429, context.Response.StatusCode);
        Assert.InRange(int.Parse(context.Response.Headers.RetryAfter!), 1, 17);
        context.Response.Body.Position = 0;
        using var document = await JsonDocument.ParseAsync(context.Response.Body);
        Assert.Equal("rate_limit_exceeded", document.RootElement.GetProperty("code").GetString());
    }

    private static ServiceProvider Services(IConfiguration configuration)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddConfiguredFixedWindowRateLimit("test", configuration.GetSection("Limits"));
        return services.BuildServiceProvider();
    }

    private static IConfigurationRoot Configuration(params (string Field, string Value)[] values) =>
        new ConfigurationBuilder().AddInMemoryCollection(values.Select(pair =>
            new KeyValuePair<string, string?>("Limits:" + pair.Field, pair.Value))).Build();

    private static DefaultHttpContext Context(IServiceProvider services, string address = "192.0.2.1")
    {
        var context = new DefaultHttpContext { RequestServices = services };
        context.Connection.RemoteIpAddress = IPAddress.Parse(address);
        return context;
    }
}
