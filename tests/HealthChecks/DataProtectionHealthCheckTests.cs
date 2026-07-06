using b17s.Porta.Data;
using b17s.Porta.HealthChecks;

using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace b17s.Porta.Tests.HealthChecks;

// Emits activities through the shared Porta ActivitySource, so it must not run in
// parallel with tests that attach a global listener and count spans.
[Collection(PortaActivitySourceCollection.Name)]
public sealed class DataProtectionHealthCheckTests
{
    [Fact]
    public async Task EphemeralProvider_IsHealthy()
    {
        var provider = BuildProvider(s => s.AddDataProtection().UseEphemeralDataProtectionProvider());
        var check = new DataProtectionHealthCheck(provider, new PortaHealthCheckOptions());

        var result = await RunAsync(check);

        Assert.Equal(HealthStatus.Healthy, result.Status);
        Assert.Equal("ok", result.Data["key_ring"]);
        Assert.False(result.Data.ContainsKey("key_store_db"));
    }

    [Fact]
    public async Task ThrowingProvider_ReportsFailureStatus()
    {
        var provider = BuildProvider(s => s.AddSingleton<IDataProtectionProvider>(new ThrowingProvider()));
        var check = new DataProtectionHealthCheck(provider, new PortaHealthCheckOptions());

        var result = await RunAsync(check);

        Assert.Equal(HealthStatus.Degraded, result.Status);
        Assert.Contains("key ring", result.Description);
        Assert.NotNull(result.Exception);
    }

    [Fact]
    public async Task NoProviderRegistered_AutoMode_IsHealthySkipped()
    {
        var provider = BuildProvider();
        var check = new DataProtectionHealthCheck(provider, new PortaHealthCheckOptions());

        var result = await RunAsync(check);

        Assert.Equal(HealthStatus.Healthy, result.Status);
        Assert.Contains("skipped", result.Description);
    }

    [Fact]
    public async Task NoProviderRegistered_CheckRequired_ReportsFailureStatus()
    {
        var provider = BuildProvider();
        var check = new DataProtectionHealthCheck(
            provider, new PortaHealthCheckOptions { CheckDataProtection = true });

        var result = await RunAsync(check);

        Assert.Equal(HealthStatus.Degraded, result.Status);
        Assert.Contains("no IDataProtectionProvider", result.Description);
    }

    [Fact]
    public async Task RegisteredKeyStoreDbContext_Reachable_IsHealthy()
    {
        var provider = BuildProvider(s =>
        {
            s.AddDataProtection().UseEphemeralDataProtectionProvider();
            s.AddDbContext<DataProtectionDbContext>(o => o.UseInMemoryDatabase("dp-health-check"));
        });
        var check = new DataProtectionHealthCheck(provider, new PortaHealthCheckOptions());

        var result = await RunAsync(check);

        Assert.Equal(HealthStatus.Healthy, result.Status);
        Assert.Equal("ok", result.Data["key_ring"]);
        Assert.Equal("ok", result.Data["key_store_db"]);
    }

    [Fact]
    public async Task KeyStoreDbContext_WithoutProvider_ReportsFailureMentioningKeyStore()
    {
        var provider = BuildProvider(s =>
        {
            s.AddDataProtection().UseEphemeralDataProtectionProvider();
            // No EF provider configured: CanConnectAsync throws, standing in for an
            // unreachable/misconfigured key database.
            s.AddDbContext<DataProtectionDbContext>();
        });
        var check = new DataProtectionHealthCheck(provider, new PortaHealthCheckOptions());

        var result = await RunAsync(check);

        Assert.Equal(HealthStatus.Degraded, result.Status);
        Assert.Contains("key store", result.Description);
        Assert.NotNull(result.Exception);
    }

    private static ServiceProvider BuildProvider(Action<IServiceCollection>? configureServices = null)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        configureServices?.Invoke(services);
        return services.BuildServiceProvider();
    }

    private static Task<HealthCheckResult> RunAsync(
        IHealthCheck check,
        HealthStatus failureStatus = HealthStatus.Degraded,
        CancellationToken? ct = null)
        => check.CheckHealthAsync(new HealthCheckContext
        {
            Registration = new HealthCheckRegistration("test", check, failureStatus, tags: null),
        }, ct ?? TestContext.Current.CancellationToken);

    private sealed class ThrowingProvider : IDataProtectionProvider
    {
        public IDataProtector CreateProtector(string purpose)
            => throw new InvalidOperationException("key ring unavailable");
    }
}
