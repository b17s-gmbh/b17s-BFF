using b17s.Porta.HealthChecks;

using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Http;
using Microsoft.Extensions.Http.Resilience;
using Microsoft.Extensions.Options;

using Polly;

namespace b17s.Porta.Tests.Extensions;

/// <summary>
/// Registration-shape tests for AddPortaHealthChecks: which checks land in
/// HealthCheckServiceOptions with which failure statuses and tags, the single-call guard,
/// options validation, and the probe HttpClient's handler configuration. Check behavior
/// itself is covered by the per-check test classes under tests/HealthChecks.
/// </summary>
public class AddPortaHealthChecksTests
{
    [Fact]
    public void RegistersAllThreeChecks_WithDefaultFailureStatusesAndTags()
    {
        var services = new ServiceCollection();

        var builder = services.AddPortaHealthChecks();

        Assert.NotNull(builder);
        var registrations = GetRegistrations(services);
        Assert.Equal(3, registrations.Count);

        var idp = Assert.Single(registrations, r => r.Name == PortaHealthCheckDefaults.IdpDiscoveryName);
        Assert.Equal(HealthStatus.Degraded, idp.FailureStatus);

        var cache = Assert.Single(registrations, r => r.Name == PortaHealthCheckDefaults.DistributedCacheName);
        // A dead session store fails every authenticated route - the pod must leave rotation.
        Assert.Equal(HealthStatus.Unhealthy, cache.FailureStatus);

        var dataProtection = Assert.Single(registrations, r => r.Name == PortaHealthCheckDefaults.DataProtectionName);
        Assert.Equal(HealthStatus.Degraded, dataProtection.FailureStatus);

        Assert.All(registrations, r =>
        {
            Assert.Contains(PortaHealthCheckDefaults.PortaTag, r.Tags);
            Assert.Contains(PortaHealthCheckDefaults.ReadyTag, r.Tags);
        });
    }

    [Fact]
    public void ConfiguredFailureStatuses_FlowIntoRegistrations()
    {
        var services = new ServiceCollection();

        services.AddPortaHealthChecks(o =>
        {
            o.IdpFailureStatus = HealthStatus.Unhealthy;
            o.DistributedCacheFailureStatus = HealthStatus.Degraded;
        });

        var registrations = GetRegistrations(services);
        Assert.Equal(HealthStatus.Unhealthy,
            registrations.Single(r => r.Name == PortaHealthCheckDefaults.IdpDiscoveryName).FailureStatus);
        Assert.Equal(HealthStatus.Degraded,
            registrations.Single(r => r.Name == PortaHealthCheckDefaults.DistributedCacheName).FailureStatus);
    }

    [Fact]
    public void SecondCall_Throws()
    {
        var services = new ServiceCollection();
        services.AddPortaHealthChecks();

        var ex = Assert.Throws<InvalidOperationException>(() => services.AddPortaHealthChecks());
        Assert.StartsWith("Porta:", ex.Message);
    }

    [Theory]
    [InlineData(true, false, false)]
    [InlineData(false, true, false)]
    [InlineData(false, false, true)]
    public void CheckSetToFalse_IsNotRegistered(bool disableIdp, bool disableCache, bool disableDataProtection)
    {
        var services = new ServiceCollection();

        services.AddPortaHealthChecks(o =>
        {
            if (disableIdp) { o.CheckIdpDiscovery = false; }
            if (disableCache) { o.CheckDistributedCache = false; }
            if (disableDataProtection) { o.CheckDataProtection = false; }
        });

        var names = GetRegistrations(services).Select(r => r.Name).ToList();
        Assert.Equal(2, names.Count);
        Assert.Equal(!disableIdp, names.Contains(PortaHealthCheckDefaults.IdpDiscoveryName));
        Assert.Equal(!disableCache, names.Contains(PortaHealthCheckDefaults.DistributedCacheName));
        Assert.Equal(!disableDataProtection, names.Contains(PortaHealthCheckDefaults.DataProtectionName));
    }

    [Theory]
    [InlineData("not-a-url")]
    [InlineData("/relative/path")]
    [InlineData("ftp://idp.test/health")]
    public void InvalidIdpProbeUrl_Throws(string url)
    {
        var services = new ServiceCollection();

        var ex = Assert.Throws<ArgumentException>(
            () => services.AddPortaHealthChecks(o => o.IdpProbeUrl = url));
        Assert.StartsWith("Porta:", ex.Message);
        Assert.Contains("IdpProbeUrl", ex.Message);
    }

    [Theory]
    [InlineData("POST")]
    [InlineData("")]
    public void InvalidIdpProbeMethod_Throws(string method)
    {
        var services = new ServiceCollection();

        var ex = Assert.Throws<ArgumentException>(
            () => services.AddPortaHealthChecks(o => o.IdpProbeMethod = method));
        Assert.Contains("IdpProbeMethod", ex.Message);
    }

    [Fact]
    public void NonPositiveProbeTimeout_Throws()
    {
        var services = new ServiceCollection();

        var ex = Assert.Throws<ArgumentException>(
            () => services.AddPortaHealthChecks(o => o.ProbeTimeout = TimeSpan.Zero));
        Assert.Contains("ProbeTimeout", ex.Message);
    }

    [Fact]
    public void NamedClient_PrimaryHandler_NoCookiesNoAutoRedirect()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddPortaHealthChecks();

        var handlerBuilder = RunHandlerBuilderActions(services);

        var primary = Assert.IsType<SocketsHttpHandler>(handlerBuilder.PrimaryHandler);
        Assert.False(primary.UseCookies);
        Assert.False(primary.AllowAutoRedirect);
    }

    [Fact]
    public void NamedClient_StripsResilienceHandlersAddedByHostDefaults()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        // Simulates a host that wraps every client in a resilience pipeline via
        // ConfigureHttpClientDefaults - retries must not apply to health probes.
        services.ConfigureHttpClientDefaults(b => b.ConfigureAdditionalHttpMessageHandlers(
            (handlers, _) => handlers.Add(new ResilienceHandler(ResiliencePipeline<HttpResponseMessage>.Empty))));
        services.AddPortaHealthChecks();

        var handlerBuilder = RunHandlerBuilderActions(services);

        Assert.DoesNotContain(handlerBuilder.AdditionalHandlers, h => h is ResilienceHandler);
    }

    private static ICollection<HealthCheckRegistration> GetRegistrations(IServiceCollection services)
    {
        using var provider = services.BuildServiceProvider();
        return provider.GetRequiredService<IOptions<HealthCheckServiceOptions>>().Value.Registrations;
    }

    /// <summary>
    /// Applies the named client's HttpMessageHandlerBuilderActions to an inspectable builder -
    /// the same mechanism DefaultHttpClientFactory uses to construct the handler pipeline.
    /// </summary>
    private static TestHandlerBuilder RunHandlerBuilderActions(IServiceCollection services)
    {
        using var provider = services.BuildServiceProvider();
        var factoryOptions = provider.GetRequiredService<IOptionsMonitor<HttpClientFactoryOptions>>()
            .Get(PortaHealthCheckDefaults.HttpClientName);
        var handlerBuilder = new TestHandlerBuilder(provider) { Name = PortaHealthCheckDefaults.HttpClientName };
        foreach (var action in factoryOptions.HttpMessageHandlerBuilderActions)
        {
            action(handlerBuilder);
        }
        return handlerBuilder;
    }

    private sealed class TestHandlerBuilder(IServiceProvider services) : HttpMessageHandlerBuilder
    {
        public override string? Name { get; set; }
        public override HttpMessageHandler PrimaryHandler { get; set; } = new HttpClientHandler();
        public override IList<DelegatingHandler> AdditionalHandlers { get; } = [];
        public override IServiceProvider Services { get; } = services;
        public override HttpMessageHandler Build() => throw new NotSupportedException();
    }
}
