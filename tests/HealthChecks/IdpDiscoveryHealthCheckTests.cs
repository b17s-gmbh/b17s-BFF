using b17s.Porta.Auth.Tokens;
using b17s.Porta.Configuration;
using b17s.Porta.HealthChecks;
using b17s.Porta.Tests.Integration;

using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace b17s.Porta.Tests.HealthChecks;

// Emits activities through the shared Porta ActivitySource, so it must not run in
// parallel with tests that attach a global listener and count spans.
[Collection(PortaActivitySourceCollection.Name)]
public sealed class IdpDiscoveryHealthCheckTests
{
    private const string Authority = "https://idp.test";

    [Fact]
    public async Task ReachableDiscoveryDocument_IsHealthy_WithStatusAndDuration()
    {
        using var idp = new FakeIdp(Authority);
        var (check, _) = CreateCheck(idp.BackchannelHandler, sessionAuthority: idp.Authority);

        var result = await RunAsync(check);

        Assert.Equal(HealthStatus.Healthy, result.Status);
        Assert.Equal(200, result.Data["status_code"]);
        Assert.True(result.Data.ContainsKey("duration_ms"));
        Assert.Equal("idp.test/.well-known/openid-configuration", result.Data["endpoint"]);
    }

    [Fact]
    public async Task UnreachableIdp_ReportsFailureStatus()
    {
        var (check, _) = CreateCheck(
            new StubHandler((_, _) => throw new HttpRequestException("connection refused")),
            sessionAuthority: Authority);

        var result = await RunAsync(check, HealthStatus.Degraded);

        Assert.Equal(HealthStatus.Degraded, result.Status);
        Assert.Contains("unreachable", result.Description);
    }

    [Fact]
    public async Task Non2xxStatus_ReportsFailureStatus()
    {
        var (check, _) = CreateCheck(
            StubHandler.RespondWith(HttpStatusCode.InternalServerError),
            sessionAuthority: Authority);

        var result = await RunAsync(check, HealthStatus.Unhealthy);

        Assert.Equal(HealthStatus.Unhealthy, result.Status);
        Assert.Contains("500", result.Description);
    }

    [Fact]
    public async Task Redirect_IsAFailure_AndNamesTheTarget()
    {
        var (check, _) = CreateCheck(
            new StubHandler((_, _) =>
            {
                var response = new HttpResponseMessage(HttpStatusCode.Redirect);
                response.Headers.Location = new Uri("https://sso.other/realms/x/.well-known/openid-configuration?probe=1");
                return Task.FromResult(response);
            }),
            sessionAuthority: Authority);

        var result = await RunAsync(check);

        Assert.Equal(HealthStatus.Degraded, result.Status);
        Assert.Contains("redirected (302)", result.Description);
        // Host+path only - the query string must not leak into the description.
        Assert.Contains("sso.other", result.Description);
        Assert.DoesNotContain("probe=1", result.Description);
    }

    [Fact]
    public async Task DelayPastProbeTimeout_ReportsFailureStatus_MentioningTimeout()
    {
        var (check, _) = CreateCheck(
            new StubHandler(async (_, ct) =>
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, ct);
                throw new UnreachableException();
            }),
            sessionAuthority: Authority,
            configure: o => o.ProbeTimeout = TimeSpan.FromMilliseconds(100));

        var result = await RunAsync(check);

        Assert.Equal(HealthStatus.Degraded, result.Status);
        Assert.Contains("timed out", result.Description);
    }

    [Fact]
    public async Task ExternalCancellation_PropagatesInsteadOfReportingFailure()
    {
        var (check, _) = CreateCheck(
            new StubHandler(async (_, ct) =>
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, ct);
                throw new UnreachableException();
            }),
            sessionAuthority: Authority);

        using var cts = new CancellationTokenSource();
        cts.CancelAfter(TimeSpan.FromMilliseconds(50));

        // A cancelled scrape / shutting-down host is not an IdP outage.
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => RunAsync(check, ct: cts.Token));
    }

    [Fact]
    public async Task Probe_SendsNoCredentials_AndHonorsHead()
    {
        var seen = new List<(HttpMethod Method, bool HasAuthorization, bool HasCookie)>();
        var (check, _) = CreateCheck(
            new StubHandler((request, _) =>
            {
                seen.Add((request.Method,
                    request.Headers.Authorization is not null,
                    request.Headers.Contains("Cookie")));
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
            }),
            sessionAuthority: Authority,
            configure: o => o.IdpProbeMethod = "HEAD");

        var result = await RunAsync(check);

        Assert.Equal(HealthStatus.Healthy, result.Status);
        var probe = Assert.Single(seen);
        Assert.Equal(HttpMethod.Head, probe.Method);
        Assert.False(probe.HasAuthorization);
        Assert.False(probe.HasCookie);
    }

    [Fact]
    public async Task NoAuthorityConfigured_AutoMode_IsHealthySkipped()
    {
        var (check, _) = CreateCheck(StubHandler.RespondWith(HttpStatusCode.OK));

        var result = await RunAsync(check);

        Assert.Equal(HealthStatus.Healthy, result.Status);
        Assert.Contains("skipped", result.Description);
    }

    [Fact]
    public async Task NoAuthorityConfigured_CheckRequired_ReportsFailureStatus()
    {
        var (check, _) = CreateCheck(
            StubHandler.RespondWith(HttpStatusCode.OK),
            configure: o => o.CheckIdpDiscovery = true);

        var result = await RunAsync(check);

        Assert.Equal(HealthStatus.Degraded, result.Status);
        Assert.Contains("no IdP authority", result.Description);
    }

    [Fact]
    public async Task AuthorityFromReferenceTokenOptionsAlone_IsProbed()
    {
        var requested = new List<Uri?>();
        var (check, _) = CreateCheck(
            new StubHandler((request, _) =>
            {
                requested.Add(request.RequestUri);
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
            }),
            referenceTokenAuthority: "https://ref-idp.test/");

        var result = await RunAsync(check);

        Assert.Equal(HealthStatus.Healthy, result.Status);
        var url = Assert.Single(requested);
        Assert.Equal("https://ref-idp.test/.well-known/openid-configuration", url!.ToString());
    }

    [Fact]
    public async Task SameAuthorityOnBothOptions_IsProbedOnce()
    {
        var requested = new List<Uri?>();
        var (check, _) = CreateCheck(
            new StubHandler((request, _) =>
            {
                requested.Add(request.RequestUri);
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
            }),
            sessionAuthority: Authority,
            referenceTokenAuthority: Authority + "/");

        await RunAsync(check);

        Assert.Single(requested);
    }

    [Fact]
    public async Task IdpProbeUrl_IsProbedVerbatim_IgnoringAuthorities()
    {
        var requested = new List<Uri?>();
        var (check, _) = CreateCheck(
            new StubHandler((request, _) =>
            {
                requested.Add(request.RequestUri);
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
            }),
            sessionAuthority: Authority,
            configure: o => o.IdpProbeUrl = "https://idp.internal/health");

        var result = await RunAsync(check);

        Assert.Equal(HealthStatus.Healthy, result.Status);
        var url = Assert.Single(requested);
        Assert.Equal("https://idp.internal/health", url!.ToString());
    }

    [Fact]
    public async Task MultipleAuthorities_OneFailing_FailsTheCheck_AndReportsWhich()
    {
        var (check, _) = CreateCheck(
            new StubHandler((request, _) => Task.FromResult(new HttpResponseMessage(
                request.RequestUri!.Host == "good.test" ? HttpStatusCode.OK : HttpStatusCode.ServiceUnavailable))),
            sessionAuthority: "https://good.test",
            referenceTokenAuthority: "https://bad.test");

        var result = await RunAsync(check);

        Assert.Equal(HealthStatus.Degraded, result.Status);
        Assert.Contains("bad.test", result.Description);
        Assert.DoesNotContain("good.test", result.Description);
    }

    [Fact]
    public async Task InvalidAuthority_ReportsFailureStatus_NamingIt()
    {
        var (check, _) = CreateCheck(
            StubHandler.RespondWith(HttpStatusCode.OK),
            sessionAuthority: "not-a-uri");

        var result = await RunAsync(check);

        Assert.Equal(HealthStatus.Degraded, result.Status);
        Assert.Contains("not-a-uri", result.Description);
        Assert.Contains("not an absolute URI", result.Description);
    }

    [Fact]
    public async Task MixedValidAndInvalidAuthorities_FailsTheCheck_AndIndexesEndpoints()
    {
        var (check, _) = CreateCheck(
            StubHandler.RespondWith(HttpStatusCode.OK),
            sessionAuthority: "https://good.test",
            referenceTokenAuthority: "not-a-uri");

        var result = await RunAsync(check);

        Assert.Equal(HealthStatus.Degraded, result.Status);
        Assert.Contains("not-a-uri", result.Description);
        // The valid authority was reachable, but the invalid one still fails the aggregate. With a
        // mix present, endpoint keys carry the [i] suffix rather than the single-endpoint bare key.
        Assert.Equal("good.test/.well-known/openid-configuration", result.Data["endpoint[0]"]);
        Assert.False(result.Data.ContainsKey("endpoint"));
    }

    private static (IdpDiscoveryHealthCheck Check, ServiceProvider Provider) CreateCheck(
        HttpMessageHandler handler,
        string? sessionAuthority = null,
        string? referenceTokenAuthority = null,
        Action<PortaHealthCheckOptions>? configure = null)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddHttpClient(PortaHealthCheckDefaults.HttpClientName)
            .ConfigurePrimaryHttpMessageHandler(() => handler);
        if (sessionAuthority is not null)
        {
            services.Configure<SessionAuthenticationConfiguration>(o => o.Authority = sessionAuthority);
        }
        if (referenceTokenAuthority is not null)
        {
            services.Configure<ReferenceTokenAuthOptions>(o => o.Authority = referenceTokenAuthority);
        }

        var options = new PortaHealthCheckOptions();
        configure?.Invoke(options);
        var provider = services.BuildServiceProvider();
        return (new IdpDiscoveryHealthCheck(provider, options), provider);
    }

    private static Task<HealthCheckResult> RunAsync(
        IHealthCheck check,
        HealthStatus failureStatus = HealthStatus.Degraded,
        CancellationToken? ct = null)
        => check.CheckHealthAsync(new HealthCheckContext
        {
            Registration = new HealthCheckRegistration("test", check, failureStatus, tags: null),
        }, ct ?? TestContext.Current.CancellationToken);

    private sealed class StubHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> respond)
        : HttpMessageHandler
    {
        public static StubHandler RespondWith(HttpStatusCode statusCode)
            => new((_, _) => Task.FromResult(new HttpResponseMessage(statusCode)));

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
            => respond(request, cancellationToken);
    }

    private sealed class UnreachableException : Exception;
}
