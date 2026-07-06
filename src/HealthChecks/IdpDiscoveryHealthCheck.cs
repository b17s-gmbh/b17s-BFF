using System.Diagnostics;

using b17s.Porta.Auth.Tokens;
using b17s.Porta.Configuration;
using b17s.Porta.Telemetry;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;

namespace b17s.Porta.HealthChecks;

/// <summary>
/// Probes the IdP's OIDC discovery document (or <see cref="PortaHealthCheckOptions.IdpProbeUrl"/>)
/// over the network with the dedicated health HttpClient.
///
/// Deliberately does NOT go through <c>IDiscoveryService</c>: its ConfigurationManager caches the
/// discovery document, so a cached copy keeps reporting green throughout an IdP outage. Healthy
/// means a direct 2xx response; redirects count as failures (auto-redirect is disabled on the
/// probe client) because a redirecting authority breaks the OIDC handshake even if the redirect
/// target is fine.
///
/// Authorities are resolved lazily at execution time from Porta's auth options, so registration
/// order relative to the auth composites does not matter. Probes carry no credentials and never
/// record query strings or response bodies.
/// </summary>
internal sealed class IdpDiscoveryHealthCheck(
    IServiceProvider serviceProvider,
    PortaHealthCheckOptions options) : IHealthCheck
{
    private const string DiscoveryPath = "/.well-known/openid-configuration";

    /// <inheritdoc/>
    public async Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        var (urls, invalidAuthorities) = ResolveProbeUrls();

        if (urls.Count == 0 && invalidAuthorities.Count == 0)
        {
            return options.CheckIdpDiscovery == true
                ? new HealthCheckResult(
                    context.Registration.FailureStatus,
                    "CheckIdpDiscovery is enabled but no IdP authority is configured and no IdpProbeUrl is set.")
                : HealthCheckResult.Healthy("no IdP authority configured - probe skipped");
        }

        var telemetryEnabled = HealthCheckTelemetry.IsEnabled(serviceProvider);
        var client = serviceProvider.GetRequiredService<IHttpClientFactory>()
            .CreateClient(PortaHealthCheckDefaults.HttpClientName);

        // One shared deadline for the whole fan-out; authorities are probed in parallel so N
        // authorities don't divide the budget. Linked CTS instead of registration/client
        // timeouts so a timeout still reports the *configured* failure status (the framework
        // maps its own timeout mechanisms to Unhealthy unconditionally).
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(options.ProbeTimeout);

        ProbeResult[] results;
        try
        {
            results = await Task.WhenAll(
                urls.Select(url => ProbeAsync(client, url, telemetryEnabled, cancellationToken, timeout.Token)));
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // Scrape aborted / host shutting down - not a dependency failure; let the
            // framework observe the cancellation instead of reporting a phantom outage.
            throw;
        }

        var data = new Dictionary<string, object>();
        for (var i = 0; i < results.Length; i++)
        {
            var suffix = results.Length == 1 && invalidAuthorities.Count == 0 ? "" : $"[{i}]";
            data[$"endpoint{suffix}"] = HostAndPath(results[i].Url);
            if (results[i].StatusCode is int statusCode)
            {
                data[$"status_code{suffix}"] = statusCode;
            }
            data[$"duration_ms{suffix}"] = (long)results[i].Elapsed.TotalMilliseconds;
        }

        var failures = results
            .Where(r => r.Error is not null)
            .Select(r => $"{HostAndPath(r.Url)}: {r.Error}")
            .Concat(invalidAuthorities.Select(a => $"authority '{a}' is not an absolute URI"))
            .ToList();

        if (failures.Count > 0)
        {
            return new HealthCheckResult(
                context.Registration.FailureStatus, string.Join("; ", failures), data: data);
        }

        return HealthCheckResult.Healthy(
            results.Length == 1
                ? "IdP discovery endpoint reachable"
                : $"all {results.Length} IdP discovery endpoints reachable",
            data);
    }

    /// <summary>
    /// Probes one URL. Never throws for dependency problems - timeouts, network errors, and
    /// unexpected responses come back as a <see cref="ProbeResult"/> with <c>Error</c> set so
    /// the aggregate result can honor the configured failure status. Only external cancellation
    /// propagates.
    /// </summary>
    private async Task<ProbeResult> ProbeAsync(
        HttpClient client, Uri url, bool telemetryEnabled,
        CancellationToken externalToken, CancellationToken probeToken)
    {
        using var activity = HealthCheckTelemetry.StartProbe(telemetryEnabled, "idp");
        var stopwatch = Stopwatch.StartNew();
        try
        {
            using var request = new HttpRequestMessage(new HttpMethod(options.IdpProbeMethod), url);
            using var response = await client.SendAsync(
                request, HttpCompletionOption.ResponseHeadersRead, probeToken);
            stopwatch.Stop();

            var statusCode = (int)response.StatusCode;
            activity?.SetTag(PortaActivitySource.Tags.HttpStatusCode, statusCode);

            string? error = null;
            if (statusCode is < 200 or >= 300)
            {
                error = statusCode is >= 300 and < 400
                    ? $"redirected ({statusCode}) to '{RedirectTarget(response.Headers.Location)}' - " +
                      "the discovery endpoint must answer 2xx directly"
                    : $"unexpected status {statusCode}";
            }

            HealthCheckTelemetry.CompleteProbe(activity, error is null, error);
            return new ProbeResult(url, statusCode, stopwatch.Elapsed, error);
        }
        catch (OperationCanceledException) when (externalToken.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            HealthCheckTelemetry.CompleteProbe(activity, success: false, "timeout");
            return new ProbeResult(url, null, stopwatch.Elapsed,
                $"timed out after {options.ProbeTimeout.TotalSeconds:0.###}s");
        }
        catch (Exception ex)
        {
            HealthCheckTelemetry.CompleteProbe(activity, success: false, ex.Message);
            return new ProbeResult(url, null, stopwatch.Elapsed, $"unreachable: {ex.Message}");
        }
    }

    private (List<Uri> Urls, List<string> InvalidAuthorities) ResolveProbeUrls()
    {
        if (!string.IsNullOrWhiteSpace(options.IdpProbeUrl))
        {
            // Validated absolute http/https in AddPortaHealthChecks; authorities are ignored.
            return ([new Uri(options.IdpProbeUrl, UriKind.Absolute)], []);
        }

        var authorities = new[]
            {
                serviceProvider.GetService<IOptions<SessionAuthenticationConfiguration>>()?.Value.Authority,
                serviceProvider.GetService<IOptions<ReferenceTokenAuthOptions>>()?.Value.Authority,
            }
            .Where(a => !string.IsNullOrWhiteSpace(a))
            .Select(a => a!.TrimEnd('/'))
            .Distinct(StringComparer.OrdinalIgnoreCase);

        var urls = new List<Uri>();
        var invalid = new List<string>();
        foreach (var authority in authorities)
        {
            if (Uri.TryCreate(authority + DiscoveryPath, UriKind.Absolute, out var url))
            {
                urls.Add(url);
            }
            else
            {
                invalid.Add(authority);
            }
        }
        return (urls, invalid);
    }

    /// <summary>Host+path only - no query strings, no fragments (rule: probes leak nothing).</summary>
    private static string HostAndPath(Uri url)
        => url.IsAbsoluteUri ? $"{url.Host}{url.AbsolutePath}" : url.ToString();

    private static string RedirectTarget(Uri? location)
        => location is null ? "<no Location header>" : HostAndPath(location);

    private readonly record struct ProbeResult(Uri Url, int? StatusCode, TimeSpan Elapsed, string? Error);
}
