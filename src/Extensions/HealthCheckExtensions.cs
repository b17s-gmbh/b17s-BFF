using b17s.Porta.HealthChecks;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Http.Resilience;

namespace b17s.Porta.Extensions;

/// <summary>
/// Registers Porta's opt-in health checks. Registration only: the library never calls
/// <c>MapHealthChecks</c> or adds middleware - the host decides whether and where to expose
/// the endpoints (see docs/health-checks.md for the recommended readiness/liveness split).
/// </summary>
public static class HealthCheckExtensions
{
    /// <summary>
    /// Adds Porta's health checks for the dependencies only Porta can check correctly:
    /// <list type="bullet">
    ///   <item><description><c>porta:idp-discovery</c> - probes the OIDC discovery document of
    ///   every authority configured on Porta's auth options (network-level, bypassing the cached
    ///   ConfigurationManager, which stays green during an IdP outage).</description></item>
    ///   <item><description><c>porta:store:distributed-cache</c> - round-trips the
    ///   <c>IDistributedCache</c> backing sessions, refresh locks, and revocation.</description></item>
    ///   <item><description><c>porta:store:data-protection</c> - verifies the Data Protection
    ///   key ring and, when Porta's EF key store is registered, key-database connectivity.
    ///   </description></item>
    /// </list>
    /// All checks are tagged <c>["porta", "ready"]</c> and auto-skip (Healthy with a "skipped"
    /// description) when their dependency isn't configured, so the one-liner is safe in every
    /// deployment shape. Call it once; a second call throws.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configure">Optional per-check overrides; see <see cref="PortaHealthCheckOptions"/>.</param>
    /// <returns>The <see cref="IHealthChecksBuilder"/>, so hosts can chain their own checks.</returns>
    /// <exception cref="InvalidOperationException">When called more than once.</exception>
    /// <exception cref="ArgumentException">When the configured options are invalid.</exception>
    public static IHealthChecksBuilder AddPortaHealthChecks(
        this IServiceCollection services,
        Action<PortaHealthCheckOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        if (services.Any(d => d.ServiceType == typeof(PortaHealthCheckState)))
        {
            throw new InvalidOperationException(
                "Porta: AddPortaHealthChecks() was called more than once on this service collection. " +
                "Register it once and use the options callback to adjust individual checks.");
        }

        var options = new PortaHealthCheckOptions();
        configure?.Invoke(options);
        Validate(options);

        services.AddSingleton<PortaHealthCheckState>();

        services.AddHttpClient(PortaHealthCheckDefaults.HttpClientName)
            .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler
            {
                // Probes carry no credentials and must observe redirects rather than follow
                // them: a redirecting discovery endpoint breaks the OIDC handshake even when
                // the redirect target responds 200.
                UseCookies = false,
                AllowAutoRedirect = false,
            })
            // A host-level ConfigureHttpClientDefaults(...AddStandardResilienceHandler()) must
            // not wrap probes in retries: a retried probe masks brief outages and stretches
            // every failure toward ProbeTimeout. Probes are health signals, not traffic.
            // (Manual strip because RemoveAllResilienceHandlers() is still [Experimental].)
            .ConfigureAdditionalHttpMessageHandlers((handlers, _) =>
            {
                for (var i = handlers.Count - 1; i >= 0; i--)
                {
                    if (handlers[i] is ResilienceHandler)
                    {
                        handlers.RemoveAt(i);
                    }
                }
            });

        var builder = services.AddHealthChecks();
        string[] tags = [PortaHealthCheckDefaults.PortaTag, PortaHealthCheckDefaults.ReadyTag];

        if (options.CheckIdpDiscovery != false)
        {
            builder.Add(new HealthCheckRegistration(
                PortaHealthCheckDefaults.IdpDiscoveryName,
                sp => new IdpDiscoveryHealthCheck(sp, options),
                options.IdpFailureStatus,
                tags));
        }

        if (options.CheckDistributedCache != false)
        {
            builder.Add(new HealthCheckRegistration(
                PortaHealthCheckDefaults.DistributedCacheName,
                sp => new DistributedCacheHealthCheck(sp, options),
                options.DistributedCacheFailureStatus,
                tags));
        }

        if (options.CheckDataProtection != false)
        {
            builder.Add(new HealthCheckRegistration(
                PortaHealthCheckDefaults.DataProtectionName,
                sp => new DataProtectionHealthCheck(sp, options),
                options.DataProtectionFailureStatus,
                tags));
        }

        return builder;
    }

    private static void Validate(PortaHealthCheckOptions options)
    {
        if (options.ProbeTimeout <= TimeSpan.Zero)
        {
            throw new ArgumentException(
                $"Porta: PortaHealthCheckOptions.ProbeTimeout must be positive, got '{options.ProbeTimeout}'.");
        }

        if (options.IdpProbeUrl is not null)
        {
            if (!Uri.TryCreate(options.IdpProbeUrl, UriKind.Absolute, out var url) ||
                (url.Scheme != Uri.UriSchemeHttp && url.Scheme != Uri.UriSchemeHttps))
            {
                throw new ArgumentException(
                    $"Porta: PortaHealthCheckOptions.IdpProbeUrl must be an absolute http/https URL, got '{options.IdpProbeUrl}'.");
            }
        }

        if (!string.Equals(options.IdpProbeMethod, "GET", StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(options.IdpProbeMethod, "HEAD", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException(
                $"Porta: PortaHealthCheckOptions.IdpProbeMethod must be GET or HEAD, got '{options.IdpProbeMethod}'.");
        }
    }
}
