using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace b17s.Porta.HealthChecks;

/// <summary>
/// Options for <see cref="Extensions.HealthCheckExtensions.AddPortaHealthChecks"/>.
///
/// Each <c>Check*</c> switch is tri-state:
/// <list type="bullet">
///   <item><description><see langword="null"/> (default) - auto: the check is registered and probes
///   if its dependency is configured/resolvable at execution time, otherwise it reports Healthy
///   with a "skipped" description.</description></item>
///   <item><description><see langword="true"/> - required: a missing/unconfigured dependency is
///   reported with the check's failure status instead of being skipped.</description></item>
///   <item><description><see langword="false"/> - the check is never registered.</description></item>
/// </list>
/// </summary>
public sealed class PortaHealthCheckOptions
{
    /// <summary>
    /// Upper bound for each check's probe work (the whole IdP probe fan-out, the cache
    /// round-trip, the key-store connectivity call). Enforced with a linked
    /// <see cref="CancellationTokenSource"/> inside the check - deliberately not via
    /// <see cref="HealthCheckRegistration.Timeout"/> or <c>HttpClient.Timeout</c>, both of
    /// which the framework maps to <see cref="HealthStatus.Unhealthy"/> unconditionally,
    /// overriding the configured failure statuses. Defaults to 5 seconds.
    /// </summary>
    public TimeSpan ProbeTimeout { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>
    /// Tri-state switch for the <c>porta:idp-discovery</c> check (see class remarks).
    /// In auto mode the check probes the OIDC discovery document of every distinct authority
    /// found on Porta's auth options and skips when none is configured.
    /// </summary>
    public bool? CheckIdpDiscovery { get; set; }

    /// <summary>
    /// Absolute http/https URL to probe instead of resolving
    /// <c>{authority}/.well-known/openid-configuration</c> from Porta's auth options.
    /// Use when the IdP exposes a dedicated health endpoint or sits behind a gateway where
    /// the discovery document is not the right liveness signal.
    /// </summary>
    public string? IdpProbeUrl { get; set; }

    /// <summary>
    /// HTTP method for the IdP probe: <c>GET</c> (default) or <c>HEAD</c>. HEAD saves the
    /// response body but not every IdP supports it on the discovery endpoint.
    /// </summary>
    public string IdpProbeMethod { get; set; } = "GET";

    /// <summary>
    /// Status reported when the IdP probe fails. Defaults to <see cref="HealthStatus.Degraded"/>:
    /// an unreachable IdP blocks new sign-ins and token refreshes, but existing sessions keep
    /// working, so pulling the pod from rotation (readiness failure) would not help.
    /// </summary>
    public HealthStatus IdpFailureStatus { get; set; } = HealthStatus.Degraded;

    /// <summary>
    /// Tri-state switch for the <c>porta:store:distributed-cache</c> check (see class remarks).
    /// In auto mode the check round-trips the registered <c>IDistributedCache</c> (sessions,
    /// refresh locks, revocation, HybridCache L2) and skips when none is registered.
    /// </summary>
    public bool? CheckDistributedCache { get; set; }

    /// <summary>
    /// Status reported when the distributed-cache probe fails. Defaults to
    /// <see cref="HealthStatus.Unhealthy"/>: a dead session store fails every authenticated
    /// route, so the pod should leave rotation.
    /// </summary>
    public HealthStatus DistributedCacheFailureStatus { get; set; } = HealthStatus.Unhealthy;

    /// <summary>
    /// Tri-state switch for the <c>porta:store:data-protection</c> check (see class remarks).
    /// In auto mode the check protect/unprotect round-trips the key ring, additionally verifies
    /// key-store database connectivity when Porta's EF-backed key store is registered, and skips
    /// when no <c>IDataProtectionProvider</c> is resolvable.
    /// </summary>
    public bool? CheckDataProtection { get; set; }

    /// <summary>
    /// Status reported when the Data Protection probe fails. Defaults to
    /// <see cref="HealthStatus.Degraded"/>: the cached key ring keeps existing traffic working
    /// for a while, so an unreachable key store is a warning, not an immediate outage.
    /// </summary>
    public HealthStatus DataProtectionFailureStatus { get; set; } = HealthStatus.Degraded;
}

/// <summary>
/// Well-known names used by <see cref="Extensions.HealthCheckExtensions.AddPortaHealthChecks"/>,
/// e.g. for <c>MapHealthChecks</c> predicates or for customizing the probe HttpClient.
/// </summary>
public static class PortaHealthCheckDefaults
{
    /// <summary>Name of the HttpClient used for IdP probes.</summary>
    public const string HttpClientName = "Porta.HealthCheck";

    /// <summary>Name of the IdP discovery check.</summary>
    public const string IdpDiscoveryName = "porta:idp-discovery";

    /// <summary>Name of the distributed-cache (session store) check.</summary>
    public const string DistributedCacheName = "porta:store:distributed-cache";

    /// <summary>Name of the Data Protection key ring / key store check.</summary>
    public const string DataProtectionName = "porta:store:data-protection";

    /// <summary>Tag applied to every Porta check.</summary>
    public const string PortaTag = "porta";

    /// <summary>Readiness tag applied to every Porta check.</summary>
    public const string ReadyTag = "ready";
}

/// <summary>
/// Marker singleton: its presence on the IServiceCollection means AddPortaHealthChecks already
/// ran (second call throws). Also carries app-lifetime state shared across check executions -
/// check instances themselves are created fresh for every execution by the registration factory.
/// </summary>
internal sealed class PortaHealthCheckState
{
    private int _memoryCacheWarned;

    /// <summary>
    /// True exactly once per app lifetime. Interlocked because health check executions can
    /// overlap (concurrent scrapes from multiple probes).
    /// </summary>
    public bool TryClaimMemoryDistributedCacheWarning()
        => Interlocked.Exchange(ref _memoryCacheWarned, 1) == 0;
}
