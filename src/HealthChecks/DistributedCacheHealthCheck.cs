using System.Diagnostics;

using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Logging;

namespace b17s.Porta.HealthChecks;

/// <summary>
/// Round-trips the registered <see cref="IDistributedCache"/> - the store Porta uses for
/// distributed sessions, refresh locks, revocation, and the HybridCache L2 - with a
/// set/get/compare on a unique throwaway key, removed afterwards and self-expiring in 30s
/// as a backstop.
///
/// A resolved <c>MemoryDistributedCache</c> is reported Healthy without probing (an in-process
/// dictionary can't fail) but logs a once-per-app-lifetime warning: it means sessions are NOT
/// shared across instances, which is almost never intended in a deployment that bothers with
/// readiness probes.
/// </summary>
internal sealed class DistributedCacheHealthCheck(
    IServiceProvider serviceProvider,
    PortaHealthCheckOptions options) : IHealthCheck
{
    /// <inheritdoc/>
    public async Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        // Lazy resolution at execution time so registration order doesn't matter.
        var cache = serviceProvider.GetService<IDistributedCache>();
        if (cache is null)
        {
            return options.CheckDistributedCache == true
                ? new HealthCheckResult(
                    context.Registration.FailureStatus,
                    "CheckDistributedCache is enabled but no IDistributedCache is registered.")
                : HealthCheckResult.Healthy("no IDistributedCache registered - probe skipped");
        }

        if (cache is MemoryDistributedCache)
        {
            var state = serviceProvider.GetRequiredService<PortaHealthCheckState>();
            if (state.TryClaimMemoryDistributedCacheWarning())
            {
                serviceProvider.GetRequiredService<ILogger<DistributedCacheHealthCheck>>()
                    .MemoryDistributedCacheDetected();
            }
            return HealthCheckResult.Healthy(
                "in-memory distributed cache - probe skipped; sessions are not shared across instances");
        }

        var implementation = cache.GetType().Name;
        var data = new Dictionary<string, object> { ["implementation"] = implementation };
        var telemetryEnabled = HealthCheckTelemetry.IsEnabled(serviceProvider);
        using var activity = HealthCheckTelemetry.StartProbe(telemetryEnabled, "distributed-cache");

        var key = $"porta:health:{Guid.NewGuid():N}";
        var payload = Guid.NewGuid().ToByteArray();

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(options.ProbeTimeout);
        var stopwatch = Stopwatch.StartNew();
        try
        {
            await cache.SetAsync(key, payload, new DistributedCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(30),
            }, timeout.Token);
            var readBack = await cache.GetAsync(key, timeout.Token);
            stopwatch.Stop();

            if (readBack is null || !payload.AsSpan().SequenceEqual(readBack))
            {
                HealthCheckTelemetry.CompleteProbe(activity, success: false, "read-back mismatch");
                return new HealthCheckResult(
                    context.Registration.FailureStatus,
                    $"distributed cache read-back mismatch ({implementation})", data: data);
            }

            data["duration_ms"] = (long)stopwatch.Elapsed.TotalMilliseconds;
            HealthCheckTelemetry.CompleteProbe(activity, success: true);
            return HealthCheckResult.Healthy(
                $"distributed cache round-trip succeeded ({implementation})", data);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // Scrape aborted / host shutting down - not a store failure.
            throw;
        }
        catch (OperationCanceledException)
        {
            HealthCheckTelemetry.CompleteProbe(activity, success: false, "timeout");
            return new HealthCheckResult(
                context.Registration.FailureStatus,
                $"distributed cache probe timed out after {options.ProbeTimeout.TotalSeconds:0.###}s ({implementation})",
                data: data);
        }
        catch (Exception ex)
        {
            HealthCheckTelemetry.CompleteProbe(activity, success: false, ex.Message);
            return new HealthCheckResult(
                context.Registration.FailureStatus,
                $"distributed cache probe failed ({implementation})", ex, data);
        }
        finally
        {
            // Best-effort cleanup within the remaining probe budget; skipped when the budget is
            // spent (a dead store would hang an unbounded RemoveAsync). The 30s absolute
            // expiration deletes stragglers either way.
            if (!timeout.IsCancellationRequested)
            {
                try
                {
                    await cache.RemoveAsync(key, timeout.Token);
                }
                catch
                {
                    // The probe verdict is already decided; cleanup failures add nothing.
                }
            }
        }
    }
}

/// <summary>
/// High-performance logging for the Porta health checks.
/// EventId range 14800-14809 is reserved for this category (14700-14704 belongs to the
/// backend-caching layer) so EventId-based filtering can tell them apart.
/// </summary>
internal static partial class PortaHealthCheckLogging
{
    [LoggerMessage(EventId = 14800, Level = LogLevel.Warning,
        Message = "The registered IDistributedCache is the in-memory MemoryDistributedCache. The " +
                  "porta:store:distributed-cache health check reports Healthy without probing, but " +
                  "sessions, refresh locks, and revocation are NOT shared across instances. Configure " +
                  "a real distributed cache (e.g. Redis or SQL) for multi-instance deployments.")]
    public static partial void MemoryDistributedCacheDetected(this ILogger logger);
}
