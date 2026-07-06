using b17s.Porta.Data;

using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace b17s.Porta.HealthChecks;

/// <summary>
/// Verifies the Data Protection material Porta depends on for session tickets and
/// refresh-token encryption, in two probes:
/// <list type="number">
///   <item><description>Key ring: <c>Protect</c>/<c>Unprotect</c> round-trip. <c>Protect</c>
///   throws when the key ring cannot be loaded or automatic key generation is disabled with no
///   valid default key. Note a reachable-but-empty key store passes - the framework silently
///   creates a fresh key there, which is healthy behavior, not a failure.</description></item>
///   <item><description>Key store: when Porta's EF-backed <see cref="DataProtectionDbContext"/>
///   is registered, <c>Database.CanConnectAsync</c> confirms the key database is reachable.
///   </description></item>
/// </list>
/// The key ring is cached in-process, so this is not live secret-store monitoring: a vault or
/// certificate outage surfaces at key rotation, not on the next scrape (called out in the docs).
/// </summary>
internal sealed class DataProtectionHealthCheck(
    IServiceProvider serviceProvider,
    PortaHealthCheckOptions options) : IHealthCheck
{
    /// <inheritdoc/>
    public async Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        // Lazy resolution at execution time so registration order doesn't matter.
        var provider = serviceProvider.GetService<IDataProtectionProvider>();
        if (provider is null)
        {
            return options.CheckDataProtection == true
                ? new HealthCheckResult(
                    context.Registration.FailureStatus,
                    "CheckDataProtection is enabled but no IDataProtectionProvider is registered.")
                : HealthCheckResult.Healthy("no IDataProtectionProvider registered - probe skipped");
        }

        var telemetryEnabled = HealthCheckTelemetry.IsEnabled(serviceProvider);
        using var activity = HealthCheckTelemetry.StartProbe(telemetryEnabled, "data-protection");

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(options.ProbeTimeout);

        var data = new Dictionary<string, object>();
        var stage = "key ring";
        try
        {
            var protector = provider.CreateProtector("Porta.HealthCheck");
            var payload = Guid.NewGuid().ToString("N");
            // Protect triggers a synchronous key-ring load on the first scrape after startup (or
            // after a key-ring reload). ProbeTimeout does NOT bound this: the linked CTS can't
            // interrupt a blocking synchronous call. Accepted because Porta's EF key ring is loaded
            // eagerly at startup and cached in-process (see class doc); only the CanConnectAsync
            // probe below is timeout-bounded.
            if (!string.Equals(payload, protector.Unprotect(protector.Protect(payload)), StringComparison.Ordinal))
            {
                HealthCheckTelemetry.CompleteProbe(activity, success: false, "round-trip mismatch");
                return new HealthCheckResult(
                    context.Registration.FailureStatus,
                    "Data Protection key ring round-trip mismatch", data: data);
            }
            data["key_ring"] = "ok";

            // The health-check framework runs each execution in its own DI scope and hands the
            // scoped provider to the registration factory, so the scoped DbContext resolves here
            // directly; nothing is captured across executions.
            stage = "key store";
            var dbContext = serviceProvider.GetService<DataProtectionDbContext>();
            if (dbContext is not null)
            {
                if (!await dbContext.Database.CanConnectAsync(timeout.Token))
                {
                    HealthCheckTelemetry.CompleteProbe(activity, success: false, "key store unreachable");
                    return new HealthCheckResult(
                        context.Registration.FailureStatus,
                        "Data Protection key store database is unreachable", data: data);
                }
                data["key_store_db"] = "ok";
            }

            HealthCheckTelemetry.CompleteProbe(activity, success: true);
            return HealthCheckResult.Healthy(
                dbContext is null
                    ? "Data Protection key ring operational"
                    : "Data Protection key ring operational; key store database reachable",
                data);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // Scrape aborted / host shutting down - not a dependency failure.
            throw;
        }
        catch (OperationCanceledException)
        {
            HealthCheckTelemetry.CompleteProbe(activity, success: false, "timeout");
            return new HealthCheckResult(
                context.Registration.FailureStatus,
                $"Data Protection {stage} probe timed out after {options.ProbeTimeout.TotalSeconds:0.###}s",
                data: data);
        }
        catch (Exception ex)
        {
            HealthCheckTelemetry.CompleteProbe(activity, success: false, ex.Message);
            return new HealthCheckResult(
                context.Registration.FailureStatus,
                $"Data Protection {stage} probe failed", ex, data);
        }
    }
}
