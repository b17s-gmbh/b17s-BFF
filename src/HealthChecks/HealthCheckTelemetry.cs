using System.Diagnostics;

using b17s.Porta.Configuration;
using b17s.Porta.Telemetry;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace b17s.Porta.HealthChecks;

/// <summary>
/// Shared telemetry for the Porta health checks: one <see cref="PortaActivitySource.Activities.HealthCheck"/>
/// client span per probe, gated on <see cref="PortaCoreOptions.EnableTelemetry"/>.
/// </summary>
internal static class HealthCheckTelemetry
{
    /// <summary>
    /// Resolves the telemetry gate. Tolerates a container without Porta core registrations:
    /// the options infrastructure then yields a default <see cref="PortaCoreOptions"/>,
    /// whose <c>EnableTelemetry</c> defaults to enabled.
    /// </summary>
    public static bool IsEnabled(IServiceProvider serviceProvider)
        => serviceProvider.GetService<IOptions<PortaCoreOptions>>()?.Value.EnableTelemetry ?? true;

    /// <summary>Starts a probe span, or returns null when telemetry is disabled (or unsampled).</summary>
    public static Activity? StartProbe(bool enabled, string dependency)
    {
        if (!enabled)
        {
            return null;
        }

        var activity = PortaActivitySource.Source.StartActivity(
            PortaActivitySource.Activities.HealthCheck, ActivityKind.Client);
        activity?.SetTag(PortaActivitySource.Tags.Component, "health_check");
        activity?.SetTag(PortaActivitySource.Tags.BackendService, dependency);
        return activity;
    }

    /// <summary>Records the probe outcome and the HealthCheckPerformed event on the span.</summary>
    public static void CompleteProbe(Activity? activity, bool success, string? failureDescription = null)
    {
        if (activity is null)
        {
            return;
        }

        activity.SetTag(PortaActivitySource.Tags.HealthStatus, success ? "healthy" : "unhealthy");
        activity.SetStatus(
            success ? ActivityStatusCode.Ok : ActivityStatusCode.Error,
            success ? null : failureDescription);
        activity.AddEvent(new ActivityEvent(PortaActivitySource.Events.HealthCheckPerformed));
    }
}
