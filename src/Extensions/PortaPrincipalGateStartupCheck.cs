using b17s.Porta.Transformers;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace b17s.Porta.Extensions;

/// <summary>
/// Surfaces the silent authentication gap at startup: a Porta endpoint that requires an authenticated
/// principal (it stamps <c>RequireAuthorization()</c>) while <b>no</b> ASP.NET Core authentication
/// scheme is registered to populate <see cref="Microsoft.AspNetCore.Http.HttpContext.User"/>. In that
/// configuration every such endpoint rejects every request with <c>401</c> before the pipeline runs -
/// a surprising failure that the per-endpoint metadata makes detectable here.
/// </summary>
/// <remarks>
/// This logs at <see cref="LogLevel.Critical"/> rather than throwing: an endpoint that authenticates
/// via an in-pipeline <c>IAuthenticationProvider</c> and is correctly marked
/// <c>.AllowAnonymousWithOptionalAuth()</c> stamps "does not require a principal" and is not counted,
/// so the check is precise - but a consumer
/// may still have an intentional reason for a scheme-less host, and failing the boot outright would be
/// heavier-handed than the fail-fast HttpClient/HA checks that guard unambiguous misconfigurations.
/// <para/>
/// This is deliberately a coarse smoke check: it asserts only that <em>some</em> scheme exists, not
/// that a scheme is actually wired to authenticate the gated endpoints. A misrouted multi-scheme setup
/// (e.g. the gated endpoints forward to a scheme that never populates the principal) still passes. It
/// catches the common "no scheme registered at all" mistake, not every authentication misconfiguration.
/// </remarks>
internal sealed class PortaPrincipalGateStartupCheck(
    ILogger<PortaPrincipalGateStartupCheck> logger,
    IServiceProvider services) : IHostedService
{
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        // Endpoints are mapped during pipeline build, before hosted services start, so the data
        // sources are populated by the time this runs.
        var requiresPrincipal = services.GetServices<EndpointDataSource>()
            .SelectMany(source => source.Endpoints)
            .Any(endpoint =>
                endpoint.Metadata.GetMetadata<PortaPrincipalRequirementMetadata>()?.RequiresAuthenticatedPrincipal == true);

        if (!requiresPrincipal)
        {
            return;
        }

        var schemeProvider = services.GetService<IAuthenticationSchemeProvider>();
        var hasScheme = schemeProvider is not null && (await schemeProvider.GetAllSchemesAsync()).Any();

        if (!hasScheme)
        {
            logger.NoAuthenticationSchemeForPrincipalGate();
        }
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}

internal static partial class PortaPrincipalGateStartupCheckLogging
{
    [LoggerMessage(EventId = 14700, Level = LogLevel.Critical,
        Message = "Porta: one or more endpoints require an authenticated user (RequireAuthorization) but no " +
                  "ASP.NET Core authentication scheme is registered to populate HttpContext.User - those " +
                  "endpoints will reject every request with 401. Register a scheme (AddPortaAuthentication, " +
                  "AddPortaJwtAuthentication, or AddPortaReferenceTokenScheme); or, for an in-pipeline " +
                  "IAuthenticationProvider (e.g. a custom API key), mark those endpoints " +
                  ".AllowAnonymousWithOptionalAuth() and enforce identity in the transformer " +
                  "(plain .AllowAnonymous() is credential-blind and never consults the provider).")]
    public static partial void NoAuthenticationSchemeForPrincipalGate(this ILogger logger);
}
