using System.Text.Json;
using System.Text.Encodings.Web;

using b17s.Porta.Configuration;
using b17s.Porta.Extensions;
using b17s.Porta.Telemetry;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;

namespace b17s.Porta.Auth;

internal sealed class ChallengeDispatchHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    IOptions<SessionAuthenticationConfiguration> configuration,
    OidcEndpointPipelineRegistry registry,
    IOptions<PortaCoreOptions> coreOptions,
    PortaMetrics? metrics = null)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    internal const string SchemeName = "PortaChallenge";
    private readonly PortaMetrics? _metrics = coreOptions.Value.EnableTelemetry ? metrics : null;

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        => Task.FromResult(AuthenticateResult.NoResult());

    protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        var challenge = configuration.Value.Challenge;
        var redirect = challenge.Mode switch
        {
            ChallengeDispatchMode.Interactive => true,
            ChallengeDispatchMode.Unauthorized => false,
            _ => challenge.Classifier?.Invoke(Context) ?? ChallengeRequestClassifier.IsInteractive(Request),
        };

        _metrics?.RecordAuthenticationChallenge(redirect ? "redirect" : "unauthorized");

        if (redirect)
        {
            await Context.ChallengeAsync(OpenIdConnectDefaults.AuthenticationScheme, properties);
            return;
        }

        Response.StatusCode = StatusCodes.Status401Unauthorized;
        Response.ContentType = "application/problem+json";
        Response.Headers.CacheControl = "no-store";
        Response.Headers.Vary = "Sec-Fetch-Mode, Sec-Fetch-Dest, Accept";

        if (HttpMethods.IsHead(Request.Method))
            return;

        var loginPath = challenge.LoginPath ?? registry.GetLoginPath() ?? "/bff/login";
        var login = Request.PathBase.Add(new PathString(loginPath)).Value;
        await JsonSerializer.SerializeAsync(Response.Body, new
        {
            type = "urn:porta:session-expired",
            title = "Authentication required",
            status = StatusCodes.Status401Unauthorized,
            login,
        }, cancellationToken: Context.RequestAborted);
    }

    protected override Task HandleForbiddenAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = StatusCodes.Status403Forbidden;
        return Task.CompletedTask;
    }
}

internal static class ChallengeRequestClassifier
{
    public static bool IsInteractive(HttpRequest request)
    {
        if (!HttpMethods.IsGet(request.Method) && !HttpMethods.IsHead(request.Method))
            return false;

        var mode = request.Headers["Sec-Fetch-Mode"].ToString();
        var destination = request.Headers["Sec-Fetch-Dest"].ToString();
        var hasFetchMetadata = request.Headers.Any(h =>
            h.Key.StartsWith("Sec-Fetch-", StringComparison.OrdinalIgnoreCase));

        if (hasFetchMetadata)
        {
            return string.Equals(mode, "navigate", StringComparison.OrdinalIgnoreCase)
                && string.Equals(destination, "document", StringComparison.OrdinalIgnoreCase);
        }

        var accept = request.GetTypedHeaders().Accept;
        if (accept is null)
            return false;

        return accept.Any(value =>
            value.Quality.GetValueOrDefault(1) > 0
            && (value.MediaType.Equals("text/html", StringComparison.OrdinalIgnoreCase)
                || value.MediaType.Equals("text/*", StringComparison.OrdinalIgnoreCase)));
    }
}
