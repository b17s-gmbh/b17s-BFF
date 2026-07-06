using b17s.Porta.Configuration;
using b17s.Porta.Extensions;
using b17s.Porta.Transformers;

using Demo.Bff;

using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.Extensions.Diagnostics.HealthChecks;

var builder = WebApplication.CreateBuilder(args);

builder.AddServiceDefaults();

// ---------------------------------------------------------------------------
// Distributed cache — Valkey (see AppHost's "cache" resource).
//
// Registers IDistributedCache backed by the Valkey container the AppHost injected the "cache"
// connection string for. This is Porta's HA "thing #1": the auth ticket store, server-side
// session store, and refresh lock all live in IDistributedCache. A real registration here wins
// over Porta's in-memory fallback (order relative to AddPortaOidcAuth does not matter), so both
// BFF instances share one session store and the /health/ready page's distributed-cache probe
// reports against real Valkey. Valkey speaks the Redis wire protocol, so the StackExchange.Redis
// client integration connects to it unchanged. See docs/ha-deployment.md.
// ---------------------------------------------------------------------------
builder.AddRedisDistributedCache("cache");

// ---------------------------------------------------------------------------
// Zitadel auto-provisioning hand-off.
//
// Keycloak's client (id + secret) is baked into the imported realm, so the AppHost can
// pass it straight through as env vars. Zitadel has no realm-import equivalent, so the
// Demo.ZitadelProvisioner creates the OIDC app at runtime and writes the resulting
// client id/secret to a JSON file. When the AppHost points us at that file we layer it
// over configuration so the OidcAuth section is complete before AddPortaOidcAuth binds it.
// (The AppHost gates this BFF on the provisioner completing, so the file already exists.)
// ---------------------------------------------------------------------------
var clientFile = builder.Configuration["Demo:OidcClientFile"];
if (!string.IsNullOrWhiteSpace(clientFile))
{
    builder.Configuration.AddJsonFile(clientFile, optional: true, reloadOnChange: true);
}

// Porta core: backend caller, transformer infrastructure, trusted-host validation.
// TrustedHosts (the backend URL) comes from the PortaCore config section.
builder.Services.AddPortaCore(builder.Configuration);

// Service credentials the BFF presents to the backend for BackendAuthPolicies.BasicAuth.
// Porta reads these from BackendServiceOptions but does not bind the section itself, so the
// consumer wires it up. The Username/Password come from the BackendService config section
// (supplied by the AppHost via env vars). Secret-classified - never logged.
builder.Services.Configure<BackendServiceOptions>(
    builder.Configuration.GetSection(BackendServiceOptions.SectionName));

// Session-based OIDC authentication. Authority / ClientId / ClientSecret / cookie policy
// all come from the OidcAuth config section (supplied per-IdP by the AppHost via env vars).
builder.Services.AddPortaOidcAuth(builder.Configuration);

// Porta's opt-in readiness health checks: idp-discovery (probes the configured IdP's discovery
// document, bypassing the cached ConfigurationManager), distributed-cache, and data-protection.
// Registration only - Porta never maps endpoints; this BFF exposes them below at /health/ready.
builder.Services.AddPortaHealthChecks();

// A custom transformer that aggregates two backend calls into one BFF response.
builder.Services.AddTransformer<UserDashboardTransformer>();

// Server-rendered landing page (Razor Pages) so the demo is clickable in a browser without a SPA.
builder.Services.AddRazorPages();

var app = builder.Build();

app.MapDefaultEndpoints();

app.UseStaticFiles();

app.UseAuthentication();
app.UseAuthorization();

// Porta's opt-in OIDC endpoints: /bff/login, /bff/logout, /bff/backchannel-logout.
app.UseOidcLogin();
app.UseOidcLogout();
app.UseOidcBackChannelLogout();

var backendUrl = builder.Configuration["Demo:BackendUrl"]
    ?? throw new InvalidOperationException("Demo:BackendUrl is not configured.");
var providerLabel = builder.Configuration["Demo:ProviderLabel"] ?? "OIDC";

// Landing page: a Razor Page (Pages/Index.cshtml, routed to "/") that shows who you are
// and links to the flows. Anonymous so you can see the "logged out" state before authenticating.
app.MapRazorPages();

// Readiness probe (dev-only) for the demo's "Check health" button: Porta's checks (tagged
// "ready") rendered as JSON so the landing page can show each dependency probe individually.
// Anonymous - readiness must answer before any session exists, and RequireAuthorizationByDefault
// would otherwise gate it. Stop the IdP container in the Aspire dashboard and re-run to watch
// porta:idp-discovery flip to Unhealthy (HTTP 503) while /alive stays green. (ServiceDefaults'
// MapDefaultEndpoints already maps /health and /alive; this adds a JSON, per-check readiness view.)
if (app.Environment.IsDevelopment())
{
    app.MapHealthChecks("/health/ready", new HealthCheckOptions
    {
        Predicate = registration => registration.Tags.Contains("ready"),
        ResponseWriter = WriteHealthJson,
    }).AllowAnonymous();
}

// Who-am-I: the BFF session identity (claims pulled from the auth cookie).
app.MapGet("/bff/user", (HttpContext ctx) =>
{
    var claims = ctx.User.Claims
        .GroupBy(c => c.Type)
        .ToDictionary(g => g.Key, g => g.Count() == 1 ? (object)g.First().Value : g.Select(c => c.Value).ToArray());
    return Results.Ok(new { authenticated = true, provider = providerLabel, claims });
}).RequireAuthorization();

// Zero-code pass-through: public backend data, no auth, forwarded as-is.
app.MapPassThrough<WeatherForecast[]>()
    .FromGet("/api/weather")
    .ToBackend("GET", $"{backendUrl}/weather")
    .AllowAnonymous()
    .Build();

// Service-to-service pass-through: requires an authenticated BFF session (the default), but the
// credential the BFF presents to the backend is NOT the user's token - it authenticates with its
// OWN service credentials over HTTP Basic (BackendAuthPolicies.BasicAuth, sourced from the
// BackendService config section). This is the machine-to-machine / service-account pattern - the
// backend's /internal endpoint rejects any call without valid Basic credentials, so this only
// succeeds because the BFF supplies them.
app.MapPassThrough<InternalResource>()
    .FromGet("/api/internal")
    .ToBackend("GET", $"{backendUrl}/internal")
    .WithBackendAuth(BackendAuthPolicies.BasicAuth)
    .Build();

// Zero-code pass-through that forwards the *user's* access token to the backend
// (BackendAuthPolicies.BearerToken). Auth is required by default (RequireAuthorizationByDefault).
app.MapPassThrough<BackendIdentity>()
    .FromGet("/api/me")
    .ToBackend("GET", $"{backendUrl}/me")
    .WithBackendAuth(BackendAuthPolicies.BearerToken)
    .Build();

// Aggregating transformer with MIXED per-backend auth: one BFF call fans out to three backends
// in parallel, each authenticating to its backend with a DIFFERENT policy -
//   me       -> BearerToken (forwards the user's access token)
//   weather  -> None        (public backend data, no credentials)
//   internal -> BasicAuth   (the BFF's own service credentials)
// Each NamedBackendEndpoint carries its own BackendAuthPolicy, which overrides the endpoint-level
// default - so there is no single .WithBackendAuth(...) here; the policy is set per backend.
app.MapTransformer<UserDashboardTransformer, DashboardResponse>()
    .FromGet("/api/dashboard")
    .ToBackends(
        new NamedBackendEndpoint
        {
            Name = "me",
            Method = "GET",
            UrlTemplate = $"{backendUrl}/me",
            BackendAuthPolicy = BackendAuthPolicies.BearerToken,
        },
        new NamedBackendEndpoint
        {
            Name = "weather",
            Method = "GET",
            UrlTemplate = $"{backendUrl}/weather",
            BackendAuthPolicy = BackendAuthPolicies.None,
        },
        new NamedBackendEndpoint
        {
            Name = "internal",
            Method = "GET",
            UrlTemplate = $"{backendUrl}/internal",
            BackendAuthPolicy = BackendAuthPolicies.BasicAuth,
        })
    .Build();

app.Run();

// Renders a HealthReport as JSON with a per-check breakdown (name / status / description /
// duration / data) so the demo page can list each Porta probe instead of a bare "Healthy".
static Task WriteHealthJson(HttpContext context, HealthReport report)
{
    context.Response.ContentType = "application/json";
    return context.Response.WriteAsJsonAsync(new
    {
        status = report.Status.ToString(),
        totalDurationMs = (long)report.TotalDuration.TotalMilliseconds,
        checks = report.Entries.Select(entry => new
        {
            name = entry.Key,
            status = entry.Value.Status.ToString(),
            description = entry.Value.Description,
            durationMs = (long)entry.Value.Duration.TotalMilliseconds,
            error = entry.Value.Exception?.Message,
            data = entry.Value.Data.Count > 0 ? entry.Value.Data : null,
        }),
    });
}

namespace Demo.Bff
{
    /// <summary>Weather item returned by the backend (BFF-side DTO for deserialization).</summary>
    internal record WeatherForecast(DateOnly Date, int TemperatureC, int TemperatureF, string? Summary);

    /// <summary>Proof payload returned by the backend's Basic-auth-protected <c>/internal</c> endpoint.</summary>
    internal record InternalResource(
        string ServedBy,
        bool BasicAuthValidated,
        string AuthenticatedAs,
        string Message);

    /// <summary>Identity echo returned by the backend's <c>/me</c> endpoint.</summary>
    internal record BackendIdentity(
        string ServedBy,
        bool UserTokenForwarded,
        string? Subject,
        string? PreferredUsername,
        string? Issuer);

    /// <summary>Aggregated dashboard the BFF composes from multiple backend calls, each authenticated differently.</summary>
    internal record DashboardResponse(
        string Provider,
        BackendIdentity? Identity,
        WeatherForecast[] Weather,
        InternalResource? Internal);
}
