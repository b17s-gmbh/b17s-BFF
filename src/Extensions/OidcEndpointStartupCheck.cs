using b17s.Porta.Middleware;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace b17s.Porta.Extensions;

/// <summary>
/// Captures what the OIDC endpoint <see cref="Microsoft.AspNetCore.Builder.IApplicationBuilder"/>
/// extensions (<c>UseSessionAdmin</c>, <c>UseOidcLogout</c>) need verified after the host starts,
/// and owns the verification itself (<see cref="VerifyPendingAsync"/>).
///
/// These checks have to query <see cref="IAuthorizationPolicyProvider.GetPolicyAsync"/> and
/// <see cref="IAuthenticationSchemeProvider.GetSchemeAsync"/>, which are async on the abstraction.
/// The stock providers complete synchronously, so older code called <c>.GetAwaiter().GetResult()</c>
/// during pipeline build - but that deadlocks the moment a consumer supplies a genuinely async
/// provider (DB-backed policy lookup, dynamic scheme registration). Recording the requirements
/// here lets <see cref="OidcEndpointStartupCheck"/> run the queries with real <c>await</c> at
/// <see cref="IHostedService.StartAsync"/>.
///
/// Host-ordering caveat: in <c>Startup.Configure</c> / TestServer-style hosts the pipeline is
/// built by the web host's own hosted service, AFTER user-registered hosted services started -
/// so the startup check runs against an empty registry. Requirements recorded after that pass
/// stay pending (<see cref="HasPendingVerification"/>) and are verified by the first-request
/// backstop that the <c>Use*</c> extensions install alongside each recording.
/// </summary>
internal sealed class OidcEndpointPipelineRegistry
{
    private readonly HashSet<string> _requiredPolicies = new(StringComparer.Ordinal);
    private readonly HashSet<string> _loginPaths = new(StringComparer.OrdinalIgnoreCase);
    private bool _globalLogoutRequested;
    private int _version;
    private int _verifiedVersion = -1;
    private readonly Lock _gate = new();

    public void RecordLoginPath(string path)
    {
        lock (_gate)
        {
            _loginPaths.Add(path);
        }
    }

    public string? GetLoginPath()
    {
        lock (_gate)
        {
            return _loginPaths.Count switch
            {
                0 => null,
                1 => _loginPaths.Single(),
                _ => throw new InvalidOperationException(
                    "Multiple OIDC login paths are registered. Configure " +
                    "SessionAuthentication.Challenge.LoginPath to select the path exposed in 401 responses."),
            };
        }
    }

    public void RequirePolicy(string policyName)
    {
        lock (_gate)
        {
            if (_requiredPolicies.Add(policyName))
            {
                _version++;
            }
        }
    }

    public void RequireGlobalLogoutPreconditions()
    {
        lock (_gate)
        {
            if (!_globalLogoutRequested)
            {
                _globalLogoutRequested = true;
                _version++;
            }
        }
    }

    /// <summary>
    /// True when requirements were recorded that no verification pass has covered yet -
    /// i.e. the pipeline was built after <see cref="OidcEndpointStartupCheck"/> already ran.
    /// </summary>
    public bool HasPendingVerification
    {
        get
        {
            lock (_gate)
            {
                return _verifiedVersion != _version;
            }
        }
    }

    /// <summary>
    /// Verifies all recorded requirements against the host's services, throwing on the first
    /// violation:
    /// <list type="bullet">
    ///   <item>Every authorization policy named by <c>UseSessionAdmin</c> must resolve via
    ///   <see cref="IAuthorizationPolicyProvider.GetPolicyAsync"/>.</item>
    ///   <item>If any <c>UseOidcLogout</c> call asked for global logout AND the OpenIdConnect
    ///   scheme is registered, the handler must have <c>SaveTokens=true</c> - otherwise
    ///   <c>id_token_hint</c> is missing from the end-session request and many IdPs reject it.</item>
    /// </list>
    /// Idempotent per requirement set: a successful pass marks the current set verified and later
    /// calls return immediately until new requirements arrive. A failed pass leaves the set
    /// pending, so the first-request backstop keeps failing every request rather than degrading
    /// to a one-shot error.
    /// </summary>
    public async Task VerifyPendingAsync(IServiceProvider services)
    {
        int version;
        string[] requiredPolicies;
        bool globalLogoutRequested;
        lock (_gate)
        {
            if (_verifiedVersion == _version)
            {
                return;
            }

            version = _version;
            requiredPolicies = _requiredPolicies.ToArray();
            globalLogoutRequested = _globalLogoutRequested;
        }

        if (requiredPolicies.Length > 0)
        {
            var authorizationPolicyProvider = services.GetService<IAuthorizationPolicyProvider>()
                ?? throw new InvalidOperationException(
                    "UseSessionAdmin requires services.AddAuthorization(...) to be called so " +
                    "IAuthorizationPolicyProvider is available to resolve the configured policy.");

            foreach (var policyName in requiredPolicies)
            {
                var policy = await authorizationPolicyProvider.GetPolicyAsync(policyName).ConfigureAwait(false);
                if (policy is null)
                {
                    throw new InvalidOperationException(
                        $"Authorization policy '{policyName}' not found. " +
                        $"Register the policy using services.AddAuthorization(options => options.AddPolicy(\"{policyName}\", ...))");
                }
            }
        }

        if (globalLogoutRequested)
        {
            // Skip the check if no scheme provider is wired up (the consumer is using a different
            // auth setup); other failures will surface at first request.
            var schemeProvider = services.GetService<IAuthenticationSchemeProvider>();
            if (schemeProvider is not null)
            {
                var oidcScheme = await schemeProvider
                    .GetSchemeAsync(OpenIdConnectDefaults.AuthenticationScheme)
                    .ConfigureAwait(false);

                if (oidcScheme is not null)
                {
                    var options = services.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>()
                        .Get(OpenIdConnectDefaults.AuthenticationScheme);
                    if (!options.SaveTokens)
                    {
                        throw new OptionsValidationException(
                            nameof(OidcLogoutOptions),
                            typeof(OidcLogoutOptions),
                            [$"{nameof(OidcLogoutOptions.PerformGlobalLogout)}=true requires the OpenIdConnect handler to be configured with SaveTokens=true so that id_token_hint can be attached to the end-session request. Set SaveTokens=true on the OIDC handler or set PerformGlobalLogout=false."]);
                    }
                }
            }
        }

        lock (_gate)
        {
            if (_verifiedVersion < version)
            {
                _verifiedVersion = version;
            }
        }
    }
}

/// <summary>
/// Runs <see cref="OidcEndpointPipelineRegistry.VerifyPendingAsync"/> once the host starts, so
/// misconfiguration fails the app at boot in the common minimal-hosting flow (where the pipeline
/// is built before <c>Run()</c>). For hosts that build the pipeline after hosted services start
/// (<c>Startup.Configure</c>, TestServer), this runs too early to see anything - the
/// first-request backstop installed by the <c>Use*</c> extensions covers those.
/// </summary>
internal sealed class OidcEndpointStartupCheck(
    OidcEndpointPipelineRegistry registry,
    IServiceProvider services) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken)
        => registry.VerifyPendingAsync(services);

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
