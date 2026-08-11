using b17s.Porta.Middleware;

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace b17s.Porta.Extensions;

/// <summary>
/// Extension methods for configuring OIDC endpoints as opt-in middleware.
/// </summary>
public static class OidcEndpointExtensions
{
    /// <summary>
    /// Adds an OIDC login endpoint that initiates the authorization code flow.
    /// This endpoint redirects to the IdP for authentication.
    /// </summary>
    /// <param name="app">The application builder</param>
    /// <param name="path">The login endpoint path (default: "/bff/login")</param>
    /// <param name="configureOptions">Optional action to configure login options</param>
    /// <returns>The application builder for chaining</returns>
    /// <remarks>
    /// <para>
    /// This middleware handles the login initiation flow:
    /// <list type="number">
    ///   <item>Validates the optional redirect_uri query parameter</item>
    ///   <item>Generates CSRF state and nonce parameters</item>
    ///   <item>Generates PKCE code_verifier and code_challenge (if enabled)</item>
    ///   <item>Redirects to the IdP's authorization endpoint</item>
    /// </list>
    /// </para>
    /// <para>
    /// After successful authentication, the IdP redirects back to /bff/callback
    /// which should be handled by your OIDC callback handler.
    /// </para>
    /// <para>
    /// Options are built per call from the DI options pipeline: any
    /// <c>services.Configure&lt;OidcLoginOptions&gt;(...)</c> /
    /// <c>PostConfigure&lt;OidcLoginOptions&gt;(...)</c> composition is applied first, then
    /// <paramref name="configureOptions"/> runs last and wins on conflicts.
    /// </para>
    /// </remarks>
    /// <example>
    /// <code>
    /// // Basic usage
    /// app.UseOidcLogin();
    ///
    /// // With custom path and options
    /// app.UseOidcLogin("/auth/login", options => {
    ///     options.DefaultRedirectUri = "/dashboard";
    ///     options.AllowedRedirectHosts = ["app.example.com", "staging.example.com"];
    /// });
    /// </code>
    /// </example>
    public static IApplicationBuilder UseOidcLogin(
        this IApplicationBuilder app,
        string path = "/bff/login",
        Action<OidcLoginOptions>? configureOptions = null)
    {
        ArgumentNullException.ThrowIfNull(app);
        ArgumentException.ThrowIfNullOrEmpty(path);

        // Presence of the registry is the sentinel for AddOidcEndpoints having run; without it
        // the middleware would fail at pipeline build with an opaque "Unable to resolve service
        // for type 'IReturnUrlProtector'" instead of this actionable message.
        var registry = GetPipelineRegistry(app, nameof(UseOidcLogin));
        registry.RecordLoginPath(path);

        var options = BuildEndpointOptions(app, configureOptions);

        var failure = RedirectUriValidation.ValidateConfiguredRedirectUri(
            options.DefaultRedirectUri,
            options.AllowedRedirectHosts,
            options.AllowLocalhost);
        if (failure is not null)
        {
            throw new OptionsValidationException(
                nameof(OidcLoginOptions),
                typeof(OidcLoginOptions),
                [$"{nameof(OidcLoginOptions.DefaultRedirectUri)}: {failure}"]);
        }

        // Use middleware with path and options
        // Constructor signature: (RequestDelegate next, IOptions<OidcLoginOptions> options, IReturnUrlProtector protector, ILogger<OidcLoginMiddleware> logger, string path)
        app.UseMiddleware<OidcLoginMiddleware>(
            Options.Create(options),
            path);

        return app;
    }

    /// <summary>
    /// Adds an OIDC logout endpoint with redirect validation.
    /// Supports both local (session only) and global (session + IdP) logout.
    /// </summary>
    /// <param name="app">The application builder</param>
    /// <param name="path">The logout endpoint path (default: "/bff/logout")</param>
    /// <param name="configureOptions">Optional action to configure logout options</param>
    /// <returns>The application builder for chaining</returns>
    /// <remarks>
    /// <para>
    /// This middleware handles logout with security-focused redirect validation:
    /// <list type="bullet">
    ///   <item>Validates that the user is authenticated before logging out</item>
    ///   <item>Validates redirect_uri against whitelist to prevent open redirects</item>
    ///   <item>Optionally revokes tokens at the IdP (global logout)</item>
    ///   <item>Clears the local session</item>
    ///   <item>Redirects to the IdP's end_session_endpoint or the specified URI</item>
    /// </list>
    /// </para>
    /// <para>
    /// Options are built per call from the DI options pipeline: any
    /// <c>services.Configure&lt;OidcLogoutOptions&gt;(...)</c> /
    /// <c>PostConfigure&lt;OidcLogoutOptions&gt;(...)</c> composition is applied first, then
    /// <paramref name="configureOptions"/> runs last and wins on conflicts.
    /// </para>
    /// </remarks>
    /// <example>
    /// <code>
    /// // Basic usage - global logout with redirect
    /// app.UseOidcLogout();
    ///
    /// // JSON response mode for SPA
    /// app.UseOidcLogout("/auth/logout", options => {
    ///     options.ReturnJson = true;
    ///     options.PerformGlobalLogout = true;
    ///     options.AllowedRedirectHosts = ["app.example.com"];
    /// });
    ///
    /// // Local logout only (no IdP round-trip)
    /// app.UseOidcLogout("/auth/logout", options => {
    ///     options.PerformGlobalLogout = false;
    /// });
    /// </code>
    /// </example>
    public static IApplicationBuilder UseOidcLogout(
        this IApplicationBuilder app,
        string path = "/bff/logout",
        Action<OidcLogoutOptions>? configureOptions = null)
    {
        ArgumentNullException.ThrowIfNull(app);
        ArgumentException.ThrowIfNullOrEmpty(path);

        var options = BuildEndpointOptions(app, configureOptions);

        var failure = RedirectUriValidation.ValidateConfiguredRedirectUri(
            options.DefaultRedirectUri,
            options.AllowedRedirectHosts,
            options.AllowLocalhost);
        if (failure is not null)
        {
            throw new OptionsValidationException(
                nameof(OidcLogoutOptions),
                typeof(OidcLogoutOptions),
                [$"{nameof(OidcLogoutOptions.DefaultRedirectUri)}: {failure}"]);
        }

        // Global logout drives an OIDC SignOutAsync, which relies on the framework
        // handler to attach id_token_hint from the saved tokens on the auth ticket.
        // If SaveTokens=false the hint is missing and many IdPs reject the
        // end-session request or skip the post-logout redirect - record the
        // requirement here so OidcEndpointStartupCheck can verify it after the
        // host is built, using async APIs as intended.
        if (options.PerformGlobalLogout)
        {
            var registry = GetPipelineRegistry(app, nameof(UseOidcLogout));
            registry.RequireGlobalLogoutPreconditions();
            UseStartupCheckBackstop(app, registry);
        }

        // Use middleware with path and options
        app.UseMiddleware<OidcLogoutMiddleware>(
            Options.Create(options),
            path);

        return app;
    }

    /// <summary>
    /// Adds an OIDC back-channel logout endpoint for IdP-initiated logout.
    /// This enables "logout from one app = logout from all apps" functionality.
    /// </summary>
    /// <param name="app">The application builder</param>
    /// <param name="path">The back-channel logout endpoint path (default: "/bff/backchannel-logout")</param>
    /// <param name="configureOptions">Optional action to configure back-channel logout options</param>
    /// <returns>The application builder for chaining</returns>
    /// <remarks>
    /// <para>
    /// Back-channel logout is an IdP-initiated flow where the IdP sends a signed JWT
    /// (logout_token) directly to this endpoint when a user logs out from another app.
    /// </para>
    /// <para>
    /// This is the one exception to the library's "no JWT validation" policy, as the
    /// logout_token must be validated to prevent malicious logout requests.
    /// </para>
    /// <para>
    /// The endpoint validates:
    /// <list type="bullet">
    ///   <item>JWT signature against the IdP's JWKS</item>
    ///   <item>Issuer (iss), audience (aud), expiration (exp) claims</item>
    ///   <item>The 'events' claim contains the back-channel logout event type</item>
    ///   <item>Extracts 'sid' (session ID) to identify which session to invalidate</item>
    /// </list>
    /// </para>
    /// <para>
    /// Important: Register this endpoint with your IdP's back-channel logout configuration.
    /// </para>
    /// <para>
    /// Options are built per call from the DI options pipeline: any
    /// <c>services.Configure&lt;OidcBackChannelLogoutOptions&gt;(...)</c> /
    /// <c>PostConfigure&lt;OidcBackChannelLogoutOptions&gt;(...)</c> composition is applied
    /// first, then <paramref name="configureOptions"/> runs last and wins on conflicts.
    /// </para>
    /// </remarks>
    /// <example>
    /// <code>
    /// // Basic usage
    /// app.UseOidcBackChannelLogout();
    ///
    /// // With custom path and relaxed validation (not recommended for production)
    /// app.UseOidcBackChannelLogout("/auth/backchannel-logout", options => {
    ///     options.ClockSkew = TimeSpan.FromMinutes(10);
    /// });
    /// </code>
    /// </example>
    public static IApplicationBuilder UseOidcBackChannelLogout(
        this IApplicationBuilder app,
        string path = "/bff/backchannel-logout",
        Action<OidcBackChannelLogoutOptions>? configureOptions = null)
    {
        ArgumentNullException.ThrowIfNull(app);
        ArgumentException.ThrowIfNullOrEmpty(path);

        var options = BuildEndpointOptions(app, configureOptions);

        // Fail-fast: turning off signature / issuer / audience validation lets an
        // anonymous caller terminate any session (or, with no audience check, lets
        // a token minted for another RP terminate sessions here). The settings exist
        // only as a Development debugging affordance; in any non-dev environment
        // they must be on. Fail closed when no IHostEnvironment is registered
        // (bare-container hosts): only an explicit Development environment may
        // relax the checks.
        var env = app.ApplicationServices.GetService<IHostEnvironment>();
        if (env is null || !env.IsDevelopment())
        {
            var failures = new List<string>();
            if (!options.ValidateSignature)
                failures.Add($"{nameof(OidcBackChannelLogoutOptions.ValidateSignature)}=false");
            if (!options.ValidateIssuer)
                failures.Add($"{nameof(OidcBackChannelLogoutOptions.ValidateIssuer)}=false");
            if (!options.ValidateAudience)
                failures.Add($"{nameof(OidcBackChannelLogoutOptions.ValidateAudience)}=false");

            if (failures.Count > 0)
            {
                throw new OptionsValidationException(
                    nameof(OidcBackChannelLogoutOptions),
                    typeof(OidcBackChannelLogoutOptions),
                    [$"Back-channel logout cannot run with {string.Join(", ", failures)} outside IHostEnvironment.IsDevelopment() " +
                     "(hosts without a registered IHostEnvironment are treated as production). " +
                     "Disabling these checks lets an unauthenticated caller terminate arbitrary sessions."]);
            }
        }

        // Use middleware with path and options
        app.UseMiddleware<OidcBackChannelLogoutMiddleware>(
            Options.Create(options),
            path);

        return app;
    }

    /// <summary>
    /// Adds session administration endpoints for managing user sessions.
    /// This endpoint is opt-in and REQUIRES an authorization policy.
    /// </summary>
    /// <param name="app">The application builder</param>
    /// <param name="path">The base path for session admin endpoints (default: "/bff/admin/sessions")</param>
    /// <param name="configureOptions">Action to configure session admin options (policy is REQUIRED)</param>
    /// <returns>The application builder for chaining</returns>
    /// <remarks>
    /// <para>
    /// This middleware provides REST endpoints for session management:
    /// <list type="bullet">
    ///   <item>GET {path}?email={email} - List all sessions for a user</item>
    ///   <item>DELETE {path}/{sessionId} - Terminate a specific session</item>
    ///   <item>DELETE {path}?email={email} - Terminate all sessions for a user</item>
    /// </list>
    /// </para>
    /// <para>
    /// Security: An authorization policy is REQUIRED. The middleware will throw at startup
    /// if RequirePolicy is not specified. This prevents accidental exposure of session
    /// management functionality.
    /// </para>
    /// <para>
    /// Options are built per call from the DI options pipeline: any
    /// <c>services.Configure&lt;SessionAdminOptions&gt;(...)</c> /
    /// <c>PostConfigure&lt;SessionAdminOptions&gt;(...)</c> composition is applied first, then
    /// <paramref name="configureOptions"/> runs last and wins on conflicts.
    /// </para>
    /// </remarks>
    /// <example>
    /// <code>
    /// // Register the required policy first
    /// builder.Services.AddAuthorization(options => {
    ///     options.AddPolicy("AdminOnly", policy => policy.RequireRole("Admin"));
    /// });
    ///
    /// // Then enable session admin with the policy
    /// app.UseSessionAdmin("/bff/admin/sessions", options => {
    ///     options.RequirePolicy = "AdminOnly";  // Required!
    /// });
    /// </code>
    /// </example>
    /// <exception cref="InvalidOperationException">
    /// Thrown if RequirePolicy is not specified or the policy doesn't exist.
    /// </exception>
    public static IApplicationBuilder UseSessionAdmin(
        this IApplicationBuilder app,
        string path = "/bff/admin/sessions",
        Action<SessionAdminOptions>? configureOptions = null)
    {
        ArgumentNullException.ThrowIfNull(app);
        ArgumentException.ThrowIfNullOrEmpty(path);

        var options = BuildEndpointOptions(app, configureOptions);

        // Validate that a policy is specified
        if (string.IsNullOrEmpty(options.RequirePolicy))
        {
            throw new InvalidOperationException(
                "UseSessionAdmin requires an authorization policy. " +
                "Set options.RequirePolicy to a valid policy name. " +
                "Example: options.RequirePolicy = \"AdminOnly\"");
        }

        // Record the policy requirement; OidcEndpointStartupCheck verifies it after the host
        // is built, using await against IAuthorizationPolicyProvider.GetPolicyAsync rather
        // than blocking the pipeline-build thread (which would deadlock against a genuinely
        // async custom policy provider).
        var pipelineRegistry = GetPipelineRegistry(app, nameof(UseSessionAdmin));
        pipelineRegistry.RequirePolicy(options.RequirePolicy);
        UseStartupCheckBackstop(app, pipelineRegistry);

        // Use authorization middleware for the session admin path
        // We'll map this as a branch with authorization
        app.UseWhen(
            context => context.Request.Path.StartsWithSegments(path),
            branch =>
            {
                branch.UseAuthorization();
                branch.Use(async (context, next) =>
                {
                    // Check authorization manually since middleware doesn't have RequireAuthorization
                    var authService = context.RequestServices.GetRequiredService<IAuthorizationService>();
                    var result = await authService.AuthorizeAsync(context.User, options.RequirePolicy);

                    if (!result.Succeeded)
                    {
                        context.Response.StatusCode = context.User.Identity?.IsAuthenticated == true ? 403 : 401;
                        await context.Response.WriteAsJsonAsync(new { error = "Access denied" }, context.RequestAborted);
                        return;
                    }

                    await next();
                });
                branch.UseMiddleware<SessionAdminMiddleware>(
                    Options.Create(options),
                    path);
            });

        return app;
    }

    /// <summary>
    /// Builds the effective options for a <c>Use*</c> call: a fresh instance created
    /// through <see cref="IOptionsFactory{TOptions}"/> - so consumer
    /// <c>Configure&lt;TOptions&gt;</c>/<c>PostConfigure&lt;TOptions&gt;</c> composition is
    /// honored - with the per-call lambda applied last so it wins on conflicts. A fresh
    /// instance per call means two endpoints registered with different lambdas never
    /// share state. Falls back to plain defaults in bare hosts without the options
    /// infrastructure.
    /// </summary>
    private static TOptions BuildEndpointOptions<TOptions>(
        IApplicationBuilder app,
        Action<TOptions>? configureOptions)
        where TOptions : class, new()
    {
        var options = app.ApplicationServices.GetService<IOptionsFactory<TOptions>>()
            ?.Create(Options.DefaultName)
            ?? new TOptions();
        configureOptions?.Invoke(options);

        return options;
    }

    private static OidcEndpointPipelineRegistry GetPipelineRegistry(IApplicationBuilder app, string methodName)
        => app.ApplicationServices.GetService<OidcEndpointPipelineRegistry>()
            ?? throw new InvalidOperationException(
                $"{methodName} requires services.AddOidcEndpoints() to have been called " +
                "(or AddPortaOidcAuth, which wires it internally).");

    /// <summary>
    /// Re-runs the registry verification on the first request when requirements were recorded
    /// after <see cref="OidcEndpointStartupCheck"/> already ran. In <c>Startup.Configure</c> /
    /// TestServer-style hosts the pipeline is built by the web host's own hosted service, AFTER
    /// user-registered hosted services started - without this backstop those hosts would get a
    /// silent false pass instead of a fail-fast error. Once everything recorded has been
    /// verified, the per-request cost is a single flag check.
    /// </summary>
    private static void UseStartupCheckBackstop(IApplicationBuilder app, OidcEndpointPipelineRegistry registry)
    {
        app.Use(async (context, next) =>
        {
            if (registry.HasPendingVerification)
            {
                await registry.VerifyPendingAsync(context.RequestServices).ConfigureAwait(false);
            }

            await next(context).ConfigureAwait(false);
        });
    }
}

/// <summary>
/// Extension methods for registering OIDC endpoint services.
/// </summary>
public static class OidcEndpointServiceExtensions
{
    /// <summary>
    /// Registers services required for OIDC endpoints.
    /// Call this if you plan to use UseOidcLogin, UseOidcLogout, UseOidcBackChannelLogout, or UseSessionAdmin.
    /// </summary>
    /// <remarks>
    /// This is automatically called by AddPortaOidcAuth(), so you only need to call this
    /// if you're using a custom authentication provider but still want the OIDC endpoints.
    /// </remarks>
    /// <param name="services">The service collection</param>
    /// <returns>The service collection for chaining</returns>
    public static IServiceCollection AddOidcEndpoints(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        // Options infrastructure floor: each Use* endpoint builds its effective options
        // through IOptionsFactory<TOptions>, so idiomatic services.Configure<TOptions>(...)
        // / PostConfigure<TOptions>(...) composition reaches the middleware, with the
        // per-call lambda applied last. No per-type Configure registration is needed -
        // the factory runs whatever the consumer registered. (Empty Configure<T>(_ => { })
        // placeholders used to live here while the middleware ignored the pipeline
        // entirely - decoys that made Configure<T> look supported when it wasn't.)
        services.AddOptions();

        // Data protection: AddPortaOidcAuth configures it with app-name + key-lifetime
        // via AddInfrastructure (AuthenticationServiceExtensions). This call is the
        // idempotent floor for the standalone path (custom auth provider calling
        // AddOidcEndpoints directly) so IReturnUrlProtector's IDataProtectionProvider
        // dependency always resolves; it intentionally does not reapply those settings.
        services.AddDataProtection();
        services.TryAddSingleton<IReturnUrlProtector, ReturnUrlProtector>();

        // Pipeline-build-time configuration (policy names, global-logout requests) is
        // recorded here so a hosted service can verify it asynchronously after the host
        // is built - avoids blocking sync-over-async against IAuthorizationPolicyProvider
        // and IAuthenticationSchemeProvider. Hosts that build the pipeline after hosted
        // services start (Startup.Configure, TestServer) are covered by a first-request
        // backstop installed alongside each recording.
        services.TryAddSingleton<OidcEndpointPipelineRegistry>();
        services.AddHostedService<OidcEndpointStartupCheck>();

        return services;
    }
}
