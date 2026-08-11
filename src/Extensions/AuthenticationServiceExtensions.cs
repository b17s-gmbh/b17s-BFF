using System.Security.Claims;

using b17s.Porta.Auth;
using b17s.Porta.Auth.Discovery;
using b17s.Porta.Auth.Providers;
using b17s.Porta.Auth.Sessions;
using b17s.Porta.Auth.Tokens;
using b17s.Porta.Configuration;
using b17s.Porta.Services;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Http.Resilience;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

using Polly;

namespace b17s.Porta.Extensions;

/// <summary>
/// Extension methods for registering BFF authentication services.
/// </summary>
public static class AuthenticationServiceExtensions
{
    /// <summary>
    /// Name of the resilient <see cref="HttpClient"/> used by all token-flow services
    /// (refresh, exchange, revocation) and OIDC discovery. Registered in
    /// <see cref="AddTokenServices"/> with <c>AddStandardResilienceHandler</c>; any
    /// consumer that fetches via <see cref="IHttpClientFactory"/> must use this name
    /// to inherit timeout/retry/circuit-breaker policy.
    /// </summary>
    public const string TokenHttpClientName = "Porta.TokenClient";

    /// <summary>
    /// Adds the full BFF authentication pipeline:
    /// <list type="bullet">
    ///   <item>ASP.NET Core Cookie + OpenIdConnect schemes (the framework handles state/nonce/PKCE/code-exchange/id_token validation).</item>
    ///   <item>Server-side ticket storage via <see cref="DistributedCacheTicketStore"/> - cookies carry only an opaque ticket id; tokens live in <see cref="Microsoft.Extensions.Caching.Distributed.IDistributedCache"/>, encrypted via <see cref="IDataProtector"/>.</item>
    ///   <item>Custom token services: refresh, revocation (RFC 7009), exchange (RFC 8693), API token caching.</item>
    ///   <item>Auto-refresh of access tokens before expiry via <see cref="IAccessTokenRefreshService"/>.</item>
    ///   <item>Session management (admin force-logout, back-channel logout).</item>
    /// </list>
    /// Requires an <see cref="Microsoft.Extensions.Caching.Distributed.IDistributedCache"/> registration. In production
    /// use Redis/Valkey via Aspire (<c>builder.AddRedisDistributedCache("cache")</c>) or
    /// <c>services.AddStackExchangeRedisCache()</c>. For development falls back to an
    /// in-memory cache via <c>AddDistributedMemoryCache()</c>.
    /// <para/>
    /// This method is idempotent: calling it more than once (in either overload, or
    /// implicitly via <c>AddPortaOidcAuth</c>) applies the additional options binding
    /// through the options pipeline but registers the authentication schemes and
    /// services only once.
    /// </summary>
    /// <param name="services">The service collection</param>
    /// <param name="configuration">The configuration root to bind <see cref="SessionAuthenticationConfiguration"/> from</param>
    /// <param name="configSectionName">Name of the configuration section to bind. Defaults to <c>"SessionAuthentication"</c></param>
    /// <returns>The service collection for chaining</returns>
    public static IServiceCollection AddPortaAuthentication(
        this IServiceCollection services,
        IConfiguration configuration,
        string configSectionName = "SessionAuthentication")
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        services.Configure<SessionAuthenticationConfiguration>(configuration.GetSection(configSectionName));

        return services.AddPortaAuthenticationCore();
    }

    /// <summary>
    /// Adds the full BFF authentication pipeline using an action to configure
    /// <see cref="SessionAuthenticationConfiguration"/>. Use this overload when callers
    /// want to bind options imperatively (or have already called
    /// <c>services.Configure&lt;SessionAuthenticationConfiguration&gt;(...)</c> elsewhere).
    /// </summary>
    /// <remarks>
    /// Single source of truth: every consumer - including the cookie/OIDC handlers and the
    /// token <see cref="HttpClient"/> - resolves <c>IOptions&lt;SessionAuthenticationConfiguration&gt;</c>.
    /// No registration-time snapshot is captured, so external
    /// <c>Configure&lt;T&gt;</c>/<c>PostConfigure&lt;T&gt;</c> composition is honored everywhere.
    /// </remarks>
    /// <param name="services">The service collection</param>
    /// <param name="configureOptions">Optional action to configure <see cref="SessionAuthenticationConfiguration"/>; pass <see langword="null"/> when options are bound elsewhere</param>
    /// <returns>The service collection for chaining</returns>
    public static IServiceCollection AddPortaAuthentication(
        this IServiceCollection services,
        Action<SessionAuthenticationConfiguration>? configureOptions = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        if (configureOptions is not null)
        {
            services.Configure(configureOptions);
        }

        return services.AddPortaAuthenticationCore();
    }

    /// <summary>
    /// Shared registration body for both <see cref="AddPortaAuthentication(IServiceCollection, IConfiguration, string)"/>
    /// and <see cref="AddPortaAuthentication(IServiceCollection, Action{SessionAuthenticationConfiguration}?)"/>.
    /// All startup-time wiring (cookie names, OIDC scheme options, resilience timeouts) binds
    /// lazily from the composed <c>IOptions&lt;SessionAuthenticationConfiguration&gt;</c> pipeline
    /// rather than an eager snapshot, so it reflects every <c>Configure</c>/<c>PostConfigure</c>
    /// the consumer registered, in any order.
    /// </summary>
    private static IServiceCollection AddPortaAuthenticationCore(
        this IServiceCollection services)
    {
        // Idempotency guard: a second pass would call AddCookie()/AddOpenIdConnect()
        // again - the duplicate scheme registration throws
        // "Scheme already exists: Cookies" at the first authentication resolve - and
        // would stack a second resilience handler on the named token HttpClient plus
        // duplicate every plain AddScoped descriptor (running SessionAuthProvider twice
        // per request through the composite). This also makes AddPortaOidcAuth (which
        // delegates here) safely combinable with a direct AddPortaAuthentication call.
        // The Configure calls in the public overloads run before this guard so repeated
        // calls still compose through the options pipeline.
        if (services.Any(d => d.ServiceType == typeof(PortaAuthenticationMarker)))
        {
            return services;
        }

        services.AddSingleton<PortaAuthenticationMarker>();

        // Validate options up-front so a misconfigured BFF fails at boot rather than
        // on the first OIDC redirect. ValidateOnStart promotes validation from
        // "on first resolve" to "on host start" so the failure surfaces as a
        // startup error instead of a 500 on the first request that touches the
        // options. The OidcAuthOptions subclass has its own validator registered
        // by AddPortaOidcAuth so we don't fire validation against an unconfigured
        // OidcAuthOptions when only AddPortaAuthentication is used.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<
                IValidateOptions<SessionAuthenticationConfiguration>,
                SessionAuthenticationConfigurationValidator>());
        services.AddOptions<SessionAuthenticationConfiguration>().ValidateOnStart();

        AddInfrastructure(services);
        AddCookieAndOidcAuthentication(services);
        services.AddAuthenticationCore();
        services.AddTokenServices();
        services.AddSessionManagement();
        services.AddOidcEndpoints();

        return services;
    }

    /// <summary>
    /// Registers infrastructure shared across the BFF auth pipeline:
    /// distributed-memory-cache fallback, ASP.NET Core session, data protection,
    /// and the custom <see cref="ITicketStore"/>.
    /// </summary>
    private static void AddInfrastructure(IServiceCollection services)
    {
        // Provide an in-memory distributed cache fallback when no real one is registered.
        // AddDistributedMemoryCache uses TryAddSingleton internally, so a previous
        // registration (e.g. AddStackExchangeRedisCache) wins - and a later one wins
        // too, because DI resolves the last IDistributedCache descriptor.
        services.AddDistributedMemoryCache();

        // Session, Data Protection and ticket-store options all bind from the composed
        // IOptions<SessionAuthenticationConfiguration> pipeline (deferred to options-build
        // time) rather than an eager registration-time snapshot, so external
        // Configure/PostConfigure of the configuration is honored.
        services.AddSession();
        services.AddOptions<Microsoft.AspNetCore.Builder.SessionOptions>()
            .Configure<IOptions<SessionAuthenticationConfiguration>>((options, cfg) =>
            {
                var config = cfg.Value;
                options.Cookie.Name = config.CookieName + ".session";
                options.Cookie.HttpOnly = config.Cookie.HttpOnly;
                options.Cookie.SecurePolicy = ParseSecurePolicy(config.Cookie.SecurePolicy);
                options.Cookie.SameSite = ParseSameSite(config.Cookie.SameSite);
                options.IdleTimeout = TimeSpan.FromMinutes(config.SessionTimeoutInMin);
                options.Cookie.IsEssential = true;
            });

        // Data Protection is required by DistributedCacheTicketStore + revocation, so
        // register unconditionally. Persistence backends (Redis) should be layered on
        // top via Aspire or the consuming app. SetApplicationName/SetDefaultKeyLifetime
        // are the eager-snapshot equivalents of configuring ApplicationDiscriminator /
        // KeyManagementOptions.NewKeyLifetime; we configure those from IOptions instead.
        services.AddDataProtection();
        services.AddOptions<DataProtectionOptions>()
            .Configure<IOptions<SessionAuthenticationConfiguration>>((options, cfg) =>
                options.ApplicationDiscriminator =
                    ResolveDataProtectionApplicationName(cfg.Value.DataProtection.ApplicationName));
        services.AddOptions<KeyManagementOptions>()
            .Configure<IOptions<SessionAuthenticationConfiguration>>((options, cfg) =>
                options.NewKeyLifetime = TimeSpan.FromDays(cfg.Value.DataProtection.KeyLifetimeDays));

        // Always register the ticket store + its options. Cookies carry only an
        // opaque id; tokens live server-side.
        services.AddOptions<TicketStoreOptions>()
            .Configure<IOptions<SessionAuthenticationConfiguration>>((opts, cfg) =>
                opts.DefaultSlidingExpiration = TimeSpan.FromMinutes(cfg.Value.SessionTimeoutInMin));
        services.AddSingleton<ITicketStore, DistributedCacheTicketStore>();

        // Refresh-lock auto-pick, deferred to first resolve so it observes the
        // *effective* IDistributedCache rather than a registration-time snapshot
        // (consumers may register Redis before or after AddPortaAuthentication).
        // A consumer-provided IRefreshLock always wins: TryAdd skips this factory
        // when one is already registered, and a later consumer registration
        // shadows it because DI resolves the last descriptor. Effective cache is
        // the in-memory fallback → in-process registry (correct for
        // single-instance dev/test); anything else → IDistributedCache-backed
        // lock (HA-safe by default). The startup check enforces that an HA
        // deployment without a proper distributed lock is either explicitly
        // acknowledged or refused.
        services.TryAddSingleton<IRefreshLock>(sp =>
            sp.GetRequiredService<IDistributedCache>() is MemoryDistributedCache
                ? ActivatorUtilities.CreateInstance<RefreshLockRegistry>(sp)
                : ActivatorUtilities.CreateInstance<DistributedCacheRefreshLock>(sp));

        // HA-readiness check: emit a single startup warning if the consumer hasn't
        // registered shared distributed cache or shared Data Protection persistence.
        // Both are HA-fatal: without them, running >1 replica behind a load balancer
        // will produce sign-in failures and cookies that don't decrypt cross-instance.
        // All signals are derived from the built container inside StartAsync
        // (effective IDistributedCache / IRefreshLock / marker registrations), so
        // consumer registration order relative to AddPortaAuthentication doesn't matter.
        services.AddHostedService<HaConfigurationStartupCheck>();

        // Transport-security downgrade guard: refuse to start (outside Development) when the
        // operator has loosened a secure default - SecurePolicy != Always or
        // RequireHttpsMetadata == false - either of which exposes the cookie / OIDC metadata
        // over plaintext HTTP. Reads IOptions<SessionAuthenticationConfiguration> (the effective
        // bound options) rather than the snapshot, since the OIDC path binds via Configure<>.
        services.AddHostedService<CookieSecurityStartupCheck>();
    }

    /// <summary>
    /// Registers ASP.NET Core's cookie + OpenIdConnect handlers and wires the
    /// <c>OnTokenValidated</c> event to <see cref="ISessionManagementService.RegisterSessionAsync"/>.
    /// </summary>
    private static void AddCookieAndOidcAuthentication(IServiceCollection services)
    {
        services.AddAuthentication(options =>
        {
            options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = ChallengeDispatchHandler.SchemeName;
            options.DefaultForbidScheme = ChallengeDispatchHandler.SchemeName;
            options.DefaultSignOutScheme = OpenIdConnectDefaults.AuthenticationScheme;
        })
        .AddCookie()
        .AddOpenIdConnect()
        .AddScheme<AuthenticationSchemeOptions, ChallengeDispatchHandler>(
            ChallengeDispatchHandler.SchemeName,
            options => options.ForwardAuthenticate = CookieAuthenticationDefaults.AuthenticationScheme);

        // Bind the cookie handler options from the composed configuration pipeline plus the
        // resolved ITicketStore. Deferring to options-build time (instead of an eager snapshot)
        // means external Configure/PostConfigure of SessionAuthenticationConfiguration is honored.
        services.AddOptions<CookieAuthenticationOptions>(CookieAuthenticationDefaults.AuthenticationScheme)
            .Configure<IOptions<SessionAuthenticationConfiguration>, ITicketStore>((opts, cfg, store) =>
            {
                var config = cfg.Value;
                opts.Cookie.Name = config.CookieName;
                opts.Cookie.HttpOnly = config.Cookie.HttpOnly;
                opts.Cookie.SecurePolicy = ParseSecurePolicy(config.Cookie.SecurePolicy);
                opts.Cookie.SameSite = ParseSameSite(config.Cookie.SameSite);
                opts.Cookie.IsEssential = true;
                opts.ExpireTimeSpan = TimeSpan.FromMinutes(config.Cookie.ExpireTimeSpanMinutes);
                opts.SlidingExpiration = config.Cookie.SlidingExpiration;

                // Server-side ticket storage: cookie carries only the opaque id.
                opts.SessionStore = store;
            });

        // Likewise bind the OpenIdConnect handler from the composed configuration. A prior
        // implementation snapshotted these values at registration, so callers using normal
        // Configure/PostConfigure composition could end up with an empty/default handler
        // (ClientId="", no Authority) while IOptions validated correctly.
        services.AddOptions<OpenIdConnectOptions>(OpenIdConnectDefaults.AuthenticationScheme)
            .Configure<IOptions<SessionAuthenticationConfiguration>>((options, cfg) =>
            {
                var config = cfg.Value;
                options.Authority = config.Authority;
                options.ClientId = config.ClientId;
                options.ClientSecret = config.ClientSecret;
                options.RequireHttpsMetadata = config.RequireHttpsMetadata;
                options.ResponseType = "code";
                options.UsePkce = config.UsePkce;
                options.SaveTokens = true;
                options.GetClaimsFromUserInfoEndpoint = config.QueryUserInfoEndpoint;

                options.Scope.Clear();
                foreach (var s in (config.Scope ?? "openid profile email").Split(' ', StringSplitOptions.RemoveEmptyEntries))
                {
                    options.Scope.Add(s);
                }

                // The signing scheme is the cookie scheme - this is what triggers
                // ITicketStore on successful sign-in.
                options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;

                options.Events.OnTokenValidated = OnTokenValidatedAsync;
            });
    }

    /// <summary>
    /// Called by the OIDC handler after id_token validation. We pull the refresh
    /// token off the token-endpoint response, encrypt it, and register the session
    /// with <see cref="ISessionManagementService"/> so that admin force-logout and
    /// back-channel logout flows can reach this session and revoke its tokens at
    /// the IdP.
    /// </summary>
    private static async Task OnTokenValidatedAsync(
        Microsoft.AspNetCore.Authentication.OpenIdConnect.TokenValidatedContext context)
    {
        var sp = context.HttpContext.RequestServices;
        var sessionManagement = sp.GetService<ISessionManagementService>();
        if (sessionManagement is null)
        {
            return;
        }

        var principal = context.Principal;
        if (principal is null)
        {
            return;
        }

        // `sub` is the primary identity key. It's the only OIDC claim guaranteed to be a
        // unique, stable, IdP-scoped identifier for the end user (OIDC Core §2). Without
        // it we have nothing safe to index sessions by - bail.
        var userId = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value
            ?? principal.FindFirst("sub")?.Value;
        if (string.IsNullOrEmpty(userId))
        {
            return;
        }

        // Email is a *secondary* index, used only for admin lookups by address. We accept
        // it strictly when the IdP attests `email_verified=true`. We never fall back to
        // `preferred_username`: per OIDC Core §5.7 it is neither unique nor verified, so
        // using it as an email-index key would collide distinct users and let an
        // unverified account squat on another user's address.
        var email = principal.FindFirst(ClaimTypes.Email)?.Value
            ?? principal.FindFirst("email")?.Value;
        var emailVerified = principal.FindFirst("email_verified")?.Value;
        if (!string.Equals(emailVerified, "true", StringComparison.OrdinalIgnoreCase)
            && !string.Equals(emailVerified, bool.TrueString, StringComparison.OrdinalIgnoreCase))
        {
            email = null;
        }

        var refreshToken = context.TokenEndpointResponse?.RefreshToken;
        var encryptedRefreshToken = sessionManagement.ProtectRefreshToken(refreshToken);

        var ip = context.HttpContext.Connection.RemoteIpAddress?.ToString();
        var userAgent = context.HttpContext.Request.Headers.UserAgent.ToString();

        // The cookie ticket id won't exist until SignInAsync runs (after this event).
        // Prefer the IdP-issued `sid` (per-login, addressable by back-channel logout),
        // otherwise mint a fresh per-login id. We deliberately do NOT fall back to
        // `sub`: it's stable across logins, so reusing it would collapse multiple
        // concurrent logins for one user onto a single metadata record.
        var sessionId = principal.FindFirst("sid")?.Value
            ?? Guid.NewGuid().ToString("N");

        // Stash the sessionId on the auth properties so that:
        //  1) DistributedCacheTicketStore.StoreAsync can use it as the ticket key
        //     (keeping metadata and ticket addressable by the same id), and
        //  2) AccessTokenRefreshService can sync rotated refresh tokens onto the
        //     same session metadata record.
        if (context.Properties is not null)
        {
            context.Properties.Items[SessionIdPropertyKey] = sessionId;
        }

        await sessionManagement.RegisterSessionAsync(
            sessionId,
            userId: userId,
            email: email,
            ipAddress: ip,
            userAgent: userAgent,
            encryptedRefreshToken: encryptedRefreshToken);
    }

    /// <summary>
    /// AuthenticationProperties.Items key under which the BFF-assigned sessionId is
    /// stored. Shared by the ticket store and the refresh path so all three
    /// (metadata, ticket, rotated tokens) stay addressable by the same id.
    /// </summary>
    internal const string SessionIdPropertyKey = ".bff.session_id";

    // Fail-fast parsers: a typo in appsettings (e.g. "Allways") used to silently
    // downgrade the cookie's secure policy or pin SameSite back to a default,
    // masking the misconfiguration. Throwing at startup forces the operator to
    // fix the value instead of shipping with weaker cookie security than intended.
    /// <summary>
    /// Resolves the Data Protection application name. An explicit non-empty
    /// config value wins; otherwise we derive a stable per-host name from the
    /// entry assembly so two unrelated BFFs on shared infrastructure don't
    /// collide on the purpose-string namespace. Falls back to <c>"Porta"</c> if
    /// the entry assembly can't be resolved (e.g. unit tests).
    /// </summary>
    internal static string ResolveDataProtectionApplicationName(string configured)
    {
        if (!string.IsNullOrWhiteSpace(configured))
        {
            return configured;
        }

        var entry = System.Reflection.Assembly.GetEntryAssembly()?.GetName().Name;
        return string.IsNullOrWhiteSpace(entry) ? "Porta" : $"{entry}/Porta";
    }

    private static CookieSecurePolicy ParseSecurePolicy(string value) => value switch
    {
        "Always" => CookieSecurePolicy.Always,
        "SameAsRequest" => CookieSecurePolicy.SameAsRequest,
        "None" => CookieSecurePolicy.None,
        _ => throw new InvalidOperationException(
            $"Invalid Cookie.SecurePolicy value '{value}'. Expected one of: " +
            "Always, SameAsRequest, None."),
    };

    private static SameSiteMode ParseSameSite(string value) => value switch
    {
        "Strict" => SameSiteMode.Strict,
        "Lax" => SameSiteMode.Lax,
        "None" => SameSiteMode.None,
        _ => throw new InvalidOperationException(
            $"Invalid Cookie.SameSite value '{value}'. Expected one of: " +
            "Strict, Lax, None."),
    };

    /// <summary>
    /// Adds core authentication providers and context services.
    /// </summary>
    private static IServiceCollection AddAuthenticationCore(
        this IServiceCollection services)
    {
        // Token storage (session-based with optional encryption)
        services.AddScoped<ITokenStorage, SessionTokenStorage>();

        // Register IReferenceTokenService for ReferenceTokenAuthProvider.
        // TryAdd so AddReferenceTokenAuthentication (opt-in) doesn't double-register.
        services.TryAddSingleton<IReferenceTokenService, ReferenceTokenService>();

        // Authentication providers
        services.AddScoped<SessionAuthProvider>();
        // ReferenceTokenAuthProvider delegates to the shared authenticator, so it must be
        // registered alongside the provider on this path too (TryAdd: AddReferenceTokenAuthentication
        // may also register it).
        services.TryAddScoped<ReferenceTokenAuthenticator>();
        services.AddScoped<ReferenceTokenAuthProvider>();

        // Register SessionAuthProvider as a composable provider. Multiple providers
        // can be registered side-by-side (session + JWT + reference token + custom);
        // see CompositeAuthenticationProvider for resolution semantics.
        services.AddScoped<IAuthenticationProviderRegistration>(sp =>
            new AuthenticationProviderRegistration(sp.GetRequiredService<SessionAuthProvider>()));

        // Discovery service for OIDC configuration. TryAdd so a multi-frontend BFF that also calls
        // AddReferenceTokenAuthentication (which registers the same service) ends up with a single
        // descriptor regardless of call order.
        services.TryAddSingleton<IDiscoveryService, DiscoveryService>();

        return services;
    }

    /// <summary>
    /// Adds token services (refresh, exchange, revocation, introspection).
    /// </summary>
    private static IServiceCollection AddTokenServices(
        this IServiceCollection services)
    {
        // Add named HttpClient for token operations with resilience. No client.Timeout is
        // set here: AddStandardResilienceHandler resets HttpClient.Timeout to infinite and
        // owns all timeouts via AttemptTimeout/TotalRequestTimeout, which
        // ConfigureTokenResilience binds from the composed
        // IOptions<SessionAuthenticationConfiguration> pipeline (read at resolve /
        // options-build time) rather than an eager registration-time snapshot, so
        // external Configure/PostConfigure of the configuration is honored.
        services.AddHttpClient(TokenHttpClientName, client =>
        {
            client.DefaultRequestHeaders.Accept.Add(
                new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));
        })
        .AddStandardResilienceHandler()
        .Configure((options, sp) =>
        {
            // Configure resilience based on configuration
            var config = sp.GetRequiredService<IOptions<SessionAuthenticationConfiguration>>().Value;
            ConfigureTokenResilience(options, config.Resilience);
        });

        // PortaCoreOptions is also registered by AddPortaCore; ensure the options
        // pipeline is wired here so AddPortaAuthentication standalone (no AddPortaCore)
        // still resolves the IOptions<PortaCoreOptions> dependency on
        // AccessTokenRefreshService / ApiTokenService for TokenRefreshSkew.
        // AddOptions<T>() is idempotent - any earlier Configure<PortaCoreOptions>(...)
        // wins.
        services.AddOptions<PortaCoreOptions>();

        // Guard against the named-client registration getting out of sync with the
        // const string consumers resolve by. If the name is missing at startup,
        // IHttpClientFactory silently returns the default unconfigured client and
        // the standard resilience handler is bypassed for every auth call.
        services.AddHostedService<AuthHttpClientStartupCheck>();

        // Register token services
        services.AddScoped<ITokenRefreshService, TokenRefreshService>();
        services.AddScoped<ITokenExchangeService, TokenExchangeService>();
        services.AddScoped<ITokenRevocationService, TokenRevocationService>();
        services.AddScoped<IApiTokenService, ApiTokenService>();
        // Refresh-lock registration is performed in AddInfrastructure; the
        // auto-pick is a resolve-time factory that observes the effective
        // IDistributedCache, so consumer registration order doesn't matter.
        services.AddScoped<IAccessTokenRefreshService>(sp => new AccessTokenRefreshService(
            sp.GetRequiredService<ITokenRefreshService>(),
            sp.GetRequiredService<IApiTokenService>(),
            sp.GetRequiredService<Microsoft.Extensions.Logging.ILogger<AccessTokenRefreshService>>(),
            sp.GetRequiredService<IRefreshLock>(),
            sp.GetRequiredService<Microsoft.Extensions.Options.IOptions<PortaCoreOptions>>(),
            sessionManagement: sp.GetService<ISessionManagementService>(),
            ticketStore: sp.GetService<Microsoft.AspNetCore.Authentication.Cookies.ITicketStore>(),
            metrics: sp.GetService<b17s.Porta.Telemetry.PortaMetrics>()));

        return services;
    }

    /// <summary>
    /// Applies <see cref="TokenRefreshResilienceConfiguration"/> onto the standard
    /// resilience pipeline used by the token <see cref="HttpClient"/>.
    /// </summary>
    /// <remarks>
    /// <c>AddStandardResilienceHandler</c> installs a full pipeline (retry +
    /// circuit breaker + timeouts) whose strategies are always present. The
    /// <see cref="TokenRefreshResilienceConfiguration.EnableRetry"/> and
    /// <see cref="TokenRefreshResilienceConfiguration.EnableCircuitBreaker"/>
    /// flags therefore cannot remove a strategy - they must neutralize it. When a
    /// flag is <c>false</c> we explicitly disable that strategy with a
    /// <c>ShouldHandle</c> predicate that never matches (no outcome is retryable;
    /// no outcome counts as a circuit failure) so the documented opt-out actually
    /// takes effect instead of silently leaving the package defaults active.
    /// Setting <c>MaxRetryAttempts = 0</c> is not an option: Polly validates the
    /// strategy options (<c>[Range(1, ...)]</c>) when the pipeline is first built,
    /// so a zero would throw <c>OptionsValidationException</c> on the first token
    /// call.
    /// </remarks>
    internal static void ConfigureTokenResilience(
        HttpStandardResilienceOptions options,
        TokenRefreshResilienceConfiguration resilience)
    {
        options.AttemptTimeout.Timeout = TimeSpan.FromSeconds(resilience.RequestTimeoutSeconds);
        options.TotalRequestTimeout.Timeout = TimeSpan.FromSeconds(resilience.RequestTimeoutSeconds * 2);

        if (resilience.EnableRetry)
        {
            options.Retry.MaxRetryAttempts = resilience.MaxRetryAttempts;
            options.Retry.Delay = TimeSpan.FromSeconds(resilience.InitialDelaySeconds);
            options.Retry.UseJitter = resilience.UseJitter;
        }
        else
        {
            // No retry strategy can be removed from the standard pipeline, so make
            // it a no-op: a predicate that never considers any outcome retryable
            // means the request is sent exactly once. MaxRetryAttempts stays at
            // its (valid) default - zeroing it fails Polly's range validation.
            options.Retry.ShouldHandle = static _ => PredicateResult.False();
        }

        if (resilience.EnableCircuitBreaker)
        {
            options.CircuitBreaker.FailureRatio = resilience.CircuitBreakerFailureRatio;
            options.CircuitBreaker.SamplingDuration = TimeSpan.FromSeconds(resilience.CircuitBreakerSamplingDurationSeconds);
            options.CircuitBreaker.MinimumThroughput = resilience.CircuitBreakerMinimumThroughput;
            options.CircuitBreaker.BreakDuration = TimeSpan.FromSeconds(resilience.CircuitBreakerBreakDurationSeconds);
        }
        else
        {
            // The circuit breaker cannot be removed either; a predicate that never
            // considers any outcome a failure keeps the circuit permanently closed.
            options.CircuitBreaker.ShouldHandle = static _ => PredicateResult.False();
        }
    }

    /// <summary>
    /// Adds session management services for admin operations.
    /// </summary>
    private static IServiceCollection AddSessionManagement(
        this IServiceCollection services)
    {
        services.AddScoped<ISessionManagementService, SessionManagementService>();

        return services;
    }

    /// <summary>
    /// Adds reference token authentication services (for API-to-API scenarios).
    /// </summary>
    /// <remarks>
    /// This method is idempotent: calling it more than once applies the additional
    /// <paramref name="configureOptions"/> through the options pipeline but registers
    /// the named <see cref="HttpClient"/>, services, and authentication provider only once.
    /// <para/>
    /// The named introspection <see cref="HttpClient"/> is registered via
    /// <see cref="ReferenceTokenServiceExtensions.AddReferenceTokenService(IServiceCollection, Action{ReferenceTokenAuthOptions}?, Action{HttpClient}?, Action{HttpStandardResilienceOptions}?)"/>,
    /// whose standard resilience pipeline owns the effective timeouts
    /// (attempt timeout 10s, total request timeout 30s by default). If that method already
    /// registered the client, its resilience configuration wins and
    /// <paramref name="configureResilience"/> is not applied.
    /// </remarks>
    /// <param name="services">The service collection</param>
    /// <param name="configureOptions">Action to configure <see cref="ReferenceTokenAuthOptions"/></param>
    /// <param name="configureResilience">Optional action to configure the introspection client's resilience pipeline (timeouts, retries, circuit breaker)</param>
    /// <returns>The service collection for chaining</returns>
    public static IServiceCollection AddReferenceTokenAuthentication(
        this IServiceCollection services,
        Action<ReferenceTokenAuthOptions> configureOptions,
        Action<HttpStandardResilienceOptions>? configureResilience = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configureOptions);

        services.Configure(configureOptions);

        // Idempotency guard: a second call would duplicate the plain AddScoped
        // registration below, running the provider twice per request through the
        // composite. (The named introspection client is guarded separately inside
        // AddReferenceTokenService.)
        if (services.Any(d => d.ServiceType == typeof(ReferenceTokenAuthenticationMarker)))
        {
            return services;
        }

        services.AddSingleton<ReferenceTokenAuthenticationMarker>();

        // Validate options up-front so a misconfigured BFF fails at boot - mirroring
        // the OIDC fail-at-boot posture - rather than rejecting every request at
        // introspection time (e.g. empty Authority). The runtime reads these options
        // via IOptionsMonitor.CurrentValue for hot reload; this covers the initial
        // snapshot only.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<
                IValidateOptions<ReferenceTokenAuthOptions>,
                ReferenceTokenAuthOptionsValidator>());
        services.AddOptions<ReferenceTokenAuthOptions>().ValidateOnStart();

        // Delegate the named introspection HttpClient + IReferenceTokenService to the
        // single owner of that registration. A previous inline AddHttpClient here set
        // client.Timeout = 30s, which AddStandardResilienceHandler silently overrides
        // with an infinite timeout - the effective timeouts live in the resilience
        // pipeline, configurable via configureResilience. Sharing the registration also
        // prevents a consumer combining both entry points from nesting a second
        // resilience handler on the same named client.
        services.AddReferenceTokenService(configureResilience: configureResilience);

        // ReferenceTokenService discovers the introspection endpoint via IDiscoveryService, which the
        // low-level AddReferenceTokenService building block intentionally leaves to its consumer. A
        // reference-token-only BFF (provider or scheme) has no other path that registers it, so without
        // this the singleton introspection service can't be constructed and the BFF fails DI validation
        // at startup. TryAdd so it composes with the session/OIDC path that also registers it.
        services.TryAddSingleton<IDiscoveryService, DiscoveryService>();

        // Shared introspection/binding/cache core. Used by both the provider (below) and the
        // PortaReferenceToken scheme; registering it here means either entry point works.
        services.TryAddScoped<ReferenceTokenAuthenticator>();

        services.TryAddScoped<ReferenceTokenAuthProvider>();
        services.AddScoped<IAuthenticationProviderRegistration>(sp =>
            new AuthenticationProviderRegistration(sp.GetRequiredService<ReferenceTokenAuthProvider>()));

        return services;
    }

    /// <summary>
    /// Registers reference-token (opaque token) authentication as a first-class ASP.NET Core
    /// authentication scheme (<see cref="PortaReferenceTokenDefaults.AuthenticationScheme"/>).
    /// Unlike <see cref="AddReferenceTokenAuthentication"/> alone - which only resolves the backend
    /// <c>AuthContext</c> in-pipeline - this populates <see cref="Microsoft.AspNetCore.Http.HttpContext.User"/>
    /// via the standard authentication middleware, so <c>RequireAuth()</c> and the per-endpoint
    /// principal gate work for opaque tokens with no consumer-side auth code.
    /// </summary>
    /// <remarks>
    /// The scheme and the in-pipeline <see cref="ReferenceTokenAuthProvider"/> share one
    /// <see cref="ReferenceTokenAuthenticator"/>, so an opaque token is introspected at most once per
    /// request. The scheme registers additively and becomes the default scheme only when no other
    /// default has been set, so a reference-token-only BFF needs nothing more while a multi-frontend BFF
    /// keeps its existing default (e.g. the cookie default from <c>AddPortaAuthentication</c>, so browser
    /// <c>RequireAuthorization</c> still redirects to OIDC login). When composing with cookie/OIDC or JWT
    /// bearer, register a policy scheme or <c>ForwardDefaultSelector</c> to pick per request, exactly as
    /// with any multi-scheme setup.
    /// <para/>
    /// Idempotent: the scheme is registered only once even if called more than once.
    /// </remarks>
    /// <param name="services">The service collection</param>
    /// <param name="configureOptions">Configures <see cref="ReferenceTokenAuthOptions"/> (authority, audiences, header, cache durations)</param>
    /// <param name="configureResilience">Optional resilience configuration for the introspection HttpClient</param>
    /// <returns>The service collection for chaining</returns>
    public static IServiceCollection AddPortaReferenceTokenScheme(
        this IServiceCollection services,
        Action<ReferenceTokenAuthOptions> configureOptions,
        Action<HttpStandardResilienceOptions>? configureResilience = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configureOptions);

        // Reuse the existing wiring: options binding/validation, introspection HttpClient + service,
        // the shared authenticator, and the in-pipeline provider (so outbound AuthContext is
        // populated identically to the provider-only path).
        services.AddReferenceTokenAuthentication(configureOptions, configureResilience);

        // Idempotency guard: a second AddScheme() for the same name throws at the first authenticate.
        if (services.Any(d => d.ServiceType == typeof(PortaReferenceTokenSchemeMarker)))
        {
            return services;
        }

        services.AddSingleton<PortaReferenceTokenSchemeMarker>();

        // Register the scheme additively (the AddScheme call forces no default), the same way
        // AddPortaJwtAuthentication registers the Bearer scheme, so it composes with cookie/OIDC and
        // JWT bearer in a multi-frontend BFF. NOTE: unlike the JWT path - which never sets a default
        // and relies on ASP.NET's single-scheme fallback - the PostConfigure below additionally
        // claims the default scheme when nothing else has, so a reference-token-only BFF needs no
        // ForwardDefaultSelector. The trade-off: in a JWT-then-reference-token composition where
        // neither path set a default, reference-token wins it - see the note on the PostConfigure.
        services.AddAuthentication()
            .AddScheme<AuthenticationSchemeOptions, PortaReferenceTokenHandler>(
                PortaReferenceTokenDefaults.AuthenticationScheme, _ => { });

        // Claim the default scheme only if nothing else already has. A reference-token-only BFF then
        // works with no further config; a multi-frontend BFF keeps its existing default (e.g. the
        // cookie default set by AddPortaAuthentication, so browser RequireAuthorization still redirects
        // to OIDC login) and selects per request via a policy scheme / ForwardDefaultSelector. Runs as
        // PostConfigure so it observes whatever any AddAuthentication(...) / AddPorta* call configured,
        // regardless of registration order.
        services.PostConfigure<AuthenticationOptions>(options =>
            options.DefaultScheme ??= PortaReferenceTokenDefaults.AuthenticationScheme);

        return services;
    }

    /// <summary>
    /// Adds JWT bearer authentication for inbound requests. Opt-in alternative to reference tokens
    /// for environments where introspection is not available.
    /// </summary>
    /// <remarks>
    /// Reference tokens remain the recommended default in a BFF context (see the README design note).
    /// Use this when your IdP issues JWTs and you cannot introspect - e.g., legacy partners, B2B
    /// federation, or third-party APIs that hand callers JWTs directly.
    /// <para/>
    /// Signing keys are fetched from the OIDC discovery document at <see cref="JwtBearerAuthOptions.Authority"/>
    /// and rotated automatically. The provider does not refresh tokens; clients must obtain new ones
    /// before expiry.
    /// <para/>
    /// The JwtBearer handler binds from the composed <c>IOptions&lt;JwtBearerAuthOptions&gt;</c>
    /// pipeline, so <c>services.Configure&lt;JwtBearerAuthOptions&gt;(...)</c> /
    /// <c>PostConfigure&lt;JwtBearerAuthOptions&gt;(...)</c> registered before or after this call
    /// (e.g. injecting the authority from a secret store) is honored.
    /// <para/>
    /// This method is idempotent: calling it more than once applies the additional
    /// <paramref name="configureOptions"/> through the options pipeline but registers
    /// the Bearer scheme, handler binding, and authentication provider only once.
    /// </remarks>
    /// <param name="services">The service collection</param>
    /// <param name="configureOptions">Action to configure <see cref="JwtBearerAuthOptions"/></param>
    /// <returns>The service collection for chaining</returns>
    /// <example>
    /// <code>
    /// builder.Services.AddPortaJwtAuthentication(options =>
    /// {
    ///     options.Authority = "https://auth.example.com";
    ///     options.ValidAudiences = ["my-porta"];
    /// });
    /// </code>
    /// </example>
    public static IServiceCollection AddPortaJwtAuthentication(
        this IServiceCollection services,
        Action<JwtBearerAuthOptions> configureOptions)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configureOptions);

        services.Configure(configureOptions);

        // Idempotency guard: a second AddJwtBearer() registers the Bearer scheme twice,
        // which throws "Scheme already exists: Bearer" at the first authentication
        // resolve, and the plain AddScoped registration below would run the provider
        // twice per request through the composite.
        if (services.Any(d => d.ServiceType == typeof(PortaJwtAuthenticationMarker)))
        {
            return services;
        }

        services.AddSingleton<PortaJwtAuthenticationMarker>();

        services.AddAuthentication()
            .AddJwtBearer();

        // Bind the JwtBearer handler from the composed IOptions<JwtBearerAuthOptions>
        // pipeline (read at options-build time) rather than a registration-time snapshot,
        // so external Configure/PostConfigure<JwtBearerAuthOptions> reaches the actual
        // handler - the same snapshot-drift fix already applied to the OpenIdConnect
        // handler in AddCookieAndOidcAuthentication.
        services.AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme)
            .Configure<IOptions<JwtBearerAuthOptions>>((jwtOptions, auth) =>
            {
                var options = auth.Value;
                jwtOptions.Authority = options.Authority;
                jwtOptions.RequireHttpsMetadata = options.RequireHttpsMetadata;
                jwtOptions.SaveToken = true; // Required so JwtBearerAuthProvider can extract the raw token

                jwtOptions.TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
                {
                    ValidateIssuer = options.ValidateIssuer,
                    ValidIssuers = options.ValidIssuers.Count > 0 ? options.ValidIssuers : null,
                    ValidateAudience = options.ValidateAudience,
                    ValidAudiences = options.ValidAudiences,
                    ValidateLifetime = options.ValidateLifetime,
                    ClockSkew = options.ClockSkew,
                    ValidAlgorithms = JwtValidationHelper.AllowedAsymmetricAlgorithms
                };
            });

        services.TryAddScoped<JwtBearerAuthProvider>();
        services.AddScoped<IAuthenticationProviderRegistration>(sp =>
            new AuthenticationProviderRegistration(sp.GetRequiredService<JwtBearerAuthProvider>()));

        return services;
    }

    /// <summary>
    /// Registers a custom authentication provider.
    /// </summary>
    /// <typeparam name="TProvider">The custom authentication provider type implementing <see cref="IAuthenticationProvider"/></typeparam>
    /// <param name="services">The service collection</param>
    /// <returns>The service collection for chaining</returns>
    /// <remarks>
    /// Use this method to register custom authentication providers for scenarios not covered by
    /// the built-in providers (session-based OIDC or reference token).
    ///
    /// Common use cases:
    /// <list type="bullet">
    ///   <item>API key authentication</item>
    ///   <item>HMAC signature validation</item>
    ///   <item>Custom JWT validation</item>
    ///   <item>External identity provider integration</item>
    /// </list>
    /// </remarks>
    /// <example>
    /// <code>
    /// // Register custom provider
    /// builder.Services.AddPortaAuthProvider&lt;ApiKeyAuthProvider&gt;();
    ///
    /// // Or with factory
    /// builder.Services.AddPortaAuthProvider&lt;ApiKeyAuthProvider&gt;(sp =>
    ///     new ApiKeyAuthProvider(sp.GetRequiredService&lt;IApiKeyValidator&gt;()));
    /// </code>
    /// </example>
    public static IServiceCollection AddPortaAuthProvider<TProvider>(this IServiceCollection services)
        where TProvider : class, IAuthenticationProvider
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddScoped<TProvider>();
        services.AddScoped<IAuthenticationProviderRegistration>(sp =>
            new AuthenticationProviderRegistration(sp.GetRequiredService<TProvider>()));

        return services;
    }

    /// <summary>
    /// Registers a custom authentication provider using a factory function.
    /// </summary>
    /// <typeparam name="TProvider">The custom authentication provider type implementing <see cref="IAuthenticationProvider"/></typeparam>
    /// <param name="services">The service collection</param>
    /// <param name="implementationFactory">Factory function to create the provider instance</param>
    /// <returns>The service collection for chaining</returns>
    public static IServiceCollection AddPortaAuthProvider<TProvider>(
        this IServiceCollection services,
        Func<IServiceProvider, TProvider> implementationFactory)
        where TProvider : class, IAuthenticationProvider
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(implementationFactory);

        services.AddScoped<TProvider>(implementationFactory);
        services.AddScoped<IAuthenticationProviderRegistration>(sp =>
            new AuthenticationProviderRegistration(sp.GetRequiredService<TProvider>()));

        return services;
    }

    /// <summary>
    /// Marker registration recording that <see cref="AddPortaAuthenticationCore"/> has
    /// already run, making repeated <c>AddPortaAuthentication</c> calls (including via
    /// <c>AddPortaOidcAuth</c>) no-ops for service registration (options configuration
    /// still composes).
    /// </summary>
    private sealed class PortaAuthenticationMarker;

    /// <summary>
    /// Marker registration recording that
    /// <see cref="AddReferenceTokenAuthentication(IServiceCollection, Action{ReferenceTokenAuthOptions}, Action{HttpStandardResilienceOptions})"/>
    /// has already run, making repeated calls no-ops for service registration
    /// (options configuration still composes).
    /// </summary>
    private sealed class ReferenceTokenAuthenticationMarker;

    /// <summary>
    /// Marker registration recording that
    /// <see cref="AddPortaJwtAuthentication(IServiceCollection, Action{JwtBearerAuthOptions})"/>
    /// has already run, making repeated calls no-ops for service registration
    /// (options configuration still composes).
    /// </summary>
    private sealed class PortaJwtAuthenticationMarker;

    /// <summary>
    /// Marker registration recording that
    /// <see cref="AddPortaReferenceTokenScheme(IServiceCollection, Action{ReferenceTokenAuthOptions}, Action{HttpStandardResilienceOptions})"/>
    /// has already registered the authentication scheme, making repeated calls no-ops for scheme
    /// registration (options configuration still composes).
    /// </summary>
    private sealed class PortaReferenceTokenSchemeMarker;
}
