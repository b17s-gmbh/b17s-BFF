using b17s.Porta.Auth.Discovery;
using b17s.Porta.Auth.Providers;
using b17s.Porta.Auth.Sessions;
using b17s.Porta.Auth.Tokens;
using b17s.Porta.Configuration;
using b17s.Porta.Services;
using b17s.Porta.Telemetry;
using b17s.Porta.Transformers;

using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Http.Resilience;
using Microsoft.Extensions.Options;

using Polly;

namespace b17s.Porta.Extensions;

/// <summary>
/// Primary extension methods for registering BFF services.
/// These are the main entry points for configuring the BFF library.
/// </summary>
public static class PortaServiceExtensions
{
    /// <summary>
    /// Adds core BFF services required for transformer-based API aggregation.
    /// This is the minimal setup needed for any BFF - no authentication included.
    /// </summary>
    /// <param name="services">The service collection</param>
    /// <param name="configureOptions">Optional action to configure BFF core options</param>
    /// <returns>The service collection for chaining</returns>
    /// <remarks>
    /// <para>
    /// This method registers:
    /// <list type="bullet">
    ///   <item>Backend caller infrastructure (HttpClients with resilience)</item>
    ///   <item>Transformer support services</item>
    ///   <item>Backend auth handler registry with built-in handlers (None, BearerToken, BasicAuth)</item>
    ///   <item>Trusted host validation for secure token forwarding</item>
    /// </list>
    /// </para>
    /// <para>
    /// For OIDC authentication, also call <see cref="AddPortaOidcAuth(IServiceCollection, Action{OidcAuthOptions})"/>.
    /// </para>
    /// <para>
    /// This method is idempotent: calling it more than once applies the additional
    /// <paramref name="configureOptions"/> through the options pipeline but registers the
    /// services only once, so named <see cref="HttpClient"/> configurations, resilience
    /// handlers, and service descriptors are never duplicated.
    /// </para>
    /// </remarks>
    /// <example>
    /// <code>
    /// // Minimal setup - no auth
    /// builder.Services.AddPortaCore(options => {
    ///     options.DefaultTimeout = TimeSpan.FromSeconds(30);
    ///     options.EnableTelemetry = true;
    /// });
    ///
    /// // With trusted hosts for token forwarding
    /// builder.Services.AddPortaCore(options => {
    ///     options.TrustedHosts = ["https://api.example.com", "https://*.internal.example.com"];
    /// });
    /// </code>
    /// </example>
    public static IServiceCollection AddPortaCore(
        this IServiceCollection services,
        Action<PortaCoreOptions>? configureOptions = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        // Configure core options through the standard options pipeline so consumer
        // Configure<PortaCoreOptions>(...) and PostConfigure<PortaCoreOptions>(...) calls
        // compose correctly. Using Options.Create(...) here would shadow the entire
        // pipeline and silently drop those calls.
        if (configureOptions is not null)
        {
            services.Configure(configureOptions);
        }

        // Idempotency guard: AddHttpClient(name, ...) configurations accumulate on the
        // named HttpClientFactoryOptions, so a second call would nest another resilience
        // handler on the retry client (multiplying effective retry counts), duplicate the
        // Accept header, and double every plain AddScoped/AddSingleton descriptor below.
        // The options configuration above intentionally runs before the guard so repeated
        // calls still compose through the options pipeline.
        if (services.Any(d => d.ServiceType == typeof(PortaCoreMarker)))
        {
            return services;
        }

        services.AddSingleton<PortaCoreMarker>();

        // Validate core options up-front so a misconfigured BFF fails at boot rather
        // than on the first backend call (HttpClient.Timeout and the resilience pipeline
        // both throw on invalid values only when the first client is created). The
        // AddOptions call also ensures IOptions<PortaCoreOptions> resolves when no
        // explicit configuration was supplied.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<PortaCoreOptions>, PortaCoreOptionsValidator>());
        services.AddOptions<PortaCoreOptions>().ValidateOnStart();

        // Register HttpContextAccessor (required for token forwarding)
        services.AddHttpContextAccessor();

        // IApiTokenService is intentionally not registered here. The built-in
        // TokenExchangeAuthHandler takes it as a nullable dependency and throws a
        // clear 401-mapping error only on the token-exchange path that actually needs
        // it. Registering a stub factory would defeat that null handling and break
        // consumers that don't use auth. It is registered for real by
        // AddPortaAuthentication() / AddPortaOidcAuth().

        // IAuthenticationProvider resolves through CompositeAuthenticationProvider.
        // Each registration extension (AddPortaOidcAuth, AddReferenceTokenAuthentication,
        // AddPortaJwtAuthentication, AddPortaAuthProvider<T>) adds an
        // IAuthenticationProviderRegistration entry; the composite tries them in
        // registration order on each request. Consumers can combine credential types
        // (session + JWT + reference token + custom) on the same endpoints.
        services.TryAddScoped<IAuthenticationProvider>(sp =>
        {
            var providers = sp.GetServices<IAuthenticationProviderRegistration>()
                .Select(r => r.Provider)
                .ToList();

            // No providers is a valid configuration: the documented "Minimal Setup (No Auth)"
            // (AddPortaCore + .AllowAnonymous()) registers none. The transformer and raw-forward
            // handlers resolve IAuthenticationProvider unconditionally, so throwing here would turn
            // every anonymous endpoint into a request-time 500. An empty composite instead yields
            // AuthenticationContext.Unauthenticated(); endpoints that genuinely require auth are
            // still gated by the principal check in the handlers, which returns 401 (not 500) when
            // no credential ever authenticates.
            var logger = sp.GetRequiredService<Microsoft.Extensions.Logging.ILogger<CompositeAuthenticationProvider>>();
            return new CompositeAuthenticationProvider(providers, logger);
        });

        // Register HttpClient without retries (default). Timeout binds from the composed
        // IOptions<PortaCoreOptions> pipeline (read at client-creation time) rather than an
        // eager snapshot, so consumer Configure/PostConfigure<PortaCoreOptions> is honored.
        services.AddHttpClient(BackendCaller.HttpClientName, (sp, client) =>
        {
            var coreOptions = sp.GetRequiredService<IOptions<PortaCoreOptions>>().Value;
            client.Timeout = coreOptions.DefaultTimeout;
            client.DefaultRequestHeaders.Accept.Add(
                new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));
        })
        // Auto-redirect is disabled: TrustedHostValidator gates the *request* URL (at startup
        // against the configured UrlTemplate, and again at request time before a user token is
        // attached), but a redirect target is never re-validated. A backend returning
        // `302 Location: https://attacker/...` would otherwise cause the client to follow,
        // leaking any custom headers added by IBackendAuthHandler (X-Api-Key, HMAC signatures,
        // etc.) - .NET only strips Authorization on cross-origin redirects.
        .ConfigurePrimaryHttpMessageHandler(() => new System.Net.Http.SocketsHttpHandler
        {
            AllowAutoRedirect = false,
        });

        // Register HttpClient with retries (used when EnableRetries = true). No client.Timeout
        // is set here: AddStandardResilienceHandler resets HttpClient.Timeout to infinite and
        // owns all timeouts via AttemptTimeout/TotalRequestTimeout, which ConfigureBackendResilience
        // binds from the composed IOptions<PortaCoreOptions> pipeline (so consumer
        // Configure/PostConfigure is honored).
        services.AddHttpClient(BackendCaller.HttpClientNameWithRetries, client =>
        {
            client.DefaultRequestHeaders.Accept.Add(
                new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));
        })
        .ConfigurePrimaryHttpMessageHandler(() => new System.Net.Http.SocketsHttpHandler
        {
            AllowAutoRedirect = false,
        })
        .AddStandardResilienceHandler()
        .Configure((resilience, sp) =>
            ConfigureBackendResilience(resilience, sp.GetRequiredService<IOptions<PortaCoreOptions>>().Value));

        // Register built-in backend auth handlers as IBackendAuthHandler. Consumers add
        // custom handlers via AddPortaAuthHandler<T> which appends to the same DI
        // enumeration. The registry is composed from the enumerable at resolve time,
        // so the order of registration calls no longer matters and duplicate calls
        // are additive instead of destructive.
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IBackendAuthHandler, NoneAuthHandler>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IBackendAuthHandler, BearerTokenAuthHandler>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IBackendAuthHandler, BasicAuthHandler>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IBackendAuthHandler, TokenExchangeAuthHandler>());

        services.TryAddSingleton<IBackendAuthHandlerRegistry>(sp =>
        {
            var registry = new BackendAuthHandlerRegistry();
            foreach (var handler in sp.GetServices<IBackendAuthHandler>())
            {
                registry.Register(handler);
            }
            return registry;
        });

        // Register the content serializer used by BackendCaller for JSON/XML/form-encoded payloads.
        // TryAdd so callers can swap in a custom IContentSerializer.
        services.TryAddSingleton<IContentSerializer, ContentSerializer>();

        // Default backend error mapper: maps backend 401/403 to 502 so the client doesn't
        // sign out the user when *backend* credentials are wrong. Use TryAdd so consumers
        // can register a custom IBackendErrorMapper (e.g. PassThroughBackendErrorMapper).
        services.TryAddSingleton<IBackendErrorMapper, DefaultBackendErrorMapper>();

        services.AddScoped<IBackendCaller, BackendCaller>();

        // Fail fast at startup if token-exchange audiences are configured but the token-exchange
        // dependency (IApiTokenService) was never registered - otherwise it only surfaces as a
        // request-time ConfigurationError on the first token-exchange route.
        services.AddHostedService<TokenExchangeConfigurationStartupCheck>();

        // Open-generic registration so MapPassThrough<TResponse>() can resolve a
        // synthetic BackendForwardingTransformer<TResponse> for any TResponse.
        services.AddTransient(typeof(BackendForwardingTransformer<>));

        // The zero-code MapRawForward() overloads default to
        // RawForwardEndpointBuilder<DefaultRawForwardTransformer>, which resolves the
        // transformer from DI at request time. Register the default here so the
        // documented no-transformer proxy examples work without the consumer having to
        // call AddRawForwardTransformer<DefaultRawForwardTransformer>() themselves.
        // TryAdd so a consumer can still override the default registration if desired.
        services.TryAddTransient<DefaultRawForwardTransformer>();

        // Register trusted host validator: WithUserToken() validation at startup, plus the
        // request-time gate in BackendCaller before a user token is forwarded.
        services.AddSingleton<ITrustedHostValidator, TrustedHostValidator>();

        // Register the matcher policy for When() predicate-based conditional routing
        services.AddSingleton<MatcherPolicy, WhenPredicateMatcherPolicy>();

        // Register BFF metrics for telemetry (always registered as BackendCaller depends on it)
        services.AddSingleton<PortaMetrics>();

        // Default TimeProvider so internal services that take TimeProvider as a
        // constructor parameter resolve to wall-clock unless the consumer
        // (typically a test host) has already registered FakeTimeProvider.
        services.TryAddSingleton(TimeProvider.System);

        // Authorization services. Porta is not authorization-agnostic: PortaCoreOptions
        // defaults RequireAuthorizationByDefault = true, so every transformer / pass-through
        // endpoint applies RequireAuthorization() unless explicitly AllowAnonymous, and the
        // OIDC endpoints / SessionAdminMiddleware resolve IAuthorizationService directly.
        // Owning this registration keeps the secure default self-consistent so consumers
        // don't have to remember a separate AddAuthorization() call just to make Porta's
        // own behavior work. AddAuthorization is idempotent (TryAdd-based) and additive,
        // so a consumer's later AddAuthorization(options => options.AddPolicy(...)) and
        // custom IAuthorizationPolicyProvider registrations still compose normally.
        services.AddAuthorization();

        // Startup guard: warn (Critical) if any Porta endpoint requires an authenticated principal
        // while no authentication scheme is registered to populate HttpContext.User. TryAddEnumerable
        // so repeated AddPortaCore calls don't run the check more than once.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IHostedService, PortaPrincipalGateStartupCheck>());

        return services;
    }

    /// <summary>
    /// Configures the standard resilience pipeline on the retrying backend
    /// <see cref="HttpClient"/> (<see cref="BackendCaller.HttpClientNameWithRetries"/>).
    /// </summary>
    /// <remarks>
    /// <c>AddStandardResilienceHandler</c> bakes a single <c>MaxRetryAttempts</c> into the pipeline,
    /// so <see cref="PortaCoreOptions.MaxRetryAttempts"/> is treated as the app-wide <em>ceiling</em>
    /// rather than the count every endpoint gets. The per-endpoint <c>WithRetries(n)</c> value is
    /// carried on the outbound request via <see cref="BackendCaller.RetryBudgetOption"/> and enforced
    /// by the <c>ShouldHandle</c> gate below, so the effective retry count is <c>min(n, ceiling)</c>.
    /// The budget is read from the resilience context (not the outcome) so it is honored for
    /// exception outcomes too, where there is no response to inspect. Requests without a budget
    /// (non-Porta callers sharing the client) fall through to the ceiling.
    /// A ceiling below 1 disables retries app-wide. It cannot be copied onto
    /// <c>MaxRetryAttempts</c> verbatim - Polly validates the strategy options
    /// (<c>[Range(1, ...)]</c>) when the pipeline is first built, so a zero would throw
    /// <c>OptionsValidationException</c> on the first backend call - and is instead modelled as a
    /// <c>ShouldHandle</c> predicate that never retries, mirroring the token-client opt-out in
    /// <see cref="b17s.Porta.Extensions.AuthenticationServiceExtensions"/>.
    /// </remarks>
    internal static void ConfigureBackendResilience(HttpStandardResilienceOptions resilience, PortaCoreOptions coreOptions)
    {
        resilience.AttemptTimeout.Timeout = coreOptions.DefaultTimeout;
        resilience.TotalRequestTimeout.Timeout = TimeSpan.FromSeconds(coreOptions.DefaultTimeout.TotalSeconds * 2);

        if (coreOptions.MaxRetryAttempts < 1)
        {
            // Retries disabled app-wide: never retry, regardless of any per-endpoint
            // WithRetries(n) budget. MaxRetryAttempts stays at its (valid) default -
            // zeroing it fails Polly's range validation at pipeline build.
            resilience.Retry.ShouldHandle = static _ => PredicateResult.False();
        }
        else
        {
            resilience.Retry.MaxRetryAttempts = coreOptions.MaxRetryAttempts;
            var isTransient = resilience.Retry.ShouldHandle;
            resilience.Retry.ShouldHandle = args =>
            {
                var budget = args.Context.GetRequestMessage() is { } message
                    && message.Options.TryGetValue(BackendCaller.RetryBudgetOption, out var n)
                    ? n
                    : coreOptions.MaxRetryAttempts;

                // args.AttemptNumber is the 0-based index of the attempt that just failed, so the first
                // retry decision sees 0. Stop once the per-endpoint budget is spent; otherwise defer to
                // the standard transient-failure predicate.
                return args.AttemptNumber >= budget
                    ? ValueTask.FromResult(false)
                    : isTransient(args);
            };
        }

        // Circuit breaker sampling duration must be at least 2x the attempt timeout
        resilience.CircuitBreaker.SamplingDuration = TimeSpan.FromSeconds(coreOptions.DefaultTimeout.TotalSeconds * 2.5);
    }

    /// <summary>
    /// Adds core BFF services with configuration binding from appsettings.
    /// </summary>
    /// <param name="services">The service collection</param>
    /// <param name="configuration">The configuration root</param>
    /// <param name="sectionName">The configuration section name for <see cref="PortaCoreOptions"/> (default: "PortaCore")</param>
    /// <returns>The service collection for chaining</returns>
    /// <remarks>
    /// In addition to <see cref="PortaCoreOptions"/> from <paramref name="sectionName"/>, this overload
    /// also binds <see cref="BackendServiceOptions"/> from the fixed
    /// <see cref="BackendServiceOptions.SectionName">"BackendService"</see> section so the built-in
    /// BasicAuth and TokenExchange backend-auth handlers pick up appsettings-supplied credentials
    /// and audiences.
    /// </remarks>
    /// <example>
    /// <code>
    /// // In appsettings.json:
    /// // "PortaCore": {
    /// //   "TrustedHosts": ["https://api.example.com"],
    /// //   "DefaultTimeout": "00:00:30"
    /// // },
    /// // "BackendService": {
    /// //   "BasicAuth": { "Username": "bff", "Password": "..." }
    /// // }
    ///
    /// builder.Services.AddPortaCore(builder.Configuration);
    /// </code>
    /// </example>
    public static IServiceCollection AddPortaCore(
        this IServiceCollection services,
        IConfiguration configuration,
        string sectionName = PortaCoreOptions.SectionName)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        // Bind the documented "BackendService" section so the built-in BasicAuth and
        // TokenExchange handlers (which consume IOptions<BackendServiceOptions>) pick up
        // appsettings-supplied credentials and audiences. Without this, consumers following
        // the docs would get empty options at runtime - silent backend-auth failures.
        // Bound through the standard options pipeline so consumer Configure/PostConfigure
        // composition still applies.
        services.Configure<BackendServiceOptions>(
            configuration.GetSection(BackendServiceOptions.SectionName));

        return services.AddPortaCore(opt => configuration.GetSection(sectionName).Bind(opt));
    }

    /// <summary>
    /// Adds OIDC authentication with session-based token storage.
    /// This is an opt-in addition to <see cref="AddPortaCore(IServiceCollection, IConfiguration, string)"/>.
    /// </summary>
    /// <param name="services">The service collection</param>
    /// <param name="configureOptions">Action to configure OIDC options</param>
    /// <returns>The service collection for chaining</returns>
    /// <remarks>
    /// <para>
    /// This method registers:
    /// <list type="bullet">
    ///   <item>Session-based authentication with cookie support</item>
    ///   <item>Token refresh, exchange, and revocation services</item>
    ///   <item>OIDC discovery service</item>
    ///   <item>Session management services</item>
    ///   <item>Data Protection for token encryption at rest</item>
    ///   <item>Logout services</item>
    /// </list>
    /// </para>
    /// <para>
    /// Requires a distributed cache (Redis/Valkey) for session storage in production.
    /// Use <c>builder.AddRedisDistributedCache("cache")</c> with Aspire or
    /// <c>services.AddStackExchangeRedisCache()</c> manually.
    /// </para>
    /// <para>
    /// This method is idempotent: calling it more than once (or combining it with
    /// <see cref="AuthenticationServiceExtensions.AddPortaAuthentication(IServiceCollection, Action{SessionAuthenticationConfiguration}?)"/>,
    /// which it wires internally) applies the additional <paramref name="configureOptions"/>
    /// through the options pipeline but registers the cookie/OIDC authentication schemes and
    /// services only once.
    /// </para>
    /// </remarks>
    /// <example>
    /// <code>
    /// builder.Services.AddPortaCore();
    /// builder.Services.AddPortaOidcAuth(options => {
    ///     options.Authority = "https://auth.example.com";
    ///     options.ClientId = "my-porta";
    ///     options.ClientSecret = builder.Configuration["Oidc:ClientSecret"];
    ///     options.Scope = "openid profile email api";
    /// });
    /// </code>
    /// </example>
    public static IServiceCollection AddPortaOidcAuth(
        this IServiceCollection services,
        Action<OidcAuthOptions> configureOptions)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configureOptions);

        services.Configure(configureOptions);

        return services.AddPortaOidcAuthCore();
    }

    /// <summary>
    /// Adds OIDC authentication with configuration binding from appsettings.
    /// </summary>
    /// <param name="services">The service collection</param>
    /// <param name="configuration">The configuration root</param>
    /// <param name="sectionName">The configuration section name (default: "OidcAuth")</param>
    /// <returns>The service collection for chaining</returns>
    /// <example>
    /// <code>
    /// // In appsettings.json:
    /// // "OidcAuth": {
    /// //   "Authority": "https://auth.example.com",
    /// //   "ClientId": "my-porta",
    /// //   "ClientSecret": "secret",
    /// //   "Scope": "openid profile email"
    /// // }
    ///
    /// builder.Services.AddPortaCore();
    /// builder.Services.AddPortaOidcAuth(builder.Configuration);
    /// </code>
    /// </example>
    public static IServiceCollection AddPortaOidcAuth(
        this IServiceCollection services,
        IConfiguration configuration,
        string sectionName = OidcAuthOptions.SectionName)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        // Bind through the options pipeline (not a one-shot snapshot) so the binding
        // is reload-aware and composes with consumer Configure/PostConfigure - the
        // same contract as AddPortaAuthentication(IConfiguration).
        services.Configure<OidcAuthOptions>(configuration.GetSection(sectionName));

        return services.AddPortaOidcAuthCore();
    }

    /// <summary>
    /// Shared registration body for both <c>AddPortaOidcAuth</c> overloads.
    /// <c>IOptions&lt;OidcAuthOptions&gt;</c> is the single source of truth: its fully
    /// composed value - including every consumer <c>Configure</c>/<c>PostConfigure</c>,
    /// e.g. a <c>ClientSecret</c> injected from a secret store - is projected into
    /// <see cref="SessionAuthenticationConfiguration"/> at options-build time, which is
    /// what the cookie/OIDC handlers and token services bind from. A prior implementation
    /// projected a registration-time snapshot instead, making
    /// <c>PostConfigure&lt;OidcAuthOptions&gt;</c> a silent no-op.
    /// </summary>
    private static IServiceCollection AddPortaOidcAuthCore(this IServiceCollection services)
    {
        // Idempotency guard: a second call would add a duplicate
        // SessionAuthenticationConfiguration projection (re-running CopyOptions per
        // options build). The Configure<OidcAuthOptions> in the public overloads runs
        // before this guard so repeated calls still compose through the options
        // pipeline; AddPortaAuthentication carries its own guard, so it is always
        // safe to delegate to it.
        if (services.Any(d => d.ServiceType == typeof(PortaOidcAuthMarker)))
        {
            return services.AddPortaAuthentication();
        }

        services.AddSingleton<PortaOidcAuthMarker>();

        // Validate OidcAuthOptions at host start so a misconfigured BFF fails on
        // boot rather than on the first OIDC redirect.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<
                IValidateOptions<OidcAuthOptions>,
                OidcAuthOptionsValidator>());
        services.AddOptions<OidcAuthOptions>().ValidateOnStart();

        // Project the composed OidcAuthOptions into SessionAuthenticationConfiguration.
        // IOptionsFactory builds a fresh value per projection: IOptions would pin the
        // boot-time value across configuration reloads, and IOptionsMonitor.CurrentValue
        // can serve a stale cache during a reload (monitor invalidation callbacks fire
        // in subscription order). CopyOptions deep-copies the mutable sub-objects so
        // the two options types never alias state.
        services.AddOptions<SessionAuthenticationConfiguration>()
            .Configure<IOptionsFactory<OidcAuthOptions>>((target, factory) =>
                CopyOptions(factory.Create(Microsoft.Extensions.Options.Options.DefaultName), target));

        // Forward OidcAuthOptions reload signals (e.g. the IConfiguration overload's
        // section change tokens) so IOptionsMonitor<SessionAuthenticationConfiguration>
        // consumers rebuild instead of holding the boot-time projection forever.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<
                IOptionsChangeTokenSource<SessionAuthenticationConfiguration>,
                OidcAuthChangeTokenForwarder>());

        return services.AddPortaAuthentication();
    }

    /// <summary>
    /// Registers a custom backend authentication handler.
    /// </summary>
    /// <typeparam name="THandler">The handler type implementing <see cref="IBackendAuthHandler"/></typeparam>
    /// <param name="services">The service collection</param>
    /// <returns>The service collection for chaining</returns>
    /// <remarks>
    /// <para>
    /// Backend auth handlers are used to authenticate requests to backend services.
    /// Each handler implements a specific authentication policy (e.g., API key, HMAC, OAuth client credentials).
    /// </para>
    /// <para>
    /// The handler's <see cref="IBackendAuthHandler.PolicyName"/> is used to reference it in endpoint configuration:
    /// <c>.WithBackendAuth("PolicyName")</c>
    /// </para>
    /// </remarks>
    /// <example>
    /// <code>
    /// // Custom handler implementation
    /// public class HmacAuthHandler : IBackendAuthHandler
    /// {
    ///     public string PolicyName => "HmacAuth";
    ///
    ///     public Task ApplyAuthAsync(HttpRequestMessage request, BackendAuthContext context)
    ///     {
    ///         var signature = ComputeHmacSignature(request);
    ///         request.Headers.Add("X-Signature", signature);
    ///         request.Headers.Add("X-Timestamp", DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString());
    ///         return Task.CompletedTask;
    ///     }
    /// }
    ///
    /// // Registration
    /// builder.Services.AddPortaCore();
    /// builder.Services.AddPortaAuthHandler&lt;HmacAuthHandler&gt;();
    ///
    /// // Usage in endpoint
    /// app.MapTransformer&lt;MyTransformer, Response&gt;()
    ///    .FromRoute("GET", "/api/data")
    ///    .ToBackend("GET", "https://partner-api.example.com/data")
    ///    .WithBackendAuth("HmacAuth")
    ///    .Build();
    /// </code>
    /// </example>
    public static IServiceCollection AddPortaAuthHandler<THandler>(this IServiceCollection services)
        where THandler : class, IBackendAuthHandler
    {
        ArgumentNullException.ThrowIfNull(services);

        // Append to the IBackendAuthHandler enumeration. The registry built in
        // AddPortaCore consumes IEnumerable<IBackendAuthHandler> at resolve time, so
        // multiple calls (and mixing of typed/factory variants) compose additively.
        // TryAddEnumerable de-duplicates by implementation type, so calling this
        // twice with the same THandler is a no-op rather than overwriting.
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IBackendAuthHandler, THandler>());
        return services;
    }

    /// <summary>
    /// Registers a custom backend authentication handler using a factory function.
    /// </summary>
    /// <typeparam name="THandler">The handler type implementing <see cref="IBackendAuthHandler"/></typeparam>
    /// <param name="services">The service collection</param>
    /// <param name="implementationFactory">Factory function to create the handler instance</param>
    /// <returns>The service collection for chaining</returns>
    /// <example>
    /// <code>
    /// builder.Services.AddPortaAuthHandler&lt;ApiKeyAuthHandler&gt;(sp =>
    ///     new ApiKeyAuthHandler(
    ///         sp.GetRequiredService&lt;IConfiguration&gt;()["ApiKeys:PartnerApi"]));
    /// </code>
    /// </example>
    public static IServiceCollection AddPortaAuthHandler<THandler>(
        this IServiceCollection services,
        Func<IServiceProvider, THandler> implementationFactory)
        where THandler : class, IBackendAuthHandler
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(implementationFactory);

        // Append to the IBackendAuthHandler enumeration via factory. TryAddEnumerable
        // de-duplicates by implementation type, so the same THandler is only added
        // once even across mixed typed/factory calls.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IBackendAuthHandler, THandler>(implementationFactory));
        return services;
    }

    /// <summary>
    /// Registers multiple custom backend authentication handlers at once.
    /// </summary>
    /// <param name="services">The service collection</param>
    /// <param name="handlerTypes">The handler types implementing <see cref="IBackendAuthHandler"/></param>
    /// <returns>The service collection for chaining</returns>
    /// <example>
    /// <code>
    /// builder.Services.AddPortaAuthHandlers(
    ///     typeof(HmacAuthHandler),
    ///     typeof(ApiKeyAuthHandler),
    ///     typeof(ClientCredentialsAuthHandler));
    /// </code>
    /// </example>
    public static IServiceCollection AddPortaAuthHandlers(
        this IServiceCollection services,
        params Type[] handlerTypes)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(handlerTypes);

        // Validate all types implement IBackendAuthHandler, then append each to the
        // IBackendAuthHandler enumeration. TryAddEnumerable de-duplicates by
        // implementation type, so calling this twice with overlapping types is safe.
        foreach (var type in handlerTypes)
        {
            if (!typeof(IBackendAuthHandler).IsAssignableFrom(type))
            {
                throw new ArgumentException(
                    $"Type {type.Name} does not implement IBackendAuthHandler",
                    nameof(handlerTypes));
            }

            services.TryAddEnumerable(
                ServiceDescriptor.Singleton(typeof(IBackendAuthHandler), type));
        }

        return services;
    }

    #region Private Helper Methods

    private static void CopyOptions(OidcAuthOptions source, SessionAuthenticationConfiguration target)
    {
        target.CookieName = source.CookieName;
        target.Scope = source.Scope;
        target.Authority = source.Authority;
        target.RequireHttpsMetadata = source.RequireHttpsMetadata;
        target.ClientId = source.ClientId;
        target.ClientSecret = source.ClientSecret;
        target.UsePkce = source.UsePkce;
        target.SessionTimeoutInMin = source.SessionTimeoutInMin;
        target.TokenExchangeStrategy = source.TokenExchangeStrategy;
        target.QueryUserInfoEndpoint = source.QueryUserInfoEndpoint;
        // Deep-copy the mutable sub-objects so the two registered options types
        // (IOptions<OidcAuthOptions> and IOptions<SessionAuthenticationConfiguration>)
        // do not alias the same instances. Aliasing would let a PostConfigure
        // mutation on one silently affect the other, defeating the single-source-of-truth
        // intent of this copy.
        target.Cookie = source.Cookie.Clone();
        target.Challenge = source.Challenge.Clone();
        target.Resilience = source.Resilience.Clone();
        target.DataProtection = source.DataProtection.Clone();
        target.SessionKeys = source.SessionKeys.Clone();
    }

    private static void CopyOptions(OidcAuthOptions source, OidcAuthOptions target)
        => CopyOptions(source, (SessionAuthenticationConfiguration)target);

    /// <summary>
    /// Marker registration recording that <see cref="AddPortaCore(IServiceCollection, Action{PortaCoreOptions}?)"/>
    /// has already run, making repeated calls no-ops for service registration
    /// (options configuration still composes).
    /// </summary>
    private sealed class PortaCoreMarker;

    /// <summary>
    /// Marker registration recording that <see cref="AddPortaOidcAuthCore"/> has already
    /// run, making repeated <c>AddPortaOidcAuth</c> calls no-ops for service registration
    /// (options configuration still composes).
    /// </summary>
    private sealed class PortaOidcAuthMarker;

    #endregion
}
