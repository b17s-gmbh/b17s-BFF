using System.Diagnostics;
using System.Text.Json;

using b17s.Porta.Auth.Providers;
using b17s.Porta.Configuration;
using b17s.Porta.Extensions;
using b17s.Porta.Telemetry;

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Caching.Hybrid;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;

namespace b17s.Porta.Transformers;

/// <summary>
/// Shared implementation for transformer endpoint builders. Holds all fluent
/// configuration state and the request handler, leaving subclasses to plug in
/// only the differences (request-body deserialization, which TransformAsync
/// overload to invoke).
/// </summary>
/// <typeparam name="TTransformer">Concrete transformer type.</typeparam>
/// <typeparam name="TBuilder">Concrete builder type (CRTP) - used so fluent
/// setters return the most-derived builder for chaining.</typeparam>
public abstract class TransformerEndpointBuilderBase<TTransformer, TBuilder> : BffEndpointBuilderBase<TBuilder>
    where TBuilder : TransformerEndpointBuilderBase<TTransformer, TBuilder>
{
    private bool _useTokenExchange;
    private string? _tokenExchangeAudience;
    private bool _enableRetries;
    private int _maxRetryAttempts = 3;
    private ContentType? _backendRequestContentType;
    private readonly NamedBackendEndpoints _namedBackends = new();
    private readonly IEndpointRouteBuilder _endpoints;
    private readonly IServiceProvider _services;
    private readonly PortaCoreOptions _options;
    private Func<HttpContext, bool>? _whenPredicate;
    private HashSet<string>? _forwardedRequestHeaders;
    private HashSet<string>? _forwardedHeaderDestinationHosts;

    private protected TransformerEndpointBuilderBase(IEndpointRouteBuilder endpoints, IServiceProvider services)
    {
        _endpoints = endpoints;
        _services = services;
        _options = services.GetService<IOptions<PortaCoreOptions>>()?.Value ?? new PortaCoreOptions();
    }

    /// <summary>
    /// Subclass hook: invoke the transformer's <c>TransformAsync</c> overload. The
    /// <c>TransformerEndpointBuilder{TTransformer, TRequest, TResponse}</c> variant deserializes the
    /// request body before calling; the <c>TransformerEndpointBuilder{TTransformer, TResponse}</c>
    /// variant ignores the body.
    /// </summary>
    /// <param name="httpContext">The current HTTP context.</param>
    /// <param name="transformerContext">The transformer context for the current request.</param>
    /// <returns>The transformer response, serialized to JSON by the caller.</returns>
    protected abstract Task<object?> InvokeTransformerAsync(HttpContext httpContext, TransformerContext transformerContext);

    /// <summary>
    /// Adds a runtime predicate that must return true for this endpoint to handle the request.
    /// If the predicate returns false, the request falls through to other matching endpoints.
    /// </summary>
    /// <param name="predicate">A function that evaluates whether this endpoint should handle the request</param>
    /// <remarks>
    /// This participates in ASP.NET Core's endpoint routing via <see cref="WhenPredicateMatcherPolicy"/>.
    /// When the predicate returns false, the endpoint is marked invalid during route matching,
    /// allowing other endpoints with the same route pattern to be selected.
    /// <para/>
    /// Use cases:
    /// <list type="bullet">
    /// <item><description>Feature flags - route to different handlers based on feature state</description></item>
    /// <item><description>A/B testing - conditionally route based on user segments</description></item>
    /// <item><description>Header-based routing - handle only requests with specific headers</description></item>
    /// <item><description>Query parameter routing - match based on query string values</description></item>
    /// </list>
    /// </remarks>
    public TBuilder When(Func<HttpContext, bool> predicate)
    {
        _whenPredicate = predicate ?? throw new ArgumentNullException(nameof(predicate));
        return Self;
    }

    /// <summary>
    /// Specifies the backend HTTP method and URL.
    /// </summary>
    /// <param name="method">Backend HTTP method</param>
    /// <param name="url">Backend URL (supports Kubernetes service names: http://user-service/api/users)</param>
    /// <param name="contentType">Content type for serializing request body. Default: JSON</param>
    /// <remarks>
    /// Placeholder syntax must match the route. A single-segment placeholder (<c>{id}</c>) is
    /// encoded as one path segment, so any <c>/</c> in the value becomes <c>%2F</c>. For a
    /// catch-all route parameter (<c>{**rest}</c>/<c>{*rest}</c>) that carries a multi-segment
    /// path, use the same catch-all syntax in the backend URL (<c>{**rest}</c>) so the <c>/</c>
    /// separators are preserved - a plain <c>{rest}</c> here encodes them and the backend will
    /// 404 on nested paths. A startup warning is logged when a catch-all route is paired with a
    /// plain backend placeholder.
    /// </remarks>
    public TBuilder ToBackend(string method, string url, ContentType contentType = ContentType.Json)
    {
        _backendMethod = method.ToUpperInvariant();
        _backendUrl = url;
        _backendRequestContentType = contentType;
        return Self;
    }

    /// <summary>Specifies a GET backend URL.</summary>
    /// <param name="url">Backend URL (supports Kubernetes service names: http://user-service/api/users)</param>
    /// <param name="contentType">Content type for serializing request body. Default: JSON</param>
    public TBuilder ToGet(string url, ContentType contentType = ContentType.Json) => ToBackend("GET", url, contentType);

    /// <summary>Specifies a POST backend URL.</summary>
    /// <param name="url">Backend URL (supports Kubernetes service names: http://user-service/api/users)</param>
    /// <param name="contentType">Content type for serializing request body. Default: JSON</param>
    public TBuilder ToPost(string url, ContentType contentType = ContentType.Json) => ToBackend("POST", url, contentType);

    /// <summary>Specifies a PUT backend URL.</summary>
    /// <param name="url">Backend URL (supports Kubernetes service names: http://user-service/api/users)</param>
    /// <param name="contentType">Content type for serializing request body. Default: JSON</param>
    public TBuilder ToPut(string url, ContentType contentType = ContentType.Json) => ToBackend("PUT", url, contentType);

    /// <summary>Specifies a DELETE backend URL.</summary>
    /// <param name="url">Backend URL (supports Kubernetes service names: http://user-service/api/users)</param>
    /// <param name="contentType">Content type for serializing request body. Default: JSON</param>
    public TBuilder ToDelete(string url, ContentType contentType = ContentType.Json) => ToBackend("DELETE", url, contentType);

    /// <summary>Specifies a PATCH backend URL.</summary>
    /// <param name="url">Backend URL (supports Kubernetes service names: http://user-service/api/users)</param>
    /// <param name="contentType">Content type for serializing request body. Default: JSON</param>
    public TBuilder ToPatch(string url, ContentType contentType = ContentType.Json) => ToBackend("PATCH", url, contentType);

    /// <summary>
    /// Configures the backend as a GraphQL endpoint.
    /// Sets POST method automatically.
    /// </summary>
    public TBuilder ToGraphQL(string url)
    {
        _backendMethod = "POST";
        _backendUrl = url;
        return Self;
    }

    /// <summary>
    /// Allows anonymous access but still attempts to populate authentication context if credentials are present.
    /// </summary>
    /// <remarks>
    /// Equivalent to <see cref="BffEndpointBuilderBase{TBuilder}.AllowAnonymous"/>: every endpoint
    /// that does not require authentication resolves the auth context optionally, so present
    /// credentials still populate <see cref="TransformerContext.AuthContext"/>.
    /// </remarks>
    public TBuilder AllowAnonymousWithOptionalAuth()
    {
        _requireAuth = false;
        _authPolicy = null;
        return Self;
    }

    /// <summary>Uses token exchange to get a backend-specific token.</summary>
    /// <param name="audience">Target audience for the exchanged token. Must be non-empty.</param>
    /// <exception cref="ArgumentException">Thrown when <paramref name="audience"/> is null or blank.</exception>
    public TBuilder WithTokenExchange(string audience)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(audience);
        _useTokenExchange = true;
        _tokenExchangeAudience = audience;
        return Self;
    }

    /// <summary>
    /// Enables automatic retries for transient backend failures (5xx, connection errors, timeouts)
    /// with exponential backoff. Retries are disabled by default.
    /// </summary>
    /// <param name="maxAttempts">
    /// Number of retry attempts for this endpoint. Capped by the app-wide
    /// <see cref="Configuration.PortaCoreOptions.MaxRetryAttempts"/> ceiling, so the effective count
    /// is <c>min(maxAttempts, ceiling)</c>; raise the ceiling to allow more.
    /// </param>
    public TBuilder WithRetries(int maxAttempts = 3)
    {
        _enableRetries = true;
        _maxRetryAttempts = maxAttempts;
        return Self;
    }

    /// <summary>
    /// Forwards the listed client request headers onto the backend call. A typed endpoint builds
    /// its backend request from scratch, so by default NO client headers are forwarded; this opts
    /// specific ones in (e.g. <c>Accept-Language</c>, <c>X-Request-Id</c>) without writing a custom
    /// transformer. Header names are case-insensitive.
    /// </summary>
    /// <param name="headers">
    /// Header names to forward when present on the incoming request. Hop-by-hop headers
    /// (<c>Connection</c>, <c>Host</c>, ...), framing headers (<c>Content-Length</c>,
    /// <c>Transfer-Encoding</c>) and entity headers describing the request body
    /// (<c>Content-Type</c>, <c>Content-Encoding</c>, ...) are rejected here: the first two can
    /// never be relayed, and the typed pipeline serializes its own backend body. Listing a
    /// sensitive header (<c>Cookie</c>, <c>Authorization</c>, <c>X-Forwarded-*</c>) is an explicit
    /// opt-in, mirroring raw-forward's allow-list - understand what the backend receives before
    /// doing so.
    /// </param>
    /// <param name="destinationHosts">
    /// Optional backend hosts the forwarded headers may reach, matched per request against the
    /// interpolated backend URL (route values can steer the host). Null or empty forwards to any
    /// destination.
    /// </param>
    public TBuilder AllowForwardingHeaders(IEnumerable<string> headers, IEnumerable<string>? destinationHosts = null)
    {
        ArgumentNullException.ThrowIfNull(headers);

        _forwardedRequestHeaders ??= new(StringComparer.OrdinalIgnoreCase);
        foreach (var header in headers)
        {
            if (string.IsNullOrWhiteSpace(header))
            {
                throw new ArgumentException("Header names must be non-empty.", nameof(headers));
            }
            // Reject never-forwardable names at configuration time instead of silently skipping
            // them per request - a listed header that can't work is a misconfiguration.
            if (RawForwardHeaderFilter.IsHopByHopHeader(header) || RawForwardHeaderFilter.IsRequestFramingHeader(header))
            {
                throw new ArgumentException(
                    $"Header '{header}' is a hop-by-hop or framing header and can never be forwarded to a backend.",
                    nameof(headers));
            }
            if (RawForwardHeaderFilter.IsContentHeader(header))
            {
                throw new ArgumentException(
                    $"Header '{header}' is an entity header describing the request body. Typed endpoints " +
                    "serialize their own backend body, so client entity headers cannot be forwarded; use " +
                    "MapRawForward() to relay a body verbatim.",
                    nameof(headers));
            }
            _forwardedRequestHeaders.Add(header);
        }

        if (destinationHosts != null)
        {
            _forwardedHeaderDestinationHosts ??= new(StringComparer.OrdinalIgnoreCase);
            foreach (var host in destinationHosts)
            {
                _forwardedHeaderDestinationHosts.Add(host);
            }
        }

        return Self;
    }

    /// <summary>
    /// Configures multiple named backend endpoints for multi-backend transformers using a fluent
    /// collection builder, avoiding object initializers:
    /// <code>
    /// .ToBackends(b =&gt; b
    ///     .ToGet("UserInfo", $"{url}/userinfo").WithAuth(BackendAuthPolicies.BearerToken)
    ///     .ToPost("Orders", $"{url}/orders").WithTokenExchange("order-api").WithRetries(3))
    /// </code>
    /// </summary>
    /// <param name="configure">Callback that declares the backends on the supplied builder.</param>
    public TBuilder ToBackends(Action<NamedBackendEndpointsBuilder> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);
        var builder = new NamedBackendEndpointsBuilder();
        configure(builder);
        return ToBackends(builder.Build());
    }

    /// <summary>
    /// Configures multiple named backend endpoints for multi-backend transformers.
    /// </summary>
    public TBuilder ToBackends(params NamedBackendEndpoint[] endpoints)
    {
        foreach (var endpoint in endpoints)
        {
            // Store the endpoint as configured. The WithBackendAuth() fallback is applied later in
            // Build() against the FINAL _backendAuthPolicy, so the result no longer depends on whether
            // WithBackendAuth() was chained before or after ToBackends(). Trusted-host validation is
            // likewise deferred to Build() (see ValidateTrustedHostsForUserTokenForwarding) so it sees
            // the effective backend-auth policy, not just the call-order-dependent WithUserToken() flag.
            _namedBackends.Add(endpoint);
        }
        return Self;
    }

    // Stamp the builder-level default backend-auth policy onto any named backend that didn't set its
    // own. Done at Build() time so call order (WithBackendAuth before/after ToBackends) is irrelevant.
    private void ApplyDefaultBackendAuthPolicy()
    {
        if (string.IsNullOrEmpty(_backendAuthPolicy))
        {
            return;
        }

        foreach (var name in _namedBackends.Names.ToArray())
        {
            if (_namedBackends.TryGet(name, out var endpoint)
                && endpoint != null
                && string.IsNullOrEmpty(endpoint.BackendAuthPolicy))
            {
                _namedBackends.Add(endpoint with { BackendAuthPolicy = _backendAuthPolicy });
            }
        }
    }

    // Fail fast at Build() (the same place trusted-host validation runs) when an endpoint selects the
    // TokenExchange policy without an inline audience and no options-level audience resolves for it -
    // rather than letting it surface as a per-request ConfigurationError. Validating here is
    // order-independent across hosting models: in the WebApplication model Build() runs before the host
    // starts; in the UseEndpoints model it runs while the pipeline is built. The request-time guard in
    // the token-exchange handler remains the backstop for backend names only known at request time.
    private void ValidateTokenExchangeAudienceResolvable()
    {
        var options = _services.GetService<IOptions<BackendServiceOptions>>()?.Value ?? new BackendServiceOptions();
        var endpointLabel = $"{_httpMethod} {_routePattern}";

        // Single-backend config carries no backend name, so only the global default audience can satisfy it.
        var singleBackendSelectsTokenExchange =
            _useTokenExchange
            || string.Equals(_backendAuthPolicy, BackendAuthPolicies.TokenExchange, StringComparison.Ordinal);
        if (singleBackendSelectsTokenExchange
            && string.IsNullOrEmpty(_tokenExchangeAudience)
            && string.IsNullOrEmpty(options.DefaultTokenExchangeAudience))
        {
            throw TokenExchangeAudienceMissing(endpointLabel);
        }

        // Named backends each carry their own name for per-backend audience lookup.
        foreach (var name in _namedBackends.Names)
        {
            if (!_namedBackends.TryGet(name, out var endpoint) || endpoint is null)
            {
                continue;
            }

            var selectsTokenExchange =
                endpoint.UseTokenExchange
                || string.Equals(endpoint.BackendAuthPolicy, BackendAuthPolicies.TokenExchange, StringComparison.Ordinal);
            var audienceResolves =
                !string.IsNullOrEmpty(endpoint.TokenExchangeAudience)
                || options.TokenExchangeAudiences.ContainsKey(endpoint.Name)
                || !string.IsNullOrEmpty(options.DefaultTokenExchangeAudience);
            if (selectsTokenExchange && !audienceResolves)
            {
                throw TokenExchangeAudienceMissing($"{endpointLabel} (backend '{endpoint.Name}')");
            }
        }
    }

    private static InvalidOperationException TokenExchangeAudienceMissing(string endpointDescription)
        => new(
            $"Porta: endpoint '{endpointDescription}' selects the TokenExchange backend-auth policy " +
            "without an inline audience, and no audience source resolves for it. Supply an audience " +
            "inline via WithTokenExchange(audience), or configure " +
            "BackendServiceOptions.DefaultTokenExchangeAudience or " +
            "BackendServiceOptions.TokenExchangeAudiences[backendName].");

    /// <summary>Builds and registers the endpoint.</summary>
    public RouteHandlerBuilder Build()
    {
        if (string.IsNullOrEmpty(_httpMethod))
            throw new InvalidOperationException("HTTP method not specified. Call FromRoute() first.");
        if (string.IsNullOrEmpty(_routePattern))
            throw new InvalidOperationException("Route pattern not specified. Call FromRoute() first.");

        var hasBackendConfig = !string.IsNullOrEmpty(_backendMethod) && !string.IsNullOrEmpty(_backendUrl);
        var hasNamedBackends = _namedBackends.Count > 0;

        if (!hasBackendConfig && !hasNamedBackends)
        {
            var transformerType = typeof(TTransformer);
            var baseType = transformerType.BaseType;
            var isMultiBackend = baseType?.IsGenericType == true &&
                                 baseType.Name.StartsWith("MultiBackendTransformer");

            if (!isMultiBackend)
            {
                throw new InvalidOperationException(
                    "Backend method not specified. Call ToBackend() or ToBackends() first, or use MultiBackendTransformer for custom backend handling.");
            }
        }

        // Resolve the backend-auth-policy fallback before validation so the validator and the
        // request handler both see the final, order-independent policy on each named backend.
        ApplyDefaultBackendAuthPolicy();

        ValidateAuthorizationRequirements();
        ValidateTrustedHostsForUserTokenForwarding();
        ValidateTokenExchangeAudienceResolvable();
        ValidateCacheableLegsAtStartup();
        ValidateForwardedHeaderConfiguration();

        // Warn (don't fail) when a catch-all route is paired with a plain backend placeholder: the
        // '/' separators in the bound value would be encoded to %2F and the backend would 404 on
        // nested paths. No-op for multi-backend (ToBackends) endpoints, which set no single _backendUrl.
        RouteInterpolationLogging.WarnOnCatchAllPlaceholderMismatch(_services, _httpMethod!, _routePattern, _backendUrl);

        // Capture values for closure
        var namedBackends = _namedBackends;
        var enableRetries = _enableRetries;
        var maxRetryAttempts = _maxRetryAttempts;
        var enableTelemetry = _options.EnableTelemetry;
        var transformerName = typeof(TTransformer).Name;
        var routePattern = _routePattern;
        var httpMethod = _httpMethod;
        var backendMethod = _backendMethod;
        var backendUrl = _backendUrl;
        var timeout = _timeout;
        var useTokenExchange = _useTokenExchange;
        var tokenExchangeAudience = _tokenExchangeAudience;
        var backendAuthPolicy = _backendAuthPolicy;
        var backendRequestContentType = _backendRequestContentType;
        var forwardedRequestHeaders = _forwardedRequestHeaders;
        var forwardedHeaderDestinationHosts = _forwardedHeaderDestinationHosts;
        // Defense-in-depth: the auth metadata we attach below can be overridden by a caller
        // who chains .AllowAnonymous() onto the RouteHandlerBuilder we return from Build().
        // Re-check the principal inside the handler so user-token forwarding / token exchange
        // cannot run anonymously - or, when a policy is configured, under-authorized - regardless
        // of post-Build() metadata mutation.
        var enforceUserIdentity = GetEffectiveRequireAuth();
        var authPolicyName = _authPolicy;

        var handler = async (HttpContext context) =>
        {
            if (enforceUserIdentity)
            {
                if (context.User?.Identity?.IsAuthenticated != true)
                {
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    return;
                }

                // Re-evaluate the configured policy too (not just authentication), so a post-Build()
                // .AllowAnonymous() that strips RequireAuthorization(policy) can't silently downgrade
                // a policy-protected endpoint to "any authenticated user".
                if (!string.IsNullOrEmpty(authPolicyName))
                {
                    var authorizationService = context.RequestServices.GetRequiredService<IAuthorizationService>();
                    var policyResult = await authorizationService.AuthorizeAsync(context.User!, resource: null, authPolicyName);
                    if (!policyResult.Succeeded)
                    {
                        context.Response.StatusCode = StatusCodes.Status403Forbidden;
                        return;
                    }
                }
            }

            var logger = context.RequestServices.GetRequiredService<ILogger<TTransformer>>();
            var authProvider = context.RequestServices.GetRequiredService<IAuthenticationProvider>();
            var backendCaller = context.RequestServices.GetRequiredService<IBackendCaller>();
            var metrics = enableTelemetry ? context.RequestServices.GetService<PortaMetrics>() : null;

            // Fixed category activity name; the specific transformer is carried on the
            // bff.transformation.strategy tag (set below) so span cardinality stays bounded.
            using var activity = enableTelemetry
                ? PortaActivitySource.Source.StartActivity(PortaActivitySource.Activities.Transformation, ActivityKind.Server)
                : null;

            var stopwatch = enableTelemetry ? Stopwatch.StartNew() : null;

            activity?.SetTag(PortaActivitySource.Tags.Component, "transformer");
            activity?.SetTag(PortaActivitySource.Tags.TransformationStrategy, transformerName);
            activity?.SetTag(PortaActivitySource.Tags.HttpMethod, httpMethod);
            activity?.SetTag(PortaActivitySource.Tags.HttpRoute, routePattern);

            try
            {
                // Optional resolution whenever the endpoint doesn't enforce identity (matching
                // RawForwardEndpointBuilder): an anonymous hit on an AllowAnonymous endpoint is
                // deliberate - not an auth failure to count - and a throwing provider degrades
                // to anonymous instead of failing the request with a 500.
                var authContext = await AuthInstrumentation.ResolveAsync(
                    authProvider, context, allowOptional: !enforceUserIdentity, metrics, enableTelemetry);

                var transformerContext = new TransformerContext
                {
                    HttpContext = context,
                    AuthContext = authContext,
                    CancellationToken = context.RequestAborted,
                    RouteValues = context.Request.RouteValues.ToDictionary(
                        kvp => kvp.Key,
                        kvp => kvp.Value),
                    QueryParameters = context.Request.Query.ToDictionary(
                        kvp => kvp.Key,
                        kvp => kvp.Value),
                    // HTTP header names are case-insensitive. ToDictionary defaults to
                    // StringComparer.Ordinal, which would break transformer code that looks
                    // up "Content-Type" while ASP.NET stored "content-type".
                    RequestHeaders = context.Request.Headers.ToDictionary(
                        kvp => kvp.Key,
                        kvp => kvp.Value,
                        StringComparer.OrdinalIgnoreCase),
                    BackendCaller = backendCaller,
                    Logger = logger,
                    TelemetryEnabled = enableTelemetry
                };

                if (hasBackendConfig)
                {
                    var effectiveBackendMethod = backendMethod == "*"
                        ? context.Request.Method
                        : backendMethod!;

                    var interpolatedUrl = RouteUrlInterpolator.AppendQueryString(
                        RouteUrlInterpolator.Interpolate(backendUrl!, transformerContext.RouteValues),
                        context.Request.QueryString.Value);

                    transformerContext.Properties["BackendRequest"] = new BackendRequest
                    {
                        Method = effectiveBackendMethod,
                        Url = interpolatedUrl,
                        Headers = ForwardedRequestHeaders.Collect(
                            transformerContext.RequestHeaders,
                            forwardedRequestHeaders,
                            forwardedHeaderDestinationHosts,
                            interpolatedUrl),
                        AccessToken = authContext.AccessToken,
                        Timeout = timeout,
                        UseTokenExchange = useTokenExchange,
                        TokenExchangeAudience = tokenExchangeAudience,
                        BackendAuthPolicy = backendAuthPolicy,
                        EnableRetries = enableRetries,
                        MaxRetryAttempts = maxRetryAttempts,
                        RequestContentType = backendRequestContentType ?? ContentType.Json
                    };
                }

                if (hasNamedBackends)
                {
                    transformerContext.Properties["NamedBackends"] = namedBackends;
                }

                var response = await InvokeTransformerAsync(context, transformerContext);

                if (!context.Response.HasStarted)
                {
                    await context.Response.WriteAsJsonAsync(response, context.RequestAborted);
                }

                // Reflect the actual outcome: a transformer that wrote its own 4xx/5xx (e.g. via
                // WriteErrorResponseAsync) must not record a green span.
                activity?.SetTag(PortaActivitySource.Tags.HttpStatusCode, context.Response.StatusCode);
                activity?.SetStatus(
                    context.Response.StatusCode >= 400 ? ActivityStatusCode.Error : ActivityStatusCode.Ok);
            }
            catch (InvalidRouteValueException ex)
            {
                logger.TransformerError(typeof(TTransformer).Name, ex);

                activity?.SetStatus(ActivityStatusCode.Error, "Invalid route value");
                activity?.SetTag(PortaActivitySource.Tags.ErrorType, nameof(InvalidRouteValueException));

                if (!context.Response.HasStarted)
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { error = "Invalid request path" }, context.RequestAborted);
                }
            }
            catch (RequestBodyDeserializationException ex)
            {
                // Only request-body parse failures land here (thrown by InvokeTransformerAsync). A
                // JsonException from serializing the RESPONSE is a server bug and must NOT be blamed
                // on the client as a 400 - it falls through to the generic 500 catch below.
                var inner = ex.InnerException ?? ex;
                logger.TransformerRequestDeserializationError(typeof(TTransformer).Name, inner);

                activity?.SetStatus(ActivityStatusCode.Error, inner.Message);
                activity?.SetTag(PortaActivitySource.Tags.ErrorType, "JsonException");
                activity?.SetTag(PortaActivitySource.Tags.ErrorMessage, inner.Message);

                if (!context.Response.HasStarted)
                {
                    // Generic message: JsonException.Message echoes the offending input position
                    // and a snippet of the body, plus framework-version-specific text that
                    // fingerprints .NET. Detail stays in the log line above.
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { error = "Invalid request body" }, context.RequestAborted);
                }
            }
            catch (HttpRequestException ex)
            {
                logger.TransformerBackendError(typeof(TTransformer).Name, ex);

                activity?.SetStatus(ActivityStatusCode.Error, ex.Message);
                activity?.SetTag(PortaActivitySource.Tags.ErrorType, "HttpRequestException");
                activity?.SetTag(PortaActivitySource.Tags.ErrorMessage, ex.Message);

                if (!context.Response.HasStarted)
                {
                    context.Response.StatusCode = 502;
                    await context.Response.WriteAsJsonAsync(new { error = "Backend service unavailable" }, context.RequestAborted);
                }
            }
            catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested)
            {
                // Client disconnected mid-request - a normal operational event, not a server fault.
                // Don't log at Error or mark the span failed; let ASP.NET Core handle the abort.
                activity?.SetStatus(ActivityStatusCode.Ok);
                throw;
            }
            catch (Exception ex)
            {
                logger.TransformerError(typeof(TTransformer).Name, ex);

                activity?.SetStatus(ActivityStatusCode.Error, ex.Message);
                activity?.SetTag(PortaActivitySource.Tags.ErrorType, ex.GetType().Name);
                activity?.SetTag(PortaActivitySource.Tags.ErrorMessage, ex.Message);

                if (!context.Response.HasStarted)
                {
                    context.Response.StatusCode = 500;
                    await context.Response.WriteAsJsonAsync(new { error = "Internal server error" }, context.RequestAborted);
                }
            }
            finally
            {
                if (stopwatch != null && metrics != null)
                {
                    stopwatch.Stop();
                    metrics.RecordTransformationDuration(stopwatch.Elapsed.TotalMilliseconds, transformerName);
                    activity?.SetTag(PortaActivitySource.Tags.HttpStatusCode, context.Response.StatusCode);
                }
            }
        };

        var routeHandler = _httpMethod switch
        {
            "GET" => _endpoints.MapGet(_routePattern, handler),
            "POST" => _endpoints.MapPost(_routePattern, handler),
            "PUT" => _endpoints.MapPut(_routePattern, handler),
            "DELETE" => _endpoints.MapDelete(_routePattern, handler),
            "PATCH" => _endpoints.MapPatch(_routePattern, handler),
            "HEAD" => _endpoints.MapMethods(_routePattern, ["HEAD"], handler),
            "OPTIONS" => _endpoints.MapMethods(_routePattern, ["OPTIONS"], handler),
            "*" => _endpoints.MapMethods(_routePattern, ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"], handler),
            _ => throw new InvalidOperationException($"Unsupported HTTP method: {_httpMethod}")
        };

        if (_whenPredicate is not null)
        {
            routeHandler.WithMetadata(new WhenPredicateMetadata(_whenPredicate));
        }

        // Folds the transformer's [RequiresAuthentication] into the effective requirement so
        // anonymous users are 401'd by ASP.NET Core authorization before reaching the transformer.
        var requireAuth = GetEffectiveRequireAuth();
        if (requireAuth)
        {
            if (!string.IsNullOrEmpty(_authPolicy))
            {
                routeHandler.RequireAuthorization(_authPolicy);
            }
            else
            {
                routeHandler.RequireAuthorization();
            }
        }
        else
        {
            routeHandler.AllowAnonymous();
        }

        // Record the resolved requirement so the startup check can flag a require-auth endpoint
        // that has no authentication scheme to populate HttpContext.User.
        routeHandler.WithMetadata(new PortaPrincipalRequirementMetadata(requireAuth));

        return routeHandler;
    }

    /// <summary>
    /// Test-only: applies the <c>WithBackendAuth</c> fallback (as <see cref="Build"/> does) and
    /// returns the resolved named backends, so a test can assert the fallback is order-independent
    /// without standing up a full host.
    /// </summary>
    internal NamedBackendEndpoints ResolveNamedBackendsForTesting()
    {
        ApplyDefaultBackendAuthPolicy();
        return _namedBackends;
    }

    private bool GetEffectiveRequireAuth()
    {
        // Read auth requirement from the transformer's type-level metadata -
        // never instantiate TTransformer here, since Build() runs at startup
        // against the root service provider.
        var transformerRequiresAuth = typeof(TTransformer)
            .IsDefined(typeof(RequiresAuthenticationAttribute), inherit: true);
        return _requireAuth ?? (transformerRequiresAuth || _options.RequireAuthorizationByDefault);
    }

    private void ValidateAuthorizationRequirements()
        => EndpointAuthorizationValidator.Validate(
            _routePattern,
            _backendAuthPolicy,
            _useTokenExchange,
            _tokenExchangeAudience,
            _namedBackends,
            GetEffectiveRequireAuth(),
            _services.GetService<IBackendAuthHandlerRegistry>(),
            typeof(TTransformer));

    // Enforce PortaCore:TrustedHosts for EVERY backend that forwards a user-derived token, not just
    // WithUserToken(). A BearerToken/TokenExchange policy (whether set per-backend or applied as the
    // builder-level WithBackendAuth() default) forwards the user's token just like WithUserToken(), so
    // it must clear the same allow-list. Runs after ApplyDefaultBackendAuthPolicy() so the effective
    // policy on each named backend is visible. The matching runtime gate lives in
    // BackendCaller.ApplyBackendAuthAsync for hand-built BackendRequests that bypass this builder.
    private void ValidateTrustedHostsForUserTokenForwarding()
    {
        var validator = _services.GetService<ITrustedHostValidator>();
        if (validator is null)
        {
            return;
        }

        if (!string.IsNullOrEmpty(_backendUrl)
            && (_useTokenExchange || BackendAuthPolicies.RequiresUserIdentity(_backendAuthPolicy)))
        {
            validator.ValidateUrl(_backendUrl, _routePattern ?? "ToBackend");
        }

        foreach (var name in _namedBackends.Names)
        {
            if (_namedBackends.TryGet(name, out var endpoint)
                && endpoint is not null
                && (endpoint.ForwardUserToken
                    || endpoint.UseTokenExchange
                    || BackendAuthPolicies.RequiresUserIdentity(endpoint.BackendAuthPolicy)))
            {
                validator.ValidateUrl(endpoint.UrlTemplate, endpoint.Name);
            }
        }
    }

    // AllowForwardingHeaders() rides on the single-backend BackendRequest the endpoint handler
    // builds; named backend legs (ToBackends) construct their own requests inside the transformer,
    // where the allow-list is invisible - fail the boot rather than silently not forwarding.
    // The Authorization check catches configuration where a built-in backend-auth policy would
    // silently overwrite the forwarded client value: BackendCaller merges custom headers BEFORE
    // applying backend auth, and the built-in handlers assign Authorization outright.
    private void ValidateForwardedHeaderConfiguration()
    {
        if (_forwardedRequestHeaders is not { Count: > 0 })
        {
            return;
        }

        if (string.IsNullOrEmpty(_backendUrl))
        {
            throw new InvalidOperationException(
                $"Porta: endpoint '{_httpMethod} {_routePattern}' calls AllowForwardingHeaders() but configures " +
                "no single backend (ToBackend/ToGet/...). Header forwarding is not supported on named " +
                "multi-backend legs; set BackendRequest.Headers inside the transformer instead.");
        }

        var policySetsAuthorization =
            _useTokenExchange
            || _backendAuthPolicy is BackendAuthPolicies.BasicAuth
                or BackendAuthPolicies.BearerToken
                or BackendAuthPolicies.TokenExchange;
        if (policySetsAuthorization && _forwardedRequestHeaders.Contains("Authorization"))
        {
            throw new InvalidOperationException(
                $"Porta: endpoint '{_httpMethod} {_routePattern}' forwards the client's Authorization header via " +
                "AllowForwardingHeaders(), but its backend-auth policy sets Authorization too and would silently " +
                "overwrite the forwarded value. Remove 'Authorization' from the allow-list or drop the " +
                "backend-auth policy / token exchange for this endpoint.");
        }
    }

    // Cross-check every cacheable leg of an AggregatingTransformer at boot, so a user-varying leg
    // cached without a per-user key (or a non-cacheable verb, or a missing HybridCache registration)
    // fails at startup instead of on the first request. The same checks run again at request time -
    // this is a fail-fast front-stop, not a replacement. Only named-backend aggregating transformers
    // have cacheable legs (WithCache is declared on a named backend leg), so other endpoints are a no-op.
    private void ValidateCacheableLegsAtStartup()
    {
        if (_namedBackends.Count == 0
            || !typeof(ICacheableLegIntrospection).IsAssignableFrom(typeof(TTransformer)))
        {
            return;
        }

        // Configure() is request-independent static configuration, so we can read the legs from a
        // throwaway instance. If the transformer can't be constructed outside a request scope (e.g. it
        // depends on a scoped service) or Configure() itself can't run here, fall back to the
        // request-time guard rather than failing an otherwise-valid startup.
        IReadOnlyList<BackendCallConfig> configs;
        object? instance = null;
        try
        {
            instance = ActivatorUtilities.CreateInstance(_services, typeof(TTransformer));
            // The returned configs are independent data, so the throwaway instance is only needed for
            // this read; dispose it here rather than leaking one per cacheable endpoint at boot.
            configs = ((ICacheableLegIntrospection)instance).GetConfiguredBackends();
        }
        catch (Exception ex)
        {
            _services.GetService<ILoggerFactory>()
                ?.CreateLogger(typeof(TTransformer))
                .CacheStartupValidationSkipped(typeof(TTransformer).Name, ex.Message);
            return;
        }
        finally
        {
            (instance as IDisposable)?.Dispose();
        }

        // Validation throws propagate (that is the point - fail the boot). Done outside the catch
        // above so a genuine misconfiguration is never swallowed as an "instance couldn't be built".
        var hasCacheableLeg = false;
        foreach (var config in configs)
        {
            if (config.Cache is null)
            {
                continue;
            }

            hasCacheableLeg = true;
            if (_namedBackends.TryGet(config.Name, out var endpoint) && endpoint is not null)
            {
                BackendCacheValidation.ValidateLegConfiguration(config, endpoint, typeof(TTransformer).Name);
            }
        }

        if (hasCacheableLeg && _services.GetService<HybridCache>() is null)
        {
            throw new InvalidOperationException(
                $"Transformer '{typeof(TTransformer).Name}' has a backend leg that declares .WithCache(...) " +
                "(or .WithGraphQLCache(...)), but no HybridCache is registered. Call services.AddHybridCache() " +
                "during startup (optionally with a distributed L2 cache such as Redis for HA). See docs/caching.md.");
        }
    }
}

/// <summary>
/// Fluent builder for configuring transformer endpoints with a request body.
/// </summary>
public sealed class TransformerEndpointBuilder<TTransformer, TRequest, TResponse>
    : TransformerEndpointBuilderBase<TTransformer, TransformerEndpointBuilder<TTransformer, TRequest, TResponse>>
    where TTransformer : ITransformer<TRequest, TResponse>
{
    internal TransformerEndpointBuilder(IEndpointRouteBuilder endpoints, IServiceProvider services)
        : base(endpoints, services) { }

    /// <inheritdoc/>
    protected override async Task<object?> InvokeTransformerAsync(HttpContext httpContext, TransformerContext transformerContext)
    {
        TRequest? requestBody = default;
        // Gate on the presence of a JSON body, not the HTTP verb. Body-bearing DELETE and OPTIONS
        // requests (and FromAny mappings that forward arbitrary methods) carry client payloads just
        // like POST/PUT/PATCH; a verb allow-list dropped them, handing the transformer default(TRequest)
        // and diverging from raw-forward, which forwards any present body. HasJsonContentType() is false
        // for body-less GET/HEAD (no Content-Type), so those still skip deserialization.
        if (httpContext.Request.HasJsonContentType())
        {
            try
            {
                requestBody = await httpContext.Request.ReadFromJsonAsync<TRequest>(httpContext.RequestAborted);
            }
            catch (JsonException ex)
            {
                // Tag this as a request-body parse failure so the handler maps it to 400. Response
                // serialization that throws JsonException stays a 500 (it's a server bug, not the
                // client's malformed input).
                throw new RequestBodyDeserializationException(ex);
            }
        }

        var transformer = httpContext.RequestServices.GetRequiredService<TTransformer>();
        // Initialize the base-class logger before dispatch so transformer helpers (GetRequiredClaim,
        // LogBackendCallFailed, the error writers) always run against the real request logger rather
        // than the NullLogger default. No-op for transformers that implement ITransformer directly.
        if (transformer is TransformerBase<TRequest, TResponse> baseTransformer)
        {
            baseTransformer.InitializeLogger(transformerContext);
        }
        return await transformer.TransformAsync(requestBody, transformerContext);
    }
}

/// <summary>
/// Fluent builder for configuring transformer endpoints with no request body.
/// </summary>
public sealed class TransformerEndpointBuilder<TTransformer, TResponse>
    : TransformerEndpointBuilderBase<TTransformer, TransformerEndpointBuilder<TTransformer, TResponse>>
    where TTransformer : ITransformer<TResponse>
{
    internal TransformerEndpointBuilder(IEndpointRouteBuilder endpoints, IServiceProvider services)
        : base(endpoints, services) { }

    /// <inheritdoc/>
    protected override async Task<object?> InvokeTransformerAsync(HttpContext httpContext, TransformerContext transformerContext)
    {
        var transformer = httpContext.RequestServices.GetRequiredService<TTransformer>();
        // Initialize the base-class logger before dispatch (see the body-bearing builder for why).
        if (transformer is TransformerBase<TResponse> baseTransformer)
        {
            baseTransformer.InitializeLogger(transformerContext);
        }
        return await transformer.TransformAsync(transformerContext);
    }
}

/// <summary>
/// Builds the forwarded-header dictionary for a typed endpoint's <see cref="BackendRequest"/>
/// from the <c>AllowForwardingHeaders()</c> allow-list. Exposed for unit testing.
/// </summary>
internal static class ForwardedRequestHeaders
{
    /// <summary>
    /// Returns the client request headers to copy onto the backend request, or null when nothing
    /// is configured, the destination host is out of scope, or no listed header is present.
    /// </summary>
    public static Dictionary<string, string>? Collect(
        IReadOnlyDictionary<string, StringValues> requestHeaders,
        IReadOnlySet<string>? allowedHeaders,
        IReadOnlySet<string>? allowedDestinationHosts,
        string destinationUrl)
    {
        if (allowedHeaders is not { Count: > 0 })
        {
            return null;
        }

        // Host scoping mirrors raw-forward's AllowedDestinationHosts: empty means any destination.
        // Checked per request (not at Build()) because route-value interpolation can steer the
        // backend host.
        if (allowedDestinationHosts is { Count: > 0 })
        {
            var host = Uri.TryCreate(destinationUrl, UriKind.Absolute, out var uri) ? uri.Host : null;
            if (host is null || !allowedDestinationHosts.Contains(host))
            {
                return null;
            }
        }

        Dictionary<string, string>? headers = null;
        foreach (var name in allowedHeaders)
        {
            if (requestHeaders.TryGetValue(name, out var values) && values.Count > 0)
            {
                // StringValues.ToString() folds multi-value headers with "," - the same folding
                // the raw-forward path applies to custom headers.
                (headers ??= new(StringComparer.OrdinalIgnoreCase))[name] = values.ToString();
            }
        }

        return headers;
    }
}

/// <summary>
/// Marks a failure to deserialize the incoming request body (as opposed to a serialization failure
/// on the response). The endpoint handler maps this to a 400 "Invalid request body"; an uncaught
/// <see cref="JsonException"/> from response serialization falls through to a generic 500.
/// </summary>
internal sealed class RequestBodyDeserializationException(JsonException inner)
    : Exception("Failed to deserialize the request body.", inner);

/// <summary>
/// High-performance logging for transformer endpoints.
/// EventId range 14040-14049 is reserved for this category (14100+ belongs to
/// the token services) so EventId-based filtering can tell them apart.
/// </summary>
internal static partial class TransformerEndpointLogging
{
    [LoggerMessage(EventId = 14040, Level = LogLevel.Error,
        Message = "Transformer {TransformerName} backend call failed")]
    public static partial void TransformerBackendError(this ILogger logger, string transformerName, Exception ex);

    [LoggerMessage(EventId = 14041, Level = LogLevel.Error,
        Message = "Transformer {TransformerName} execution failed")]
    public static partial void TransformerError(this ILogger logger, string transformerName, Exception ex);

    [LoggerMessage(EventId = 14042, Level = LogLevel.Warning,
        Message = "Transformer {TransformerName} request body deserialization failed")]
    public static partial void TransformerRequestDeserializationError(this ILogger logger, string transformerName, Exception ex);

    [LoggerMessage(EventId = 14043, Level = LogLevel.Debug,
        Message = "Startup cache validation skipped for transformer {TransformerName}: it could not be " +
                  "instantiated/configured outside a request scope ({Reason}). Per-leg cache safety is " +
                  "still enforced at request time.")]
    public static partial void CacheStartupValidationSkipped(this ILogger logger, string transformerName, string reason);
}
