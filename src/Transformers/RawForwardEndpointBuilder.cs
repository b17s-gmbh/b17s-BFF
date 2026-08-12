using System.Diagnostics;
using System.Net;

using b17s.Porta.Auth.Providers;
using b17s.Porta.Configuration;
using b17s.Porta.Extensions;
using b17s.Porta.Telemetry;

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace b17s.Porta.Transformers;

/// <summary>
/// Fluent builder for configuring raw forwarding endpoints.
/// Use this for zero-transformation proxying of binary content, files, or non-JSON APIs.
/// </summary>
/// <typeparam name="TTransformer">The transformer type implementing <see cref="IRawTransformer"/></typeparam>
public sealed class RawForwardEndpointBuilder<TTransformer> : BffEndpointBuilderBase<RawForwardEndpointBuilder<TTransformer>>
    where TTransformer : class, IRawTransformer
{
    private RawForwardHeaderPassThrough? _headerPassThrough;
    private readonly IEndpointRouteBuilder _endpoints;
    private readonly IServiceProvider _services;
    private readonly PortaCoreOptions _options;

    internal RawForwardEndpointBuilder(IEndpointRouteBuilder endpoints, IServiceProvider services)
    {
        _endpoints = endpoints;
        _services = services;
        _options = services.GetService<IOptions<PortaCoreOptions>>()?.Value ?? new PortaCoreOptions();
    }

    /// <summary>
    /// Specifies the backend HTTP method and URL. The URL may contain route-parameter
    /// placeholders that are interpolated from the incoming request.
    /// </summary>
    /// <remarks>
    /// Placeholder syntax must match the route. A single-segment placeholder (<c>{id}</c>) is
    /// encoded as one path segment, so any <c>/</c> in the value becomes <c>%2F</c>. For a
    /// catch-all route parameter (<c>{**rest}</c>/<c>{*rest}</c>) that carries a multi-segment
    /// path, use the same catch-all syntax in the backend URL (<c>{**rest}</c>) so the <c>/</c>
    /// separators are preserved - a plain <c>{rest}</c> here encodes them and the backend will
    /// 404 on nested paths. A startup warning is logged when a catch-all route is paired with a
    /// plain backend placeholder.
    /// </remarks>
    public RawForwardEndpointBuilder<TTransformer> ToBackend(string method, string url)
    {
        _backendMethod = method.ToUpperInvariant();
        _backendUrl = url;
        return Self;
    }

    /// <summary>Specifies a GET backend URL. Shorthand for <see cref="ToBackend(string, string)"/> with "GET".</summary>
    /// <param name="url">Backend URL (supports <c>{param}</c> route interpolation)</param>
    public RawForwardEndpointBuilder<TTransformer> ToGet(string url) => ToBackend("GET", url);

    /// <summary>Specifies a POST backend URL. Shorthand for <see cref="ToBackend(string, string)"/> with "POST".</summary>
    /// <param name="url">Backend URL (supports <c>{param}</c> route interpolation)</param>
    public RawForwardEndpointBuilder<TTransformer> ToPost(string url) => ToBackend("POST", url);

    /// <summary>Specifies a PUT backend URL. Shorthand for <see cref="ToBackend(string, string)"/> with "PUT".</summary>
    /// <param name="url">Backend URL (supports <c>{param}</c> route interpolation)</param>
    public RawForwardEndpointBuilder<TTransformer> ToPut(string url) => ToBackend("PUT", url);

    /// <summary>Specifies a DELETE backend URL. Shorthand for <see cref="ToBackend(string, string)"/> with "DELETE".</summary>
    /// <param name="url">Backend URL (supports <c>{param}</c> route interpolation)</param>
    public RawForwardEndpointBuilder<TTransformer> ToDelete(string url) => ToBackend("DELETE", url);

    /// <summary>Specifies a PATCH backend URL. Shorthand for <see cref="ToBackend(string, string)"/> with "PATCH".</summary>
    /// <param name="url">Backend URL (supports <c>{param}</c> route interpolation)</param>
    public RawForwardEndpointBuilder<TTransformer> ToPatch(string url) => ToBackend("PATCH", url);

    /// <summary>
    /// Opts specific sensitive headers (Cookie, Authorization, X-Forwarded-*) back into
    /// the forward path for this endpoint. By default these are stripped to avoid leaking
    /// the BFF session cookie or client credentials to backends.
    /// </summary>
    /// <param name="headers">Header names to forward. Case-insensitive.</param>
    /// <param name="destinationHosts">
    /// Optional list of backend hosts the allowed headers may reach. If null or empty,
    /// the allowed headers apply to any destination.
    /// </param>
    public RawForwardEndpointBuilder<TTransformer> AllowForwardingHeaders(
        IEnumerable<string> headers,
        IEnumerable<string>? destinationHosts = null)
    {
        _headerPassThrough ??= new RawForwardHeaderPassThrough();
        foreach (var header in headers)
        {
            _headerPassThrough.AllowedHeaders.Add(header);
        }
        if (destinationHosts != null)
        {
            foreach (var host in destinationHosts)
            {
                _headerPassThrough.AllowedDestinationHosts.Add(host);
            }
        }
        return this;
    }

    /// <summary>
    /// Opts specific sensitive backend response headers (Set-Cookie,
    /// Strict-Transport-Security, Content-Security-Policy, Server, X-Powered-By) back
    /// into the response path for this endpoint. By default these are stripped so a
    /// backend can't plant cookies on the BFF's domain or override BFF-owned policy
    /// headers.
    /// </summary>
    /// <param name="headers">Response header names to forward. Case-insensitive.</param>
    public RawForwardEndpointBuilder<TTransformer> AllowForwardingResponseHeaders(
        IEnumerable<string> headers)
    {
        _headerPassThrough ??= new RawForwardHeaderPassThrough();
        foreach (var header in headers)
        {
            _headerPassThrough.AllowedResponseHeaders.Add(header);
        }
        return this;
    }

    /// <summary>
    /// Test-only accessor for the configured header pass-through allow-list.
    /// </summary>
    internal RawForwardHeaderPassThrough? GetConfiguredHeaderPassThroughForTesting() => _headerPassThrough;

    /// <summary>
    /// Test-only accessor for the configured backend method and URL.
    /// </summary>
    internal (string? Method, string? Url) GetConfiguredBackendForTesting() => (_backendMethod, _backendUrl);

    /// <summary>
    /// Builds and registers the raw forwarding endpoint.
    /// </summary>
    public RouteHandlerBuilder Build()
    {
        if (string.IsNullOrEmpty(_httpMethod))
            throw new InvalidOperationException("HTTP method not specified. Call FromRoute() first.");
        if (string.IsNullOrEmpty(_routePattern))
            throw new InvalidOperationException("Route pattern not specified. Call FromRoute() first.");
        if (string.IsNullOrEmpty(_backendMethod) || string.IsNullOrEmpty(_backendUrl))
            throw new InvalidOperationException("Backend not specified. Call ToBackend() first.");

        EndpointAuthorizationValidator.ValidatePolicyRegistered(
            _backendAuthPolicy,
            _services.GetService<IBackendAuthHandlerRegistry>(),
            $"raw-forward endpoint '{_routePattern}'");

        // A BearerToken/TokenExchange policy forwards the user's token to the backend, so the
        // destination must clear PortaCore:TrustedHosts at startup - same guarantee the transformer
        // builder enforces. BackendCaller re-checks at request time as defense-in-depth.
        if (BackendAuthPolicies.RequiresUserIdentity(_backendAuthPolicy))
        {
            _services.GetService<ITrustedHostValidator>()?.ValidateUrl(_backendUrl, _routePattern!);
        }

        // Raw-forward has no inline-audience option: a TokenExchange policy here can only be satisfied
        // by an options-level default audience. Fail fast at Build() when none is configured, rather
        // than letting it surface as a per-request ConfigurationError.
        if (string.Equals(_backendAuthPolicy, BackendAuthPolicies.TokenExchange, StringComparison.Ordinal))
        {
            var backendOptions = _services.GetService<IOptions<BackendServiceOptions>>()?.Value;
            if (string.IsNullOrEmpty(backendOptions?.DefaultTokenExchangeAudience))
            {
                throw new InvalidOperationException(
                    $"Porta: raw-forward endpoint '{_httpMethod} {_routePattern}' selects the TokenExchange " +
                    "backend-auth policy, which has no inline audience, and no " +
                    "BackendServiceOptions.DefaultTokenExchangeAudience is configured. Configure a default " +
                    "audience, or use a transformer/pass-through endpoint with WithTokenExchange(audience).");
            }
        }

        // Warn (don't fail) when a catch-all route is paired with a plain backend placeholder: the
        // '/' separators in the bound value would be encoded to %2F and the backend would 404 on
        // nested paths. See RouteUrlInterpolator for the encoding rules.
        RouteInterpolationLogging.WarnOnCatchAllPlaceholderMismatch(_services, _httpMethod!, _routePattern, _backendUrl);

        // Capture values for closure
        var backendMethod = _backendMethod;
        var backendUrl = _backendUrl;
        var timeout = _timeout;
        var backendAuthPolicy = _backendAuthPolicy;
        var enableTelemetry = _options.EnableTelemetry;
        var transformerName = typeof(TTransformer).Name;
        var routePattern = _routePattern;
        var httpMethod = _httpMethod;
        var headerPassThrough = _headerPassThrough ?? _options.DefaultRawForwardHeaderPassThrough;
        var maxResponseBytes = _options.MaxRawForwardResponseBytes;
        var readIdleTimeout = _options.RawForwardReadIdleTimeout;
        // Defense-in-depth: the auth metadata we attach below can be overridden by a caller
        // who chains .AllowAnonymous() onto the RouteHandlerBuilder we return from Build().
        // Re-check the principal inside the handler so authenticated raw-forward endpoints
        // cannot be silently rendered anonymous - or, when a policy is configured, under-authorized -
        // by post-Build() metadata mutation.
        var transformerRequiresAuthAtBuild = typeof(TTransformer)
            .IsDefined(typeof(RequiresAuthenticationAttribute), inherit: true);
        var enforceUserIdentity = _requireAuth
            ?? (transformerRequiresAuthAtBuild || _options.RequireAuthorizationByDefault);
        var authPolicyName = _authPolicy;
        var optionalUserIdentity = _optionalUserIdentity;

        // A backend policy that forwards the user's identity must not be paired with anonymous
        // access unless it is explicitly optional on an AllowAnonymousWithOptionalAuth() endpoint:
        // otherwise enforceUserIdentity would be false, skipping the auth gate below while the
        // user-token-dependent backend policy stays attached. Catch this at startup the same way
        // the typed endpoint builder does (EndpointAuthorizationValidator.Validate).
        EndpointAuthorizationValidator.ValidateSingleBackend(
            _routePattern,
            _backendAuthPolicy,
            enforceUserIdentity,
            typeof(TTransformer),
            optionalUserIdentity,
            _backendAuthOptional);

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
            var transformer = context.RequestServices.GetRequiredService<TTransformer>();
            var authProvider = context.RequestServices.GetRequiredService<IAuthenticationProvider>();
            var backendCaller = context.RequestServices.GetRequiredService<IBackendCaller>();
            // Same backend-error mapper the typed routes use (see BackendCaller). Raw forward must
            // remap backend credential failures (401/403 -> 502) too, otherwise a backend auth
            // failure streams straight to the client and signs the user out. Fall back to the
            // default mapper if none is registered, mirroring BackendCaller's own resolution.
            var errorMapper = context.RequestServices.GetService<IBackendErrorMapper>() ?? new DefaultBackendErrorMapper();
            var metrics = enableTelemetry ? context.RequestServices.GetService<PortaMetrics>() : null;

            // Fixed category activity name; the specific transformer is carried on the
            // bff.transformation.strategy tag (set below) so span cardinality stays bounded.
            using var activity = enableTelemetry
                ? PortaActivitySource.Source.StartActivity(PortaActivitySource.Activities.RawForward, ActivityKind.Server)
                : null;

            var stopwatch = enableTelemetry ? Stopwatch.StartNew() : null;

            activity?.SetTag(PortaActivitySource.Tags.Component, "raw_forward");
            activity?.SetTag(PortaActivitySource.Tags.TransformationStrategy, transformerName);
            activity?.SetTag(PortaActivitySource.Tags.HttpMethod, httpMethod);
            activity?.SetTag(PortaActivitySource.Tags.HttpRoute, routePattern);

            // Declared outside the try so the finally can dispose it. RawBackendResult owns the
            // backend HttpResponseMessage; default() disposes as a safe no-op if we never call out.
            var result = default(RawBackendResult);

            try
            {
                // Three-rung auth ladder (matching the typed endpoint builder). RequireAuth:
                // required resolution. AllowAnonymousWithOptionalAuth: optional resolution -
                // present credentials populate the context, anonymous hits are deliberate.
                // AllowAnonymous (explicitly or by default): credential-blind - the provider is
                // never consulted and the transformer always sees an empty AuthContext.
                // (Resolution records the bff.authentication span + bff.auth.* metrics.)
                var authContext = enforceUserIdentity || optionalUserIdentity
                    ? await AuthInstrumentation.ResolveAsync(
                        authProvider, context, allowOptional: !enforceUserIdentity, metrics, enableTelemetry)
                    : AuthenticationContext.Unauthenticated();

                // AllowAnonymousWithOptionalAuth(policy): the authenticated treatment is gated on
                // the policy. A credentialed caller that fails it is served the anonymous view
                // (never a 403 - anonymous access is allowed anyway).
                if (optionalUserIdentity && authContext.IsAuthenticated && !string.IsNullOrEmpty(authPolicyName))
                {
                    var authorizationService = context.RequestServices.GetRequiredService<IAuthorizationService>();
                    var policyResult = await authorizationService.AuthorizeAsync(context.User, resource: null, authPolicyName);
                    if (!policyResult.Succeeded)
                    {
                        authContext = AuthenticationContext.Unauthenticated();
                    }
                }

                // Optional-flagged user-identity backend auth is applied only for authenticated
                // callers; anonymous callers reach the backend with no auth. Mandatory identity
                // policies cannot reach this point on an optional endpoint - startup rejects them.
                var anonymousCaller = optionalUserIdentity && !authContext.IsAuthenticated;

                // Build transformer context
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
                    // HTTP header names are case-insensitive; preserve that semantics on the dict
                    // we hand to transformers and to the outbound header filter.
                    RequestHeaders = context.Request.Headers.ToDictionary(
                        kvp => kvp.Key,
                        kvp => kvp.Value,
                        StringComparer.OrdinalIgnoreCase),
                    BackendCaller = backendCaller,
                    Logger = logger,
                    TelemetryEnabled = enableTelemetry
                };

                // Determine effective backend method
                var effectiveBackendMethod = backendMethod == "*"
                    ? context.Request.Method
                    : backendMethod!;

                // Interpolate URL with route values and forward query parameters. The query merge
                // is shared with the typed path (RouteUrlInterpolator.AppendQueryString) so the two
                // can't drift apart again.
                var interpolatedUrl = RouteUrlInterpolator.AppendQueryString(
                    RouteUrlInterpolator.Interpolate(backendUrl!, transformerContext.RouteValues),
                    context.Request.QueryString.Value);

                // Build backend request
                var backendRequest = new BackendRequest
                {
                    Method = effectiveBackendMethod,
                    Url = interpolatedUrl,
                    AccessToken = authContext.AccessToken,
                    Timeout = timeout,
                    BackendAuthPolicy = anonymousCaller && BackendAuthPolicies.RequiresUserIdentity(backendAuthPolicy)
                        ? BackendAuthPolicies.None
                        : backendAuthPolicy
                };

                // Call backend with raw streaming. NOTE: the request (upload) direction is streamed
                // straight through without a per-endpoint size/idle cap - unlike the response
                // direction (CopyBoundedAsync below), which enforces MaxRawForwardResponseBytes /
                // RawForwardReadIdleTimeout. Over-large and slow-loris uploads are deliberately
                // delegated to Kestrel's global limits (MaxRequestBodySize, MinRequestBodyDataRate,
                // RequestHeadersTimeout). This asymmetry is intentional and documented in
                // docs/raw-forwarding.md ("Request Direction - Kestrel Reliance") and SECURITY.md.
                Stream? requestBody = null;
                string? contentType = null;

                // Forward the body for any verb that actually carries one - not just POST/PUT/PATCH.
                // DELETE and OPTIONS legitimately ship payloads (e.g. bulk-delete bodies), so gate on
                // whether a body is present rather than an allowlist of methods. Detect a real body via
                // Content-Length or a chunked Transfer-Encoding instead of "is the stream readable"
                // (the inbound Body stream is always readable), so a bodyless GET never gets an empty
                // StreamContent attached. HTTP/2 and HTTP/3 data frames do not require Content-Length
                // or Transfer-Encoding headers, so RequestHasBody also consults the transport-level
                // IHttpRequestBodyDetectionFeature.CanHaveBody to catch framed bodies.
                if (RequestHasBody(context.Request))
                {
                    requestBody = context.Request.Body;
                    contentType = context.Request.ContentType ?? "application/octet-stream";
                }

                // Let transformer modify the request (via a custom HttpRequestMessage)
                // We'll create a temporary message just for the hooks
                using var tempRequest = new HttpRequestMessage(new HttpMethod(effectiveBackendMethod), interpolatedUrl);

                // Determine destination host for allow-list scoping
                string? destinationHost = null;
                if (Uri.TryCreate(interpolatedUrl, UriKind.Absolute, out var destUri))
                {
                    destinationHost = destUri.Host;
                }

                // The inbound peer's IP gates whether spoofable Forwarded / X-Forwarded-* metadata
                // is trusted enough to relay onward (only reverse proxies in TrustedForwardingProxies).
                var remoteIp = context.Connection.RemoteIpAddress;

                // Copy headers from incoming request, stripping sensitive headers unless explicitly
                // allowed. Entity (content) headers are split off into contentHeaders: the request-
                // headers collection silently rejects them, so they must be lifted onto the forwarded
                // StreamContent instead of being dropped (Content-Encoding, Content-Disposition, ...).
                var contentHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                // Tracks exactly which headers (and values) were copied from the client so the
                // post-rewrite re-scope below can distinguish them from transformer-set headers.
                var clientForwardedHeaders = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
                foreach (var (key, value) in transformerContext.RequestHeaders)
                {
                    if (!ShouldForwardClientHeader(key, destinationHost, remoteIp, headerPassThrough))
                    {
                        continue;
                    }

                    if (RawForwardHeaderFilter.IsContentHeader(key))
                    {
                        // Content-Type is forwarded via the dedicated contentType path below, so it is
                        // not duplicated here. Other entity headers are carried on the body content.
                        if (!key.Equals("Content-Type", StringComparison.OrdinalIgnoreCase))
                        {
                            contentHeaders[key] = value.ToString();
                        }
                        continue;
                    }

                    var clientValues = value.ToArray();
                    if (tempRequest.Headers.TryAddWithoutValidation(key, clientValues))
                    {
                        clientForwardedHeaders[key] = clientValues!;
                    }
                }

                // Let transformer modify request
                transformer.ModifyRequest(tempRequest, transformerContext);

                // Honour a URL rewrite performed in ModifyRequest. The hook is documented to allow
                // "modify the URL" (see IRawTransformer.ModifyRequest), but the rewritten RequestUri
                // used to be discarded - the backend was always called with the originally interpolated
                // URL. Read it back so custom transformers can actually redirect the backend call.
                // A null RequestUri (transformer cleared it) falls back to the interpolated URL.
                var finalUrl = tempRequest.RequestUri?.ToString() ?? interpolatedUrl;

                // If the transformer redirected the call to a DIFFERENT host, the sensitive client
                // headers copied above were allow-listed against the ORIGINAL destination host. A
                // rewrite must not be allowed to smuggle the client's Authorization/Cookie/etc. to a
                // host the operator never allow-listed for those headers, so re-scope the client
                // headers against the final host and strip any that are no longer permitted. Headers
                // the transformer set or replaced in ModifyRequest are trusted server-side intent
                // and are kept: only headers still carrying the exact values copied from the client
                // are re-evaluated (compared against the snapshot taken before ModifyRequest ran).
                // (User-token forwarding is independently re-validated against the final URL in
                // BackendCaller's trusted-host gate, so a rewrite cannot leak the OAuth token either.)
                string? finalHost = Uri.TryCreate(finalUrl, UriKind.Absolute, out var finalUri) ? finalUri.Host : null;
                if (!string.Equals(finalHost, destinationHost, StringComparison.OrdinalIgnoreCase))
                {
                    foreach (var (key, clientValues) in clientForwardedHeaders)
                    {
                        if (ShouldForwardClientHeader(key, finalHost, remoteIp, headerPassThrough))
                        {
                            continue;
                        }

                        if (tempRequest.Headers.TryGetValues(key, out var currentValues)
                            && currentValues.SequenceEqual(clientValues, StringComparer.Ordinal))
                        {
                            tempRequest.Headers.Remove(key);
                        }
                    }
                }

                // Update backend request URL + headers from the modified temp request
                var customHeaders = new Dictionary<string, string>();
                foreach (var header in tempRequest.Headers)
                {
                    customHeaders[header.Key] = string.Join(",", header.Value);
                }
                backendRequest = backendRequest with { Url = finalUrl, Headers = customHeaders, ContentHeaders = contentHeaders };

                // Call backend
                if (requestBody != null && contentType != null)
                {
                    result = await backendCaller.CallRawAsync(backendRequest, requestBody, contentType, context.RequestAborted);
                }
                else
                {
                    result = await backendCaller.CallRawAsync(backendRequest, context.RequestAborted);
                }

                if (!result.IsSuccess)
                {
                    // Transport-level failure (timeout, network, config error, or an auth-handler
                    // exception surfaced as 401). Route through the configured mapper so an
                    // auth-handler 401 becomes a 502 rather than leaking to the client.
                    var (failStatus, failMessage) = errorMapper.MapError(
                        result.StatusCode, result.Error, backendRequest);

                    logger.LogWarning("Raw forward backend call failed: {StatusCode} -> {MappedStatus} {Error}",
                        result.StatusCode, failStatus, result.Error);

                    context.Response.StatusCode = failStatus;
                    await context.Response.WriteAsJsonAsync(new { error = failMessage }, context.RequestAborted);
                    return;
                }

                // Stream response back to client
                var response = result.Response!;
                var backendStatus = (int)response.StatusCode;

                // A backend response was received, but a backend credential failure (401/403) must
                // not pass straight through: the frontend would read it as the *user's* session
                // being invalid and sign them out. Run the backend status through the same
                // IBackendErrorMapper the typed routes use; if it reclassifies the status
                // (e.g. 401/403 -> 502), emit a clean BFF error instead of streaming the backend's
                // auth-failure response (status, headers, and body) to the client. Statuses the
                // mapper passes through (404, 409, 500, ...) stream as before - raw forward is a
                // proxy and those are legitimate to relay.
                var (mappedStatus, mappedMessage) = errorMapper.MapError(
                    backendStatus, response.ReasonPhrase, backendRequest);
                if (mappedStatus != backendStatus)
                {
                    logger.LogWarning("Raw forward backend returned {BackendStatus}; mapped to {MappedStatus}",
                        backendStatus, mappedStatus);

                    context.Response.StatusCode = mappedStatus;
                    await context.Response.WriteAsJsonAsync(new { error = mappedMessage }, context.RequestAborted);

                    activity?.SetTag(PortaActivitySource.Tags.HttpStatusCode, mappedStatus);
                    activity?.SetStatus(ActivityStatusCode.Error);
                    return;
                }

                context.Response.StatusCode = backendStatus;

                // Let the transformer scrub/augment backend response headers BEFORE we
                // copy them to the outbound response and BEFORE the body is streamed.
                // (Once the body starts streaming, response.HasStarted flips and
                // headers can no longer be mutated.)
                transformer.ModifyResponseHeaders(response.Headers, transformerContext);

                // Copy response headers, stripping hop-by-hop and sensitive backend
                // headers (Set-Cookie, HSTS, CSP, Server, X-Powered-By) unless
                // explicitly opted in via AllowedResponseHeaders.
                foreach (var header in response.Headers)
                {
                    if (ShouldForwardBackendResponseHeader(header.Key, headerPassThrough))
                    {
                        context.Response.Headers[header.Key] = header.Value.ToArray();
                    }
                }

                // Copy content headers (same filtering applies - Set-Cookie won't
                // appear here in practice, but a custom Server header on the entity
                // would, and we still want it gated).
                if (response.Content != null)
                {
                    foreach (var header in response.Content.Headers)
                    {
                        if (ShouldForwardBackendResponseHeader(header.Key, headerPassThrough))
                        {
                            context.Response.Headers[header.Key] = header.Value.ToArray();
                        }
                    }

                    // Stream the body with a max-size cap and per-read idle timeout. A misbehaving
                    // backend can otherwise stream unbounded bytes (egress amplification) or
                    // slow-loris a connection by dribbling one byte per minute (worker pinning).
                    await using var responseStream = await response.Content.ReadAsStreamAsync(context.RequestAborted);
                    await CopyBoundedAsync(
                        responseStream,
                        context.Response.Body,
                        maxResponseBytes,
                        readIdleTimeout,
                        context.RequestAborted);
                }

                // Reflect the forwarded status: a relayed backend 4xx/5xx must not record a green span.
                activity?.SetTag(PortaActivitySource.Tags.HttpStatusCode, context.Response.StatusCode);
                activity?.SetStatus(
                    context.Response.StatusCode >= 400 ? ActivityStatusCode.Error : ActivityStatusCode.Ok);
            }
            catch (InvalidRouteValueException ex)
            {
                logger.LogWarning("Raw forward rejected route value: {Reason}", ex.Message);

                activity?.SetStatus(ActivityStatusCode.Error, "Invalid route value");

                if (!context.Response.HasStarted)
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { error = "Invalid request path" }, context.RequestAborted);
                }
            }
            catch (RawForwardResponseTooLargeException ex)
            {
                logger.LogWarning("Raw forward aborted: response exceeded cap of {MaxBytes} bytes", ex.MaxBytes);
                activity?.SetStatus(ActivityStatusCode.Error, "Response too large");
                if (!context.Response.HasStarted)
                {
                    // Headers were already copied from the backend (Content-Encoding, Content-Length,
                    // Content-Disposition, cache headers, ...) before bounded streaming began. Reset
                    // the response so the JSON error body is not emitted alongside stale backend
                    // headers that describe a body we never sent.
                    context.Response.Clear();
                    context.Response.StatusCode = 502;
                    await context.Response.WriteAsJsonAsync(new { error = "Backend response too large" }, context.RequestAborted);
                }
                // If we already started streaming, the connection is left in a torn state - that
                // is the right outcome: the client must not be fed a "complete" body we truncated.
            }
            catch (RawForwardReadTimeoutException ex)
            {
                logger.LogWarning("Raw forward aborted: backend stalled for {Timeout} between reads", ex.IdleTimeout);
                activity?.SetStatus(ActivityStatusCode.Error, "Backend stalled");
                if (!context.Response.HasStarted)
                {
                    // See the size-cap branch above: drop the already-copied backend headers before
                    // emitting the JSON error so they don't describe a body that never streamed.
                    context.Response.Clear();
                    context.Response.StatusCode = 504;
                    await context.Response.WriteAsJsonAsync(new { error = "Backend response stalled" }, context.RequestAborted);
                }
            }
            catch (HttpRequestException ex)
            {
                logger.LogError(ex, "Raw forward backend call failed: {Method} {Url}",
                    backendMethod, backendUrl);

                activity?.SetStatus(ActivityStatusCode.Error, ex.Message);

                if (!context.Response.HasStarted)
                {
                    // The failure may have surfaced after backend headers were copied (e.g. opening
                    // the response stream); reset so they don't leak onto the JSON error.
                    context.Response.Clear();
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
                logger.LogError(ex, "Raw forward execution failed");

                activity?.SetStatus(ActivityStatusCode.Error, ex.Message);

                if (!context.Response.HasStarted)
                {
                    // Reset any backend headers copied before the failure so the JSON error stands alone.
                    context.Response.Clear();
                    context.Response.StatusCode = 500;
                    await context.Response.WriteAsJsonAsync(new { error = "Internal server error" }, context.RequestAborted);
                }
            }
            finally
            {
                // RawBackendResult owns the backend HttpResponseMessage; dispose it so the
                // response (and its content) is released even though the body stream above
                // was disposed separately.
                result.Dispose();

                if (stopwatch != null && metrics != null)
                {
                    stopwatch.Stop();
                    metrics.RecordTransformationDuration(stopwatch.Elapsed.TotalMilliseconds, $"RawForward:{transformerName}");
                }
            }
        };

        var routeHandler = _httpMethod switch
        {
            "GET" => _endpoints.MapGet(_routePattern!, handler),
            "POST" => _endpoints.MapPost(_routePattern!, handler),
            "PUT" => _endpoints.MapPut(_routePattern!, handler),
            "DELETE" => _endpoints.MapDelete(_routePattern!, handler),
            "PATCH" => _endpoints.MapPatch(_routePattern!, handler),
            "HEAD" => _endpoints.MapMethods(_routePattern!, ["HEAD"], handler),
            "OPTIONS" => _endpoints.MapMethods(_routePattern!, ["OPTIONS"], handler),
            "*" => _endpoints.MapMethods(_routePattern!, ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"], handler),
            _ => throw new InvalidOperationException($"Unsupported HTTP method: {_httpMethod}")
        };

        // Apply authorization. enforceUserIdentity was computed above from the transformer's
        // type-level [RequiresAuthentication] metadata - we never instantiate TTransformer
        // here, since Build() runs at startup against the root service provider and
        // constructing it would capture any scoped / HttpContext-bound dependency from the
        // root (captive deps).
        if (enforceUserIdentity)
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
        routeHandler.WithMetadata(new PortaPrincipalRequirementMetadata(enforceUserIdentity));

        return routeHandler;
    }


    /// <summary>
    /// Streams <paramref name="source"/> into <paramref name="destination"/> in chunks, aborting
    /// if the total bytes copied exceed <paramref name="maxBytes"/> or if any single read takes
    /// longer than <paramref name="readIdleTimeout"/>. Both checks defend the BFF worker against
    /// hostile backends; they do not retry - the connection is closed and the response truncated.
    /// </summary>
    private static async Task CopyBoundedAsync(
        Stream source,
        Stream destination,
        long maxBytes,
        TimeSpan readIdleTimeout,
        CancellationToken cancellationToken)
    {
        const int BufferSize = 81920;
        var buffer = new byte[BufferSize];
        long total = 0;
        var unlimitedSize = maxBytes <= 0;
        var unlimitedIdle = readIdleTimeout <= TimeSpan.Zero;

        while (true)
        {
            int read;
            if (unlimitedIdle)
            {
                read = await source.ReadAsync(buffer.AsMemory(), cancellationToken);
            }
            else
            {
                using var idle = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                idle.CancelAfter(readIdleTimeout);
                try
                {
                    read = await source.ReadAsync(buffer.AsMemory(), idle.Token);
                }
                catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
                {
                    throw new RawForwardReadTimeoutException(readIdleTimeout);
                }
            }

            if (read == 0)
            {
                return;
            }

            total += read;
            if (!unlimitedSize && total > maxBytes)
            {
                throw new RawForwardResponseTooLargeException(maxBytes);
            }

            await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
        }
    }

    /// <summary>
    /// Whether the incoming request carries a body that should be forwarded to the backend.
    /// Gated on the request framing rather than stream readability, because the inbound request
    /// body stream is always readable - even for bodyless verbs - so probing the stream would
    /// attach an empty <see cref="StreamContent"/> to a bodyless GET.
    /// </summary>
    /// <remarks>
    /// Three framing signals, in order:
    /// <list type="number">
    /// <item><description>A positive <c>Content-Length</c> is a body.</description></item>
    /// <item><description>A chunked <c>Transfer-Encoding</c> is a body - HTTP/1.1 streamed uploads
    /// omit <c>Content-Length</c>.</description></item>
    /// <item><description>HTTP/2 and HTTP/3 carry the body in DATA frames with neither header set;
    /// the transport END_STREAM flag on the HEADERS frame is the only reliable signal, surfaced via
    /// <see cref="IHttpRequestBodyDetectionFeature.CanHaveBody"/>. An explicit <c>Content-Length: 0</c>
    /// overrides this and means "no body".</description></item>
    /// </list>
    /// Marked <c>internal</c> (not <c>private</c>) so the framing logic can be unit-tested directly
    /// against a stubbed <see cref="IHttpRequestBodyDetectionFeature"/> - TestServer cannot synthesize
    /// an HTTP/2 DATA-frame body that omits both Content-Length and Transfer-Encoding.
    /// </remarks>
    internal static bool RequestHasBody(HttpRequest request)
    {
        if (request.ContentLength is > 0)
        {
            return true;
        }

        // Chunked uploads omit Content-Length; detect them via Transfer-Encoding: chunked.
        var transferEncoding = request.Headers.TransferEncoding;
        if (transferEncoding.Count > 0
            && transferEncoding.Any(v => v != null && v.Contains("chunked", StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }

        // A client that explicitly declared Content-Length: 0 promised no body - honour that rather
        // than falling through to the HTTP/2/3 framing probe, which would otherwise allow one.
        if (request.ContentLength is 0)
        {
            return false;
        }

        // HTTP/2 / HTTP/3 DATA-frame bodies carry neither Content-Length nor Transfer-Encoding.
        // CanHaveBody reflects the transport END_STREAM flag - the only reliable framed-body signal.
        return request.HttpContext.Features.Get<IHttpRequestBodyDetectionFeature>()?.CanHaveBody ?? false;
    }

    private static bool ShouldForwardClientHeader(
        string headerName,
        string? destinationHost,
        IPAddress? remoteIp,
        RawForwardHeaderPassThrough passThrough)
        => RawForwardHeaderFilter.ShouldForwardClientHeader(headerName, destinationHost, remoteIp, passThrough);

    private static bool ShouldForwardBackendResponseHeader(
        string headerName,
        RawForwardHeaderPassThrough passThrough)
        => RawForwardHeaderFilter.ShouldForwardBackendResponseHeader(headerName, passThrough);
}

/// <summary>
/// Header filtering rules applied by raw-forward endpoints. Exposed for unit testing.
/// </summary>
internal static class RawForwardHeaderFilter
{
    public static bool IsHopByHopHeader(string headerName)
    {
        return headerName.Equals("Connection", StringComparison.OrdinalIgnoreCase) ||
               headerName.Equals("Keep-Alive", StringComparison.OrdinalIgnoreCase) ||
               headerName.Equals("Proxy-Authenticate", StringComparison.OrdinalIgnoreCase) ||
               headerName.Equals("Proxy-Authorization", StringComparison.OrdinalIgnoreCase) ||
               headerName.Equals("TE", StringComparison.OrdinalIgnoreCase) ||
               headerName.Equals("Trailer", StringComparison.OrdinalIgnoreCase) ||
               headerName.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase) ||
               headerName.Equals("Upgrade", StringComparison.OrdinalIgnoreCase) ||
               headerName.Equals("Host", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Framing headers we never carry from the client request onto the outbound backend
    /// request. <see cref="StreamContent"/> re-asserts Content-Length based on what we
    /// actually send; carrying the inbound value forward alongside that is a classic
    /// request-smuggling primitive (CL.TE / CL.CL) where the BFF and backend disagree
    /// on where the request body ends. Stripped on the *request* side only - the
    /// response-side filter still lets Content-Length flow back to the client.
    /// </summary>
    public static bool IsRequestFramingHeader(string headerName)
    {
        return headerName.Equals("Content-Length", StringComparison.OrdinalIgnoreCase) ||
               headerName.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// HTTP entity (content) headers that belong on <see cref="System.Net.Http.HttpContent.Headers"/>
    /// rather than the request line. <c>HttpRequestMessage.Headers</c> silently rejects these, so
    /// raw-forward must lift them onto the forwarded <see cref="System.Net.Http.StreamContent"/> or
    /// they are lost. <c>Content-Length</c> is deliberately excluded - it is a framing header
    /// (see <see cref="IsRequestFramingHeader"/>) re-asserted by the outbound content itself.
    /// </summary>
    public static bool IsContentHeader(string headerName)
    {
        return headerName.Equals("Content-Type", StringComparison.OrdinalIgnoreCase) ||
               headerName.Equals("Content-Encoding", StringComparison.OrdinalIgnoreCase) ||
               headerName.Equals("Content-Disposition", StringComparison.OrdinalIgnoreCase) ||
               headerName.Equals("Content-Language", StringComparison.OrdinalIgnoreCase) ||
               headerName.Equals("Content-Location", StringComparison.OrdinalIgnoreCase) ||
               headerName.Equals("Content-Range", StringComparison.OrdinalIgnoreCase) ||
               headerName.Equals("Content-MD5", StringComparison.OrdinalIgnoreCase) ||
               headerName.Equals("Allow", StringComparison.OrdinalIgnoreCase) ||
               headerName.Equals("Expires", StringComparison.OrdinalIgnoreCase) ||
               headerName.Equals("Last-Modified", StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsSensitiveClientHeader(string headerName)
    {
        return headerName.Equals("Cookie", StringComparison.OrdinalIgnoreCase) ||
               headerName.Equals("Set-Cookie", StringComparison.OrdinalIgnoreCase) ||
               headerName.Equals("Authorization", StringComparison.OrdinalIgnoreCase) ||
               IsForwardingHeader(headerName);
    }

    /// <summary>
    /// Forwarding-metadata headers that let an upstream peer claim the original client IP,
    /// host, or scheme: the standard <c>Forwarded</c> header (RFC 7239) and the de-facto
    /// <c>X-Forwarded-*</c> family. A malicious client can spoof these, so raw-forward strips
    /// them by default. They are honoured only when the inbound connection originates from a
    /// configured reverse proxy (see <see cref="RawForwardHeaderPassThrough.TrustedForwardingProxies"/>)
    /// or when explicitly opted in via <see cref="RawForwardHeaderPassThrough.AllowedHeaders"/>.
    /// </summary>
    public static bool IsForwardingHeader(string headerName)
    {
        return headerName.Equals("Forwarded", StringComparison.OrdinalIgnoreCase) ||
               headerName.StartsWith("X-Forwarded-", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Whether the inbound connection's remote IP belongs to a configured trusted reverse
    /// proxy, in which case its <c>Forwarded</c> / <c>X-Forwarded-*</c> headers may be relayed
    /// to the backend. Entries may be plain IP addresses (<c>"10.0.0.5"</c>) or CIDR ranges
    /// (<c>"10.0.0.0/8"</c>). IPv4-mapped IPv6 remote addresses (e.g. <c>"::ffff:10.0.0.5"</c>,
    /// the form Kestrel reports for a dual-stack socket) are normalized before comparison so
    /// that an IPv4 entry still matches.
    /// </summary>
    public static bool IsTrustedForwardingProxy(IPAddress? remoteIp, IReadOnlyCollection<string> trustedProxies)
    {
        if (remoteIp is null || trustedProxies.Count == 0)
        {
            return false;
        }

        var normalized = remoteIp.IsIPv4MappedToIPv6 ? remoteIp.MapToIPv4() : remoteIp;

        foreach (var entry in trustedProxies)
        {
            if (entry.Contains('/'))
            {
                if (IPNetwork.TryParse(entry, out var network) &&
                    (network.Contains(normalized) || network.Contains(remoteIp)))
                {
                    return true;
                }
            }
            else if (IPAddress.TryParse(entry, out var candidate) &&
                     (candidate.Equals(normalized) || candidate.Equals(remoteIp)))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Headers from the backend response that must not flow to the client by default.
    /// Set-Cookie would let a backend plant cookies on the BFF's domain (potentially
    /// shadowing the BFF session cookie); HSTS / CSP / Server / X-Powered-By are policy
    /// or fingerprinting headers the BFF should own rather than relay verbatim.
    /// </summary>
    public static bool IsSensitiveBackendResponseHeader(string headerName)
    {
        return headerName.Equals("Set-Cookie", StringComparison.OrdinalIgnoreCase) ||
               headerName.Equals("Strict-Transport-Security", StringComparison.OrdinalIgnoreCase) ||
               headerName.Equals("Content-Security-Policy", StringComparison.OrdinalIgnoreCase) ||
               headerName.Equals("Content-Security-Policy-Report-Only", StringComparison.OrdinalIgnoreCase) ||
               headerName.Equals("Server", StringComparison.OrdinalIgnoreCase) ||
               headerName.Equals("X-Powered-By", StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsHeaderAllowed(string headerName, string? destinationHost, RawForwardHeaderPassThrough passThrough)
    {
        if (!passThrough.AllowedHeaders.Contains(headerName))
        {
            return false;
        }

        if (passThrough.AllowedDestinationHosts.Count == 0)
        {
            return true;
        }

        return destinationHost != null && passThrough.AllowedDestinationHosts.Contains(destinationHost);
    }

    /// <summary>
    /// Determines whether an inbound client header should be forwarded to the backend
    /// in raw-forward mode. Strips hop-by-hop and sensitive headers unless the latter
    /// are explicitly opted in via <paramref name="passThrough"/>.
    /// </summary>
    public static bool ShouldForwardClientHeader(
        string headerName,
        string? destinationHost,
        IPAddress? remoteIp,
        RawForwardHeaderPassThrough passThrough)
    {
        if (IsHopByHopHeader(headerName))
        {
            return false;
        }

        if (IsRequestFramingHeader(headerName))
        {
            return false;
        }

        if (IsSensitiveClientHeader(headerName) &&
            !IsHeaderAllowed(headerName, destinationHost, passThrough) &&
            !(IsForwardingHeader(headerName) && IsTrustedForwardingProxy(remoteIp, passThrough.TrustedForwardingProxies)))
        {
            return false;
        }

        return true;
    }

    /// <summary>
    /// Determines whether a backend response header should be forwarded to the client
    /// in raw-forward mode. Strips hop-by-hop and sensitive backend headers
    /// (Set-Cookie, HSTS, CSP, Server, X-Powered-By) unless explicitly opted in via
    /// <see cref="RawForwardHeaderPassThrough.AllowedResponseHeaders"/>.
    /// </summary>
    public static bool ShouldForwardBackendResponseHeader(
        string headerName,
        RawForwardHeaderPassThrough passThrough)
    {
        if (IsHopByHopHeader(headerName))
        {
            return false;
        }

        if (IsSensitiveBackendResponseHeader(headerName) &&
            !passThrough.AllowedResponseHeaders.Contains(headerName))
        {
            return false;
        }

        return true;
    }
}

internal sealed class RawForwardResponseTooLargeException(long maxBytes)
    : Exception($"Backend response exceeded raw-forward cap of {maxBytes} bytes.")
{
    public long MaxBytes { get; } = maxBytes;
}

internal sealed class RawForwardReadTimeoutException(TimeSpan idleTimeout)
    : Exception($"Backend stalled for longer than {idleTimeout} between reads.")
{
    public TimeSpan IdleTimeout { get; } = idleTimeout;
}
