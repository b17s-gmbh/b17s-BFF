using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

using b17s.Porta.Auth.Tokens;
using b17s.Porta.Configuration;
using b17s.Porta.Telemetry;

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace b17s.Porta.Transformers;

/// <summary>
/// Default implementation of IBackendCaller with token forwarding and resilience.
/// </summary>
/// <remarks>
/// <paramref name="accessTokenRefresh"/> and <paramref name="httpContextAccessor"/> are optional:
/// they are only registered when Porta authentication is added. They are consulted on the
/// refresh-on-401 path (<see cref="PortaCoreOptions.RefreshBackendTokenOn401"/>, default on) -
/// when either is absent a backend 401 is surfaced unchanged - and
/// <paramref name="httpContextAccessor"/> additionally supplies the authenticated user's claims
/// to <see cref="BackendAuthContext.Claims"/>.
/// <para>
/// Registered scoped, so a single instance is shared by every backend call in a request - including
/// the parallel legs of an aggregation. That lets the refresh-on-401 path serialise the user-token
/// refresh through <see cref="_refreshGate"/> and reuse the rotated token in-memory across legs, so
/// concurrent 401s trigger exactly one IdP refresh / one cookie rewrite. See
/// <see cref="RefreshUserTokenAsync"/>.
/// </para>
/// </remarks>
public sealed class BackendCaller(
    IHttpClientFactory httpClientFactory,
    IBackendAuthHandlerRegistry authHandlerRegistry,
    IContentSerializer contentSerializer,
    PortaMetrics? metrics,
    ILogger<BackendCaller> logger,
    IOptions<PortaCoreOptions> coreOptions,
    IBackendErrorMapper? errorMapper = null,
    IAccessTokenRefreshService? accessTokenRefresh = null,
    IHttpContextAccessor? httpContextAccessor = null,
    ITrustedHostValidator? trustedHostValidator = null) : IBackendCaller, IDisposable
{
    // Default to the framework's 401/403 -> 502 mapper when nothing is registered. Optional
    // so existing tests that instantiate BackendCaller directly don't have to wire a mapper.
    private readonly IBackendErrorMapper _errorMapper = errorMapper ?? new DefaultBackendErrorMapper();

    // Refresh-on-401 serialisation, scoped to this request (BackendCaller is scoped).
    // SemaphoreSlim - not System.Threading.Lock - because the guarded section is async
    // (ForceRefreshAsync does IdP HTTP + cookie SignInAsync) and Lock cannot be held across await.
    private readonly SemaphoreSlim _refreshGate = new(1, 1);
    private string? _rotatedToken;
    private string? _consumedStaleToken;
    private bool _refreshAttempted;
    /// <summary>
    /// The name of the named <see cref="HttpClient"/> used for backend calls without the
    /// resilience (retry) pipeline. Registered by <c>AddPortaCore</c>.
    /// </summary>
    public const string HttpClientName = "Porta.BackendCaller";

    /// <summary>
    /// The name of the named <see cref="HttpClient"/> used for backend calls with the standard
    /// resilience (retry/back-off) pipeline, selected when <see cref="BackendRequest.EnableRetries"/>
    /// is set. Registered by <c>AddPortaCore</c>.
    /// </summary>
    public const string HttpClientNameWithRetries = "Porta.BackendCaller.WithRetries";

    /// <summary>
    /// Per-request key carrying the endpoint's retry budget (the <c>WithRetries(n)</c> value) on
    /// the outbound <see cref="HttpRequestMessage"/>. The retry pipeline on
    /// <see cref="HttpClientNameWithRetries"/> bakes a single, app-wide attempt count, so the
    /// per-endpoint count is threaded here and enforced by the pipeline's <c>ShouldHandle</c> gate
    /// (see <c>AddPortaCore</c>). Read via <c>HttpResilienceContextExtensions.GetRequestMessage</c>
    /// so it is honored on both response and exception outcomes. The pipeline's own
    /// <c>MaxRetryAttempts</c> (bound to <see cref="PortaCoreOptions.MaxRetryAttempts"/>) remains the
    /// app-wide ceiling: the effective retry count is <c>min(budget, ceiling)</c>.
    /// </summary>
    internal static readonly HttpRequestOptionsKey<int> RetryBudgetOption = new("Porta.RetryBudget");

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false
    };

    private readonly int _maxBodyLogLength = coreOptions.Value.MaxBodyLogLength;
    private readonly long _maxBackendResponseBytes = coreOptions.Value.MaxBackendResponseBytes;
    private readonly bool _refreshOn401Enabled = coreOptions.Value.RefreshBackendTokenOn401;

    // Telemetry is opt-out via PortaCoreOptions.EnableTelemetry (default on). When disabled we skip
    // Porta's own backend spans and metrics so operators can fully opt out (see the transformer and
    // raw-forward builders, which already gate the same way).
    //
    // We deliberately only suppress *our* activity creation; we never touch Activity.Current. An
    // upstream reverse proxy's trace context stays ambient and still propagates to the backend via
    // the outbound HttpClient, so external/host-level traces (and the reverse proxy's spans) are
    // never dropped just because Porta's own instrumentation is off.
    private readonly bool _enableTelemetry = coreOptions.Value.EnableTelemetry;

    // Null when telemetry is disabled so the metrics?.Record... call sites below become no-ops
    // without sprinkling EnableTelemetry checks through every recording path.
    private readonly PortaMetrics? _metrics = coreOptions.Value.EnableTelemetry ? metrics : null;

    /// <summary>
    /// Reads the response body into a string, refusing to buffer more than
    /// <see cref="PortaCoreOptions.MaxBackendResponseBytes"/>. Returns <c>null</c>
    /// when the body is too large to deserialize safely; the caller MUST treat
    /// that as a backend error rather than continuing with a partial body.
    /// </summary>
    private async Task<string?> ReadBoundedResponseStringAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        if (_maxBackendResponseBytes <= 0)
        {
            return await response.Content.ReadAsStringAsync(cancellationToken);
        }

        // Reject responses whose advertised Content-Length already exceeds the cap.
        var contentLength = response.Content.Headers.ContentLength;
        if (contentLength.HasValue && contentLength.Value > _maxBackendResponseBytes)
        {
            return null;
        }

        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        // Read at most maxBytes + 1: if we still have unread data after that, the body is too large.
        var maxBytes = _maxBackendResponseBytes;
        var buffer = new byte[Math.Min(81920, maxBytes + 1)];
        using var memory = new MemoryStream();
        long total = 0;
        while (true)
        {
            var toRead = (int)Math.Min(buffer.Length, (maxBytes + 1) - total);
            if (toRead <= 0)
            {
                break;
            }
            var read = await stream.ReadAsync(buffer.AsMemory(0, toRead), cancellationToken);
            if (read == 0)
            {
                break;
            }
            total += read;
            if (total > maxBytes)
            {
                return null;
            }
            memory.Write(buffer, 0, read);
        }

        // Use the charset advertised by the backend if any; default to UTF-8.
        var charset = response.Content.Headers.ContentType?.CharSet;
        Encoding encoding;
        try
        {
            encoding = string.IsNullOrEmpty(charset) ? Encoding.UTF8 : Encoding.GetEncoding(charset.Trim('"'));
        }
        catch (ArgumentException)
        {
            encoding = Encoding.UTF8;
        }
        return encoding.GetString(memory.GetBuffer(), 0, (int)memory.Length);
    }

    /// <summary>
    /// Truncates a body for Trace logs per <see cref="PortaCoreOptions.MaxBodyLogLength"/>.
    /// Returns null when body logging is disabled (length == 0); the caller must skip logging.
    /// </summary>
    private string? PrepareBodyForLog(string body)
    {
        if (_maxBodyLogLength == 0)
        {
            return null;
        }
        if (_maxBodyLogLength < 0 || body.Length <= _maxBodyLogLength)
        {
            return body;
        }
        return string.Concat(body.AsSpan(0, _maxBodyLogLength), "… (truncated, ", body.Length.ToString(System.Globalization.CultureInfo.InvariantCulture), " chars total)");
    }

    /// <inheritdoc/>
    public async Task<BackendResult<TResponse>> CallAsync<TResponse>(BackendRequest request, CancellationToken cancellationToken)
    {
        var sendResult = await SendRequestAsync<object>(request, null, cancellationToken);
        if (!sendResult.IsSuccess)
        {
            var (status, message, errorType) = MapSendFailure(sendResult, request);
            return BackendResult<TResponse>.Failure(status, message, errorType);
        }
        // Dispose the response once we're done with it. Mandatory under ResponseHeadersRead:
        // the body stream - and the underlying connection - stays open until the message is
        // disposed, so a missing using here would leak connections from the pool.
        using var response = sendResult.Response!;
        return await DeserializeResponseAsync<TResponse>(response, request, cancellationToken);
    }

    /// <inheritdoc/>
    public async Task<BackendResult<TResponse>> CallAsync<TRequest, TResponse>(BackendRequest request, TRequest body, CancellationToken cancellationToken)
    {
        var sendResult = await SendRequestAsync(request, body, cancellationToken);
        if (!sendResult.IsSuccess)
        {
            var (status, message, errorType) = MapSendFailure(sendResult, request);
            return BackendResult<TResponse>.Failure(status, message, errorType);
        }
        using var response = sendResult.Response!;
        return await DeserializeResponseAsync<TResponse>(response, request, cancellationToken);
    }

    /// <inheritdoc/>
    public async Task<BackendResult> CallAsync(BackendRequest request, CancellationToken cancellationToken)
    {
        var sendResult = await SendRequestAsync<object>(request, null, cancellationToken);
        if (!sendResult.IsSuccess)
        {
            var (status, message, errorType) = MapSendFailure(sendResult, request);
            return BackendResult.Failure(status, message, errorType);
        }
        using var response = sendResult.Response!;
        if (!response.IsSuccessStatusCode)
        {
            return MapHttpErrorToResult(response, request);
        }
        return BackendResult.Success((int)response.StatusCode);
    }

    /// <inheritdoc/>
    public async Task<BackendResult> CallAsync<TRequest>(BackendRequest request, TRequest body, CancellationToken cancellationToken)
    {
        var sendResult = await SendRequestAsync(request, body, cancellationToken);
        if (!sendResult.IsSuccess)
        {
            var (status, message, errorType) = MapSendFailure(sendResult, request);
            return BackendResult.Failure(status, message, errorType);
        }
        using var response = sendResult.Response!;
        if (!response.IsSuccessStatusCode)
        {
            return MapHttpErrorToResult(response, request);
        }
        return BackendResult.Success((int)response.StatusCode);
    }

    /// <inheritdoc/>
    public async Task<BackendObjectResult> CallAsync(BackendRequest request, Type responseType, CancellationToken cancellationToken)
    {
        var sendResult = await SendRequestAsync<object>(request, null, cancellationToken);
        if (!sendResult.IsSuccess)
        {
            var (status, message, errorType) = MapSendFailure(sendResult, request);
            return BackendObjectResult.Failure(status, message, errorType);
        }
        using var response = sendResult.Response!;
        return await DeserializeResponseAsObjectAsync(response, request, responseType, cancellationToken);
    }

    /// <inheritdoc/>
    public async Task<BackendObjectResult> CallWithBodyAsync(BackendRequest request, object body, Type responseType, CancellationToken cancellationToken)
    {
        var sendResult = await SendRequestAsync(request, body, cancellationToken);
        if (!sendResult.IsSuccess)
        {
            var (status, message, errorType) = MapSendFailure(sendResult, request);
            return BackendObjectResult.Failure(status, message, errorType);
        }
        using var response = sendResult.Response!;
        return await DeserializeResponseAsObjectAsync(response, request, responseType, cancellationToken);
    }

    /// <inheritdoc/>
    public async Task<GraphQLResult<TResponse>> CallGraphQLAsync<TResponse>(
        BackendRequest request,
        string query,
        object? variables,
        string dataPath,
        string? operationName = null,
        CancellationToken cancellationToken = default)
    {
        // Create GraphQL request payload
        var graphqlRequest = new GraphQLRequest
        {
            Query = query,
            Variables = variables,
            OperationName = operationName
        };

        // Force POST method for GraphQL
        var graphqlBackendRequest = request with { Method = "POST" };

        // Send the request
        var sendResult = await SendRequestAsync(graphqlBackendRequest, graphqlRequest, cancellationToken);
        if (!sendResult.IsSuccess)
        {
            var (status, message, errorType) = MapSendFailure(sendResult, graphqlBackendRequest);
            return GraphQLResult<TResponse>.FromBackendError(status, message, errorType);
        }

        using var response = sendResult.Response!;
        var statusCode = (int)response.StatusCode;
        var logUrl = SanitizeUrl(request.Url);

        // Read response content with a size cap. A multi-GB GraphQL response would otherwise OOM the BFF.
        var content = await ReadBoundedResponseStringAsync(response, cancellationToken);
        if (content == null)
        {
            logger.BackendResponseTooLarge(logUrl, statusCode, _maxBackendResponseBytes);
            return GraphQLResult<TResponse>.FromBackendError(
                statusCode,
                "Backend response exceeds maximum allowed size",
                BackendErrorType.InvalidResponse);
        }
        logger.BackendResponseMeta(logUrl, statusCode, content.Length, response.Content.Headers.ContentType?.ToString());
        var loggedBody = PrepareBodyForLog(content);
        if (loggedBody != null)
        {
            logger.BackendResponseBody(logUrl, statusCode, loggedBody);
        }

        // Parse the GraphQL envelope first - even on a non-2xx status - so a structured `errors`
        // body is surfaced with its proper code -> status mapping. An empty/unparseable body
        // cannot carry GraphQL errors, so parse failures are deferred until after the HTTP-status
        // gate below.
        GraphQLResponse? graphqlResponse = null;
        JsonException? parseError = null;
        if (!string.IsNullOrWhiteSpace(content))
        {
            try
            {
                graphqlResponse = JsonSerializer.Deserialize<GraphQLResponse>(content, JsonOptions);
            }
            catch (JsonException ex)
            {
                parseError = ex;
                logger.BackendDeserializationFailed(logUrl, statusCode, content.Length, ex);
                var loggedFailedBody = PrepareBodyForLog(content);
                if (loggedFailedBody != null)
                {
                    logger.BackendDeserializationFailedBody(logUrl, statusCode, loggedFailedBody);
                }
            }
        }

        // A transport-level 401/403 means the backend rejected the BFF's forwarded credential -
        // even when a GraphQL `errors` envelope rides along (many servers pair HTTP 401 with
        // {"errors":[{"extensions":{"code":"UNAUTHENTICATED"}}]} for the same rejection). Consult
        // the IBackendErrorMapper BEFORE the envelope-wins rule below, so the default 401/403 -> 502
        // neutralization cannot be bypassed by the envelope; otherwise the client would see the 401
        // and sign the user out over a backend credential problem. A custom mapper that passes the
        // status through unchanged opts back into the envelope's code -> status mapping. (An
        // application-level auth error - UNAUTHENTICATED over HTTP 200 - is the user's denial and
        // still surfaces via the envelope below.)
        if (statusCode is 401 or 403)
        {
            var mapped = MapHttpErrorToGraphQLResult<TResponse>(statusCode, response.ReasonPhrase, request);
            if (mapped.HttpStatusCode != statusCode)
            {
                // Mapper rewrote the status: the envelope (if any) is suppressed client-side, so
                // keep its detail visible to operators via the usual warning log.
                if (graphqlResponse?.Errors is { Count: > 0 } suppressedErrors)
                {
                    logger.GraphQLErrorsReceived(logUrl, suppressedErrors.Count,
                        string.Join("; ", suppressedErrors.Select(e => e.Message)));
                }
                return mapped;
            }
        }

        // A GraphQL `errors` envelope wins over the raw HTTP status: backends may return errors
        // alongside a non-2xx response, and the GraphQL code -> status mapping is more specific.
        // (Transport 401/403 was already routed through the error mapper above.)
        if (graphqlResponse?.Errors is { Count: > 0 } graphqlErrors)
        {
            logger.GraphQLErrorsReceived(logUrl, graphqlErrors.Count,
                string.Join("; ", graphqlErrors.Select(e => e.Message)));
            return GraphQLResult<TResponse>.FromGraphQLErrors(graphqlErrors, statusCode);
        }

        // No GraphQL `errors` to surface. A non-2xx HTTP status is therefore a backend/transport
        // failure (502, 401, 403, 500, ...), NOT a successful empty-data response. Route it
        // through the same IBackendErrorMapper the typed CallAsync overloads use so backend
        // credential failures (401/403) map to 502 instead of leaking to the client and signing
        // the user out.
        if (!response.IsSuccessStatusCode)
        {
            return MapHttpErrorToGraphQLResult<TResponse>(statusCode, response.ReasonPhrase, request);
        }

        // From here on the HTTP status was 2xx: body-shape problems are malformed-response errors.
        if (string.IsNullOrWhiteSpace(content))
        {
            return GraphQLResult<TResponse>.FromBackendError(
                statusCode,
                "Empty response from GraphQL backend",
                BackendErrorType.InvalidResponse);
        }

        if (parseError != null)
        {
            return GraphQLResult<TResponse>.FromBackendError(
                statusCode,
                $"Invalid GraphQL response format: {parseError.Message}",
                BackendErrorType.InvalidResponse);
        }

        if (graphqlResponse == null)
        {
            return GraphQLResult<TResponse>.FromBackendError(
                statusCode,
                "Null GraphQL response",
                BackendErrorType.InvalidResponse);
        }

        // Extract data from response
        if (graphqlResponse.Data == null || graphqlResponse.Data.Value.ValueKind == JsonValueKind.Null)
        {
            // No data and no errors - unusual but valid
            return GraphQLResult<TResponse>.Success(default!, statusCode);
        }

        // Extract value at dataPath
        var extractedData = graphqlResponse.Data.Value.ExtractPath<TResponse>(dataPath);
        return GraphQLResult<TResponse>.Success(extractedData!, statusCode);
    }

    /// <inheritdoc/>
    public async Task<RawBackendResult> CallRawAsync(BackendRequest request, CancellationToken cancellationToken)
    {
        var sendResult = await SendRawRequestAsync(request, null, null, cancellationToken);
        if (!sendResult.IsSuccess)
        {
            return RawBackendResult.Failure(sendResult.StatusCode, sendResult.Error!, sendResult.ErrorType);
        }
        return RawBackendResult.Success(sendResult.Response!);
    }

    /// <inheritdoc/>
    public async Task<RawBackendResult> CallRawAsync(BackendRequest request, Stream requestBody, string contentType, CancellationToken cancellationToken)
    {
        var sendResult = await SendRawRequestAsync(request, requestBody, contentType, cancellationToken);
        if (!sendResult.IsSuccess)
        {
            return RawBackendResult.Failure(sendResult.StatusCode, sendResult.Error!, sendResult.ErrorType);
        }
        return RawBackendResult.Success(sendResult.Response!);
    }

    private async Task<SendResult> SendRawRequestAsync(
        BackendRequest request,
        Stream? bodyStream,
        string? contentType,
        CancellationToken cancellationToken)
    {
        // Extract service name from URL for telemetry
        var serviceName = ExtractServiceName(request.Url);
        // Logs get the same query-stripped URL as spans - query strings can carry tokens/API keys.
        var logUrl = SanitizeUrl(request.Url);

        // Start telemetry activity for backend call (suppressed when telemetry is opted out; the
        // ambient reverse-proxy/host trace context still flows to the backend - see _enableTelemetry).
        // Fixed category activity name; the specific backend is carried on the
        // bff.backend.service tag (set below) so span cardinality stays bounded.
        using var activity = _enableTelemetry
            ? PortaActivitySource.Source.StartActivity(
                PortaActivitySource.Activities.BackendCall,
                ActivityKind.Client)
            : null;

        var stopwatch = Stopwatch.StartNew();

        activity?.SetTag(PortaActivitySource.Tags.Component, "backend");
        activity?.SetTag(PortaActivitySource.Tags.BackendService, serviceName);
        activity?.SetTag(PortaActivitySource.Tags.HttpMethod, request.Method);
        activity?.SetTag(PortaActivitySource.Tags.HttpUrl, logUrl);
        activity?.SetTag(PortaActivitySource.Tags.BackendProtocol, "http");
        activity?.SetTag("bff.raw_request", true);

        // Select the appropriate HttpClient based on retry settings
        var clientName = request.EnableRetries ? HttpClientNameWithRetries : HttpClientName;
        var httpClient = httpClientFactory.CreateClient(clientName);

        if (request.Timeout.HasValue)
        {
            httpClient.Timeout = request.Timeout.Value;
        }

        var httpRequest = new HttpRequestMessage(new HttpMethod(request.Method), request.Url);

        // Thread the per-endpoint retry budget onto the request so the retry pipeline's ShouldHandle
        // gate spends exactly WithRetries(n) attempts (clamped to the app-wide ceiling) instead of
        // the global count. No-op on the non-retry client, which ignores the option.
        if (request.EnableRetries)
        {
            httpRequest.Options.Set(RetryBudgetOption, request.MaxRetryAttempts);
        }

        // Add custom headers
        if (request.Headers != null)
        {
            foreach (var (key, value) in request.Headers)
            {
                httpRequest.Headers.TryAddWithoutValidation(key, value);
            }
        }

        // Apply backend authentication based on policy. Raw forward does not participate in the
        // refresh-on-401 retry path, so the captured access token is used as-is.
        var authResult = await ApplyBackendAuthAsync(
            httpRequest, request, request.AccessToken, forceFreshCredential: false,
            activity, stopwatch, serviceName, cancellationToken);
        if (authResult != null)
        {
            return authResult.Value;
        }

        // Set body stream if present
        if (bodyStream != null && contentType != null)
        {
            httpRequest.Content = new StreamContent(bodyStream);
            // Parse (not the string ctor): inbound Content-Type routinely carries parameters
            // (charset, multipart boundary). The MediaTypeHeaderValue(string) ctor rejects those
            // with a FormatException; Parse accepts the full header value.
            httpRequest.Content.Headers.ContentType = System.Net.Http.Headers.MediaTypeHeaderValue.Parse(contentType);

            // Preserve inbound entity headers the request-headers collection cannot carry
            // (Content-Encoding, Content-Disposition, Content-Language, Content-Range, ...).
            // Content-Type is set above; framing headers (Content-Length / Transfer-Encoding)
            // are deliberately excluded upstream and re-asserted by StreamContent itself.
            if (request.ContentHeaders != null)
            {
                foreach (var (key, value) in request.ContentHeaders)
                {
                    httpRequest.Content.Headers.TryAddWithoutValidation(key, value);
                }
            }
        }

        logger.BackendCallStarting(request.Method, logUrl);

        try
        {
            // Use ResponseHeadersRead to avoid buffering the response body
            var response = await httpClient.SendAsync(httpRequest, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            var statusCode = (int)response.StatusCode;

            logger.BackendCallCompleted(request.Method, logUrl, statusCode);

            // Record telemetry
            stopwatch.Stop();
            activity?.SetTag(PortaActivitySource.Tags.HttpStatusCode, statusCode);
            activity?.SetStatus(response.IsSuccessStatusCode ? ActivityStatusCode.Ok : ActivityStatusCode.Error);

            _metrics?.RecordBackendRequest(serviceName, "http", statusCode);
            _metrics?.RecordBackendCallDuration(stopwatch.Elapsed.TotalMilliseconds, serviceName, "http");

            return SendResult.Ok(response);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // Genuine caller cancellation (client disconnect or a global request timeout) is not
            // a backend fault. Propagate it so the request actually aborts, instead of laundering
            // it into a 500/504 SendResult that downstream aggregation reads as a degraded backend.
            // The HttpClient.Timeout path below is a TaskCanceledException whose token is NOT this
            // one, so genuine per-request timeouts still map to a 504.
            throw;
        }
        catch (TaskCanceledException ex) when (ex.InnerException is TimeoutException)
        {
            logger.BackendCallFailed(request.Method, logUrl, ex);
            RecordBackendError(activity, stopwatch, serviceName, 504, "Request timed out", ex);
            return SendResult.Timeout("Request timed out");
        }
        catch (HttpRequestException ex)
        {
            logger.BackendCallFailed(request.Method, logUrl, ex);
            RecordBackendError(activity, stopwatch, serviceName, 502, "Backend service unavailable", ex);
            return SendResult.NetworkError("Backend service unavailable");
        }
        catch (Exception ex)
        {
            logger.BackendCallFailed(request.Method, logUrl, ex);
            RecordBackendError(activity, stopwatch, serviceName, 500, "An unexpected error occurred", ex);
            return SendResult.UnknownError("An unexpected error occurred");
        }
    }

    private async Task<SendResult?> ApplyBackendAuthAsync(
        HttpRequestMessage httpRequest,
        BackendRequest request,
        string? accessToken,
        bool forceFreshCredential,
        Activity? activity,
        Stopwatch stopwatch,
        string serviceName,
        CancellationToken cancellationToken)
    {
        // Token exchange is dispatched through the registry like every other policy.
        // Honour callers that set UseTokenExchange directly without a policy string.
        var policyExplicit = !string.IsNullOrEmpty(request.BackendAuthPolicy);
        var policy = ResolveEffectivePolicy(request);

        // Defense-in-depth trusted-host gate. The endpoint builders validate the destination against
        // PortaCore:TrustedHosts at startup, but a transformer that hand-builds a BackendRequest can
        // reach here with a user-identity policy (BearerToken/TokenExchange) pointed at any host. Before
        // a user-derived token is attached, re-check the (already-interpolated) destination and fail
        // closed if it is not trusted - never forward the token to a host the operator didn't allow-list.
        if (BackendAuthPolicies.RequiresUserIdentity(policy)
            && trustedHostValidator is not null
            && !trustedHostValidator.IsTrusted(request.Url))
        {
            logger.BackendAuthError(
                request.Method,
                SanitizeUrl(request.Url),
                $"Refusing to forward user token for policy '{policy}': destination host is not in PortaCore:TrustedHosts.");
            RecordBackendError(activity, stopwatch, serviceName, 502, "Untrusted backend host");
            return SendResult.NetworkError("Backend host is not trusted for user-token forwarding");
        }

        var handler = authHandlerRegistry.GetHandler(policy);

        if (handler == null)
        {
            // An explicit policy that doesn't resolve is a configuration error.
            // Fail closed rather than silently forwarding the user's bearer token to
            // a backend the developer never authorized.
            if (policyExplicit)
            {
                logger.BackendAuthError(
                    request.Method,
                    SanitizeUrl(request.Url),
                    $"Unknown backend auth policy '{policy}'. Registered policies: [{string.Join(", ", authHandlerRegistry.GetRegisteredPolicies())}]");
                RecordBackendError(activity, stopwatch, serviceName, 500, "Unknown backend auth policy");
                return SendResult.ConfigurationError($"Unknown backend auth policy '{policy}'");
            }

            logger.LogWarning("No auth handler found for policy '{Policy}', using None", policy);
            handler = authHandlerRegistry.GetHandler(BackendAuthPolicies.None);
        }

        if (handler != null)
        {
            var authContext = new BackendAuthContext
            {
                AccessToken = accessToken,
                Claims = GetUserClaims(),
                BackendRequest = request,
                // Thread the request's cancellation through. Token-exchange handlers do an STS
                // round-trip here; with CancellationToken.None a hung token endpoint ignored the
                // request deadline entirely.
                CancellationToken = cancellationToken,
                ForceFreshCredential = forceFreshCredential
            };

            try
            {
                await handler.ApplyAuthAsync(httpRequest, authContext);
                logger.AppliedBackendAuthPolicy(policy);
            }
            catch (BackendAuthConfigurationException ex)
            {
                // Server-side misconfiguration (e.g. token exchange with no audience, or
                // IApiTokenService not registered) - a 5xx-class operator problem, NOT a user
                // credential rejection. Mapping it to 401 would send on-call chasing the user.
                logger.BackendAuthError(request.Method, SanitizeUrl(request.Url), ex.Message);
                RecordBackendError(activity, stopwatch, serviceName, 500, "Backend auth misconfigured", ex);
                return SendResult.ConfigurationError($"Backend auth misconfigured: {ex.Message}");
            }
            catch (Exception ex)
            {
                // Generic client-facing message: the exception detail is logged above but can
                // describe IdP/token-exchange internals, so it must never reach the client.
                logger.BackendAuthError(request.Method, SanitizeUrl(request.Url), ex.Message);
                RecordBackendError(activity, stopwatch, serviceName, 401, "Authentication failed");
                return SendResult.AuthError("Backend authentication failed");
            }
        }

        return null; // No error
    }

    /// <summary>
    /// Snapshots the authenticated user's claims for <see cref="BackendAuthContext.Claims"/>.
    /// Empty when there is no authenticated user or the host did not register
    /// <see cref="IHttpContextAccessor"/>; first value wins for repeated claim types.
    /// </summary>
    private IReadOnlyDictionary<string, string> GetUserClaims()
    {
        var user = httpContextAccessor?.HttpContext?.User;
        if (user?.Identity?.IsAuthenticated != true)
        {
            return new Dictionary<string, string>();
        }

        var claims = new Dictionary<string, string>();
        foreach (var claim in user.Claims)
        {
            claims.TryAdd(claim.Type, claim.Value);
        }

        return claims;
    }

    /// <summary>
    /// Maps a failed <see cref="SendResult"/> (auth-handler failure, timeout, network or config
    /// error - no backend HTTP response exists) through the configured <see cref="IBackendErrorMapper"/>
    /// before it becomes a client-visible status. Without this, an auth-handler exception surfaced
    /// as a synthetic 401 would bypass the mapper - which otherwise only sees real backend
    /// responses - and a BFF credential problem would sign the user out (the exact failure mode
    /// the default 401 -&gt; 502 mapping exists to prevent). The raw paths (<c>CallRawAsync</c>)
    /// stay unmapped; <c>RawForwardEndpointBuilder</c> applies the mapper itself.
    /// </summary>
    private (int StatusCode, string Message, BackendErrorType ErrorType) MapSendFailure(SendResult sendResult, BackendRequest request)
    {
        var (mappedStatus, mappedMessage) = _errorMapper.MapError(sendResult.StatusCode, sendResult.Error, request);
        // The mapped status is the client-visible code; the error type keeps describing what
        // actually went wrong (AuthenticationError, Timeout, NetworkError, ConfigurationError, ...)
        // so callers can branch on the real cause even when the default mapper neutralizes an
        // auth-stage 401 to 502. No downstream conversion derives a status from the error type
        // (GraphQLResult.ToBackendResult surfaces MappedStatusCode for exactly that reason), so
        // keeping the unmapped type cannot resurrect a neutralized status.
        return (mappedStatus, mappedMessage, sendResult.ErrorType);
    }

    /// <summary>
    /// Classifies the ORIGINAL backend status - before the <see cref="IBackendErrorMapper"/>
    /// rewrites it - so <see cref="BackendErrorType"/> keeps describing what the backend actually
    /// did: a real backend 401 stays <see cref="BackendErrorType.AuthenticationError"/> even when
    /// the default mapper surfaces it as 502, and a mapped 502 can't masquerade as a backend
    /// <see cref="BackendErrorType.ServerError"/>.
    /// </summary>
    private static BackendErrorType ClassifyBackendStatus(int statusCode) => statusCode switch
    {
        401 => BackendErrorType.AuthenticationError,
        403 => BackendErrorType.AuthorizationError,
        >= 400 and < 500 => BackendErrorType.ClientError,
        >= 500 => BackendErrorType.ServerError,
        _ => BackendErrorType.Unknown
    };

    private BackendResult MapHttpErrorToResult(HttpResponseMessage response, BackendRequest request)
    {
        var statusCode = (int)response.StatusCode;
        var error = response.ReasonPhrase ?? "Request failed";

        // Run the configured IBackendErrorMapper first. The default maps backend 401/403 to
        // 502 Bad Gateway so the client UI doesn't sign the user out when *backend* credentials
        // are wrong (vs. *user* credentials being wrong). Custom mappers can override per route.
        // The error type is classified from the ORIGINAL status so it keeps naming the real
        // failure (a remapped backend 401 stays AuthenticationError, surfaced as 502).
        var (mappedStatus, mappedMessage) = _errorMapper.MapError(statusCode, error, request);
        return BackendResult.Failure(mappedStatus, mappedMessage, ClassifyBackendStatus(statusCode));
    }

    private GraphQLResult<TResponse> MapHttpErrorToGraphQLResult<TResponse>(int statusCode, string? reasonPhrase, BackendRequest request)
    {
        var error = reasonPhrase ?? "Request failed";

        // Same mapping the typed paths use (see MapHttpErrorToResult / DeserializeResponseAsync):
        // the default IBackendErrorMapper maps backend 401/403 to 502 so a *backend* credential
        // failure doesn't surface as a 401 and sign the user out. The error type is classified
        // from the ORIGINAL status; ToBackendResult surfaces MappedStatusCode (never a status
        // derived from the error type), so the unmapped 401 cannot resurface client-side.
        var (mappedStatus, mappedMessage) = _errorMapper.MapError(statusCode, error, request);
        return GraphQLResult<TResponse>.FromBackendError(mappedStatus, mappedMessage, ClassifyBackendStatus(statusCode));
    }

    private async Task<SendResult> SendRequestAsync<TRequest>(
        BackendRequest request,
        TRequest? body,
        CancellationToken cancellationToken)
    {
        // Telemetry (span + stopwatch) is owned per-attempt inside AttemptSendAsync, so the
        // refresh-on-401 retry gets its own span/timing instead of overwriting the first attempt's.

        // Refresh-on-401 (default on; opt out via PortaCore:RefreshBackendTokenOn401). Only for
        // user-token policies (BearerToken/TokenExchange) - refreshing the session token cannot help
        // BasicAuth/None backends - and only when a refresh service and request context are available.
        var httpContext = httpContextAccessor?.HttpContext;
        if (_refreshOn401Enabled
            && BackendAuthPolicies.RequiresUserIdentity(ResolveEffectivePolicy(request))
            && accessTokenRefresh is not null
            && httpContext is not null)
        {
            return await SendWithRefreshOn401Async(request, body, httpContext, cancellationToken);
        }

        // Mint-fresh-on-401 for the BFF's own client-credentials identity (same opt-out flag).
        // The cached M2M token may have been revoked or its signing keys rotated; the retry runs
        // the auth handler with ForceFreshCredential so it bypasses the token cache. No user
        // session is involved, so this needs neither a refresh service nor an HttpContext.
        if (_refreshOn401Enabled
            && string.Equals(ResolveEffectivePolicy(request), BackendAuthPolicies.ClientCredentials, StringComparison.Ordinal))
        {
            return await SendWithClientCredentialsRetryOn401Async(request, body, cancellationToken);
        }

        return await AttemptSendAsync(request, body, request.AccessToken, cancellationToken);
    }

    /// <summary>
    /// Sends once; on a raw backend <c>401</c> retries exactly once with
    /// <see cref="BackendAuthContext.ForceFreshCredential"/> set, so the ClientCredentials handler
    /// discards its cached token and mints a fresh one. A second <c>401</c> is surfaced unchanged -
    /// the fresh token being rejected means the problem is not staleness.
    /// </summary>
    private async Task<SendResult> SendWithClientCredentialsRetryOn401Async<TRequest>(
        BackendRequest request,
        TRequest? body,
        CancellationToken cancellationToken)
    {
        var result = await AttemptSendAsync(request, body, request.AccessToken, cancellationToken);

        if (!IsRawUnauthorized(result))
        {
            return result;
        }

        // The first 401 response is no longer needed; release it before re-sending.
        result.Response?.Dispose();
        logger.BackendMintingFreshClientCredentialsOn401(request.Method, SanitizeUrl(request.Url));
        return await AttemptSendAsync(request, body, request.AccessToken, cancellationToken, isRefreshRetry: true);
    }

    /// <summary>
    /// Sends once; on a raw backend <c>401</c> refreshes the user's access token and retries exactly
    /// once with the rotated token. The retry is skipped when the token does not actually rotate
    /// (no refreshable session, refresh failed, or a sibling leg already consumed this stale token),
    /// so a non-refreshable inbound auth (e.g. inbound JWT / reference token) surfaces the 401
    /// immediately with no wasted round and no loop.
    /// </summary>
    private async Task<SendResult> SendWithRefreshOn401Async<TRequest>(
        BackendRequest request,
        TRequest? body,
        HttpContext httpContext,
        CancellationToken cancellationToken)
    {
        var staleToken = request.AccessToken;
        var result = await AttemptSendAsync(request, body, staleToken, cancellationToken);

        if (!IsRawUnauthorized(result))
        {
            return result;
        }

        var refreshed = await RefreshUserTokenAsync(httpContext, staleToken, cancellationToken);
        if (refreshed is null || string.Equals(refreshed, staleToken, StringComparison.Ordinal))
        {
            // No rotation -> retrying with the same token would just 401 again.
            return result;
        }

        // The first 401 response is no longer needed; release it before re-sending.
        result.Response?.Dispose();
        logger.BackendRefreshingOn401(request.Method, SanitizeUrl(request.Url));
        return await AttemptSendAsync(request, body, refreshed, cancellationToken, isRefreshRetry: true);
    }

    /// <summary>
    /// Refreshes the user's access token under a per-request gate, returning the rotated token (or
    /// <c>null</c> when refresh is not possible). Serialises all <see cref="HttpContext"/> access
    /// across the parallel legs of an aggregation and caches the outcome in-memory keyed by the stale
    /// token, so concurrent 401s trigger exactly one IdP refresh and one cookie rewrite. The in-memory
    /// cache is also why siblings don't re-read via <c>AuthenticateAsync</c>, which would not observe a
    /// same-request <c>SignInAsync</c> and would refresh again with the already-consumed refresh token.
    /// </summary>
    private async Task<string?> RefreshUserTokenAsync(HttpContext httpContext, string? staleToken, CancellationToken cancellationToken)
    {
        await _refreshGate.WaitAsync(cancellationToken);
        try
        {
            // A sibling leg already attempted refresh for this exact stale token: reuse its outcome
            // (rotated token, or null if that attempt failed) without a second IdP round-trip.
            if (_refreshAttempted && string.Equals(staleToken, _consumedStaleToken, StringComparison.Ordinal))
            {
                return _rotatedToken;
            }

            var refreshed = await accessTokenRefresh!.ForceRefreshAsync(httpContext, staleToken);
            _consumedStaleToken = staleToken;
            _rotatedToken = refreshed;
            _refreshAttempted = true;
            return refreshed;
        }
        finally
        {
            _refreshGate.Release();
        }
    }

    private static bool IsRawUnauthorized(SendResult result)
        => result.IsSuccess && result.Response is { StatusCode: HttpStatusCode.Unauthorized };

    // The effective backend-auth policy: an explicit policy string wins, otherwise UseTokenExchange
    // selects TokenExchange and the fall-through is None. Shared by the auth-application and the
    // refresh-on-401 eligibility check so the two never disagree.
    private static string ResolveEffectivePolicy(BackendRequest request)
        => request.BackendAuthPolicy
            ?? (request.UseTokenExchange ? BackendAuthPolicies.TokenExchange : BackendAuthPolicies.None);

    /// <summary>
    /// Releases the per-request refresh gate used to serialize the refresh-on-401 path.
    /// </summary>
    public void Dispose() => _refreshGate.Dispose();

    /// <summary>
    /// Builds and sends a single backend request with the given <paramref name="accessToken"/>,
    /// mapping the outcome to a <see cref="SendResult"/>. Rebuilt per attempt so the refresh-on-401
    /// retry re-serializes the body and re-applies auth with a rotated token. Each attempt owns its
    /// own child span and stopwatch so the retry's timing/status never overwrites the first attempt's.
    /// </summary>
    private async Task<SendResult> AttemptSendAsync<TRequest>(
        BackendRequest request,
        TRequest? body,
        string? accessToken,
        CancellationToken cancellationToken,
        bool isRefreshRetry = false)
    {
        var serviceName = ExtractServiceName(request.Url);
        // Logs get the same query-stripped URL as spans - query strings can carry tokens/API keys.
        var logUrl = SanitizeUrl(request.Url);

        // Per-attempt span + stopwatch. Sharing one of each across the refresh-on-401 retry froze
        // the stopwatch at the first attempt's duration and let the retry's 200 overwrite the first
        // attempt's 401 on a single span, erasing the refresh from the trace.
        // Fixed category activity name; the specific backend is carried on the
        // bff.backend.service tag (set below) so span cardinality stays bounded.
        using var activity = _enableTelemetry
            ? PortaActivitySource.Source.StartActivity(
                PortaActivitySource.Activities.BackendCall,
                ActivityKind.Client)
            : null;

        var stopwatch = Stopwatch.StartNew();

        activity?.SetTag(PortaActivitySource.Tags.Component, "backend");
        activity?.SetTag(PortaActivitySource.Tags.BackendService, serviceName);
        activity?.SetTag(PortaActivitySource.Tags.HttpMethod, request.Method);
        activity?.SetTag(PortaActivitySource.Tags.HttpUrl, logUrl);
        activity?.SetTag(PortaActivitySource.Tags.BackendProtocol, "http");
        activity?.SetTag("bff.backend.refresh_retry", isRefreshRetry);

        // Select the appropriate HttpClient based on retry settings
        var clientName = request.EnableRetries ? HttpClientNameWithRetries : HttpClientName;
        var httpClient = httpClientFactory.CreateClient(clientName);

        if (request.Timeout.HasValue)
        {
            httpClient.Timeout = request.Timeout.Value;
        }

        var httpRequest = new HttpRequestMessage(new HttpMethod(request.Method), request.Url);

        // Thread the per-endpoint retry budget onto the request so the retry pipeline's ShouldHandle
        // gate spends exactly WithRetries(n) attempts (clamped to the app-wide ceiling) instead of
        // the global count. No-op on the non-retry client, which ignores the option.
        if (request.EnableRetries)
        {
            httpRequest.Options.Set(RetryBudgetOption, request.MaxRetryAttempts);
        }

        // Note: W3C Trace Context headers (traceparent/tracestate) are automatically propagated
        // by AddHttpClientInstrumentation() configured in ServiceDefaults. No manual injection needed.

        // Add custom headers
        if (request.Headers != null)
        {
            foreach (var (key, value) in request.Headers)
            {
                httpRequest.Headers.TryAddWithoutValidation(key, value);
            }
        }

        // Apply backend authentication using the auth handler registry. A refresh retry also
        // flags ForceFreshCredential so self-caching handlers (ClientCredentials) re-mint.
        var authResult = await ApplyBackendAuthAsync(
            httpRequest, request, accessToken, forceFreshCredential: isRefreshRetry,
            activity, stopwatch, serviceName, cancellationToken);
        if (authResult != null)
        {
            return authResult.Value;
        }

        // Serialize body if present, using the configured request content type.
        // GraphQL paths force-serialize as JSON via the GraphQLRequest envelope and rely on JSON below;
        // CallGraphQLAsync sets up its own request shape, so the RequestContentType from the public API
        // applies to the standard CallAsync flows where the field is meaningful.
        if (body != null)
        {
            string serialized;
            string mediaType;
            if (body is GraphQLRequest)
            {
                // GraphQL is always JSON, regardless of RequestContentType
                serialized = JsonSerializer.Serialize(body, JsonOptions);
                mediaType = ContentTypes.Json;
            }
            else
            {
                serialized = contentSerializer.Serialize(body, body.GetType(), request.RequestContentType);
                mediaType = request.RequestContentType.ToMediaType();
            }
            httpRequest.Content = new StringContent(serialized, Encoding.UTF8, mediaType);
        }

        logger.BackendCallStarting(request.Method, logUrl);

        try
        {
            // ResponseHeadersRead so the bounded reader (ReadBoundedResponseStringAsync) can enforce
            // the size cap BEFORE the whole body is buffered - matching the raw path. The body stream
            // and its connection stay open until the response is disposed, which the public Call*
            // methods now guarantee via `using`.
            var response = await httpClient.SendAsync(httpRequest, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            var statusCode = (int)response.StatusCode;

            logger.BackendCallCompleted(request.Method, logUrl, statusCode);

            // Record telemetry
            stopwatch.Stop();
            activity?.SetTag(PortaActivitySource.Tags.HttpStatusCode, statusCode);
            activity?.SetStatus(response.IsSuccessStatusCode ? ActivityStatusCode.Ok : ActivityStatusCode.Error);

            _metrics?.RecordBackendRequest(serviceName, "http", statusCode);
            _metrics?.RecordBackendCallDuration(stopwatch.Elapsed.TotalMilliseconds, serviceName, "http");

            return SendResult.Ok(response);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // Genuine caller cancellation (client disconnect or a global request timeout) is not
            // a backend fault. Propagate it so the request actually aborts, instead of laundering
            // it into a 500/504 SendResult that downstream aggregation reads as a degraded backend.
            // The HttpClient.Timeout path below is a TaskCanceledException whose token is NOT this
            // one, so genuine per-request timeouts still map to a 504.
            throw;
        }
        catch (TaskCanceledException ex) when (ex.InnerException is TimeoutException)
        {
            logger.BackendCallFailed(request.Method, logUrl, ex);
            RecordBackendError(activity, stopwatch, serviceName, 504, "Request timed out", ex);
            return SendResult.Timeout("Request timed out");
        }
        catch (HttpRequestException ex)
        {
            logger.BackendCallFailed(request.Method, logUrl, ex);
            RecordBackendError(activity, stopwatch, serviceName, 502, "Backend service unavailable", ex);
            return SendResult.NetworkError("Backend service unavailable");
        }
        catch (Exception ex)
        {
            logger.BackendCallFailed(request.Method, logUrl, ex);
            RecordBackendError(activity, stopwatch, serviceName, 500, "An unexpected error occurred", ex);
            return SendResult.UnknownError("An unexpected error occurred");
        }
    }

    private void RecordBackendError(Activity? activity, Stopwatch stopwatch, string serviceName, int statusCode, string errorMessage, Exception? ex = null)
    {
        stopwatch.Stop();
        activity?.SetStatus(ActivityStatusCode.Error, errorMessage);
        activity?.SetTag(PortaActivitySource.Tags.HttpStatusCode, statusCode);
        activity?.SetTag(PortaActivitySource.Tags.ErrorMessage, errorMessage);
        if (ex != null)
        {
            activity?.SetTag(PortaActivitySource.Tags.ErrorType, ex.GetType().Name);
            // Stack trace is recorded as an event attribute (OTel semantic conventions),
            // not as a span tag - avoids high cardinality and potential PII in tags.
            activity?.AddException(ex);
        }

        _metrics?.RecordBackendRequest(serviceName, "http", statusCode);
        _metrics?.RecordBackendCallDuration(stopwatch.Elapsed.TotalMilliseconds, serviceName, "http");
    }

    private static string ExtractServiceName(string url)
    {
        try
        {
            var uri = new Uri(url);
            // Use the host as service name, or the first path segment for localhost
            if (uri.Host is "localhost" or "127.0.0.1")
            {
                var segments = uri.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
                return segments.Length > 0 ? segments[0] : "localhost";
            }
            return uri.Host;
        }
        catch
        {
            return "unknown";
        }
    }

    // Strip query strings and fragments so secrets passed as query parameters
    // (e.g. tokens, API keys) don't leak into OpenTelemetry exporters or logs.
    private static string SanitizeUrl(string url)
    {
        try
        {
            var uri = new Uri(url);
            return uri.GetLeftPart(UriPartial.Path);
        }
        catch
        {
            var queryIndex = url.IndexOf('?');
            var fragmentIndex = url.IndexOf('#');
            var cut = queryIndex >= 0 && fragmentIndex >= 0
                ? Math.Min(queryIndex, fragmentIndex)
                : Math.Max(queryIndex, fragmentIndex);
            return cut >= 0 ? url[..cut] : url;
        }
    }

    private readonly struct SendResult
    {
        public bool IsSuccess { get; }
        public HttpResponseMessage? Response { get; }
        public int StatusCode { get; }
        public string? Error { get; }
        public BackendErrorType ErrorType { get; }

        private SendResult(bool isSuccess, HttpResponseMessage? response, int statusCode, string? error, BackendErrorType errorType)
        {
            IsSuccess = isSuccess;
            Response = response;
            StatusCode = statusCode;
            Error = error;
            ErrorType = errorType;
        }

        public static SendResult Ok(HttpResponseMessage response) => new(true, response, (int)response.StatusCode, null, BackendErrorType.None);
        public static SendResult AuthError(string error) => new(false, null, 401, error, BackendErrorType.AuthenticationError);
        public static SendResult ConfigurationError(string error) => new(false, null, 500, error, BackendErrorType.ConfigurationError);
        public static SendResult NetworkError(string error) => new(false, null, 502, error, BackendErrorType.NetworkError);
        public static SendResult Timeout(string error) => new(false, null, 504, error, BackendErrorType.Timeout);
        public static SendResult UnknownError(string error) => new(false, null, 500, error, BackendErrorType.Unknown);
    }

    private async Task<BackendResult<TResponse>> DeserializeResponseAsync<TResponse>(
        HttpResponseMessage response,
        BackendRequest request,
        CancellationToken cancellationToken)
    {
        var url = SanitizeUrl(request.Url);
        var statusCode = (int)response.StatusCode;

        if (!response.IsSuccessStatusCode)
        {
            var error = response.ReasonPhrase ?? "Request failed";
            // Error-path body is best-effort: capped to avoid the same OOM, but on overflow we
            // just log without the body rather than rewriting the upstream error to "too large".
            var responseBody = await ReadBoundedResponseStringAsync(response, cancellationToken) ?? string.Empty;
            logger.BackendErrorResponseMeta(url, statusCode, error, responseBody.Length, response.Content.Headers.ContentType?.ToString());
            var loggedErrorBody = PrepareBodyForLog(responseBody);
            if (loggedErrorBody != null)
            {
                logger.BackendErrorResponseBody(url, statusCode, error, loggedErrorBody);
            }

            // Defer to the configured IBackendErrorMapper for 401/403 -> 502 (or whatever
            // policy the consumer registered). This keeps every non-success path consistent.
            // The error type is classified from the ORIGINAL status (see ClassifyBackendStatus).
            var (mappedStatus, mappedMessage) = _errorMapper.MapError(statusCode, error, request);
            return BackendResult<TResponse>.Failure(mappedStatus, mappedMessage, ClassifyBackendStatus(statusCode));
        }

        var content = await ReadBoundedResponseStringAsync(response, cancellationToken);
        if (content == null)
        {
            logger.BackendResponseTooLarge(url, statusCode, _maxBackendResponseBytes);
            return BackendResult<TResponse>.Failure(statusCode, "Backend response exceeds maximum allowed size", BackendErrorType.InvalidResponse);
        }

        logger.BackendResponseMeta(url, statusCode, content.Length, response.Content.Headers.ContentType?.ToString());
        var loggedBody = PrepareBodyForLog(content);
        if (loggedBody != null)
        {
            logger.BackendResponseBody(url, statusCode, loggedBody);
        }

        if (string.IsNullOrWhiteSpace(content))
        {
            return BackendResult<TResponse>.Success(default!, statusCode);
        }

        var responseContentType = ContentTypes.FromMediaType(response.Content.Headers.ContentType?.MediaType);

        // Identical control flow in Debug and Release: a malformed body always maps to
        // InvalidResponse. (Previously Debug let the exception propagate, so the catch/mapping
        // below was never exercised by the test suite - the one place it most needed to be.)
        try
        {
            var result = (TResponse)contentSerializer.Deserialize(content, typeof(TResponse), responseContentType)!;
            return BackendResult<TResponse>.Success(result, statusCode);
        }
        catch (Exception ex) when (ex is JsonException or System.Xml.XmlException or InvalidOperationException)
        {
            logger.BackendDeserializationFailed(url, statusCode, content.Length, ex);
            var loggedFailedBody = PrepareBodyForLog(content);
            if (loggedFailedBody != null)
            {
                logger.BackendDeserializationFailedBody(url, statusCode, loggedFailedBody);
            }
            return BackendResult<TResponse>.Failure(statusCode, $"Invalid response format: {ex.Message}", BackendErrorType.InvalidResponse);
        }
    }

    private async Task<BackendObjectResult> DeserializeResponseAsObjectAsync(
        HttpResponseMessage response,
        BackendRequest request,
        Type responseType,
        CancellationToken cancellationToken)
    {
        var url = SanitizeUrl(request.Url);
        var statusCode = (int)response.StatusCode;

        if (!response.IsSuccessStatusCode)
        {
            var error = response.ReasonPhrase ?? "Request failed";
            var responseBody = await ReadBoundedResponseStringAsync(response, cancellationToken) ?? string.Empty;
            logger.BackendErrorResponseMeta(url, statusCode, error, responseBody.Length, response.Content.Headers.ContentType?.ToString());
            var loggedErrorBody = PrepareBodyForLog(responseBody);
            if (loggedErrorBody != null)
            {
                logger.BackendErrorResponseBody(url, statusCode, error, loggedErrorBody);
            }

            var (mappedStatus, mappedMessage) = _errorMapper.MapError(statusCode, error, request);
            return BackendObjectResult.Failure(mappedStatus, mappedMessage, ClassifyBackendStatus(statusCode));
        }

        var content = await ReadBoundedResponseStringAsync(response, cancellationToken);
        if (content == null)
        {
            logger.BackendResponseTooLarge(url, statusCode, _maxBackendResponseBytes);
            return BackendObjectResult.Failure(statusCode, "Backend response exceeds maximum allowed size", BackendErrorType.InvalidResponse);
        }

        logger.BackendResponseMeta(url, statusCode, content.Length, response.Content.Headers.ContentType?.ToString());
        var loggedBody = PrepareBodyForLog(content);
        if (loggedBody != null)
        {
            logger.BackendResponseBody(url, statusCode, loggedBody);
        }

        if (string.IsNullOrWhiteSpace(content))
        {
            return BackendObjectResult.Success(null, statusCode);
        }

        var responseContentType = ContentTypes.FromMediaType(response.Content.Headers.ContentType?.MediaType);

        // Identical control flow in Debug and Release - see DeserializeResponseAsync.
        try
        {
            var result = contentSerializer.Deserialize(content, responseType, responseContentType);
            return BackendObjectResult.Success(result, statusCode);
        }
        catch (Exception ex) when (ex is JsonException or System.Xml.XmlException or InvalidOperationException)
        {
            logger.BackendDeserializationFailed(url, statusCode, content.Length, ex);
            var loggedFailedBody = PrepareBodyForLog(content);
            if (loggedFailedBody != null)
            {
                logger.BackendDeserializationFailedBody(url, statusCode, loggedFailedBody);
            }
            return BackendObjectResult.Failure(statusCode, $"Invalid response format: {ex.Message}", BackendErrorType.InvalidResponse);
        }
    }
}

/// <summary>
/// High-performance logging for BackendCaller.
/// </summary>
internal static partial class BackendCallerLogging
{
    [LoggerMessage(EventId = 14000, Level = LogLevel.Debug,
        Message = "Backend call starting: {Method} {Url}")]
    public static partial void BackendCallStarting(this ILogger logger, string method, string url);

    [LoggerMessage(EventId = 14001, Level = LogLevel.Debug,
        Message = "Backend call completed: {Method} {Url} - Status: {StatusCode}")]
    public static partial void BackendCallCompleted(this ILogger logger, string method, string url, int statusCode);

    [LoggerMessage(EventId = 14002, Level = LogLevel.Error,
        Message = "Backend call failed: {Method} {Url}")]
    public static partial void BackendCallFailed(this ILogger logger, string method, string url, Exception ex);

    [LoggerMessage(EventId = 14003, Level = LogLevel.Error,
        Message = "Backend call failed: {Method} {Url} - {Reason}")]
    public static partial void BackendCallFailed(this ILogger logger, string method, string url, string reason);

    [LoggerMessage(EventId = 14004, Level = LogLevel.Error,
        Message = "Backend authentication error: {Method} {Url} - {Reason}")]
    public static partial void BackendAuthError(this ILogger logger, string method, string url, string reason);

    [LoggerMessage(EventId = 14005, Level = LogLevel.Warning,
        Message = "Backend error response: {Url} - {StatusCode} {Reason} - BodySize: {BodySize} bytes, ContentType: {ContentType}")]
    public static partial void BackendErrorResponseMeta(this ILogger logger, string url, int statusCode, string reason, int bodySize, string? contentType);

    [LoggerMessage(EventId = 14015, Level = LogLevel.Trace,
        Message = "Backend error response body: {Url} - {StatusCode} {Reason} - Body: {ResponseBody}")]
    public static partial void BackendErrorResponseBody(this ILogger logger, string url, int statusCode, string reason, string responseBody);

    [LoggerMessage(EventId = 14006, Level = LogLevel.Error,
        Message = "Backend response deserialization failed: {Url} - {StatusCode} - BodySize: {BodySize} bytes")]
    public static partial void BackendDeserializationFailed(this ILogger logger, string url, int statusCode, int bodySize, Exception ex);

    [LoggerMessage(EventId = 14016, Level = LogLevel.Trace,
        Message = "Backend response deserialization failed body: {Url} - {StatusCode} - Body: {ResponseBody}")]
    public static partial void BackendDeserializationFailedBody(this ILogger logger, string url, int statusCode, string responseBody);

    [LoggerMessage(EventId = 14007, Level = LogLevel.Debug,
        Message = "Backend response: {Url} - {StatusCode} - BodySize: {BodySize} bytes, ContentType: {ContentType}")]
    public static partial void BackendResponseMeta(this ILogger logger, string url, int statusCode, int bodySize, string? contentType);

    [LoggerMessage(EventId = 14017, Level = LogLevel.Trace,
        Message = "Backend response body: {Url} - {StatusCode} - Body: {ResponseBody}")]
    public static partial void BackendResponseBody(this ILogger logger, string url, int statusCode, string responseBody);

    [LoggerMessage(EventId = 14008, Level = LogLevel.Warning,
        Message = "GraphQL errors received: {Url} - {ErrorCount} errors: {Errors}")]
    public static partial void GraphQLErrorsReceived(this ILogger logger, string url, int errorCount, string errors);

    [LoggerMessage(EventId = 14009, Level = LogLevel.Debug,
        Message = "Applied backend auth policy: {Policy}")]
    public static partial void AppliedBackendAuthPolicy(this ILogger logger, string policy);

    [LoggerMessage(EventId = 14010, Level = LogLevel.Warning,
        Message = "Backend response rejected: {Url} - {StatusCode} - body exceeds MaxBackendResponseBytes={MaxBytes}")]
    public static partial void BackendResponseTooLarge(this ILogger logger, string url, int statusCode, long maxBytes);

    [LoggerMessage(EventId = 14011, Level = LogLevel.Debug,
        Message = "Backend returned 401; refreshing user token and retrying once: {Method} {Url}")]
    public static partial void BackendRefreshingOn401(this ILogger logger, string method, string url);

    [LoggerMessage(EventId = 14012, Level = LogLevel.Debug,
        Message = "Backend returned 401; minting fresh client-credentials token and retrying once: {Method} {Url}")]
    public static partial void BackendMintingFreshClientCredentialsOn401(this ILogger logger, string method, string url);
}
