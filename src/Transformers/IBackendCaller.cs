namespace b17s.Porta.Transformers;

/// <summary>
/// Service for calling backend APIs with automatic token forwarding and resilience.
/// Supports both Kubernetes service names and external URLs.
/// </summary>
public interface IBackendCaller
{
    /// <summary>
    /// Calls a backend service with the specified request.
    /// </summary>
    /// <typeparam name="TResponse">The expected response type</typeparam>
    /// <param name="request">The request configuration</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>The result containing either the response or error information</returns>
    Task<BackendResult<TResponse>> CallAsync<TResponse>(BackendRequest request, CancellationToken cancellationToken);

    /// <summary>
    /// Calls a backend service with a request body.
    /// </summary>
    /// <typeparam name="TRequest">The request body type</typeparam>
    /// <typeparam name="TResponse">The expected response type</typeparam>
    /// <param name="request">The request configuration</param>
    /// <param name="body">The request body to serialize</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>The result containing either the response or error information</returns>
    Task<BackendResult<TResponse>> CallAsync<TRequest, TResponse>(BackendRequest request, TRequest body, CancellationToken cancellationToken);

    /// <summary>
    /// Calls a backend service without expecting a response body (204 No Content).
    /// </summary>
    /// <param name="request">The request configuration</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>The result indicating success or failure</returns>
    Task<BackendResult> CallAsync(BackendRequest request, CancellationToken cancellationToken);

    /// <summary>
    /// Calls a backend service with a request body, no response expected.
    /// </summary>
    /// <typeparam name="TRequest">The request body type</typeparam>
    /// <param name="request">The request configuration</param>
    /// <param name="body">The request body to serialize</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>The result indicating success or failure</returns>
    Task<BackendResult> CallAsync<TRequest>(BackendRequest request, TRequest body, CancellationToken cancellationToken);

    /// <summary>
    /// Calls a backend service with runtime type information (for declarative transformers).
    /// </summary>
    /// <param name="request">The request configuration</param>
    /// <param name="responseType">The expected response type</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>The result containing either the response object or error information</returns>
    Task<BackendObjectResult> CallAsync(BackendRequest request, Type responseType, CancellationToken cancellationToken);

    /// <summary>
    /// Calls a backend service with a request body using runtime type information (for declarative transformers).
    /// </summary>
    /// <param name="request">The request configuration</param>
    /// <param name="body">The request body to serialize</param>
    /// <param name="responseType">The expected response type</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>The result containing either the response object or error information</returns>
    Task<BackendObjectResult> CallWithBodyAsync(BackendRequest request, object body, Type responseType, CancellationToken cancellationToken);

    /// <summary>
    /// Calls a GraphQL backend with the specified query and variables.
    /// Handles GraphQL-specific request/response formatting and error extraction.
    /// </summary>
    /// <typeparam name="TResponse">The expected response type (extracted from data.{dataPath})</typeparam>
    /// <param name="request">The request configuration (URL should point to GraphQL endpoint)</param>
    /// <param name="query">The GraphQL query string</param>
    /// <param name="variables">Optional variables for the query</param>
    /// <param name="dataPath">Path to extract data from response (e.g., "product", "user.orders")</param>
    /// <param name="operationName">Optional operation name when query contains multiple operations</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>The result containing either the extracted data or error information</returns>
    /// <example>
    /// var result = await backendCaller.CallGraphQLAsync&lt;Product&gt;(
    ///     request,
    ///     "query GetProduct($id: ID!) { product(id: $id) { id name price } }",
    ///     new { id = "123" },
    ///     dataPath: "product",
    ///     cancellationToken: ct
    /// );
    /// </example>
    Task<GraphQLResult<TResponse>> CallGraphQLAsync<TResponse>(
        BackendRequest request,
        string query,
        object? variables,
        string dataPath,
        string? operationName = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Calls a backend service and returns the raw HTTP response without parsing.
    /// Use this for streaming binary content, file downloads, or non-JSON responses.
    /// </summary>
    /// <param name="request">The request configuration</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>
    /// A <see cref="RawBackendResult"/> containing the raw HTTP response.
    /// The caller is responsible for disposing the result when done.
    /// </returns>
    /// <remarks>
    /// Unlike other CallAsync methods, this does not parse the response body.
    /// The response can be streamed directly to the client using:
    /// <code>
    /// var result = await backendCaller.CallRawAsync(request, ct);
    /// if (result.IsSuccess)
    /// {
    ///     context.Response.StatusCode = result.StatusCode;
    ///     context.Response.ContentType = result.ContentType;
    ///     await result.Response!.Content.CopyToAsync(context.Response.Body);
    /// }
    /// </code>
    /// </remarks>
    Task<RawBackendResult> CallRawAsync(BackendRequest request, CancellationToken cancellationToken);

    /// <summary>
    /// Calls a backend service with a request body and returns the raw HTTP response without parsing.
    /// Use this for proxying requests with body content where the response should be streamed.
    /// </summary>
    /// <param name="request">The request configuration</param>
    /// <param name="requestBody">The request body stream to forward to the backend</param>
    /// <param name="contentType">The content type of the request body</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>
    /// A <see cref="RawBackendResult"/> containing the raw HTTP response.
    /// The caller is responsible for disposing the result when done.
    /// </returns>
    Task<RawBackendResult> CallRawAsync(BackendRequest request, Stream requestBody, string contentType, CancellationToken cancellationToken);
}

/// <summary>
/// Result of a raw backend call with an unparsed response.
/// Use this when you need to stream the response body without deserialization.
/// </summary>
/// <remarks>
/// The response message is owned by this struct and should be disposed when no longer needed.
/// The response body can be accessed via <see cref="Response"/> for streaming directly to the client.
/// </remarks>
public readonly struct RawBackendResult : IDisposable
{
    /// <summary>
    /// Indicates whether the backend call was successful (2xx status code).
    /// </summary>
    public bool IsSuccess { get; }

    /// <summary>
    /// The HTTP status code from the backend.
    /// </summary>
    public int StatusCode { get; }

    /// <summary>
    /// The raw HTTP response message. Available only on success.
    /// Use <see cref="HttpResponseMessage.Content"/> to access the body stream.
    /// </summary>
    public HttpResponseMessage? Response { get; }

    /// <summary>
    /// Error message if the call failed.
    /// </summary>
    public string? Error { get; }

    /// <summary>
    /// The type of error that occurred.
    /// </summary>
    public BackendErrorType ErrorType { get; }

    /// <summary>
    /// The Content-Type header from the backend response.
    /// </summary>
    public string? ContentType => Response?.Content.Headers.ContentType?.MediaType;

    /// <summary>
    /// The Content-Length header from the backend response, if available.
    /// </summary>
    public long? ContentLength => Response?.Content.Headers.ContentLength;

    private RawBackendResult(bool isSuccess, int statusCode, HttpResponseMessage? response, string? error, BackendErrorType errorType)
    {
        IsSuccess = isSuccess;
        StatusCode = statusCode;
        Response = response;
        Error = error;
        ErrorType = errorType;
    }

    /// <summary>
    /// Creates a successful raw result with the HTTP response.
    /// </summary>
    public static RawBackendResult Success(HttpResponseMessage response)
        => new(true, (int)response.StatusCode, response, null, BackendErrorType.None);

    /// <summary>
    /// Creates a failed raw result.
    /// </summary>
    public static RawBackendResult Failure(int statusCode, string error, BackendErrorType errorType = BackendErrorType.Unknown)
        => new(false, statusCode, null, error, errorType);

    /// <summary>
    /// Creates an authentication failure result.
    /// </summary>
    public static RawBackendResult AuthenticationFailure(string error)
        => new(false, 401, null, error, BackendErrorType.AuthenticationError);

    /// <summary>
    /// Creates an authorization failure result.
    /// </summary>
    public static RawBackendResult AuthorizationFailure(string error)
        => new(false, 403, null, error, BackendErrorType.AuthorizationError);

    /// <summary>
    /// Creates a network failure result.
    /// </summary>
    public static RawBackendResult NetworkFailure(string error)
        => new(false, 502, null, error, BackendErrorType.NetworkError);

    /// <summary>
    /// Creates a timeout failure result.
    /// </summary>
    public static RawBackendResult TimeoutFailure(string error)
        => new(false, 504, null, error, BackendErrorType.Timeout);

    /// <summary>
    /// Disposes the underlying HTTP response message.
    /// </summary>
    public void Dispose() => Response?.Dispose();
}

/// <summary>
/// Result of a backend call with a response body as object (for runtime type scenarios).
/// </summary>
public readonly struct BackendObjectResult
{
    /// <summary>
    /// Indicates whether the backend call succeeded (2xx status code).
    /// </summary>
    public bool IsSuccess { get; }

    /// <summary>
    /// The (possibly error-mapped) HTTP status code associated with the result.
    /// </summary>
    public int StatusCode { get; }

    /// <summary>
    /// The deserialized response object. Available only on success; <c>null</c> when the
    /// backend returned an empty body or when the call failed.
    /// </summary>
    public object? Value { get; }

    /// <summary>
    /// The error message when the call failed; <c>null</c> on success.
    /// </summary>
    public string? Error { get; }

    /// <summary>
    /// The category of error that occurred. <see cref="BackendErrorType.None"/> on success.
    /// </summary>
    public BackendErrorType ErrorType { get; }

    private BackendObjectResult(bool isSuccess, int statusCode, object? value, string? error, BackendErrorType errorType)
    {
        IsSuccess = isSuccess;
        StatusCode = statusCode;
        Value = value;
        Error = error;
        ErrorType = errorType;
    }

    /// <summary>
    /// Creates a successful result carrying the deserialized response object.
    /// </summary>
    /// <param name="value">The deserialized response object (may be <c>null</c> for an empty body).</param>
    /// <param name="statusCode">The HTTP status code. Defaults to 200.</param>
    public static BackendObjectResult Success(object? value, int statusCode = 200) => new(true, statusCode, value, null, BackendErrorType.None);

    /// <summary>
    /// Creates a failed result with the given status code, error message, and error type.
    /// </summary>
    /// <param name="statusCode">The HTTP status code to surface.</param>
    /// <param name="error">A human-readable error message.</param>
    /// <param name="errorType">The category of error. Defaults to <see cref="BackendErrorType.Unknown"/>.</param>
    public static BackendObjectResult Failure(int statusCode, string error, BackendErrorType errorType = BackendErrorType.Unknown) => new(false, statusCode, null, error, errorType);
}

/// <summary>
/// Type of backend error.
/// </summary>
public enum BackendErrorType
{
    /// <summary>
    /// No error - the backend call succeeded.
    /// </summary>
    None,

    /// <summary>
    /// The backend could not be reached (connection failure, DNS error, or other transport-level fault).
    /// Surfaced as 502 Bad Gateway.
    /// </summary>
    NetworkError,

    /// <summary>
    /// Authentication against the backend failed (e.g. the forwarded or exchanged credential was rejected).
    /// </summary>
    AuthenticationError,

    /// <summary>
    /// The backend rejected the request as forbidden - authenticated but not authorized for the resource.
    /// </summary>
    AuthorizationError,

    /// <summary>
    /// The backend call timed out before a response was received. Surfaced as 504 Gateway Timeout.
    /// </summary>
    Timeout,

    /// <summary>
    /// The backend returned a 5xx server error.
    /// </summary>
    ServerError,
    /// <summary>
    /// 4xx returned by the backend that isn't 401 or 403 - typically a malformed
    /// request, validation failure, or a missing/disabled resource. The remote
    /// service answered correctly; the caller (or the BFF acting on behalf of
    /// the caller) was the source of the problem.
    /// </summary>
    ClientError,

    /// <summary>
    /// The backend returned a 2xx status but the response body could not be parsed,
    /// was malformed, or exceeded the configured maximum response size.
    /// </summary>
    InvalidResponse,
    /// <summary>
    /// The BFF could not apply backend authentication because of a server-side
    /// configuration or dependency problem (e.g. token exchange selected with no
    /// audience configured, or <c>IApiTokenService</c> not registered). This is a
    /// 5xx-class operator problem, deliberately distinct from
    /// <see cref="AuthenticationError"/> so a misconfiguration is not mistaken for
    /// a genuine user-credential rejection.
    /// </summary>
    ConfigurationError,

    /// <summary>
    /// An unexpected or uncategorized error occurred.
    /// </summary>
    Unknown
}

/// <summary>
/// Result of a backend call without a response body.
/// </summary>
public readonly struct BackendResult
{
    /// <summary>
    /// Indicates whether the backend call succeeded (2xx status code).
    /// </summary>
    public bool IsSuccess { get; }

    /// <summary>
    /// The (possibly error-mapped) HTTP status code associated with the result.
    /// </summary>
    public int StatusCode { get; }

    /// <summary>
    /// The error message when the call failed; <c>null</c> on success.
    /// </summary>
    public string? Error { get; }

    /// <summary>
    /// The category of error that occurred. <see cref="BackendErrorType.None"/> on success.
    /// </summary>
    public BackendErrorType ErrorType { get; }

    private BackendResult(bool isSuccess, int statusCode, string? error, BackendErrorType errorType)
    {
        IsSuccess = isSuccess;
        StatusCode = statusCode;
        Error = error;
        ErrorType = errorType;
    }

    /// <summary>
    /// Creates a successful result.
    /// </summary>
    /// <param name="statusCode">The HTTP status code. Defaults to 200.</param>
    public static BackendResult Success(int statusCode = 200) => new(true, statusCode, null, BackendErrorType.None);

    /// <summary>
    /// Creates a failed result with the given status code, error message, and error type.
    /// </summary>
    /// <param name="statusCode">The HTTP status code to surface.</param>
    /// <param name="error">A human-readable error message.</param>
    /// <param name="errorType">The category of error. Defaults to <see cref="BackendErrorType.Unknown"/>.</param>
    public static BackendResult Failure(int statusCode, string error, BackendErrorType errorType = BackendErrorType.Unknown) => new(false, statusCode, error, errorType);

    /// <summary>
    /// Creates an authentication failure result (status 401, <see cref="BackendErrorType.AuthenticationError"/>).
    /// </summary>
    /// <param name="error">A human-readable error message.</param>
    public static BackendResult AuthenticationFailure(string error) => new(false, 401, error, BackendErrorType.AuthenticationError);

    /// <summary>
    /// Creates an authorization failure result (status 403, <see cref="BackendErrorType.AuthorizationError"/>).
    /// </summary>
    /// <param name="error">A human-readable error message.</param>
    public static BackendResult AuthorizationFailure(string error) => new(false, 403, error, BackendErrorType.AuthorizationError);

    /// <summary>
    /// Creates a network failure result (status 502, <see cref="BackendErrorType.NetworkError"/>).
    /// </summary>
    /// <param name="error">A human-readable error message.</param>
    public static BackendResult NetworkFailure(string error) => new(false, 502, error, BackendErrorType.NetworkError);

    /// <summary>
    /// Creates a timeout failure result (status 504, <see cref="BackendErrorType.Timeout"/>).
    /// </summary>
    /// <param name="error">A human-readable error message.</param>
    public static BackendResult TimeoutFailure(string error) => new(false, 504, error, BackendErrorType.Timeout);
}

/// <summary>
/// Result of a backend call with a response body.
/// </summary>
public readonly struct BackendResult<T>
{
    /// <summary>
    /// Indicates whether the backend call succeeded (2xx status code).
    /// </summary>
    public bool IsSuccess { get; }

    /// <summary>
    /// The (possibly error-mapped) HTTP status code associated with the result.
    /// </summary>
    public int StatusCode { get; }

    /// <summary>
    /// The deserialized response value. Available only on success; <c>default</c> when the
    /// backend returned an empty body or when the call failed.
    /// </summary>
    public T? Value { get; }

    /// <summary>
    /// The error message when the call failed; <c>null</c> on success.
    /// </summary>
    public string? Error { get; }

    /// <summary>
    /// The category of error that occurred. <see cref="BackendErrorType.None"/> on success.
    /// </summary>
    public BackendErrorType ErrorType { get; }

    private BackendResult(bool isSuccess, int statusCode, T? value, string? error, BackendErrorType errorType)
    {
        IsSuccess = isSuccess;
        StatusCode = statusCode;
        Value = value;
        Error = error;
        ErrorType = errorType;
    }

    /// <summary>
    /// Creates a successful result carrying the deserialized response value.
    /// </summary>
    /// <param name="value">The deserialized response value.</param>
    /// <param name="statusCode">The HTTP status code. Defaults to 200.</param>
    public static BackendResult<T> Success(T value, int statusCode = 200) => new(true, statusCode, value, null, BackendErrorType.None);

    /// <summary>
    /// Creates a failed result with the given status code, error message, and error type.
    /// </summary>
    /// <param name="statusCode">The HTTP status code to surface.</param>
    /// <param name="error">A human-readable error message.</param>
    /// <param name="errorType">The category of error. Defaults to <see cref="BackendErrorType.Unknown"/>.</param>
    public static BackendResult<T> Failure(int statusCode, string error, BackendErrorType errorType = BackendErrorType.Unknown) => new(false, statusCode, default, error, errorType);

    /// <summary>
    /// Creates an authentication failure result (status 401, <see cref="BackendErrorType.AuthenticationError"/>).
    /// </summary>
    /// <param name="error">A human-readable error message.</param>
    public static BackendResult<T> AuthenticationFailure(string error) => new(false, 401, default, error, BackendErrorType.AuthenticationError);

    /// <summary>
    /// Creates an authorization failure result (status 403, <see cref="BackendErrorType.AuthorizationError"/>).
    /// </summary>
    /// <param name="error">A human-readable error message.</param>
    public static BackendResult<T> AuthorizationFailure(string error) => new(false, 403, default, error, BackendErrorType.AuthorizationError);

    /// <summary>
    /// Creates a network failure result (status 502, <see cref="BackendErrorType.NetworkError"/>).
    /// </summary>
    /// <param name="error">A human-readable error message.</param>
    public static BackendResult<T> NetworkFailure(string error) => new(false, 502, default, error, BackendErrorType.NetworkError);

    /// <summary>
    /// Creates a timeout failure result (status 504, <see cref="BackendErrorType.Timeout"/>).
    /// </summary>
    /// <param name="error">A human-readable error message.</param>
    public static BackendResult<T> TimeoutFailure(string error) => new(false, 504, default, error, BackendErrorType.Timeout);
}

/// <summary>
/// Backend authentication policy names.
/// </summary>
public static class BackendAuthPolicies
{
    /// <summary>
    /// No authentication - backend is publicly accessible.
    /// </summary>
    public const string None = "None";

    /// <summary>
    /// HTTP Basic authentication using credentials configured via <see cref="Configuration.BackendServiceOptions"/>.
    /// </summary>
    public const string BasicAuth = "BasicAuth";

    /// <summary>
    /// Fixed API key configured via <see cref="Configuration.BackendServiceOptions"/>. Sent as
    /// <c>Authorization: Bearer &lt;token&gt;</c> by default; the scheme is configurable, or the
    /// key can be sent raw in a custom header (e.g. <c>X-Api-Key</c>). Like <see cref="BasicAuth"/>,
    /// this is the BFF's own credential - it never carries the caller's identity.
    /// </summary>
    public const string ApiKey = "ApiKey";

    /// <summary>
    /// OAuth2 client-credentials grant (RFC 6749 §4.4): the BFF mints an access token for its
    /// OWN machine-to-machine identity (configured under <c>BackendService:ClientCredentials</c>,
    /// deliberately separate from the login client) and sends it as a Bearer credential. Tokens
    /// are cached process-wide until shortly before expiry. Like <see cref="BasicAuth"/> and
    /// <see cref="ApiKey"/>, this never carries the caller's identity.
    /// </summary>
    public const string ClientCredentials = "ClientCredentials";

    /// <summary>
    /// Forward the user's Bearer token to the backend.
    /// </summary>
    public const string BearerToken = "BearerToken";

    /// <summary>
    /// Use token exchange to get a backend-specific token.
    /// </summary>
    public const string TokenExchange = "TokenExchange";

    /// <summary>
    /// Checks if the given authentication policy requires a user identity (authenticated user).
    /// </summary>
    /// <param name="policy">The authentication policy name</param>
    /// <returns>True if the policy requires user authentication</returns>
    public static bool RequiresUserIdentity(string? policy) => policy is BearerToken or TokenExchange;
}

/// <summary>
/// Configuration for a backend API call.
/// </summary>
public record BackendRequest
{
    /// <summary>
    /// The HTTP method (GET, POST, PUT, DELETE, PATCH).
    /// </summary>
    public required string Method { get; init; }

    /// <summary>
    /// The backend URL. Supports:
    /// - Kubernetes service: "http://user-service/api/users"
    /// - External URL: "https://api.example.com/users"
    /// </summary>
    public required string Url { get; init; }

    /// <summary>
    /// Additional headers to include in the request.
    /// </summary>
    public Dictionary<string, string>? Headers { get; init; }

    /// <summary>
    /// Entity (content) headers to apply to the request body, such as
    /// <c>Content-Encoding</c>, <c>Content-Disposition</c>, <c>Content-Language</c> or
    /// <c>Content-Range</c>. These cannot live in <see cref="Headers"/>: the request-headers
    /// collection silently rejects content headers, so raw forwarding plumbs them here and the
    /// caller applies them to the outbound <see cref="System.Net.Http.StreamContent"/>. Only
    /// honoured when a request body is forwarded. <c>Content-Type</c> is supplied separately via
    /// the body overload of <see cref="IBackendCaller.CallRawAsync(BackendRequest, System.IO.Stream, string, System.Threading.CancellationToken)"/>.
    /// </summary>
    public Dictionary<string, string>? ContentHeaders { get; init; }

    /// <summary>
    /// The access token to forward (populated by the framework).
    /// </summary>
    public string? AccessToken { get; init; }

    /// <summary>
    /// Optional timeout override for this specific request, applied to <c>HttpClient.Timeout</c>.
    /// </summary>
    /// <remarks>
    /// With <see cref="EnableRetries"/> set, this is a <b>total</b> budget across the whole
    /// resilience pipeline (all retry attempts plus back-off), not a per-attempt timeout - because
    /// <c>HttpClient.Timeout</c> wraps the entire send including retries. A value of 5s does not
    /// grant 3×5s for three attempts; it caps the combined duration at 5s. Per-attempt and total
    /// budgets for the retrying client are otherwise governed by the standard resilience handler
    /// (see <c>AddPortaCore</c>'s <c>HttpClientNameWithRetries</c> registration).
    /// </remarks>
    public TimeSpan? Timeout { get; init; }

    /// <summary>
    /// Whether to use token exchange for backend-specific tokens.
    /// If true, exchanges the user's token for a backend-specific token.
    /// Default: false
    /// </summary>
    public bool UseTokenExchange { get; init; } = false;

    /// <summary>
    /// Target audience for token exchange (e.g., "user-service-api").
    /// Only used when UseTokenExchange is true.
    /// </summary>
    public string? TokenExchangeAudience { get; init; }

    /// <summary>
    /// Backend authentication policy to use (e.g., "BasicAuth", "BearerToken").
    /// See <see cref="BackendAuthPolicies"/> for available options.
    /// </summary>
    public string? BackendAuthPolicy { get; init; }

    /// <summary>
    /// Logical name of the backend this request targets. Used by built-in auth
    /// handlers (e.g. <c>BasicAuth</c>) to look up per-backend credentials in
    /// <see cref="Configuration.BackendServiceOptions.Backends"/>. When null,
    /// handlers fall back to the default configuration.
    /// </summary>
    public string? BackendName { get; init; }

    /// <summary>
    /// Whether to enable automatic retries for transient failures.
    /// Default: false (retries are disabled by default)
    /// </summary>
    public bool EnableRetries { get; init; } = false;

    /// <summary>
    /// Maximum number of retry attempts when retries are enabled.
    /// Only used when EnableRetries is true.
    /// Default: 3
    /// </summary>
    public int MaxRetryAttempts { get; init; } = 3;

    /// <summary>
    /// Content type used to serialize the request body sent to the backend.
    /// Default: <see cref="ContentType.Json"/>.
    /// </summary>
    public ContentType RequestContentType { get; init; } = ContentType.Json;
}

/// <summary>
/// Configuration for a named backend endpoint used in multi-backend transformers.
/// </summary>
public record NamedBackendEndpoint
{
    /// <summary>
    /// The logical name of this backend endpoint (e.g., "UserInfo", "ProductInfo").
    /// Used by transformers to reference this endpoint without hardcoding URLs.
    /// </summary>
    public required string Name { get; init; }

    /// <summary>
    /// The HTTP method (GET, POST, PUT, DELETE, PATCH).
    /// </summary>
    public required string Method { get; init; }

    /// <summary>
    /// The backend URL template. Supports route parameter interpolation using {param} syntax.
    /// Examples:
    /// - "http://users-service/api/userinfo"
    /// - "http://products-service/api/products/{productId}"
    /// </summary>
    public required string UrlTemplate { get; init; }

    /// <summary>
    /// Whether to use token exchange for this backend.
    /// </summary>
    public bool UseTokenExchange { get; init; }

    /// <summary>
    /// Target audience for token exchange.
    /// </summary>
    public string? TokenExchangeAudience { get; init; }

    /// <summary>
    /// Optional timeout override for this backend.
    /// </summary>
    public TimeSpan? Timeout { get; init; }

    /// <summary>
    /// Backend authentication policy to use.
    /// See <see cref="BackendAuthPolicies"/> for available options.
    /// </summary>
    public string? BackendAuthPolicy { get; init; }

    /// <summary>
    /// Whether this endpoint forwards the user's token directly (via WithUserToken()).
    /// Used for startup validation against trusted hosts.
    /// </summary>
    public bool ForwardUserToken { get; init; }

    /// <summary>
    /// Whether this leg's user-identity auth is optional: applied only when the caller
    /// authenticated, skipped (no auth) when anonymous. Only valid on endpoints marked
    /// <c>AllowAnonymousWithOptionalAuth()</c> and only with a user-identity policy - the
    /// startup validator rejects every other placement.
    /// </summary>
    public bool OptionalAuth { get; init; }

    /// <summary>
    /// Whether to enable automatic retries for transient failures.
    /// Default: false (retries are disabled by default)
    /// </summary>
    public bool EnableRetries { get; init; } = false;

    /// <summary>
    /// Maximum number of retry attempts when retries are enabled.
    /// Only used when EnableRetries is true.
    /// Default: 3
    /// </summary>
    public int MaxRetryAttempts { get; init; } = 3;

    /// <summary>
    /// Creates a BackendRequest from this endpoint configuration.
    /// </summary>
    /// <param name="routeValues">Route values for URL interpolation</param>
    /// <param name="accessToken">
    /// The user's access token to forward, taken from the transformer's
    /// <see cref="b17s.Porta.Auth.Providers.AuthenticationContext.AccessToken"/>. Set it for every
    /// named backend regardless of policy (matching the single-backend builder); the auth handler
    /// only consumes it when the policy needs it - <c>BearerToken</c> forwards it, <c>TokenExchange</c>
    /// uses it as the subject token, while <c>None</c>/<c>BasicAuth</c> ignore it. Omitting it is what
    /// previously left aggregated/named backends with no credential.
    /// </param>
    /// <returns>A configured BackendRequest</returns>
    public BackendRequest ToBackendRequest(IReadOnlyDictionary<string, object?>? routeValues = null, string? accessToken = null)
    {
        var url = routeValues != null
            ? RouteUrlInterpolator.Interpolate(UrlTemplate, routeValues)
            : UrlTemplate;

        return new BackendRequest
        {
            Method = Method,
            Url = url,
            AccessToken = accessToken,
            BackendName = Name,
            UseTokenExchange = UseTokenExchange,
            TokenExchangeAudience = TokenExchangeAudience,
            Timeout = Timeout,
            BackendAuthPolicy = BackendAuthPolicy,
            EnableRetries = EnableRetries,
            MaxRetryAttempts = MaxRetryAttempts
        };
    }

    /// <summary>
    /// Creates a NamedBackendEndpoint from a tuple (name, method, url) with optional auth policy.
    /// </summary>
    public static NamedBackendEndpoint FromTuple(string name, string method, string url, string? authPolicy = null)
    {
        return new NamedBackendEndpoint
        {
            Name = name,
            Method = method.ToUpperInvariant(),
            UrlTemplate = url,
            BackendAuthPolicy = authPolicy
        };
    }

    /// <summary>
    /// Creates a NamedBackendEndpoint with token exchange configuration.
    /// </summary>
    public static NamedBackendEndpoint WithTokenExchange(string name, string method, string url, string audience)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(audience);
        return new NamedBackendEndpoint
        {
            Name = name,
            Method = method.ToUpperInvariant(),
            UrlTemplate = url,
            BackendAuthPolicy = BackendAuthPolicies.TokenExchange,
            UseTokenExchange = true,
            TokenExchangeAudience = audience
        };
    }
}

/// <summary>
/// Fluent collection builder used by the <c>ToBackends(configure =&gt; ...)</c> overload to declare
/// several named backends without object initializers. Each <c>ToGet</c>/<c>ToPost</c>/... call adds a
/// backend; the per-backend modifiers (<c>WithAuth</c>, <c>WithUserToken</c>, <c>WithTokenExchange</c>,
/// <c>WithTimeout</c>, <c>WithRetries</c>) apply to the most recently added backend, so calls read
/// top-to-bottom:
/// <code>
/// .ToBackends(b =&gt; b
///     .ToGet("UserInfo", $"{url}/userinfo").WithAuth(BackendAuthPolicies.BearerToken)
///     .ToPost("Orders", $"{url}/orders").WithTokenExchange("order-api").WithRetries(3))
/// </code>
/// </summary>
public sealed class NamedBackendEndpointsBuilder
{
    private readonly List<NamedBackendEndpoint> _endpoints = [];

    /// <summary>Adds a GET backend with the given logical name and URL template.</summary>
    /// <param name="name">Logical name (must match the name used in the aggregator's <c>Configure</c>)</param>
    /// <param name="url">Backend URL template (supports <c>{param}</c> route interpolation)</param>
    public NamedBackendEndpointsBuilder ToGet(string name, string url) => Add(name, "GET", url);

    /// <summary>Adds a POST backend with the given logical name and URL template.</summary>
    /// <param name="name">Logical name (must match the name used in the aggregator's <c>Configure</c>)</param>
    /// <param name="url">Backend URL template (supports <c>{param}</c> route interpolation)</param>
    public NamedBackendEndpointsBuilder ToPost(string name, string url) => Add(name, "POST", url);

    /// <summary>Adds a PUT backend with the given logical name and URL template.</summary>
    /// <param name="name">Logical name (must match the name used in the aggregator's <c>Configure</c>)</param>
    /// <param name="url">Backend URL template (supports <c>{param}</c> route interpolation)</param>
    public NamedBackendEndpointsBuilder ToPut(string name, string url) => Add(name, "PUT", url);

    /// <summary>Adds a DELETE backend with the given logical name and URL template.</summary>
    /// <param name="name">Logical name (must match the name used in the aggregator's <c>Configure</c>)</param>
    /// <param name="url">Backend URL template (supports <c>{param}</c> route interpolation)</param>
    public NamedBackendEndpointsBuilder ToDelete(string name, string url) => Add(name, "DELETE", url);

    /// <summary>Adds a PATCH backend with the given logical name and URL template.</summary>
    /// <param name="name">Logical name (must match the name used in the aggregator's <c>Configure</c>)</param>
    /// <param name="url">Backend URL template (supports <c>{param}</c> route interpolation)</param>
    public NamedBackendEndpointsBuilder ToPatch(string name, string url) => Add(name, "PATCH", url);

    /// <summary>Adds a backend with an explicit HTTP method (escape hatch for verbs without a shorthand).</summary>
    /// <param name="method">HTTP method (e.g. HEAD, OPTIONS)</param>
    /// <param name="name">Logical name (must match the name used in the aggregator's <c>Configure</c>)</param>
    /// <param name="url">Backend URL template (supports <c>{param}</c> route interpolation)</param>
    public NamedBackendEndpointsBuilder ToBackend(string method, string name, string url) => Add(name, method, url);

    /// <summary>Sets the backend authentication policy on the most recently added backend.</summary>
    /// <param name="authPolicy">The backend authentication policy name.</param>
    /// <param name="optional">
    /// When true, the policy is applied only for callers that authenticated (requires a
    /// user-identity policy and an <c>AllowAnonymousWithOptionalAuth()</c> endpoint).
    /// </param>
    public NamedBackendEndpointsBuilder WithAuth(string authPolicy, bool optional = false)
        => Mutate(e => e with { BackendAuthPolicy = authPolicy, OptionalAuth = optional });

    /// <summary>
    /// Forwards the user's OAuth token directly to the most recently added backend (sets <c>BearerToken</c>).
    /// </summary>
    /// <remarks>
    /// SECURITY: Only use this for trusted internal services that share the same identity provider. The
    /// user's token will be forwarded to the backend, allowing it to act on behalf of the user. The
    /// destination host must be listed in <c>PortaCore:TrustedHosts</c> (see
    /// <see cref="Configuration.PortaCoreOptions.TrustedHosts"/>).
    /// </remarks>
    public NamedBackendEndpointsBuilder WithUserToken(bool optional = false)
        => Mutate(e => e with { BackendAuthPolicy = BackendAuthPolicies.BearerToken, ForwardUserToken = true, OptionalAuth = optional });

    /// <summary>Uses token exchange for the most recently added backend, scoped to the given audience.</summary>
    /// <param name="audience">Target audience for the exchanged token. Must be non-empty.</param>
    /// <param name="optional">
    /// When true, the exchange runs only for callers that authenticated (requires an
    /// <c>AllowAnonymousWithOptionalAuth()</c> endpoint).
    /// </param>
    /// <exception cref="ArgumentException">Thrown when <paramref name="audience"/> is null or blank.</exception>
    public NamedBackendEndpointsBuilder WithTokenExchange(string audience, bool optional = false)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(audience);
        return Mutate(e => e with
        {
            BackendAuthPolicy = BackendAuthPolicies.TokenExchange,
            UseTokenExchange = true,
            TokenExchangeAudience = audience,
            OptionalAuth = optional
        });
    }

    /// <summary>Sets a timeout override on the most recently added backend.</summary>
    public NamedBackendEndpointsBuilder WithTimeout(TimeSpan timeout)
        => Mutate(e => e with { Timeout = timeout });

    /// <summary>Enables automatic retries for transient failures on the most recently added backend.</summary>
    /// <param name="maxAttempts">Number of retry attempts for this backend, capped by the app-wide <see cref="Configuration.PortaCoreOptions.MaxRetryAttempts"/> ceiling (effective count <c>min(maxAttempts, ceiling)</c>). Default: 3</param>
    public NamedBackendEndpointsBuilder WithRetries(int maxAttempts = 3)
        => Mutate(e => e with { EnableRetries = true, MaxRetryAttempts = maxAttempts });

    private NamedBackendEndpointsBuilder Add(string name, string method, string url)
    {
        _endpoints.Add(new NamedBackendEndpoint
        {
            Name = name,
            Method = method.ToUpperInvariant(),
            UrlTemplate = url
        });
        return this;
    }

    private NamedBackendEndpointsBuilder Mutate(Func<NamedBackendEndpoint, NamedBackendEndpoint> mutate)
    {
        if (_endpoints.Count == 0)
        {
            throw new InvalidOperationException(
                "Add a backend with ToGet/ToPost/... before configuring it with WithAuth/WithUserToken/WithTokenExchange/WithTimeout/WithRetries.");
        }

        _endpoints[^1] = mutate(_endpoints[^1]);
        return this;
    }

    internal NamedBackendEndpoint[] Build() => [.. _endpoints];
}

/// <summary>
/// Fluent builder for creating NamedBackendEndpoint with per-backend auth configuration.
/// </summary>
public sealed class BackendEndpointBuilder
{
    private readonly string _name;
    private readonly string _method;
    private readonly string _url;
    private string? _authPolicy;
    private bool _useTokenExchange;
    private string? _tokenExchangeAudience;
    private TimeSpan? _timeout;

    private BackendEndpointBuilder(string name, string method, string url)
    {
        _name = name;
        _method = method.ToUpperInvariant();
        _url = url;
    }

    /// <summary>
    /// Creates a new backend endpoint builder.
    /// </summary>
    /// <param name="name">Logical name of the endpoint</param>
    /// <param name="method">HTTP method</param>
    /// <param name="url">Backend URL template</param>
    public static BackendEndpointBuilder Create(string name, string method, string url)
        => new(name, method, url);

    /// <summary>
    /// Sets the backend authentication policy.
    /// </summary>
    public BackendEndpointBuilder WithAuth(string authPolicy)
    {
        _authPolicy = authPolicy;
        return this;
    }

    /// <summary>
    /// Configures token exchange for this backend.
    /// </summary>
    /// <param name="audience">Target audience for the exchanged token. Must be non-empty.</param>
    /// <exception cref="ArgumentException">Thrown when <paramref name="audience"/> is null or blank.</exception>
    public BackendEndpointBuilder WithTokenExchange(string audience)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(audience);
        _authPolicy = BackendAuthPolicies.TokenExchange;
        _useTokenExchange = true;
        _tokenExchangeAudience = audience;
        return this;
    }

    /// <summary>
    /// Sets a timeout override for this backend.
    /// </summary>
    public BackendEndpointBuilder WithTimeout(TimeSpan timeout)
    {
        _timeout = timeout;
        return this;
    }

    /// <summary>
    /// Builds the NamedBackendEndpoint.
    /// </summary>
    public NamedBackendEndpoint Build()
    {
        return new NamedBackendEndpoint
        {
            Name = _name,
            Method = _method,
            UrlTemplate = _url,
            BackendAuthPolicy = _authPolicy,
            UseTokenExchange = _useTokenExchange,
            TokenExchangeAudience = _tokenExchangeAudience,
            Timeout = _timeout
        };
    }

    /// <summary>
    /// Implicit conversion to NamedBackendEndpoint for fluent API.
    /// </summary>
    public static implicit operator NamedBackendEndpoint(BackendEndpointBuilder builder) => builder.Build();
}

/// <summary>
/// Extension methods for backend endpoint tuple configuration.
/// Allows fluent per-backend auth configuration on (name, method, url) tuples.
/// </summary>
public static class BackendEndpointExtensions
{
    /// <summary>
    /// Configures the backend authentication policy for this endpoint.
    /// </summary>
    /// <param name="endpoint">The endpoint tuple (name, method, url)</param>
    /// <param name="authPolicy">The authentication policy (see <see cref="BackendAuthPolicies"/>)</param>
    /// <returns>A configured NamedBackendEndpoint</returns>
    /// <example>
    /// ("UserInfo", "POST", $"{url}/userinfo").WithAuth(BackendAuthPolicies.BasicAuth)
    /// </example>
    public static NamedBackendEndpoint WithAuth(
        this (string Name, string Method, string Url) endpoint,
        string authPolicy)
    {
        return new NamedBackendEndpoint
        {
            Name = endpoint.Name,
            Method = endpoint.Method.ToUpperInvariant(),
            UrlTemplate = endpoint.Url,
            BackendAuthPolicy = authPolicy
        };
    }

    /// <summary>
    /// Forwards the user's OAuth token to this backend.
    /// Use only for trusted internal services that share the same identity provider.
    /// </summary>
    /// <param name="endpoint">The endpoint tuple (name, method, url)</param>
    /// <returns>A configured NamedBackendEndpoint with BearerToken policy</returns>
    /// <remarks>
    /// SECURITY: Only use this for trusted internal services. The user's token will be
    /// forwarded to the backend, allowing it to act on behalf of the user. The destination
    /// host must be listed in <c>PortaCore:TrustedHosts</c> (see
    /// <see cref="Configuration.PortaCoreOptions.TrustedHosts"/>).
    /// </remarks>
    /// <example>
    /// ("InternalApi", "GET", $"{internalUrl}/data").WithUserToken()
    /// </example>
    public static NamedBackendEndpoint WithUserToken(
        this (string Name, string Method, string Url) endpoint)
    {
        return new NamedBackendEndpoint
        {
            Name = endpoint.Name,
            Method = endpoint.Method.ToUpperInvariant(),
            UrlTemplate = endpoint.Url,
            BackendAuthPolicy = BackendAuthPolicies.BearerToken,
            ForwardUserToken = true
        };
    }

    /// <summary>
    /// Uses OAuth token exchange to get a backend-specific token.
    /// The user's token is exchanged for a new token scoped to the specified audience.
    /// </summary>
    /// <param name="endpoint">The endpoint tuple (name, method, url)</param>
    /// <param name="audience">The target audience for the exchanged token</param>
    /// <returns>A configured NamedBackendEndpoint with TokenExchange policy</returns>
    /// <example>
    /// ("OrderService", "GET", $"{orderUrl}/orders").WithTokenExchange("order-api")
    /// </example>
    public static NamedBackendEndpoint WithTokenExchange(
        this (string Name, string Method, string Url) endpoint,
        string audience)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(audience);
        return new NamedBackendEndpoint
        {
            Name = endpoint.Name,
            Method = endpoint.Method.ToUpperInvariant(),
            UrlTemplate = endpoint.Url,
            BackendAuthPolicy = BackendAuthPolicies.TokenExchange,
            UseTokenExchange = true,
            TokenExchangeAudience = audience
        };
    }

    /// <summary>
    /// Sets a timeout override for this backend endpoint.
    /// </summary>
    /// <param name="endpoint">A configured NamedBackendEndpoint</param>
    /// <param name="timeout">The timeout duration</param>
    /// <returns>The endpoint with timeout configured</returns>
    /// <example>
    /// ("SlowApi", "GET", $"{url}/slow").WithAuth(policy).WithTimeout(TimeSpan.FromSeconds(30))
    /// </example>
    public static NamedBackendEndpoint WithTimeout(this NamedBackendEndpoint endpoint, TimeSpan timeout) => endpoint with { Timeout = timeout };

    /// <summary>
    /// Sets a timeout override for this backend endpoint tuple.
    /// Note: This creates an endpoint with no authentication. Chain with .WithAuth() first if auth is needed.
    /// </summary>
    /// <param name="endpoint">The endpoint tuple (name, method, url)</param>
    /// <param name="timeout">The timeout duration</param>
    /// <returns>A configured NamedBackendEndpoint with timeout</returns>
    public static NamedBackendEndpoint WithTimeout(
        this (string Name, string Method, string Url) endpoint,
        TimeSpan timeout)
    {
        return new NamedBackendEndpoint
        {
            Name = endpoint.Name,
            Method = endpoint.Method.ToUpperInvariant(),
            UrlTemplate = endpoint.Url,
            BackendAuthPolicy = BackendAuthPolicies.None,
            Timeout = timeout
        };
    }

    /// <summary>
    /// Enables automatic retries for transient failures on this backend endpoint.
    /// </summary>
    /// <param name="endpoint">A configured NamedBackendEndpoint</param>
    /// <param name="maxAttempts">Number of retry attempts for this backend, capped by the app-wide <see cref="Configuration.PortaCoreOptions.MaxRetryAttempts"/> ceiling (effective count <c>min(maxAttempts, ceiling)</c>). Default: 3</param>
    /// <returns>The endpoint with retries enabled</returns>
    /// <example>
    /// ("FlakyApi", "GET", $"{url}/data").WithAuth(policy).WithRetries(3)
    /// </example>
    public static NamedBackendEndpoint WithRetries(this NamedBackendEndpoint endpoint, int maxAttempts = 3)
        => endpoint with { EnableRetries = true, MaxRetryAttempts = maxAttempts };

    /// <summary>
    /// Enables automatic retries for transient failures on this backend endpoint tuple.
    /// Note: This creates an endpoint with no authentication. Chain with .WithAuth() first if auth is needed.
    /// </summary>
    /// <param name="endpoint">The endpoint tuple (name, method, url)</param>
    /// <param name="maxAttempts">Number of retry attempts for this backend, capped by the app-wide <see cref="Configuration.PortaCoreOptions.MaxRetryAttempts"/> ceiling (effective count <c>min(maxAttempts, ceiling)</c>). Default: 3</param>
    /// <returns>A configured NamedBackendEndpoint with retries enabled</returns>
    public static NamedBackendEndpoint WithRetries(
        this (string Name, string Method, string Url) endpoint,
        int maxAttempts = 3)
    {
        return new NamedBackendEndpoint
        {
            Name = endpoint.Name,
            Method = endpoint.Method.ToUpperInvariant(),
            UrlTemplate = endpoint.Url,
            BackendAuthPolicy = BackendAuthPolicies.None,
            EnableRetries = true,
            MaxRetryAttempts = maxAttempts
        };
    }
}

/// <summary>
/// Collection of named backend endpoints for multi-backend transformers.
/// </summary>
public sealed class NamedBackendEndpoints
{
    private readonly Dictionary<string, NamedBackendEndpoint> _endpoints = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Adds an endpoint to the collection.
    /// </summary>
    public void Add(NamedBackendEndpoint endpoint) => _endpoints[endpoint.Name] = endpoint;

    /// <summary>
    /// Gets an endpoint by name.
    /// </summary>
    /// <param name="name">The endpoint name</param>
    /// <returns>The endpoint configuration</returns>
    /// <exception cref="InvalidOperationException">Thrown when endpoint is not found</exception>
    public NamedBackendEndpoint Get(string name)
    {
        if (!_endpoints.TryGetValue(name, out var endpoint))
        {
            throw new InvalidOperationException(
                $"Backend endpoint '{name}' not configured. " +
                $"Available endpoints: {string.Join(", ", _endpoints.Keys)}. " +
                "Ensure ToBackends() is called with this endpoint name in the endpoint registration.");
        }
        return endpoint;
    }

    /// <summary>
    /// Tries to get an endpoint by name.
    /// </summary>
    public bool TryGet(string name, out NamedBackendEndpoint? endpoint) => _endpoints.TryGetValue(name, out endpoint);

    /// <summary>
    /// Gets all configured endpoint names.
    /// </summary>
    public IEnumerable<string> Names => _endpoints.Keys;

    /// <summary>
    /// Gets the count of configured endpoints.
    /// </summary>
    public int Count => _endpoints.Count;

    /// <summary>
    /// Returns a copy in which every leg with <see cref="NamedBackendEndpoint.OptionalAuth"/> is
    /// downgraded to <see cref="BackendAuthPolicies.None"/>. Used by optional-auth endpoints
    /// (<c>AllowAnonymousWithOptionalAuth()</c>) for anonymous callers, who have no token to
    /// forward or exchange. Non-optional legs are shared unchanged - the startup validator
    /// guarantees no mandatory user-identity leg exists on an optional-auth endpoint.
    /// </summary>
    internal NamedBackendEndpoints WithoutOptionalAuth()
    {
        var copy = new NamedBackendEndpoints();
        foreach (var endpoint in _endpoints.Values)
        {
            copy.Add(endpoint.OptionalAuth
                ? endpoint with
                {
                    BackendAuthPolicy = BackendAuthPolicies.None,
                    UseTokenExchange = false,
                    ForwardUserToken = false,
                    TokenExchangeAudience = null,
                    OptionalAuth = false
                }
                : endpoint);
        }
        return copy;
    }
}
