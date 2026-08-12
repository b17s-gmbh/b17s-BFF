namespace b17s.Porta.Transformers;

/// <summary>
/// Abstraction for applying authentication to backend HTTP requests.
/// Implement this interface to add custom backend authentication policies beyond the built-in ones.
/// </summary>
/// <remarks>
/// <para>
/// The BFF library uses backend auth handlers to authenticate requests to backend services.
/// Each handler is identified by a unique policy name (e.g., "BasicAuth", "BearerToken").
/// </para>
/// <para>
/// Built-in handlers:
/// <list type="bullet">
/// <item><description><c>None</c> - No authentication</description></item>
/// <item><description><c>BearerToken</c> - Forwards user's OAuth token</description></item>
/// <item><description><c>TokenExchange</c> - Exchanges user token for backend-specific token</description></item>
/// <item><description><c>BasicAuth</c> - HTTP Basic auth with configured credentials</description></item>
/// </list>
/// </para>
/// <para>
/// To add a custom handler:
/// <code>
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
/// services.AddPortaAuthHandler&lt;HmacAuthHandler&gt;();
/// </code>
/// </para>
/// </remarks>
public interface IBackendAuthHandler
{
    /// <summary>
    /// The unique policy name that identifies this authentication handler.
    /// This name is used in <c>.WithBackendAuth("PolicyName")</c> when configuring endpoints.
    /// </summary>
    string PolicyName { get; }

    /// <summary>
    /// Applies authentication to the outgoing HTTP request.
    /// </summary>
    /// <param name="request">The HTTP request message to authenticate</param>
    /// <param name="context">Context containing user info, tokens, and request metadata</param>
    /// <returns>A task that completes when authentication is applied</returns>
    /// <remarks>
    /// Common authentication patterns:
    /// <list type="bullet">
    /// <item><description>Add Authorization header: <c>request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token)</c></description></item>
    /// <item><description>Add custom headers: <c>request.Headers.Add("X-Api-Key", apiKey)</c></description></item>
    /// <item><description>Add query parameters: Modify the request URI</description></item>
    /// </list>
    /// </remarks>
    Task ApplyAuthAsync(HttpRequestMessage request, BackendAuthContext context);
}

/// <summary>
/// Context provided to backend auth handlers containing user identity, tokens, and request metadata.
/// </summary>
public sealed class BackendAuthContext
{
    /// <summary>
    /// The user's access token from the current session (if authenticated).
    /// </summary>
    public string? AccessToken { get; init; }

    /// <summary>
    /// Claims from the authenticated user, or empty when the request has no authenticated user
    /// (or the host did not register <c>IHttpContextAccessor</c>).
    /// Key is the claim type, value is the claim value. When the user carries multiple claims of
    /// the same type (e.g. several <c>role</c> claims), the first value wins.
    /// </summary>
    public IReadOnlyDictionary<string, string> Claims { get; init; } = new Dictionary<string, string>();

    /// <summary>
    /// The backend request being authenticated.
    /// </summary>
    public required BackendRequest BackendRequest { get; init; }

    /// <summary>
    /// Cancellation token for the request.
    /// </summary>
    public CancellationToken CancellationToken { get; init; }

    /// <summary>
    /// True when this application runs on the retry of a call whose first attempt the backend
    /// rejected with <c>401</c>. Handlers that cache a credential they mint themselves (e.g. the
    /// built-in <c>ClientCredentials</c> handler) should bypass/invalidate their cache and acquire
    /// a fresh one; handlers whose credential comes from elsewhere can ignore it.
    /// </summary>
    public bool ForceFreshCredential { get; init; }
}

/// <summary>
/// Registry for backend auth handlers. Resolves handlers by policy name.
/// </summary>
public interface IBackendAuthHandlerRegistry
{
    /// <summary>
    /// Gets the handler for the specified policy name.
    /// </summary>
    /// <param name="policyName">The policy name (e.g., "BasicAuth", "BearerToken")</param>
    /// <returns>The handler, or null if not found</returns>
    IBackendAuthHandler? GetHandler(string policyName);

    /// <summary>
    /// Gets all registered handler policy names.
    /// </summary>
    IEnumerable<string> GetRegisteredPolicies();
}

/// <summary>
/// Default implementation of the backend auth handler registry.
/// </summary>
public sealed class BackendAuthHandlerRegistry : IBackendAuthHandlerRegistry
{
    private readonly Dictionary<string, IBackendAuthHandler> _handlers = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Registers a handler in the registry.
    /// </summary>
    public void Register(IBackendAuthHandler handler) => _handlers[handler.PolicyName] = handler;

    /// <inheritdoc />
    public IBackendAuthHandler? GetHandler(string policyName) => _handlers.TryGetValue(policyName, out var handler) ? handler : null;

    /// <inheritdoc />
    public IEnumerable<string> GetRegisteredPolicies() => _handlers.Keys;
}
