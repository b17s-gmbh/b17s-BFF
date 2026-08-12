using System;

namespace b17s.Porta.Transformers;

/// <summary>
/// Common base class for fluent BFF endpoint builders.
/// Extracts duplicate configuration methods for HTTP mapping, timeouts, and auth policies.
/// </summary>
public abstract class BffEndpointBuilderBase<TBuilder>
    where TBuilder : BffEndpointBuilderBase<TBuilder>
{
    private protected string? _httpMethod;
    private protected string? _routePattern;
    private protected string? _backendMethod;
    private protected string? _backendUrl;
    private protected string? _authPolicy;
    private protected bool? _requireAuth;
    // Set by AllowAnonymousWithOptionalAuth(): the endpoint admits anonymous callers but keeps
    // its user-identity backend-auth configuration (BearerToken/TokenExchange) for callers that
    // do present credentials. Only the transformer builder exposes a setter; raw forward does not.
    private protected bool _optionalUserIdentity;
    // Set by WithBackendAuth(policy, optional: true) / WithTokenExchange(audience, optional: true):
    // the backend auth is applied only when the caller authenticated. Valid solely on
    // AllowAnonymousWithOptionalAuth() endpoints with a user-identity policy; the validator
    // rejects every other placement at startup.
    private protected bool _backendAuthOptional;
    private protected TimeSpan? _timeout;
    private protected string? _backendAuthPolicy;

    /// <summary>
    /// The current instance typed as the most-derived builder (CRTP), so fluent setters can return
    /// <typeparamref name="TBuilder"/> for chaining.
    /// </summary>
    protected TBuilder Self => (TBuilder)this;

    /// <summary>
    /// Specifies the incoming HTTP method and route pattern.
    /// </summary>
    public TBuilder FromRoute(string method, string routePattern)
    {
        _httpMethod = method.ToUpperInvariant();
        _routePattern = routePattern;
        return Self;
    }

    /// <summary>Specifies a GET route pattern.</summary>
    public TBuilder FromGet(string routePattern) => FromRoute("GET", routePattern);

    /// <summary>Specifies a POST route pattern.</summary>
    public TBuilder FromPost(string routePattern) => FromRoute("POST", routePattern);

    /// <summary>Specifies a PUT route pattern.</summary>
    public TBuilder FromPut(string routePattern) => FromRoute("PUT", routePattern);

    /// <summary>Specifies a DELETE route pattern.</summary>
    public TBuilder FromDelete(string routePattern) => FromRoute("DELETE", routePattern);

    /// <summary>Specifies a PATCH route pattern.</summary>
    public TBuilder FromPatch(string routePattern) => FromRoute("PATCH", routePattern);

    /// <summary>Specifies a HEAD route pattern.</summary>
    public TBuilder FromHead(string routePattern) => FromRoute("HEAD", routePattern);

    /// <summary>Specifies an OPTIONS route pattern.</summary>
    public TBuilder FromOptions(string routePattern) => FromRoute("OPTIONS", routePattern);

    /// <summary>
    /// Matches any HTTP method on the specified route pattern.
    /// </summary>
    public TBuilder FromAny(string routePattern)
    {
        _httpMethod = "*";
        _routePattern = routePattern;
        return Self;
    }

    /// <summary>
    /// Forwards to backend using the same HTTP method as the incoming request.
    /// </summary>
    public TBuilder ToAny(string url)
    {
        _backendMethod = "*";
        _backendUrl = url;
        return Self;
    }

    /// <summary>Requires authentication with an optional policy.</summary>
    public TBuilder RequireAuth(string? policy = null)
    {
        _requireAuth = true;
        _authPolicy = policy;
        _optionalUserIdentity = false;
        return Self;
    }

    /// <summary>
    /// Allows anonymous access (no authentication required). Typed transformer endpoints treat
    /// this as credential-blind: the auth context is never resolved, so the transformer always
    /// sees an empty <c>AuthContext</c> even when the caller sent valid credentials, and a
    /// user-identity backend-auth policy (BearerToken / TokenExchange) cannot be combined with it.
    /// Use <c>AllowAnonymousWithOptionalAuth()</c> on transformer endpoints to resolve credentials
    /// opportunistically instead.
    /// </summary>
    public TBuilder AllowAnonymous()
    {
        _requireAuth = false;
        _authPolicy = null;
        _optionalUserIdentity = false;
        return Self;
    }

    /// <summary>
    /// Allows anonymous access while still resolving the caller's credentials when present: the
    /// auth context is resolved optionally, so an authenticated caller's identity populates the
    /// transformer's <c>AuthContext</c> while an anonymous request passes through with an empty
    /// one. This is the middle rung of the auth ladder - <c>AllowAnonymous()</c> is
    /// credential-blind (never resolves auth), <c>RequireAuth()</c> is mandatory.
    /// </summary>
    /// <param name="policy">
    /// Optional authorization policy gating the authenticated treatment. When set, a caller with
    /// valid credentials must also pass this policy (evaluated against <c>HttpContext.User</c>, so
    /// an authentication scheme must be registered - same requirement as <c>RequireAuth(policy)</c>)
    /// to count as authenticated; a caller that fails it is served the anonymous view instead of a
    /// 403 - anonymous access is allowed anyway, so failing the policy only removes privilege.
    /// </param>
    /// <remarks>
    /// To also authenticate the BACKEND call for callers that presented credentials, pair this with
    /// optional backend auth: <c>WithBackendAuth(BackendAuthPolicies.BearerToken, optional: true)</c>,
    /// <c>WithTokenExchange(audience, optional: true)</c> (typed endpoints), or
    /// <c>WithUserToken(optional: true)</c> / <c>WithAuth(policy, optional: true)</c> on a named
    /// backend. The BFF then converts whatever the frontend sent (e.g. a session cookie) into the
    /// credential the backend expects for authenticated callers, and calls the backend with no auth
    /// for anonymous ones. Mandatory (non-optional) user-identity backend auth cannot be combined
    /// with this method - it promises an identity that anonymous callers do not have, and startup
    /// fails.
    /// <para/>
    /// Trusted-host validation still applies: a backend that can receive the user's token (directly
    /// or via exchange) must be listed in <c>PortaCore:TrustedHosts</c>, exactly as on a
    /// <c>RequireAuth()</c> endpoint.
    /// </remarks>
    public TBuilder AllowAnonymousWithOptionalAuth(string? policy = null)
    {
        _requireAuth = false;
        _authPolicy = policy;
        _optionalUserIdentity = true;
        return Self;
    }

    /// <summary>Sets a timeout for the backend call.</summary>
    public TBuilder WithTimeout(TimeSpan timeout)
    {
        _timeout = timeout;
        return Self;
    }

    /// <summary>Specifies the backend authentication policy.</summary>
    /// <param name="policy">The backend authentication policy name (see <c>BackendAuthPolicies</c>).</param>
    /// <param name="optional">
    /// When true, the policy is applied only for callers that authenticated; anonymous callers hit
    /// the backend with no auth. Only valid for user-identity policies (BearerToken/TokenExchange)
    /// on an endpoint marked <c>AllowAnonymousWithOptionalAuth()</c> - any other placement fails at
    /// startup, because it either can never change behavior (RequireAuth) or has no optional auth
    /// resolution to key off (AllowAnonymous, non-identity policies).
    /// </param>
    public TBuilder WithBackendAuth(string policy, bool optional = false)
    {
        _backendAuthPolicy = policy;
        _backendAuthOptional = optional;
        return Self;
    }
}
