namespace b17s.Porta.Transformers;

/// <summary>
/// Startup-time gate for the endpoint-auth / backend-auth matrix. Throws when a transformer
/// endpoint has at least one backend that requires user identity (forwarded user token, token
/// exchange, or a backend-auth policy that names a user) but the endpoint cannot guarantee one:
/// <list type="bullet">
/// <item><description><c>RequireAuth()</c> endpoints may use any backend auth - identity is always
/// present. The <c>optional</c> flag is rejected there as dead configuration.</description></item>
/// <item><description><c>AllowAnonymousWithOptionalAuth()</c> endpoints may use user-identity
/// backend auth only in its <c>optional: true</c> form (applied when the caller authenticated,
/// skipped when anonymous). Mandatory user-identity backend auth is rejected - it promises an
/// identity anonymous callers do not have.</description></item>
/// <item><description><c>AllowAnonymous()</c> endpoints are credential-blind and reject
/// user-identity backend auth in any form.</description></item>
/// </list>
/// A transformer-level <see cref="RequiresAuthenticationAttribute"/> is never exempt - it declares
/// the transformer cannot run without an identity at all.
/// </summary>
internal static class EndpointAuthorizationValidator
{
    /// <summary>
    /// Throws if the named backend-auth policy is not registered. Catches typos
    /// like <c>WithBackendAuth("BAsicAUth")</c> at build time so that requests
    /// can never silently fall back to forwarding the user's bearer token.
    /// </summary>
    public static void ValidatePolicyRegistered(
        string? policy,
        IBackendAuthHandlerRegistry? registry,
        string context)
    {
        if (string.IsNullOrEmpty(policy) || registry == null)
        {
            return;
        }

        if (registry.GetHandler(policy) == null)
        {
            var registered = string.Join(", ", registry.GetRegisteredPolicies());
            throw new InvalidOperationException(
                $"Unknown backend auth policy '{policy}' for {context}. " +
                $"Registered policies: [{registered}]. " +
                $"Check for typos or register the handler with services.AddPortaAuthHandler<T>().");
        }
    }


    public static void Validate(
        string? routePattern,
        string? backendAuthPolicy,
        bool useTokenExchange,
        string? tokenExchangeAudience,
        NamedBackendEndpoints namedBackends,
        bool effectiveRequireAuth,
        IBackendAuthHandlerRegistry? authHandlerRegistry = null,
        Type? transformerType = null,
        bool optionalUserIdentity = false,
        bool backendAuthOptional = false)
    {
        ValidatePolicyRegistered(backendAuthPolicy, authHandlerRegistry, $"endpoint '{routePattern}'");
        foreach (var name in namedBackends.Names)
        {
            if (namedBackends.TryGet(name, out var endpoint) && endpoint != null)
            {
                ValidatePolicyRegistered(
                    endpoint.BackendAuthPolicy,
                    authHandlerRegistry,
                    $"endpoint '{routePattern}' backend '{endpoint.Name}'");
            }
        }

        // The optional flag is only meaningful on a user-identity policy of an
        // AllowAnonymousWithOptionalAuth() endpoint; reject every other placement loudly.
        if (backendAuthOptional)
        {
            ValidateOptionalPlacement(
                $"endpoint '{routePattern}'",
                backendAuthPolicy,
                useTokenExchange || BackendAuthPolicies.RequiresUserIdentity(backendAuthPolicy),
                optionalUserIdentity);
        }

        foreach (var name in namedBackends.Names)
        {
            if (namedBackends.TryGet(name, out var endpoint)
                && endpoint is { OptionalAuth: true })
            {
                ValidateOptionalPlacement(
                    $"endpoint '{routePattern}' backend '{endpoint.Name}'",
                    endpoint.BackendAuthPolicy,
                    endpoint.ForwardUserToken
                        || endpoint.UseTokenExchange
                        || BackendAuthPolicies.RequiresUserIdentity(endpoint.BackendAuthPolicy),
                    optionalUserIdentity);
            }
        }

        // MANDATORY identity sources need a guaranteed identity (RequireAuth). Optional-flagged
        // sources are exempt - they downgrade to no-auth for anonymous callers at request time.
        // A [RequiresAuthentication] transformer is always mandatory: it cannot run anonymously.
        var backendsRequiringIdentity = CollectIdentitySources(
            transformerType,
            backendAuthOptional ? null : backendAuthPolicy,
            useTokenExchange && !backendAuthOptional,
            tokenExchangeAudience);

        foreach (var name in namedBackends.Names)
        {
            if (namedBackends.TryGet(name, out var endpoint)
                && endpoint is { OptionalAuth: false })
            {
                if (endpoint.ForwardUserToken
                    || BackendAuthPolicies.RequiresUserIdentity(endpoint.BackendAuthPolicy)
                    || endpoint.UseTokenExchange)
                {
                    backendsRequiringIdentity.Add($"'{endpoint.Name}' (policy: {endpoint.BackendAuthPolicy ?? "None"})");
                }
            }
        }

        ThrowIfAnonymous(routePattern, backendsRequiringIdentity, effectiveRequireAuth, optionalUserIdentity);
    }

    /// <summary>
    /// Single-backend variant of <see cref="Validate"/> for builders that carry one
    /// backend policy and a require-auth flag (raw forwarding). Enforces the same
    /// auth-ladder rules as typed endpoints: a mandatory user-identity policy needs a
    /// guaranteed identity, an <c>optional: true</c> policy needs an
    /// <c>AllowAnonymousWithOptionalAuth()</c> endpoint and a user-identity policy.
    /// </summary>
    public static void ValidateSingleBackend(
        string? routePattern,
        string? backendAuthPolicy,
        bool effectiveRequireAuth,
        Type? transformerType = null,
        bool optionalUserIdentity = false,
        bool backendAuthOptional = false)
    {
        if (backendAuthOptional)
        {
            ValidateOptionalPlacement(
                $"endpoint '{routePattern}'",
                backendAuthPolicy,
                BackendAuthPolicies.RequiresUserIdentity(backendAuthPolicy),
                optionalUserIdentity);
        }

        var backendsRequiringIdentity = CollectIdentitySources(
            transformerType,
            backendAuthOptional ? null : backendAuthPolicy,
            useTokenExchange: false,
            tokenExchangeAudience: null);
        ThrowIfAnonymous(routePattern, backendsRequiringIdentity, effectiveRequireAuth, optionalUserIdentity);
    }

    // The optional flag's two invalid placements: on a policy that never carries the caller's
    // identity (nothing to make optional), or on an endpoint without optional auth resolution
    // (RequireAuth: can never change behavior; AllowAnonymous: never resolves credentials).
    private static void ValidateOptionalPlacement(
        string context,
        string? policy,
        bool isUserIdentityAuth,
        bool optionalUserIdentity)
    {
        if (!isUserIdentityAuth)
        {
            throw new InvalidOperationException(
                $"{context} marks backend auth as optional, but policy '{policy ?? "None"}' never carries " +
                "the caller's identity, so there is nothing to apply optionally. Remove the optional flag " +
                "or use a user-identity policy (BearerToken/TokenExchange).");
        }

        if (!optionalUserIdentity)
        {
            throw new InvalidOperationException(
                $"{context} marks backend auth as optional, but the endpoint is not marked " +
                "AllowAnonymousWithOptionalAuth(). On RequireAuth() endpoints the flag can never change " +
                "behavior (identity is always present); on AllowAnonymous() endpoints credentials are " +
                "never resolved. Mark the endpoint AllowAnonymousWithOptionalAuth() or remove the flag.");
        }
    }

    private static List<string> CollectIdentitySources(
        Type? transformerType,
        string? backendAuthPolicy,
        bool useTokenExchange,
        string? tokenExchangeAudience)
    {
        var sources = new List<string>();

        if (transformerType?.IsDefined(typeof(RequiresAuthenticationAttribute), inherit: true) == true)
        {
            sources.Add($"transformer {transformerType.Name} ([RequiresAuthentication])");
        }

        if (BackendAuthPolicies.RequiresUserIdentity(backendAuthPolicy))
        {
            sources.Add($"ToBackend (policy: {backendAuthPolicy})");
        }

        if (useTokenExchange)
        {
            sources.Add($"ToBackend (token exchange: {tokenExchangeAudience})");
        }

        return sources;
    }

    private static void ThrowIfAnonymous(
        string? routePattern,
        List<string> backendsRequiringIdentity,
        bool effectiveRequireAuth,
        bool optionalUserIdentity)
    {
        if (backendsRequiringIdentity.Count > 0 && !effectiveRequireAuth)
        {
            var hint = optionalUserIdentity
                ? "Mark the backend auth optional (WithBackendAuth(policy, optional: true) / " +
                  "WithTokenExchange(audience, optional: true) / WithUserToken(optional: true)) so it " +
                  "applies only to authenticated callers, or use RequireAuth()."
                : "Use RequireAuth(), or AllowAnonymousWithOptionalAuth() with the backend auth marked " +
                  "optional (e.g. WithBackendAuth(policy, optional: true)) to forward the user's token " +
                  "only when a caller is authenticated.";
            throw new InvalidOperationException(
                $"Endpoint '{routePattern}' requires user identity but allows anonymous access. {hint} " +
                $"Sources requiring identity: [{string.Join(", ", backendsRequiringIdentity)}]");
        }
    }
}
