namespace b17s.Porta.Configuration;

/// <summary>
/// Configuration for a backend service used by the built-in BasicAuth handler.
/// For more advanced scenarios, implement a custom IBackendAuthHandler.
/// </summary>
public sealed class BackendServiceOptions
{
    /// <summary>
    /// The default configuration section name (<c>"BackendService"</c>) this options type binds to.
    /// </summary>
    public const string SectionName = "BackendService";

    /// <summary>
    /// Base URL of the backend service. Used as the destination host for the built-in
    /// BasicAuth handler and as the default target for single-backend deployments.
    /// </summary>
    public string BaseUrl { get; set; } = string.Empty;

    /// <summary>
    /// Default Basic auth credentials, used when no per-backend entry matches the
    /// current request's backend name. Kept for backwards compatibility with
    /// single-backend deployments.
    /// </summary>
    public BasicAuthOptions BasicAuth { get; set; } = new();

    /// <summary>
    /// Per-backend Basic auth credentials, keyed by the backend name supplied via
    /// <c>BackendRequest.BackendName</c>. When the name matches, these credentials
    /// override <see cref="BasicAuth"/>; otherwise see <see cref="AllowGlobalBasicAuthFallback"/>.
    /// </summary>
    public Dictionary<string, BasicAuthOptions> Backends { get; set; }
        = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Controls what happens when a request names a specific backend (via
    /// <c>BackendRequest.BackendName</c>) that has no matching entry in <see cref="Backends"/>.
    /// <para>
    /// Default <c>false</c> (fail closed): the BasicAuth handler sends no <c>Authorization</c>
    /// header rather than falling back to the global <see cref="BasicAuth"/> default - which could
    /// silently forward credentials intended for a different host. Set <c>true</c> to restore the
    /// legacy behaviour where named backends without their own credentials share the global default.
    /// </para>
    /// <para>
    /// This setting does not affect requests that carry no backend name at all; those always use
    /// <see cref="BasicAuth"/>, since that is the unambiguous single-backend / default configuration.
    /// </para>
    /// </summary>
    public bool AllowGlobalBasicAuthFallback { get; set; }

    /// <summary>
    /// Default API key for the built-in ApiKey handler, used when no per-backend entry
    /// matches the current request's backend name.
    /// </summary>
    public ApiKeyOptions ApiKey { get; set; } = new();

    /// <summary>
    /// Per-backend API keys, keyed by the backend name supplied via
    /// <c>BackendRequest.BackendName</c>. When the name matches, this key overrides
    /// <see cref="ApiKey"/>; otherwise see <see cref="AllowGlobalApiKeyFallback"/>.
    /// </summary>
    public Dictionary<string, ApiKeyOptions> ApiKeys { get; set; }
        = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Controls what happens when a request names a specific backend (via
    /// <c>BackendRequest.BackendName</c>) that has no matching entry in <see cref="ApiKeys"/>.
    /// Default <c>false</c> (fail closed): the ApiKey handler sends no credential rather than
    /// falling back to the global <see cref="ApiKey"/> default - which could silently forward a
    /// key intended for a different host. Set <c>true</c> to let named backends without their own
    /// key share the global default. Requests that carry no backend name always use
    /// <see cref="ApiKey"/>.
    /// </summary>
    public bool AllowGlobalApiKeyFallback { get; set; }

    /// <summary>
    /// Default OAuth client-credentials configuration for the built-in ClientCredentials
    /// handler, used when no per-backend entry matches the current request's backend name.
    /// Deliberately separate from <c>SessionAuthentication</c>: the BFF's machine-to-machine
    /// identity is configured here explicitly and never inherited from the login client.
    /// </summary>
    public ClientCredentialsOptions ClientCredentials { get; set; } = new();

    /// <summary>
    /// Per-backend client-credentials configurations, keyed by the backend name supplied via
    /// <c>BackendRequest.BackendName</c>. When the name matches, this entry overrides
    /// <see cref="ClientCredentials"/>; otherwise see
    /// <see cref="AllowGlobalClientCredentialsFallback"/>.
    /// </summary>
    public Dictionary<string, ClientCredentialsOptions> ClientCredentialsBackends { get; set; }
        = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Controls what happens when a request names a specific backend (via
    /// <c>BackendRequest.BackendName</c>) that has no matching entry in
    /// <see cref="ClientCredentialsBackends"/>. Default <c>false</c> (fail closed): the handler
    /// fails the call as a configuration error rather than minting a token with the global
    /// <see cref="ClientCredentials"/> client - whose scopes may grant more than that backend
    /// should receive. Set <c>true</c> to let named backends without their own entry share the
    /// global default. Requests that carry no backend name always use
    /// <see cref="ClientCredentials"/>.
    /// </summary>
    public bool AllowGlobalClientCredentialsFallback { get; set; }

    /// <summary>
    /// Default audience used by the built-in TokenExchange auth handler when an
    /// endpoint declares <c>BackendAuthPolicies.TokenExchange</c> without supplying
    /// an audience inline (i.e. via <c>WithTokenExchange(audience)</c>). When set,
    /// applies to any backend that doesn't override it via
    /// <see cref="TokenExchangeAudiences"/>.
    /// </summary>
    public string? DefaultTokenExchangeAudience { get; set; }

    /// <summary>
    /// Per-backend token exchange audiences, keyed by the backend name supplied via
    /// <c>BackendRequest.BackendName</c>. When the name matches, this audience is
    /// used; otherwise the handler falls back to
    /// <see cref="DefaultTokenExchangeAudience"/>.
    /// </summary>
    public Dictionary<string, string> TokenExchangeAudiences { get; set; }
        = new(StringComparer.OrdinalIgnoreCase);
}

/// <summary>
/// Fixed API key configuration for the built-in ApiKey backend-auth handler.
/// </summary>
public sealed class ApiKeyOptions
{
    /// <summary>
    /// The API key value. Secret-classified - never log this value. When empty, the handler
    /// sends no credential and logs a warning.
    /// </summary>
    public string Token { get; set; } = string.Empty;

    /// <summary>
    /// The <c>Authorization</c> scheme the key is sent under (<c>Authorization: {Scheme} {Token}</c>).
    /// Default <c>Bearer</c>. Ignored when <see cref="HeaderName"/> is set.
    /// </summary>
    public string Scheme { get; set; } = "Bearer";

    /// <summary>
    /// Optional custom header to carry the key instead of <c>Authorization</c>. When set, the
    /// token is sent raw as <c>{HeaderName}: {Token}</c> (e.g. <c>X-Api-Key: s3cret</c>) and
    /// <see cref="Scheme"/> is ignored.
    /// </summary>
    public string? HeaderName { get; set; }
}

/// <summary>
/// OAuth2 client-credentials (RFC 6749 §4.4) configuration for the built-in ClientCredentials
/// backend-auth handler. All three of <see cref="TokenEndpoint"/>, <see cref="ClientId"/> and
/// <see cref="ClientSecret"/> are required when the policy is selected - the handler fails the
/// call as a configuration error when any is missing. Deliberately not inherited from
/// <c>SessionAuthentication</c>.
/// </summary>
public sealed class ClientCredentialsOptions
{
    /// <summary>
    /// The IdP token endpoint the <c>client_credentials</c> grant is posted to
    /// (e.g. <c>https://idp.example.com/connect/token</c>).
    /// </summary>
    public string TokenEndpoint { get; set; } = string.Empty;

    /// <summary>
    /// The OAuth client id of the BFF's machine-to-machine client.
    /// </summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>
    /// The OAuth client secret. Secret-classified - never log this value.
    /// </summary>
    public string ClientSecret { get; set; } = string.Empty;

    /// <summary>
    /// Optional space-separated scopes requested with the grant. Omitted from the token
    /// request when empty.
    /// </summary>
    public string? Scope { get; set; }

    /// <summary>
    /// Optional <c>audience</c> parameter (used by some IdPs, e.g. Auth0). Omitted from the
    /// token request when empty.
    /// </summary>
    public string? Audience { get; set; }
}

/// <summary>
/// Basic authentication credentials.
/// </summary>
public sealed class BasicAuthOptions
{
    /// <summary>
    /// The user name sent in the <c>Authorization: Basic</c> header.
    /// </summary>
    public string Username { get; set; } = string.Empty;

    /// <summary>
    /// The password sent in the <c>Authorization: Basic</c> header. Secret-classified - never log this value.
    /// </summary>
    public string Password { get; set; } = string.Empty;
}
