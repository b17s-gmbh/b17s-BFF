using Microsoft.AspNetCore.Http;

namespace b17s.Porta.Configuration;

/// <summary>
/// Configuration for session-based authentication
/// </summary>
public class SessionAuthenticationConfiguration
{
    /// <summary>
    /// Name of the authentication cookie
    /// </summary>
    public string CookieName { get; set; } = "__Porta";

    /// <summary>
    /// OAuth scopes to request
    /// </summary>
    public string Scope { get; set; } = "openid profile email";

    /// <summary>
    /// OIDC authority URL
    /// </summary>
    public string Authority { get; set; } = string.Empty;

    /// <summary>
    /// Whether to require HTTPS for OIDC metadata and the OIDC handler's authority (default: true).
    /// Set to false only for local development against a non-HTTPS IdP.
    /// </summary>
    public bool RequireHttpsMetadata { get; set; } = true;

    /// <summary>
    /// OAuth client ID
    /// </summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>
    /// OAuth client secret
    /// </summary>
    public string ClientSecret { get; set; } = string.Empty;

    /// <summary>
    /// Whether to use PKCE
    /// </summary>
    public bool UsePkce { get; set; } = true;

    /// <summary>
    /// Session timeout in minutes
    /// </summary>
    public int SessionTimeoutInMin { get; set; } = 60;

    /// <summary>
    /// Token exchange strategy
    /// </summary>
    public string TokenExchangeStrategy { get; set; } = "default";

    /// <summary>
    /// Whether to query the OIDC UserInfo endpoint for additional claims after id_token validation.
    /// </summary>
    public bool QueryUserInfoEndpoint { get; set; } = true;

    /// <summary>
    /// Cookie security settings
    /// </summary>
    public CookieSecurityConfiguration Cookie { get; set; } = new();

    /// <summary>
    /// Controls how the default authentication challenge distinguishes interactive
    /// browser navigations from programmatic requests.
    /// </summary>
    public ChallengeDispatchConfiguration Challenge { get; set; } = new();

    /// <summary>
    /// Token refresh resilience configuration for retry logic and circuit breaker
    /// </summary>
    public TokenRefreshResilienceConfiguration Resilience { get; set; } = new();

    /// <summary>
    /// Data Protection configuration for encrypting tokens at rest in Redis/Valkey
    /// </summary>
    public DataProtectionConfiguration DataProtection { get; set; } = new();

    /// <summary>
    /// Session key configuration for storing tokens in session storage.
    /// IMPORTANT: When multiple BFF instances share the same Redis instance,
    /// each BFF should have a unique key prefix to avoid collisions.
    /// </summary>
    public SessionKeyConfiguration SessionKeys { get; set; } = new();
}

/// <summary>Controls Porta's default authentication challenge dispatcher.</summary>
public sealed class ChallengeDispatchConfiguration
{
    /// <summary>Gets or sets the dispatch mode. The default is <see cref="ChallengeDispatchMode.Auto"/>.</summary>
    public ChallengeDispatchMode Mode { get; set; } = ChallengeDispatchMode.Auto;

    /// <summary>
    /// Optional final classifier override used in <see cref="ChallengeDispatchMode.Auto"/>.
    /// Return <see langword="true"/> to redirect to OIDC or <see langword="false"/> to return 401.
    /// This hook replaces the built-in classifier, including its safe-method check.
    /// </summary>
    public Func<HttpContext, bool>? Classifier { get; set; }

    /// <summary>
    /// Optional login endpoint path for applications that do not use <c>UseOidcLogin</c>,
    /// or to disambiguate multiple registered login endpoints.
    /// </summary>
    public string? LoginPath { get; set; }

    internal ChallengeDispatchConfiguration Clone() => (ChallengeDispatchConfiguration)MemberwiseClone();
}

/// <summary>Specifies how Porta responds to the default authentication challenge.</summary>
public enum ChallengeDispatchMode
{
    /// <summary>Redirect safe interactive document navigations; return 401 otherwise.</summary>
    Auto,
    /// <summary>Always redirect to the configured OIDC scheme (legacy behavior).</summary>
    Interactive,
    /// <summary>Always return HTTP 401 without redirecting.</summary>
    Unauthorized,
}

/// <summary>
/// Cookie security configuration
/// </summary>
public sealed class CookieSecurityConfiguration
{
    /// <summary>
    /// Cookie SameSite policy
    /// </summary>
    public string SameSite { get; set; } = "Strict";

    /// <summary>
    /// Whether cookie should be HTTP only
    /// </summary>
    public bool HttpOnly { get; set; } = true;

    /// <summary>
    /// Cookie secure policy
    /// </summary>
    public string SecurePolicy { get; set; } = "Always";

    /// <summary>
    /// Cookie expiration time span in minutes
    /// </summary>
    public int ExpireTimeSpanMinutes { get; set; } = 60;

    /// <summary>
    /// Whether to use sliding expiration
    /// </summary>
    public bool SlidingExpiration { get; set; } = false;

    /// <summary>
    /// Creates a shallow-field copy. All members are value types or immutable strings,
    /// so this is a full deep copy and prevents two registered options instances from
    /// aliasing the same sub-object (see <see cref="b17s.Porta.Configuration.OidcAuthOptions"/>).
    /// </summary>
    internal CookieSecurityConfiguration Clone() => (CookieSecurityConfiguration)MemberwiseClone();
}

/// <summary>
/// Token refresh resilience configuration for handling transient failures
/// </summary>
public sealed class TokenRefreshResilienceConfiguration
{
    /// <summary>
    /// Whether to enable retry logic for token refresh (default: true)
    /// </summary>
    public bool EnableRetry { get; set; } = true;

    /// <summary>
    /// Maximum number of retry attempts (default: 3).
    /// Must be at least 1 when <see cref="EnableRetry"/> is <c>true</c> (validated at
    /// startup); to disable retries set <see cref="EnableRetry"/> to <c>false</c>.
    /// </summary>
    public int MaxRetryAttempts { get; set; } = 3;

    /// <summary>
    /// Initial delay before first retry in seconds (default: 1)
    /// Used as base for exponential backoff: delay = InitialDelaySeconds * 2^retryAttempt
    /// </summary>
    public double InitialDelaySeconds { get; set; } = 1.0;

    /// <summary>
    /// Whether to use jitter to prevent thundering herd (default: true)
    /// Adds randomization to retry delays to spread out retry attempts
    /// </summary>
    public bool UseJitter { get; set; } = true;

    /// <summary>
    /// Whether to enable circuit breaker pattern (default: true)
    /// Stops retrying when IdP is consistently failing
    /// </summary>
    public bool EnableCircuitBreaker { get; set; } = true;

    /// <summary>
    /// Failure ratio threshold to open circuit breaker (default: 0.5 = 50%)
    /// If 50% of requests fail within the sampling window, circuit opens
    /// </summary>
    public double CircuitBreakerFailureRatio { get; set; } = 0.5;

    /// <summary>
    /// Sampling duration for circuit breaker in seconds (default: 30)
    /// Time window to measure failure ratio
    /// </summary>
    public double CircuitBreakerSamplingDurationSeconds { get; set; } = 30.0;

    /// <summary>
    /// Minimum throughput required before circuit breaker activates (default: 10)
    /// Prevents circuit from opening on low traffic
    /// </summary>
    public int CircuitBreakerMinimumThroughput { get; set; } = 10;

    /// <summary>
    /// Duration to keep circuit open before attempting recovery in seconds (default: 30)
    /// After this period, circuit moves to half-open state to test recovery
    /// </summary>
    public double CircuitBreakerBreakDurationSeconds { get; set; } = 30.0;

    /// <summary>
    /// HTTP request timeout in seconds (default: 10)
    /// Maximum time to wait for IdP response
    /// </summary>
    public double RequestTimeoutSeconds { get; set; } = 10.0;

    /// <summary>
    /// Creates a full copy (all members are value types). Prevents two registered
    /// options instances from aliasing the same sub-object.
    /// </summary>
    internal TokenRefreshResilienceConfiguration Clone() => (TokenRefreshResilienceConfiguration)MemberwiseClone();
}

/// <summary>
/// Data Protection configuration for encrypting sensitive data at rest
/// </summary>
public sealed class DataProtectionConfiguration
{
    /// <summary>
    /// Application name used for Data Protection key-derivation purpose-strings.
    /// IMPORTANT: Must be identical across all BFF instances in the cluster.
    /// Change this value to rotate all encryption keys.
    ///
    /// Default (when left empty): derived at startup from the host's entry-assembly
    /// name plus "/Porta" - e.g. <c>"MyApp.Api/Porta"</c>. This auto-uniquifies the
    /// purpose-string namespace so two unrelated BFFs on shared infrastructure
    /// (same Redis, same EF store) don't collide. Set explicitly to opt out of
    /// the auto-derivation (e.g. to keep the same value when renaming an
    /// assembly, or to share keys across applications by design).
    /// </summary>
    public string ApplicationName { get; set; } = string.Empty;

    /// <summary>
    /// Number of days before keys expire and are rotated.
    /// Default: 90 days (recommended by Microsoft)
    /// </summary>
    public int KeyLifetimeDays { get; set; } = 90;

    // Note: Redis persistence and key encryption at rest are wired explicitly via
    // the AddPortaDataProtection* / AddPortaDataProtectionWithEntityFrameworkStore
    // helpers (see DataProtectionExtensions). The BFF used to surface knobs here
    // for connection strings, key prefixes, and certificate thumbprints, but
    // they were never read - leaving them on the type lied to consumers that
    // configuration alone was enough to enable the corresponding behavior.

    /// <summary>
    /// Creates a full copy (all members are value types or immutable strings).
    /// Prevents two registered options instances from aliasing the same sub-object.
    /// </summary>
    internal DataProtectionConfiguration Clone() => (DataProtectionConfiguration)MemberwiseClone();
}

/// <summary>
/// Session key configuration for storing authentication tokens in session storage.
/// When multiple BFF instances share the same Redis instance, each should use a unique prefix.
/// </summary>
public sealed class SessionKeyConfiguration
{
    /// <summary>
    /// Key prefix for all session keys used by this BFF instance.
    /// Default: "porta" - IMPORTANT: Change this when sharing Redis with other BFF instances.
    /// Example: "customer-portal.porta" or "admin-porta"
    /// </summary>
    public string Prefix { get; set; } = "porta";

    /// <summary>
    /// Key for storing the access token in the session.
    /// Full key will be: {Prefix}.access_token
    /// </summary>
    public string AccessTokenKey { get; set; } = "access_token";

    /// <summary>
    /// Key for storing the ID token in the session.
    /// Full key will be: {Prefix}.id_token
    /// </summary>
    public string IdTokenKey { get; set; } = "id_token";

    /// <summary>
    /// Key for storing the refresh token in the session.
    /// Full key will be: {Prefix}.refresh_token
    /// </summary>
    public string RefreshTokenKey { get; set; } = "refresh_token";

    /// <summary>
    /// Key for storing the token expiration time in the session.
    /// Full key will be: {Prefix}.expires_at
    /// </summary>
    public string ExpiresAtKey { get; set; } = "expires_at";

    /// <summary>
    /// Key for storing API-specific access tokens in the session.
    /// Full key will be: {Prefix}.api_access_token
    /// </summary>
    public string ApiAccessTokenKey { get; set; } = "api_access_token";

    /// <summary>
    /// Key prefix for user-specific session data.
    /// Full key will be: {Prefix}.user.{property}
    /// </summary>
    public string UserPrefix { get; set; } = "user";

    /// <summary>
    /// Key for storing authentication context in the session.
    /// Full key will be: {Prefix}.auth_context
    /// </summary>
    public string AuthContextKey { get; set; } = "auth_context";

    /// <summary>
    /// Gets the full session key with prefix.
    /// </summary>
    /// <param name="key">The unprefixed key name (e.g. one of the <c>*Key</c> properties)</param>
    /// <returns>The session key in the form <c>{Prefix}.{key}</c></returns>
    public string GetFullKey(string key) => $"{Prefix}.{key}";

    /// <summary>
    /// Gets the full access token key.
    /// </summary>
    /// <returns>The prefixed session key for <see cref="AccessTokenKey"/></returns>
    public string GetAccessTokenKey() => GetFullKey(AccessTokenKey);

    /// <summary>
    /// Gets the full ID token key.
    /// </summary>
    /// <returns>The prefixed session key for <see cref="IdTokenKey"/></returns>
    public string GetIdTokenKey() => GetFullKey(IdTokenKey);

    /// <summary>
    /// Gets the full refresh token key.
    /// </summary>
    /// <returns>The prefixed session key for <see cref="RefreshTokenKey"/></returns>
    public string GetRefreshTokenKey() => GetFullKey(RefreshTokenKey);

    /// <summary>
    /// Gets the full expires at key.
    /// </summary>
    /// <returns>The prefixed session key for <see cref="ExpiresAtKey"/></returns>
    public string GetExpiresAtKey() => GetFullKey(ExpiresAtKey);

    /// <summary>
    /// Gets the full API access token key.
    /// </summary>
    /// <returns>The prefixed session key for <see cref="ApiAccessTokenKey"/></returns>
    public string GetApiAccessTokenKey() => GetFullKey(ApiAccessTokenKey);

    /// <summary>
    /// Gets the full user prefix.
    /// </summary>
    /// <returns>The prefixed key namespace for <see cref="UserPrefix"/></returns>
    public string GetUserPrefix() => GetFullKey(UserPrefix);

    /// <summary>
    /// Gets the full auth context key.
    /// </summary>
    /// <returns>The prefixed session key for <see cref="AuthContextKey"/></returns>
    public string GetAuthContextKey() => GetFullKey(AuthContextKey);

    /// <summary>
    /// Creates a full copy (all members are immutable strings). Prevents two
    /// registered options instances from aliasing the same sub-object.
    /// </summary>
    internal SessionKeyConfiguration Clone() => (SessionKeyConfiguration)MemberwiseClone();
}
