using b17s.Porta.Transformers;

namespace b17s.Porta.Configuration;

/// <summary>
/// Core configuration options for the BFF library.
/// These are generic options that apply to any BFF deployment, regardless of specific backends.
/// </summary>
public sealed class PortaCoreOptions
{
    /// <summary>
    /// Configuration section name in appsettings.json.
    /// Example: "PortaCore": { "TrustedHosts": ["https://api.example.com"] }
    /// </summary>
    public const string SectionName = "PortaCore";

    /// <summary>
    /// Trusted hosts for user token forwarding (WithUserToken()).
    /// Supports exact matches and wildcard patterns:
    /// - "https://api.example.com" - exact match
    /// - "https://*.example.com" - wildcard subdomain
    /// - "https://api.example.com:8080" - with port
    ///
    /// SECURITY: Only add hosts that you control. User OAuth tokens will be forwarded to these hosts.
    /// </summary>
    public List<string> TrustedHosts { get; set; } = [];

    /// <summary>
    /// Default timeout for backend calls.
    /// Default: 30 seconds
    /// </summary>
    public TimeSpan DefaultTimeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Maximum number of retry attempts when retries are enabled via WithRetries().
    /// Note: Retries are disabled by default and must be explicitly enabled per-endpoint.
    /// A value below 1 disables retries app-wide, including for endpoints that opt in
    /// via WithRetries().
    /// Default: 3
    /// </summary>
    public int MaxRetryAttempts { get; set; } = 3;

    /// <summary>
    /// Whether a backend <c>401 Unauthorized</c> on a user-token policy (<c>BearerToken</c> or
    /// <c>TokenExchange</c>) triggers a one-shot refresh of the user's access token followed by a
    /// single retry with the rotated token. Enabled by default; set to <c>false</c> to opt out
    /// globally.
    /// <para>
    /// The refresh is bounded: exactly one IdP refresh + one retry per request (serialized and
    /// deduplicated across the parallel legs of an aggregation), and the retry is skipped when the
    /// token does not actually rotate - so it never loops and is a no-op for non-refreshable inbound
    /// auth (inbound JWT / reference tokens). Backends authenticated with <c>BasicAuth</c>/<c>None</c>
    /// are never affected, since refreshing the user token cannot fix their credentials.
    /// </para>
    /// <para>
    /// Opt out if a backend legitimately returns <c>401</c> for reasons unrelated to a stale token
    /// (refreshing on every such response would churn the user's refresh token for no benefit).
    /// </para>
    /// </summary>
    public bool RefreshBackendTokenOn401 { get; set; } = true;

    /// <summary>
    /// Whether a successful token refresh also updates the session (cookie) principal's claims
    /// from the NEW <c>id_token</c>, when the IdP returns one with the refresh response. Enabled
    /// by default; set to <c>false</c> to keep the login-time claims for the whole session.
    /// <para>
    /// Semantics: for every claim type present in the new <c>id_token</c>, the session's claims of
    /// that type are replaced with the new values (multi-value types like roles are replaced as a
    /// set, so revoked values disappear). Claim types the new <c>id_token</c> does not carry are
    /// left untouched - IdPs commonly issue leaner id_tokens on refresh than at login, and
    /// treating absence as revocation would silently strip login-only claims. OIDC protocol and
    /// login-time claims (<c>iss</c>, <c>aud</c>, <c>nonce</c>, <c>auth_time</c>, <c>amr</c>, ...)
    /// are never copied.
    /// </para>
    /// <para>
    /// The new <c>id_token</c>'s <c>iss</c> and <c>sub</c> must match the session's previous
    /// <c>id_token</c> (OIDC Core §12.2); on mismatch - or when the token cannot be parsed - the
    /// claims update is skipped with a warning and the refresh proceeds with the existing
    /// principal. The signature is not re-validated: the token arrived over the BFF's own
    /// client-authenticated TLS channel to the token endpoint, the same trust that accepts the
    /// rotated access token.
    /// </para>
    /// </summary>
    public bool RefreshClaimsFromIdToken { get; set; } = true;

    /// <summary>
    /// Whether transformer endpoints require authorization by default.
    /// When true (default), endpoints require authentication unless explicitly marked with AllowAnonymous().
    /// When false, endpoints allow anonymous access unless explicitly marked with RequireAuth().
    /// Default: true
    /// </summary>
    public bool RequireAuthorizationByDefault { get; set; } = true;

    /// <summary>
    /// Whether to enable automatic OpenTelemetry tracing and metrics for transformers.
    /// When enabled, the framework automatically instruments:
    /// - Transformer execution (traces + duration metrics)
    /// - Backend calls (traces + duration/status metrics)
    /// - Multi-backend aggregation (per-backend child spans)
    ///
    /// Spans use fixed category activity names (e.g. "bff.transformation", "bff.backend"); the
    /// specific transformer/backend is carried on a tag ("bff.transformation.strategy",
    /// "bff.backend.service") rather than baked into the activity name.
    ///
    /// Disabling this suppresses only Porta's own spans and metrics; it does not touch the ambient
    /// trace context. An upstream reverse proxy's (or host instrumentation's) trace stays current and
    /// still propagates to backend calls, so external traces are not broken by opting out.
    /// Default: true
    /// </summary>
    public bool EnableTelemetry { get; set; } = true;

    /// <summary>
    /// Whether to tag each cached aggregation leg's <c>bff.backend</c> span with its (hashed) cache key
    /// (<c>cache.key.hash</c>). Off by default: the key varies per route/body/user, so emitting it on
    /// every span adds high-cardinality noise. Enable temporarily to debug cache hit/miss behaviour in
    /// production. Has no effect unless <see cref="EnableTelemetry"/> is also enabled.
    /// Default: false.
    /// </summary>
    public bool VerboseCacheTelemetry { get; set; }

    /// <summary>
    /// Maximum number of bytes the BFF will buffer from a backend response body before
    /// failing the call with <see cref="b17s.Porta.Transformers.BackendErrorType.InvalidResponse"/>.
    /// Applies to the deserialized-response paths (JSON/XML/form) in
    /// <see cref="b17s.Porta.Transformers.BackendCaller"/> and to raw-forward responses
    /// in <see cref="b17s.Porta.Transformers.RawForwardEndpointBuilder{T}"/>.
    ///
    /// SECURITY: Without this cap a misbehaving (or malicious) backend can return a
    /// multi-gigabyte body that the BFF will buffer into a string before deserializing,
    /// trivially OOM'ing the process. A non-positive value (&lt;= 0) disables the cap.
    ///
    /// Default: 10 MiB (10 * 1024 * 1024).
    /// </summary>
    public long MaxBackendResponseBytes { get; set; } = 10 * 1024 * 1024;

    /// <summary>
    /// Maximum bytes the raw-forward path will stream from a backend before closing the
    /// connection with a 502. Separate from <see cref="MaxBackendResponseBytes"/> because
    /// raw-forward legitimately streams larger payloads (file downloads, etc.) but should
    /// still have a ceiling to bound BFF egress.
    ///
    /// Default: 100 MiB. Set to a non-positive value to disable the cap.
    /// </summary>
    public long MaxRawForwardResponseBytes { get; set; } = 100L * 1024 * 1024;

    /// <summary>
    /// Maximum time the raw-forward path will wait between successive reads from a
    /// backend response stream before aborting the call. Defeats slow-loris backends
    /// that dribble bytes to hold a BFF worker open indefinitely.
    ///
    /// Default: 30 seconds. Set to a non-positive value to disable the idle cap.
    /// </summary>
    public TimeSpan RawForwardReadIdleTimeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Maximum number of characters of a backend response body that may be written to the
    /// Trace-level body logs (event IDs 14015, 14016, 14017). Bodies longer than this are
    /// truncated and a marker like "… (truncated, N chars total)" is appended.
    ///
    /// SECURITY: Backend response bodies frequently contain PII or tokens (e.g. GraphQL `me`
    /// queries, OIDC userinfo). Even at Trace level, dumping full bodies risks leaking those
    /// to log sinks. The default cap of 512 chars keeps just enough for diagnostics.
    ///
    /// Special values:
    /// - <c>-1</c>: unlimited (no truncation). Opt-in only - log bodies may contain secrets.
    /// - <c>0</c>: do not emit body logs at all (only metadata logs are written).
    ///
    /// Default: 512
    /// </summary>
    public int MaxBodyLogLength { get; set; } = 512;

    /// <summary>
    /// Clock skew applied when deciding whether an access token is "near expiry"
    /// and should be proactively refreshed. A token whose remaining lifetime is
    /// less than or equal to this value is treated as expired.
    ///
    /// Used by both <see cref="b17s.Porta.Auth.Tokens.AccessTokenRefreshService"/>
    /// (cookie-session access tokens) and the API-token cache in
    /// <see cref="b17s.Porta.Auth.Tokens.ApiTokenService"/>. Keeping a single value
    /// avoids surprising mismatches where one layer considers a token live and
    /// another considers it stale.
    ///
    /// Default: 60 seconds.
    /// </summary>
    public TimeSpan TokenRefreshSkew { get; set; } = TimeSpan.FromSeconds(60);

    /// <summary>
    /// Whether to log raw IdP error response bodies on token exchange/refresh/revocation/introspection
    /// failures. When false (default) the body is dropped before it can land in log sinks or
    /// failure-result strings - only the HTTP status code is recorded. When true, the body is
    /// captured at Debug level and truncated to <see cref="IdpErrorBodyMaxBytes"/>.
    /// <para>
    /// SECURITY: Verbose IdPs (Keycloak, IdentityServer in dev mode, etc.) frequently echo the
    /// submitted refresh token, client secret, or PII back inside the error JSON. When this flag
    /// is true those values may end up in centralized logs and exception telemetry. Leave this off
    /// in production; enable only on a single instance for ad-hoc debugging.
    /// </para>
    /// </summary>
    public bool LogIdpErrorBodies { get; set; }

    /// <summary>
    /// Maximum number of bytes of an IdP error response body that may be logged when
    /// <see cref="LogIdpErrorBodies"/> is enabled. Larger bodies are truncated. Default: 512.
    /// </summary>
    public int IdpErrorBodyMaxBytes { get; set; } = 512;

    /// <summary>
    /// Default raw-forward header pass-through allow-list applied when an endpoint does not
    /// configure its own allow-list. By default, the BFF strips Cookie, Authorization, the
    /// standard <c>Forwarded</c> header, and the <c>X-Forwarded-*</c> family (plus standard
    /// hop-by-hop headers) from raw-forwarded requests to prevent leaking the BFF session
    /// cookie or client credentials to backends, and to stop clients spoofing the forwarded
    /// client IP / host / scheme. Add header names to
    /// <see cref="RawForwardHeaderPassThrough.AllowedHeaders"/> (case-insensitive) to opt them
    /// back in globally, or list trusted front proxies in
    /// <see cref="RawForwardHeaderPassThrough.TrustedForwardingProxies"/> to relay the
    /// forwarding-metadata headers only when the request arrives from a real reverse proxy.
    /// </summary>
    public RawForwardHeaderPassThrough DefaultRawForwardHeaderPassThrough { get; set; } = new();
}
