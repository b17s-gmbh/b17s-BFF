using System.Diagnostics;
using System.Globalization;
using System.Security.Claims;

using b17s.Porta.Auth.Sessions;
using b17s.Porta.Configuration;
using b17s.Porta.Telemetry;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace b17s.Porta.Auth.Tokens;

/// <summary>
/// Reads the current access token off the cookie auth ticket and, when near
/// expiry, refreshes it via <see cref="ITokenRefreshService"/>, updating the
/// ticket so that subsequent reads see the rotated tokens.
///
/// Per-user locking ensures only one refresh fires concurrently for the same
/// principal, regardless of how many in-flight requests trigger the check.
/// </summary>
public sealed class AccessTokenRefreshService : IAccessTokenRefreshService
{
    private const string CookieScheme = CookieAuthenticationDefaults.AuthenticationScheme;

    // Mirror of the key written by AuthenticationServiceExtensions.OnTokenValidated.
    // Refresh-token rotation must update SessionManagementService metadata under the
    // same id used at registration, otherwise admin/back-channel revocation runs
    // against the rotated-out token.
    private const string SessionIdPropertyKey = ".bff.session_id";

    private readonly ITokenRefreshService _refreshService;
    private readonly IApiTokenService _apiTokenService;
    private readonly ISessionManagementService? _sessionManagement;
    private readonly ITicketStore? _ticketStore;
    private readonly ILogger<AccessTokenRefreshService> _logger;
    private readonly IRefreshLock _refreshLock;
    private readonly PortaMetrics? _metrics;
    private readonly TimeSpan _refreshSkew;
    private readonly bool _refreshClaimsFromIdToken;
    private readonly TimeProvider _timeProvider;

    internal AccessTokenRefreshService(
        ITokenRefreshService refreshService,
        IApiTokenService apiTokenService,
        ILogger<AccessTokenRefreshService> logger,
        IRefreshLock refreshLock,
        IOptions<PortaCoreOptions> coreOptions,
        ISessionManagementService? sessionManagement = null,
        ITicketStore? ticketStore = null,
        PortaMetrics? metrics = null,
        TimeProvider? timeProvider = null)
    {
        _refreshService = refreshService;
        _apiTokenService = apiTokenService;
        _sessionManagement = sessionManagement;
        _ticketStore = ticketStore;
        _logger = logger;
        _refreshLock = refreshLock;
        _metrics = metrics;
        _refreshSkew = coreOptions.Value.TokenRefreshSkew;
        _refreshClaimsFromIdToken = coreOptions.Value.RefreshClaimsFromIdToken;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <inheritdoc/>
    public async Task<AccessTokenResult> GetAccessTokenAsync(HttpContext context)
    {
        var auth = await context.AuthenticateAsync(CookieScheme);
        if (!auth.Succeeded || auth.Principal is null || auth.Properties is null)
        {
            return AccessTokenResult.None;
        }

        var accessToken = auth.Properties.GetTokenValue("access_token");
        var refreshToken = auth.Properties.GetTokenValue("refresh_token");
        var expiresAt = ParseExpiresAt(auth.Properties.GetTokenValue("expires_at"));

        if (string.IsNullOrEmpty(accessToken))
        {
            return AccessTokenResult.None;
        }

        if (!IsNearExpiry(expiresAt) || string.IsNullOrEmpty(refreshToken))
        {
            return AccessTokenResult.FromTicket(accessToken, refreshToken, auth.Properties.GetTokenValue("id_token"), expiresAt);
        }

        return await TryRefreshAsync(context, auth, refreshToken, fallback: accessToken);
    }

    /// <inheritdoc/>
    public async Task<string?> ForceRefreshAsync(HttpContext context, string? staleAccessToken = null)
    {
        var auth = await context.AuthenticateAsync(CookieScheme);
        if (!auth.Succeeded || auth.Principal is null || auth.Properties is null)
        {
            return null;
        }

        var accessToken = auth.Properties.GetTokenValue("access_token");
        var refreshToken = auth.Properties.GetTokenValue("refresh_token");
        if (string.IsNullOrEmpty(refreshToken))
        {
            // Nothing to refresh with - hand back whatever we have so the caller's retry
            // at least re-sends the current token rather than nothing.
            return accessToken;
        }

        var lockKey = GetUserLockKey(context, auth);
        await using var handle = await _refreshLock.AcquireAsync(lockKey, TimeSpan.FromSeconds(10), context.RequestAborted);
        if (!handle.Acquired)
        {
            _logger.RefreshLockTimeout(lockKey);
            return accessToken;
        }

        try
        {
            // Re-read the CURRENT ticket under the lock - another request (or replica) may have
            // refreshed already. See ReadCurrentTicketAsync: prefer the shared ticket store so a
            // rotation we couldn't observe via the cached AuthenticateAsync result is still seen.
            var current = await ReadCurrentTicketAsync(context, auth);
            if (current is null)
            {
                return accessToken;
            }

            var (principal, properties) = current.Value;
            var freshAccessToken = properties.GetTokenValue("access_token");

            // If the token already changed under the lock, a concurrent request rotated it.
            // Skip a second IdP round-trip and let the caller retry with the rotated token.
            if (!string.IsNullOrEmpty(staleAccessToken)
                && !string.Equals(freshAccessToken, staleAccessToken, StringComparison.Ordinal))
            {
                return freshAccessToken;
            }

            var freshRefreshToken = properties.GetTokenValue("refresh_token") ?? refreshToken;
            var result = await PerformRefreshAsync(context, principal, properties, freshRefreshToken, fallback: freshAccessToken ?? accessToken);

            // On invalid_grant the session was just signed out; null tells the caller's
            // refresh-on-401 retry there is no token worth re-sending.
            return result.SessionTerminated ? null : result.AccessToken;
        }
        catch (Exception ex) when (!ex.IsCanceledBy(context.RequestAborted))
        {
            _logger.AccessTokenRefreshError(ex);
            return accessToken;
        }
    }

    private async Task<AccessTokenResult> TryRefreshAsync(HttpContext context, AuthenticateResult auth, string refreshToken, string fallback)
    {
        var lockKey = GetUserLockKey(context, auth);
        await using var handle = await _refreshLock.AcquireAsync(lockKey, TimeSpan.FromSeconds(10), context.RequestAborted);
        if (!handle.Acquired)
        {
            _logger.RefreshLockTimeout(lockKey);
            return AccessTokenResult.FromToken(fallback);
        }

        try
        {
            // Re-read the CURRENT ticket under the lock - another request (or replica) may have
            // refreshed already. See ReadCurrentTicketAsync: prefer the shared ticket store so a
            // rotation we couldn't observe via the cached AuthenticateAsync result is still seen,
            // collapsing concurrent refreshes to a single IdP round-trip.
            var current = await ReadCurrentTicketAsync(context, auth);
            if (current is null)
            {
                return AccessTokenResult.FromToken(fallback);
            }

            var (principal, properties) = current.Value;
            var freshAccessToken = properties.GetTokenValue("access_token");
            var freshExpiresAt = ParseExpiresAt(properties.GetTokenValue("expires_at"));
            if (!IsNearExpiry(freshExpiresAt))
            {
                // A concurrent request/replica already rotated; surface the store ticket's full
                // token set - the caller's per-request-cached authenticate result predates it.
                return AccessTokenResult.FromTicket(
                    freshAccessToken,
                    properties.GetTokenValue("refresh_token"),
                    properties.GetTokenValue("id_token"),
                    freshExpiresAt);
            }

            var freshRefreshToken = properties.GetTokenValue("refresh_token") ?? refreshToken;
            return await PerformRefreshAsync(context, principal, properties, freshRefreshToken, fallback);
        }
        catch (Exception ex) when (!ex.IsCanceledBy(context.RequestAborted))
        {
            _logger.AccessTokenRefreshError(ex);
            return AccessTokenResult.FromToken(fallback);
        }
    }

    /// <summary>
    /// Reads the up-to-date auth ticket under the refresh lock. Prefers the shared
    /// <see cref="ITicketStore"/> (keyed by the BFF session id) over the supplied <paramref name="auth"/>,
    /// because <c>AuthenticateAsync</c> caches its result per request and therefore cannot observe a
    /// rotation written by a concurrent request - or by another replica into the shared distributed
    /// store - after this request authenticated. Falls back to the request's authenticate result when
    /// no ticket store is wired or the session id is absent.
    /// </summary>
    private async Task<(ClaimsPrincipal Principal, AuthenticationProperties Properties)?> ReadCurrentTicketAsync(HttpContext context, AuthenticateResult auth)
    {
        // Prefer the shared ticket store (keyed by the BFF session id): it reflects a rotation written
        // by a concurrent request or another replica, which the per-request-cached AuthenticateAsync
        // cannot observe once this request has already authenticated.
        if (_ticketStore is not null
            && auth.Properties?.Items.TryGetValue(SessionIdPropertyKey, out var sessionId) == true
            && !string.IsNullOrEmpty(sessionId))
        {
            var ticket = await _ticketStore.RetrieveAsync(sessionId);
            if (ticket?.Principal is not null && ticket.Properties is not null)
            {
                return (ticket.Principal, ticket.Properties);
            }
        }

        // No ticket store (or no session id / no stored ticket): fall back to a fresh authenticate.
        var fresh = await context.AuthenticateAsync(CookieScheme);
        if (fresh.Succeeded && fresh.Principal is not null && fresh.Properties is not null)
        {
            return (fresh.Principal, fresh.Properties);
        }

        return null;
    }

    /// <summary>
    /// Calls the IdP refresh grant and writes the rotated tokens back onto the cookie ticket.
    /// Caller must already hold the per-user refresh lock and have re-read the current ticket
    /// (<paramref name="principal"/>/<paramref name="properties"/>) under it. Returns the rotated
    /// access token, <paramref name="fallback"/> when the IdP fails transiently, or
    /// <see cref="AccessTokenResult.SignedOut"/> when the IdP rejects the refresh token outright.
    /// </summary>
    private async Task<AccessTokenResult> PerformRefreshAsync(HttpContext context, ClaimsPrincipal principal, AuthenticationProperties properties, string freshRefreshToken, string? fallback)
    {
        // One span per actual IdP refresh grant. The specific outcome is carried on the span status
        // and the bff.token.refreshes / bff.token.refresh_failures counters (reason tag), not the name.
        using var activity = PortaActivitySource.Source.StartActivity(
            PortaActivitySource.Activities.TokenRefresh, ActivityKind.Client);
        activity?.SetTag(PortaActivitySource.Tags.Component, "token_refresh");

        // Thread the inbound request's cancellation so a hung IdP cannot block this refresh
        // indefinitely (and exceed the refresh-lock TTL). The token client also has its own
        // explicit timeout / resilience pipeline (see AddTokenServices) as a backstop.
        var result = await _refreshService.RefreshAsync(freshRefreshToken, context.RequestAborted);
        if (result.Response is null)
        {
            if (result.IsInvalidGrant)
            {
                // The IdP rejected the refresh token itself (revoked / expired / rotated-out):
                // the session is dead and no retry can revive it. Fail closed - sign out and drop
                // the API tokens derived from this session - rather than serving the stale access
                // token until it too expires, which would let a revoked session keep working.
                _logger.RefreshInvalidGrantSignedOut();
                _metrics?.RecordTokenRefresh(success: false, reason: "invalid_grant");
                activity?.SetStatus(ActivityStatusCode.Error, "invalid_grant");
                await _apiTokenService.InvalidateApiTokensAsync(context);
                await context.SignOutAsync(CookieScheme);
                return AccessTokenResult.SignedOut();
            }

            // Transient failure: keep serving the current token; a later request will retry.
            _logger.RefreshFailedReturningStale();
            _metrics?.RecordTokenRefresh(success: false, reason: "transient");
            activity?.SetStatus(ActivityStatusCode.Error, "transient");
            return AccessTokenResult.FromToken(fallback);
        }

        var response = result.Response;

        // Invalidate downstream API tokens (token-exchange results) - they were
        // derived from the now-stale access token.
        await _apiTokenService.InvalidateApiTokensAsync(context);

        var newExpiresAt = _timeProvider.GetUtcNow().AddSeconds(response.ExpiresIn);

        // Captured BEFORE the token update below: the previous id_token is the OIDC Core §12.2
        // reference the claims update validates the new one against (same iss, same sub).
        var previousIdToken = properties.GetTokenValue("id_token");

        properties.UpdateTokenValue("access_token", response.AccessToken);
        if (!string.IsNullOrEmpty(response.RefreshToken))
        {
            properties.UpdateTokenValue("refresh_token", response.RefreshToken);
        }
        if (!string.IsNullOrEmpty(response.IdToken))
        {
            properties.UpdateTokenValue("id_token", response.IdToken);
        }
        properties.UpdateTokenValue(
            "expires_at",
            newExpiresAt.ToString("o", CultureInfo.InvariantCulture));

        // When the IdP returned a new id_token, refresh the session's claims from it so claim
        // changes (roles granted/revoked, ...) propagate without a re-login. A failed update
        // (unparsable token, iss/sub mismatch) keeps the existing principal and only warns - the
        // token rotation itself must not be lost over a claims problem.
        var signInPrincipal = principal;
        if (_refreshClaimsFromIdToken && !string.IsNullOrEmpty(response.IdToken))
        {
            var updated = IdTokenClaimsUpdater.TryBuildUpdatedPrincipal(principal, previousIdToken, response.IdToken);
            if (updated is not null)
            {
                signInPrincipal = updated;
                _logger.SessionClaimsRefreshedFromIdToken();
            }
            else
            {
                _logger.SessionClaimsRefreshSkipped();
            }
        }

        // SignInAsync persists the rotated ticket into the (shared) ticket store under the session's
        // key, so the next request/replica that acquires the lock observes it via ReadCurrentTicketAsync
        // and skips a redundant IdP refresh.
        await context.SignInAsync(CookieScheme, signInPrincipal, properties);

        // Keep session metadata's refresh token in sync with the rotated value
        // so that later admin / back-channel logout revokes the *current* token
        // at the IdP, not the rotated-out one.
        if (_sessionManagement is not null
            && !string.IsNullOrEmpty(response.RefreshToken)
            && properties.Items.TryGetValue(SessionIdPropertyKey, out var sessionId)
            && !string.IsNullOrEmpty(sessionId))
        {
            var encrypted = _sessionManagement.ProtectRefreshToken(response.RefreshToken);
            await _sessionManagement.UpdateRefreshTokenAsync(sessionId, encrypted);
        }

        _logger.AccessTokenRefreshed(response.ExpiresIn);
        _metrics?.RecordTokenRefresh(success: true);
        activity?.SetStatus(ActivityStatusCode.Ok);

        // Read the rotated set back off the updated properties (the IdP may have withheld a new
        // refresh/id token, in which case the ticket keeps the previous one). Callers cannot
        // re-read the ticket themselves: AuthenticateAsync caches its result per request.
        return AccessTokenResult.FromTicket(
            response.AccessToken,
            properties.GetTokenValue("refresh_token"),
            properties.GetTokenValue("id_token"),
            newExpiresAt);
    }

    private bool IsNearExpiry(DateTimeOffset? expiresAt)
    {
        if (expiresAt is null)
        {
            return false;
        }
        return _timeProvider.GetUtcNow().Add(_refreshSkew) >= expiresAt.Value;
    }

    private static DateTimeOffset? ParseExpiresAt(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return null;
        }

        // The OIDC handler writes "expires_at" in ISO 8601 (round-trippable) format.
        if (DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var parsed))
        {
            return parsed;
        }

        // Tolerate Unix-seconds for callers that wrote tokens manually.
        if (long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var unixSeconds))
        {
            return DateTimeOffset.FromUnixTimeSeconds(unixSeconds);
        }

        return null;
    }

    private static string GetUserLockKey(HttpContext context, AuthenticateResult auth)
    {
        // The returned key is written into the distributed-cache keyspace (DistributedCacheRefreshLock)
        // and emitted in the lock-timeout log line, so every identifier is fingerprinted rather than
        // embedded raw: session ids are credential-equivalent and the `sub` is PII (SECURITY.md). The
        // SHA-256 fingerprint is deterministic, so the same user still maps to the same lock across
        // replicas and connections - preserving the single-flight refresh guarantee this method exists for.

        // Preferred: OIDC sub claim - stable across replicas and connections for the user.
        var principal = auth.Principal;
        var userId = principal?.FindFirst("sub")?.Value
            ?? context.User?.FindFirst("sub")?.Value
            // Also accept other commonly mapped identifier claim types so identity
            // providers that emit nameidentifier (post claim-mapping) still serialize.
            ?? principal?.FindFirst(ClaimTypes.NameIdentifier)?.Value
            ?? context.User?.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (!string.IsNullOrEmpty(userId))
        {
            return LogRedaction.FingerprintLockComponent("user", userId);
        }

        // BFF session id is written onto the cookie properties at sign-in
        // (see AuthenticationServiceExtensions.OnTokenValidated). When the principal
        // has no `sub` (e.g. provider config drift), the cookie's BFF session id is
        // still stable for the user and serializes refreshes across their connections.
        if (auth.Properties?.Items is { } items
            && items.TryGetValue(SessionIdPropertyKey, out var bffSessionId)
            && !string.IsNullOrEmpty(bffSessionId))
        {
            return LogRedaction.FingerprintLockComponent("bff-session", bffSessionId);
        }

        // context.Session throws when no ISessionFeature is registered. The cookie
        // auth scheme doesn't require UseSession(), so guard the access.
        if (context.Features.Get<Microsoft.AspNetCore.Http.Features.ISessionFeature>() is { } sessionFeature
            && !string.IsNullOrEmpty(sessionFeature.Session?.Id))
        {
            return LogRedaction.FingerprintLockComponent("session", sessionFeature.Session.Id);
        }

        // Last resort. connection.Id makes each in-flight connection its own lock,
        // which re-introduces the stampede this method exists to prevent - but it's
        // strictly better than throwing. The `connection:` category survives in the
        // fingerprinted key so operators can spot the misconfiguration in the timeout log.
        return LogRedaction.FingerprintLockComponent("connection", context.Connection.Id);
    }

}

internal static partial class AccessTokenRefreshServiceLogging
{
    [LoggerMessage(EventId = 14400, Level = LogLevel.Warning,
        Message = "Refresh lock acquisition timed out for {LockKey}")]
    public static partial void RefreshLockTimeout(this ILogger logger, string lockKey);

    [LoggerMessage(EventId = 14401, Level = LogLevel.Information,
        Message = "Access token refreshed; expires in {ExpiresIn}s")]
    public static partial void AccessTokenRefreshed(this ILogger logger, int expiresIn);

    [LoggerMessage(EventId = 14402, Level = LogLevel.Warning,
        Message = "Token refresh returned null; serving stale access token")]
    public static partial void RefreshFailedReturningStale(this ILogger logger);

    [LoggerMessage(EventId = 14404, Level = LogLevel.Warning,
        Message = "Refresh token rejected by IdP (invalid_grant); signing out the dead session")]
    public static partial void RefreshInvalidGrantSignedOut(this ILogger logger);

    [LoggerMessage(EventId = 14403, Level = LogLevel.Error,
        Message = "Unexpected error during access token refresh")]
    public static partial void AccessTokenRefreshError(this ILogger logger, Exception ex);

    [LoggerMessage(EventId = 14405, Level = LogLevel.Debug,
        Message = "Session claims refreshed from the new id_token returned with the token refresh")]
    public static partial void SessionClaimsRefreshedFromIdToken(this ILogger logger);

    [LoggerMessage(EventId = 14406, Level = LogLevel.Warning,
        Message = "Claims refresh skipped: the id_token returned with the token refresh could not be " +
                  "validated against the session (unparsable, or iss/sub mismatch per OIDC Core 12.2). " +
                  "The session keeps its previous claims; the rotated tokens were stored normally.")]
    public static partial void SessionClaimsRefreshSkipped(this ILogger logger);
}
