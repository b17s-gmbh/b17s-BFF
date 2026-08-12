using System.Collections.Concurrent;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;

using b17s.Porta.Configuration;
using b17s.Porta.Extensions;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace b17s.Porta.Auth.Tokens;

/// <summary>
/// Parameters for one <c>client_credentials</c> token acquisition. Also the cache identity:
/// two requests share a cached token exactly when endpoint, client, scope, and audience all match.
/// </summary>
public sealed record ClientCredentialsTokenRequest
{
    /// <summary>The IdP token endpoint the grant is posted to.</summary>
    public required string TokenEndpoint { get; init; }

    /// <summary>The OAuth client id.</summary>
    public required string ClientId { get; init; }

    /// <summary>The OAuth client secret. Secret-classified - never log this value.</summary>
    public required string ClientSecret { get; init; }

    /// <summary>Optional space-separated scopes; omitted from the request when empty.</summary>
    public string? Scope { get; init; }

    /// <summary>Optional <c>audience</c> parameter; omitted from the request when empty.</summary>
    public string? Audience { get; init; }
}

/// <summary>
/// Acquires and caches OAuth2 <c>client_credentials</c> (RFC 6749 §4.4) access tokens for the
/// BFF's own machine-to-machine identity. Used by the built-in <c>ClientCredentials</c>
/// backend-auth policy.
/// </summary>
public interface IClientCredentialsTokenService
{
    /// <summary>
    /// Returns a valid access token for the given client/scope/audience, minting one via the
    /// token endpoint on first use and serving it from a process-wide cache until shortly
    /// before expiry. Concurrent callers for the same identity share one in-flight request.
    /// </summary>
    /// <param name="request">The client/scope/audience to acquire a token for.</param>
    /// <param name="forceRefresh">
    /// True on a 401-retry: the cached token was rejected by the backend, so a completed cache
    /// entry is discarded and a fresh token minted. An in-flight acquisition (started after the
    /// rejected token was minted, hence already fresh) is joined instead of duplicated.
    /// </param>
    /// <param name="cancellationToken">Bounds this caller's wait; a shared in-flight fetch continues for other waiters.</param>
    /// <exception cref="InvalidOperationException">
    /// The token endpoint rejected the request or returned no usable token. Failures are never
    /// cached - the next call retries.
    /// </exception>
    Task<string> GetTokenAsync(ClientCredentialsTokenRequest request, bool forceRefresh = false, CancellationToken cancellationToken = default);
}

/// <summary>
/// Default <see cref="IClientCredentialsTokenService"/>. The cache is process-wide (there is no
/// user to partition by), keyed by endpoint + client + scope + audience + a hash of the secret
/// (so a rotated secret mints a fresh token instead of serving the stale one). Entries expire a
/// safety margin before the IdP's <c>expires_in</c>; failed acquisitions are evicted immediately
/// so an IdP hiccup never poisons the cache.
/// </summary>
public sealed class ClientCredentialsTokenService(
    IHttpClientFactory httpClientFactory,
    IOptionsMonitor<PortaCoreOptions> coreOptionsMonitor,
    TimeProvider timeProvider,
    ILogger<ClientCredentialsTokenService> logger) : IClientCredentialsTokenService
{
    private static readonly TimeSpan MaxExpiryMargin = TimeSpan.FromSeconds(60);

    private readonly ConcurrentDictionary<string, Lazy<Task<CachedToken>>> _cache = new();

    /// <inheritdoc/>
    public async Task<string> GetTokenAsync(ClientCredentialsTokenRequest request, bool forceRefresh = false, CancellationToken cancellationToken = default)
    {
        var key = CacheKey(request);

        // 401-retry: the backend rejected the cached token (revoked, rotated signing keys, ...),
        // so discard it before minting. Only a COMPLETED entry is evicted - an in-flight fetch was
        // started after the rejected token was minted, so it is already fresh; join it instead of
        // duplicating the IdP round-trip.
        if (forceRefresh
            && _cache.TryGetValue(key, out var rejected)
            && rejected.IsValueCreated
            && rejected.Value.IsCompleted)
        {
            _cache.TryRemove(KeyValuePair.Create(key, rejected));
        }

        // Bounded to two passes: pass 1 serves (or evicts) whatever the cache holds; pass 2 is
        // guaranteed to mint. A token WE minted in this call is returned even when it counts as
        // already expired (an IdP that sends expires_in <= 0 yields uncacheable single-use tokens)
        // - looping on it would refetch forever.
        for (var attempt = 0; ; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var mine = new Lazy<Task<CachedToken>>(
                () => FetchTokenAsync(request),
                LazyThreadSafetyMode.ExecutionAndPublication);
            var entry = _cache.GetOrAdd(key, mine);
            var mintedByThisCall = ReferenceEquals(entry, mine);

            CachedToken token;
            try
            {
                // The fetch itself is shared by every concurrent waiter, so it is not tied to any
                // single caller's cancellation token - each caller only bounds its own WAIT.
                token = await entry.Value.WaitAsync(cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                // This caller gave up; the shared fetch (and other waiters) continue unaffected.
                throw;
            }
            catch
            {
                // Never cache a failure. Evict exactly the faulted entry (a newer entry another
                // caller already replaced it with stays), then rethrow to this caller.
                _cache.TryRemove(KeyValuePair.Create(key, entry));
                throw;
            }

            if (token.ExpiresAt > timeProvider.GetUtcNow())
            {
                return token.AccessToken;
            }

            // Expired: evict this specific entry so no later caller is served from it.
            _cache.TryRemove(KeyValuePair.Create(key, entry));

            // Freshly minted (or second pass, where the entry we joined was itself just minted):
            // this is as fresh as a token gets - return it instead of refetching.
            if (mintedByThisCall || attempt > 0)
            {
                return token.AccessToken;
            }
        }
    }

    private async Task<CachedToken> FetchTokenAsync(ClientCredentialsTokenRequest request)
    {
        logger.ClientCredentialsTokenRequested(request.TokenEndpoint, request.ClientId, request.Scope, request.Audience);

        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = request.ClientId,
            ["client_secret"] = request.ClientSecret,
        };

        // Scope and audience are optional; some IdPs reject empty values, so omit the fields
        // entirely when unconfigured (matching the token-exchange and refresh services).
        if (!string.IsNullOrEmpty(request.Scope))
        {
            form["scope"] = request.Scope;
        }

        if (!string.IsNullOrEmpty(request.Audience))
        {
            form["audience"] = request.Audience;
        }

        var httpClient = httpClientFactory.CreateClient(AuthenticationServiceExtensions.TokenHttpClientName);
        using var content = new FormUrlEncodedContent(form);
        var httpResponse = await httpClient.PostAsync(request.TokenEndpoint, content);

        if (!httpResponse.IsSuccessStatusCode)
        {
            logger.ClientCredentialsTokenFailed(request.ClientId, (int)httpResponse.StatusCode);
            var coreOptions = coreOptionsMonitor.CurrentValue;
            if (coreOptions.LogIdpErrorBodies)
            {
                var errorContent = await IdpErrorBodyReader.ReadSafeAsync(httpResponse, coreOptions, CancellationToken.None);
                logger.ClientCredentialsTokenErrorResponse(errorContent);
            }

            // Keep the message opaque: IdP error bodies can echo request parameters. Detail is in
            // the structured log above.
            throw new InvalidOperationException(
                $"Client-credentials token request failed: {(int)httpResponse.StatusCode}");
        }

        var response = await httpResponse.Content.ReadFromJsonAsync<TokenExchangeResponse>();
        if (response is null || string.IsNullOrEmpty(response.AccessToken))
        {
            // Fail closed - "Authorization: Bearer " (empty) reads as anonymous to many backends.
            logger.ClientCredentialsTokenEmpty(request.ClientId, request.TokenEndpoint);
            throw new InvalidOperationException("Client-credentials token response contained no access token.");
        }

        var expiresAt = ComputeExpiry(response.ExpiresIn);
        logger.ClientCredentialsTokenAcquired(request.ClientId, response.ExpiresIn);
        return new CachedToken(response.AccessToken, expiresAt);
    }

    // Cache until a safety margin before the IdP's expiry so an entry is never served in its
    // final moments (in-flight backend calls would race the expiry). Very short lifetimes keep
    // at least half their life; a missing/zero expires_in disables caching for that token.
    private DateTimeOffset ComputeExpiry(int expiresInSeconds)
    {
        var now = timeProvider.GetUtcNow();
        if (expiresInSeconds <= 0)
        {
            return now;
        }

        var lifetime = TimeSpan.FromSeconds(expiresInSeconds);
        var margin = TimeSpan.FromTicks(Math.Min(MaxExpiryMargin.Ticks, lifetime.Ticks / 2));
        return now + lifetime - margin;
    }

    private static string CacheKey(ClientCredentialsTokenRequest request)
    {
        // Hash (never store) the secret in the key so a rotated secret mints a fresh token
        // instead of serving one issued to the old credential.
        var secretHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(request.ClientSecret)));
        return string.Join('|', request.TokenEndpoint, request.ClientId, request.Scope, request.Audience, secretHash);
    }

    private sealed record CachedToken(string AccessToken, DateTimeOffset ExpiresAt);
}

/// <summary>
/// High-performance logging for <see cref="ClientCredentialsTokenService"/>.
/// EventId range 11400-11409 is reserved for this category.
/// </summary>
internal static partial class ClientCredentialsTokenServiceLogging
{
    [LoggerMessage(EventId = 11400, Level = LogLevel.Debug,
        Message = "Requesting client-credentials token from {TokenEndpoint} for client {ClientId} (scope: {Scope}, audience: {Audience})")]
    public static partial void ClientCredentialsTokenRequested(
        this ILogger logger, string tokenEndpoint, string clientId, string? scope, string? audience);

    [LoggerMessage(EventId = 11401, Level = LogLevel.Warning,
        Message = "Client-credentials token request for client {ClientId} failed with status code {StatusCode}")]
    public static partial void ClientCredentialsTokenFailed(this ILogger logger, string clientId, int statusCode);

    [LoggerMessage(EventId = 11402, Level = LogLevel.Debug,
        Message = "Client-credentials token error response: {ErrorContent}")]
    public static partial void ClientCredentialsTokenErrorResponse(this ILogger logger, string errorContent);

    [LoggerMessage(EventId = 11403, Level = LogLevel.Error,
        Message = "Client-credentials token response for client {ClientId} from {TokenEndpoint} contained no access token")]
    public static partial void ClientCredentialsTokenEmpty(this ILogger logger, string clientId, string tokenEndpoint);

    [LoggerMessage(EventId = 11404, Level = LogLevel.Information,
        Message = "Client-credentials token acquired for client {ClientId}, expires in {ExpiresIn}s")]
    public static partial void ClientCredentialsTokenAcquired(this ILogger logger, string clientId, int expiresIn);
}
