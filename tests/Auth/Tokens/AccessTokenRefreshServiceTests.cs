using System.Diagnostics.Metrics;
using System.Globalization;
using System.Security.Claims;

using b17s.Porta.Auth.Sessions;
using b17s.Porta.Auth.Tokens;
using b17s.Porta.Configuration;
using b17s.Porta.Telemetry;
using b17s.Porta.Tests.Telemetry;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;

namespace b17s.Porta.Tests.Auth.Tokens;

public class AccessTokenRefreshServiceTests
{
    [Fact]
    public async Task GetAccessTokenAsync_Unauthenticated_ReturnsNoToken()
    {
        using var ctx = new TestContext { Authenticated = false };

        var result = await ctx.Service.GetAccessTokenAsync(ctx.HttpContext);

        Assert.Null(result.AccessToken);
        Assert.False(result.SessionTerminated);
    }

    [Fact]
    public async Task GetAccessTokenAsync_NotNearExpiry_ReturnsTokenWithoutRefresh()
    {
        using var ctx = new TestContext
        {
            AccessToken = "fresh-access",
            RefreshToken = "rt",
            ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(30),
        };

        var result = await ctx.Service.GetAccessTokenAsync(ctx.HttpContext);

        Assert.Equal("fresh-access", result.AccessToken);
        Assert.Equal(0, ctx.RefreshCalls);
    }

    [Fact]
    public async Task GetAccessTokenAsync_NearExpiry_RefreshesAndReturnsNewToken()
    {
        using var ctx = new TestContext
        {
            AccessToken = "stale-access",
            RefreshToken = "rt",
            ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(5), // within PortaCoreOptions.TokenRefreshSkew (60s default)
            RefreshResult = new TokenExchangeResponse
            {
                AccessToken = "new-access",
                RefreshToken = "new-rt",
                IdToken = "new-id",
                ExpiresIn = 3600,
                TokenType = "Bearer",
            },
        };

        var result = await ctx.Service.GetAccessTokenAsync(ctx.HttpContext);

        Assert.Equal("new-access", result.AccessToken);
        Assert.Equal(1, ctx.RefreshCalls);
        Assert.Equal(1, ctx.SignInCalls);
        Assert.Equal(1, ctx.ApiTokenInvalidationCalls);
        Assert.Equal("new-access", ctx.LastSignedInProperties?.GetTokenValue("access_token"));
        Assert.Equal("new-rt", ctx.LastSignedInProperties?.GetTokenValue("refresh_token"));
    }

    [Fact]
    public async Task GetAccessTokenAsync_NearExpiry_WithRotatedRefreshTokenAndSessionId_SyncsMetadata()
    {
        // Regression: after refresh-token rotation, AccessTokenRefreshService must
        // call ISessionManagementService.UpdateRefreshTokenAsync so admin and
        // back-channel revocation later target the *current* refresh token, not
        // the rotated-out one stored at registration time.
        using var ctx = new TestContext
        {
            AccessToken = "stale-access",
            RefreshToken = "old-rt",
            ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(5),
            SessionId = "sid-42",
            RefreshResult = new TokenExchangeResponse
            {
                AccessToken = "new-access",
                RefreshToken = "rotated-rt",
                ExpiresIn = 3600,
                TokenType = "Bearer",
            },
        };

        var result = await ctx.Service.GetAccessTokenAsync(ctx.HttpContext);

        Assert.Equal("new-access", result.AccessToken);
        var call = Assert.Single(ctx.Sessions.UpdateRefreshTokenCalls);
        Assert.Equal("sid-42", call.SessionId);
        Assert.Equal("ENC(rotated-rt)", call.EncryptedRefreshToken);
    }

    [Fact]
    public async Task GetAccessTokenAsync_RotationButNoSessionIdOnTicket_DoesNotSyncMetadata()
    {
        // Without a sessionId stashed on the ticket properties we have no key
        // to address the metadata record, so sync must not fire - better to
        // skip than to write under a guessed id.
        using var ctx = new TestContext
        {
            AccessToken = "stale-access",
            RefreshToken = "old-rt",
            ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(5),
            // SessionId left null.
            RefreshResult = new TokenExchangeResponse
            {
                AccessToken = "new-access",
                RefreshToken = "rotated-rt",
                ExpiresIn = 3600,
                TokenType = "Bearer",
            },
        };

        var result = await ctx.Service.GetAccessTokenAsync(ctx.HttpContext);

        Assert.Equal("new-access", result.AccessToken);
        Assert.Empty(ctx.Sessions.UpdateRefreshTokenCalls);
    }

    [Fact]
    public async Task GetAccessTokenAsync_RotationWithoutNewRefreshToken_DoesNotSyncMetadata()
    {
        // If the IdP returns a refreshed access token but no new refresh token,
        // there's nothing to update - the registered refresh token is still
        // current.
        using var ctx = new TestContext
        {
            AccessToken = "stale-access",
            RefreshToken = "old-rt",
            ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(5),
            SessionId = "sid-42",
            RefreshResult = new TokenExchangeResponse
            {
                AccessToken = "new-access",
                RefreshToken = string.Empty, // simulate IdP not rotating
                ExpiresIn = 3600,
                TokenType = "Bearer",
            },
        };

        var result = await ctx.Service.GetAccessTokenAsync(ctx.HttpContext);

        Assert.Equal("new-access", result.AccessToken);
        Assert.Empty(ctx.Sessions.UpdateRefreshTokenCalls);
    }

    [Fact]
    public async Task GetAccessTokenAsync_NearExpiryButNoRefreshToken_ReturnsStaleAccessToken()
    {
        using var ctx = new TestContext
        {
            AccessToken = "stale-access",
            RefreshToken = null,
            ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(5),
        };

        var result = await ctx.Service.GetAccessTokenAsync(ctx.HttpContext);

        Assert.Equal("stale-access", result.AccessToken);
        Assert.Equal(0, ctx.RefreshCalls);
    }

    [Fact]
    public async Task GetAccessTokenAsync_RefreshReturnsNull_FallsBackToOldAccessToken()
    {
        using var ctx = new TestContext
        {
            AccessToken = "stale-access",
            RefreshToken = "rt",
            ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(5),
            RefreshResult = null,
        };

        var result = await ctx.Service.GetAccessTokenAsync(ctx.HttpContext);

        Assert.Equal("stale-access", result.AccessToken);
        Assert.False(result.SessionTerminated);
        Assert.Equal(1, ctx.RefreshCalls);
        Assert.Equal(0, ctx.SignInCalls);
    }

    [Fact]
    public async Task SuccessfulRefresh_RecordsTokenRefreshSuccess()
    {
        using var harness = RecordingMetricsHarness.Create();
        using var ctx = new TestContext(metricsOverride: harness.Metrics)
        {
            AccessToken = "stale-access",
            RefreshToken = "rt",
            ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(5),
            RefreshResult = new TokenExchangeResponse
            {
                AccessToken = "new-access",
                RefreshToken = "new-rt",
                ExpiresIn = 3600,
                TokenType = "Bearer",
            },
        };

        await ctx.Service.GetAccessTokenAsync(ctx.HttpContext);

        Assert.Single(harness.Drain("bff.token.refreshes"));
        Assert.Empty(harness.Drain("bff.token.refresh_failures"));
    }

    [Fact]
    public async Task InvalidGrantRefresh_RecordsTokenRefreshFailure_WithReason()
    {
        using var harness = RecordingMetricsHarness.Create();
        using var ctx = new TestContext(metricsOverride: harness.Metrics)
        {
            AccessToken = "stale-access",
            RefreshToken = "rt",
            ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(5),
            RefreshResult = null,
            RefreshFailure = RefreshFailureReason.InvalidGrant,
        };

        await ctx.Service.GetAccessTokenAsync(ctx.HttpContext);

        var failures = harness.Drain("bff.token.refresh_failures");
        Assert.Single(failures);
        Assert.Equal("invalid_grant", failures[0].Tags["reason"]);
        Assert.Empty(harness.Drain("bff.token.refreshes"));
    }

    [Fact]
    public async Task GetAccessTokenAsync_RefreshInvalidGrant_SignsOutAndReportsSessionTerminated()
    {
        // W3: a hard invalid_grant (refresh token revoked/expired/rotated-out at the IdP) must
        // NOT fall back to serving the stale access token - that would let a revoked session keep
        // working until the access token expires. Fail closed: sign out + drop API tokens, and
        // report SessionTerminated so callers (SessionAuthProvider) don't resurrect the ticket's
        // stale access token either.
        using var ctx = new TestContext
        {
            AccessToken = "stale-access",
            RefreshToken = "rt",
            ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(5),
            RefreshResult = null,
            RefreshFailure = RefreshFailureReason.InvalidGrant,
        };

        var result = await ctx.Service.GetAccessTokenAsync(ctx.HttpContext);

        Assert.True(result.SessionTerminated);
        Assert.Null(result.AccessToken);
        Assert.Equal(1, ctx.RefreshCalls);
        Assert.Equal(0, ctx.SignInCalls);
        Assert.Equal(1, ctx.SignOutCalls);
        Assert.Equal(1, ctx.ApiTokenInvalidationCalls);
    }

    [Fact]
    public async Task GetAccessTokenAsync_NearExpiry_ThreadsRequestAbortedToRefresh()
    {
        // W4: the request-driven refresh path must thread the inbound request's CancellationToken
        // (HttpContext.RequestAborted) into ITokenRefreshService.RefreshAsync so a hung IdP cannot
        // block the request past the refresh-lock TTL. Previously the parameterless overload was
        // used, discarding the token (-> CancellationToken.None).
        using var cts = new CancellationTokenSource();
        using var ctx = new TestContext
        {
            AccessToken = "stale-access",
            RefreshToken = "rt",
            ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(5),
            RefreshResult = new TokenExchangeResponse
            {
                AccessToken = "new-access",
                ExpiresIn = 3600,
                TokenType = "Bearer",
            },
        };
        ctx.HttpContext.RequestAborted = cts.Token;

        var result = await ctx.Service.GetAccessTokenAsync(ctx.HttpContext);

        Assert.Equal("new-access", result.AccessToken);
        Assert.Equal(1, ctx.RefreshCalls);
        Assert.Equal(cts.Token, ctx.LastRefreshCancellationToken);
    }

    [Fact]
    public async Task GetAccessTokenAsync_RefreshCanceled_Propagates_DoesNotServeStaleToken()
    {
        // A client disconnect / host shutdown cancels RequestAborted mid-refresh. That must surface
        // as cancellation, not be swallowed into "serve the stale access token" - which both wastes
        // work during the disconnect and reports the abort as an ordinary transient refresh failure.
        // RecordingRefreshLock reports the lock acquired so we actually reach the refresh call.
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();
        using var ctx = new TestContext(new RecordingRefreshLock())
        {
            AccessToken = "stale-access",
            RefreshToken = "rt",
            ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(5),
            RefreshThrows = new OperationCanceledException(),
        };
        ctx.HttpContext.RequestAborted = cts.Token;

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => ctx.Service.GetAccessTokenAsync(ctx.HttpContext));
    }

    [Fact]
    public async Task GetAccessTokenAsync_RefreshThrowsNonCancellation_FallsBackToStaleToken()
    {
        // The cancellation filter must stay narrow: an unexpected, non-cancellation error keeps the
        // existing fail-soft behaviour (serve the stale token) rather than propagating to the request.
        using var ctx = new TestContext(new RecordingRefreshLock())
        {
            AccessToken = "stale-access",
            RefreshToken = "rt",
            ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(5),
            RefreshThrows = new InvalidOperationException("boom"),
        };

        var result = await ctx.Service.GetAccessTokenAsync(ctx.HttpContext);

        Assert.Equal("stale-access", result.AccessToken);
    }

    [Fact]
    public async Task GetAccessTokenAsync_NoExpiresAt_DoesNotRefresh()
    {
        using var ctx = new TestContext
        {
            AccessToken = "no-expiry",
            RefreshToken = "rt",
            ExpiresAt = null,
        };

        var result = await ctx.Service.GetAccessTokenAsync(ctx.HttpContext);

        Assert.Equal("no-expiry", result.AccessToken);
        Assert.Equal(0, ctx.RefreshCalls);
    }

    // Claims refresh: a new id_token returned with the refresh response updates the session
    // principal's claims (per re-asserted type), so IdP-side changes (roles granted/revoked)
    // propagate without a re-login. Detailed update semantics live in IdTokenClaimsUpdaterTests;
    // here we pin the wiring: updated principal signed in, opt-out honored, mismatch ignored.

    [Fact]
    public async Task Refresh_WithNewIdToken_SignsInUpdatedClaims()
    {
        using var ctx = new TestContext
        {
            AccessToken = "stale-access",
            RefreshToken = "rt",
            ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(5),
            RefreshResult = new TokenExchangeResponse
            {
                AccessToken = "new-access",
                IdToken = UnsignedIdToken(sub: "user-1", role: "editor"),
                ExpiresIn = 3600,
                TokenType = "Bearer",
            },
        };

        await ctx.Service.GetAccessTokenAsync(ctx.HttpContext);

        Assert.NotNull(ctx.LastSignedInPrincipal);
        Assert.Equal("editor", ctx.LastSignedInPrincipal!.FindFirst("role")?.Value);
        Assert.Equal("user-1", ctx.LastSignedInPrincipal.FindFirst("sub")?.Value);
    }

    [Fact]
    public async Task Refresh_ClaimsRefreshDisabled_SignsInOriginalPrincipal()
    {
        using var ctx = new TestContext(coreOptionsOverride: new PortaCoreOptions { RefreshClaimsFromIdToken = false })
        {
            AccessToken = "stale-access",
            RefreshToken = "rt",
            ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(5),
            RefreshResult = new TokenExchangeResponse
            {
                AccessToken = "new-access",
                IdToken = UnsignedIdToken(sub: "user-1", role: "editor"),
                ExpiresIn = 3600,
                TokenType = "Bearer",
            },
        };

        await ctx.Service.GetAccessTokenAsync(ctx.HttpContext);

        Assert.NotNull(ctx.LastSignedInPrincipal);
        Assert.Null(ctx.LastSignedInPrincipal!.FindFirst("role"));
    }

    [Fact]
    public async Task Refresh_IdTokenForDifferentSubject_KeepsExistingClaims()
    {
        // OIDC Core 12.2 guard end-to-end: a refresh id_token for another subject must not
        // rewrite this session's claims - tokens still rotate normally.
        using var ctx = new TestContext
        {
            AccessToken = "stale-access",
            RefreshToken = "rt",
            ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(5),
            RefreshResult = new TokenExchangeResponse
            {
                AccessToken = "new-access",
                IdToken = UnsignedIdToken(sub: "user-2", role: "admin"),
                ExpiresIn = 3600,
                TokenType = "Bearer",
            },
        };

        var result = await ctx.Service.GetAccessTokenAsync(ctx.HttpContext);

        Assert.Equal("new-access", result.AccessToken);
        Assert.NotNull(ctx.LastSignedInPrincipal);
        Assert.Null(ctx.LastSignedInPrincipal!.FindFirst("role"));
    }

    /// <summary>Minimal unsigned id_token (alg none) - the updater parses without signature validation.</summary>
    private static string UnsignedIdToken(string sub, string role)
    {
        static string Base64Url(string json) =>
            Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(json)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        var header = Base64Url("""{"alg":"none","typ":"JWT"}""");
        var payload = Base64Url($$"""{"iss":"https://idp.test","sub":"{{sub}}","role":"{{role}}"}""");
        return $"{header}.{payload}.";
    }

    // SECURITY.md: session ids are credential-equivalent and the `sub` is PII; neither may
    // reach the refresh-lock key, which is both written into the distributed-cache keyspace
    // and emitted in the lock-timeout log line. The key must be a non-reversible fingerprint.

    [Fact]
    public async Task RefreshLockKey_OnSubPath_IsFingerprintedAndOmitsRawSubject()
    {
        var lockSpy = new RecordingRefreshLock();
        using var ctx = new TestContext(lockSpy)
        {
            AccessToken = "stale-access",
            RefreshToken = "rt",
            SessionId = "bff-session-secret-1234",
            ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(5),
        };

        await ctx.Service.GetAccessTokenAsync(ctx.HttpContext);

        Assert.NotNull(lockSpy.LastKey);
        Assert.Equal(LogRedaction.FingerprintLockComponent("user", "user-1"), lockSpy.LastKey);
        Assert.DoesNotContain("user-1", lockSpy.LastKey);
        // The credential-equivalent session id must never leak into the lock key either.
        Assert.DoesNotContain("bff-session-secret-1234", lockSpy.LastKey);
    }

    [Fact]
    public async Task RefreshLockKey_OnBffSessionFallback_IsFingerprintedAndOmitsRawSessionId()
    {
        var lockSpy = new RecordingRefreshLock();
        using var ctx = new TestContext(lockSpy)
        {
            IncludeSubClaim = false,
            AccessToken = "stale-access",
            RefreshToken = "rt",
            SessionId = "bff-session-secret-1234",
            ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(5),
        };

        await ctx.Service.GetAccessTokenAsync(ctx.HttpContext);

        Assert.NotNull(lockSpy.LastKey);
        Assert.Equal(LogRedaction.FingerprintLockComponent("bff-session", "bff-session-secret-1234"), lockSpy.LastKey);
        Assert.DoesNotContain("bff-session-secret-1234", lockSpy.LastKey);
    }

    // ForceRefreshAsync is the refresh-on-401 retry path: callers hand in the token that
    // just got rejected and expect either a rotated token, the current token (when refresh
    // isn't possible right now), or null (when the session is dead and no retry can help).

    [Fact]
    public async Task ForceRefreshAsync_Unauthenticated_ReturnsNull()
    {
        using var ctx = new TestContext { Authenticated = false };

        var token = await ctx.Service.ForceRefreshAsync(ctx.HttpContext);

        Assert.Null(token);
        Assert.Equal(0, ctx.RefreshCalls);
    }

    [Fact]
    public async Task ForceRefreshAsync_NoRefreshToken_ReturnsCurrentAccessTokenWithoutRefresh()
    {
        using var ctx = new TestContext
        {
            AccessToken = "current-access",
            RefreshToken = null,
        };

        var token = await ctx.Service.ForceRefreshAsync(ctx.HttpContext);

        Assert.Equal("current-access", token);
        Assert.Equal(0, ctx.RefreshCalls);
    }

    [Fact]
    public async Task ForceRefreshAsync_RefreshesEvenWhenNotNearExpiry_AndReturnsRotatedToken()
    {
        // Force-refresh is the 401-retry path: the resource server already rejected the
        // token, so expiry-based skew must not gate the refresh.
        using var ctx = new TestContext
        {
            AccessToken = "rejected-access",
            RefreshToken = "rt",
            ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(30),
            RefreshResult = new TokenExchangeResponse
            {
                AccessToken = "new-access",
                RefreshToken = "new-rt",
                ExpiresIn = 3600,
                TokenType = "Bearer",
            },
        };

        var token = await ctx.Service.ForceRefreshAsync(ctx.HttpContext, staleAccessToken: "rejected-access");

        Assert.Equal("new-access", token);
        Assert.Equal(1, ctx.RefreshCalls);
        Assert.Equal(1, ctx.SignInCalls);
        Assert.Equal(1, ctx.ApiTokenInvalidationCalls);
        Assert.Equal("new-access", ctx.LastSignedInProperties?.GetTokenValue("access_token"));
    }

    [Fact]
    public async Task ForceRefreshAsync_TokenAlreadyRotatedUnderLock_ReturnsRotatedTokenWithoutIdpRoundTrip()
    {
        // A concurrent request may have rotated the token between the caller's 401 and
        // this lock acquisition. The re-read under the lock must detect the change and
        // skip a second IdP round-trip.
        using var ctx = new TestContext
        {
            AccessToken = "already-rotated",
            RefreshToken = "rt",
        };

        var token = await ctx.Service.ForceRefreshAsync(ctx.HttpContext, staleAccessToken: "rejected-access");

        Assert.Equal("already-rotated", token);
        Assert.Equal(0, ctx.RefreshCalls);
        Assert.Equal(0, ctx.SignInCalls);
    }

    [Fact]
    public async Task ForceRefreshAsync_LockTimeout_ReturnsCurrentTokenWithoutRefresh()
    {
        // Lock-timeout → serve-stale fallback: when the per-user lock cannot be acquired
        // the caller gets the current token back rather than an error - another request
        // is presumably mid-refresh and the retry will pick up its result.
        using var ctx = new TestContext(new NotAcquiredRefreshLock())
        {
            AccessToken = "current-access",
            RefreshToken = "rt",
        };

        var token = await ctx.Service.ForceRefreshAsync(ctx.HttpContext, staleAccessToken: "current-access");

        Assert.Equal("current-access", token);
        Assert.Equal(0, ctx.RefreshCalls);
    }

    [Fact]
    public async Task ForceRefreshAsync_InvalidGrant_SignsOutAndReturnsNull()
    {
        // invalid_grant means the session is dead; null tells the caller's refresh-on-401
        // retry there is no token worth re-sending.
        using var ctx = new TestContext
        {
            AccessToken = "rejected-access",
            RefreshToken = "rt",
            RefreshResult = null,
            RefreshFailure = RefreshFailureReason.InvalidGrant,
        };

        var token = await ctx.Service.ForceRefreshAsync(ctx.HttpContext, staleAccessToken: "rejected-access");

        Assert.Null(token);
        Assert.Equal(1, ctx.SignOutCalls);
        Assert.Equal(1, ctx.ApiTokenInvalidationCalls);
    }

    [Fact]
    public async Task ForceRefreshAsync_TransientFailure_ReturnsStaleToken()
    {
        using var ctx = new TestContext
        {
            AccessToken = "rejected-access",
            RefreshToken = "rt",
            RefreshResult = null,
            RefreshFailure = RefreshFailureReason.Transient,
        };

        var token = await ctx.Service.ForceRefreshAsync(ctx.HttpContext, staleAccessToken: "rejected-access");

        Assert.Equal("rejected-access", token);
        Assert.Equal(1, ctx.RefreshCalls);
        Assert.Equal(0, ctx.SignOutCalls);
    }

    [Fact]
    public async Task ForceRefreshAsync_RefreshThrowsNonCancellation_ReturnsStaleToken()
    {
        using var ctx = new TestContext(new RecordingRefreshLock())
        {
            AccessToken = "rejected-access",
            RefreshToken = "rt",
            RefreshThrows = new InvalidOperationException("boom"),
        };

        var token = await ctx.Service.ForceRefreshAsync(ctx.HttpContext, staleAccessToken: "rejected-access");

        Assert.Equal("rejected-access", token);
    }

    [Fact]
    public async Task ForceRefreshAsync_RefreshCanceled_PropagatesCancellation()
    {
        // Mirrors the GetAccessTokenAsync contract: a client disconnect mid-refresh must
        // surface as cancellation, not be swallowed into "serve the stale token".
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();
        using var ctx = new TestContext(new RecordingRefreshLock())
        {
            AccessToken = "rejected-access",
            RefreshToken = "rt",
            RefreshThrows = new OperationCanceledException(),
        };
        ctx.HttpContext.RequestAborted = cts.Token;

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => ctx.Service.ForceRefreshAsync(ctx.HttpContext, staleAccessToken: "rejected-access"));
    }

    [Fact]
    public async Task GetAccessTokenAsync_LockTimeout_ServesStaleTokenWithoutRefresh()
    {
        // Same serve-stale fallback on the request-driven path: a near-expiry token whose
        // refresh lock is held elsewhere is returned as-is instead of blocking or failing.
        using var ctx = new TestContext(new NotAcquiredRefreshLock())
        {
            AccessToken = "stale-access",
            RefreshToken = "rt",
            ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(5),
        };

        var result = await ctx.Service.GetAccessTokenAsync(ctx.HttpContext);

        Assert.Equal("stale-access", result.AccessToken);
        Assert.False(result.SessionTerminated);
        Assert.Equal(0, ctx.RefreshCalls);
        Assert.Equal(0, ctx.SignInCalls);
    }

    /// <summary>Simulates a lock-acquisition timeout: every acquire reports not acquired.</summary>
    private sealed class NotAcquiredRefreshLock : IRefreshLock
    {
        public Task<RefreshLockHandle> AcquireAsync(string lockKey, TimeSpan timeout, CancellationToken cancellationToken = default)
            => Task.FromResult(RefreshLockHandle.NotAcquired);
    }

    /// <summary>Captures the key handed to the refresh lock; reports the lock as acquired.</summary>
    private sealed class RecordingRefreshLock : IRefreshLock
    {
        public string? LastKey { get; private set; }

        public Task<RefreshLockHandle> AcquireAsync(string lockKey, TimeSpan timeout, CancellationToken cancellationToken = default)
        {
            LastKey = lockKey;
            return Task.FromResult(new RefreshLockHandle(true));
        }
    }

    /// <summary>
    /// Stitches together a fake <see cref="IAuthenticationService"/> with a
    /// pre-populated ticket plus stub refresh / api-token services. The system
    /// under test calls AuthenticateAsync/SignInAsync via the DI container.
    /// </summary>
    private sealed class TestContext : IDisposable
    {
        public bool Authenticated { get; init; } = true;
        public string? AccessToken { get; init; }
        public string? RefreshToken { get; init; }
        public string? IdToken { get; init; } = "id-1";
        public DateTimeOffset? ExpiresAt { get; init; }
        public string? SessionId { get; init; }

        // When false, the built ticket omits the `sub` claim so the lock-key
        // derivation falls through to the BFF-session-id path.
        public bool IncludeSubClaim { get; init; } = true;
        public TokenExchangeResponse? RefreshResult { get; set; }

        // When RefreshResult is null, the kind of failure the stubbed refresh reports.
        public RefreshFailureReason RefreshFailure { get; init; } = RefreshFailureReason.Transient;

        // When set, the stubbed refresh throws this instead of returning a result, so we can
        // exercise the catch-handler's cancellation filter.
        public Exception? RefreshThrows { get; init; }

        public int RefreshCalls { get; private set; }
        public CancellationToken LastRefreshCancellationToken { get; private set; }
        public int SignInCalls { get; private set; }
        public int SignOutCalls { get; private set; }
        public int ApiTokenInvalidationCalls { get; private set; }
        public AuthenticationProperties? LastSignedInProperties { get; private set; }
        public ClaimsPrincipal? LastSignedInPrincipal { get; private set; }
        public StubSessionManagementService Sessions { get; }

        public AccessTokenRefreshService Service { get; }
        public HttpContext HttpContext { get; }

        public TestContext(
            IRefreshLock? refreshLockOverride = null,
            PortaMetrics? metricsOverride = null,
            PortaCoreOptions? coreOptionsOverride = null)
        {
            var fakeAuth = new FakeAuthenticationService(this);
            var refreshService = new StubTokenRefreshService(this);
            var apiTokenService = new StubApiTokenService(this);
            Sessions = new StubSessionManagementService();

            var services = new ServiceCollection();
            services.AddSingleton<IAuthenticationService>(fakeAuth);
            // The framework's AuthenticationHttpContextExtensions look up
            // IAuthenticationSchemeProvider as part of resolution; we provide
            // a no-op since the fake IAuthenticationService bypasses scheme lookup.
            services.AddSingleton<IAuthenticationSchemeProvider, NullSchemeProvider>();
            services.AddSingleton<IAuthenticationHandlerProvider, NullHandlerProvider>();
            HttpContext = new DefaultHttpContext { RequestServices = services.BuildServiceProvider() };

            var metrics = metricsOverride ?? new PortaMetrics(new TestMeterFactory());
            LockRegistry = new RefreshLockRegistry(metrics);
            Service = new AccessTokenRefreshService(
                refreshService,
                apiTokenService,
                NullLogger<AccessTokenRefreshService>.Instance,
                refreshLockOverride ?? LockRegistry,
                Microsoft.Extensions.Options.Options.Create(coreOptionsOverride ?? new PortaCoreOptions()),
                sessionManagement: Sessions,
                metrics: metrics);
        }

        public RefreshLockRegistry LockRegistry { get; }

        public void Dispose() => LockRegistry.Dispose();

        public AuthenticateResult BuildResult()
        {
            if (!Authenticated)
            {
                return AuthenticateResult.NoResult();
            }

            var identity = new ClaimsIdentity(authenticationType: CookieAuthenticationDefaults.AuthenticationScheme);
            if (IncludeSubClaim)
            {
                identity.AddClaim(new Claim("sub", "user-1"));
            }
            var principal = new ClaimsPrincipal(identity);
            var properties = new AuthenticationProperties();
            if (!string.IsNullOrEmpty(SessionId))
            {
                properties.Items[".bff.session_id"] = SessionId;
            }
            var tokens = new List<AuthenticationToken>();
            if (!string.IsNullOrEmpty(AccessToken)) tokens.Add(new AuthenticationToken { Name = "access_token", Value = AccessToken });
            if (!string.IsNullOrEmpty(RefreshToken)) tokens.Add(new AuthenticationToken { Name = "refresh_token", Value = RefreshToken });
            if (!string.IsNullOrEmpty(IdToken)) tokens.Add(new AuthenticationToken { Name = "id_token", Value = IdToken });
            if (ExpiresAt.HasValue) tokens.Add(new AuthenticationToken { Name = "expires_at", Value = ExpiresAt.Value.ToString("o", CultureInfo.InvariantCulture) });
            properties.StoreTokens(tokens);

            return AuthenticateResult.Success(new AuthenticationTicket(principal, properties, CookieAuthenticationDefaults.AuthenticationScheme));
        }

        public void RecordRefresh(CancellationToken cancellationToken)
        {
            RefreshCalls++;
            LastRefreshCancellationToken = cancellationToken;
        }
        public void RecordSignOut() => SignOutCalls++;
        public void RecordApiTokenInvalidation() => ApiTokenInvalidationCalls++;
        public void RecordSignIn(ClaimsPrincipal principal, AuthenticationProperties? properties)
        {
            SignInCalls++;
            LastSignedInPrincipal = principal;
            LastSignedInProperties = properties;
        }

        private sealed class FakeAuthenticationService(TestContext ctx) : IAuthenticationService
        {
            public Task<AuthenticateResult> AuthenticateAsync(HttpContext context, string? scheme)
                => Task.FromResult(ctx.BuildResult());

            public Task ChallengeAsync(HttpContext context, string? scheme, AuthenticationProperties? properties)
                => Task.CompletedTask;

            public Task ForbidAsync(HttpContext context, string? scheme, AuthenticationProperties? properties)
                => Task.CompletedTask;

            public Task SignInAsync(HttpContext context, string? scheme, ClaimsPrincipal principal, AuthenticationProperties? properties)
            {
                ctx.RecordSignIn(principal, properties);
                return Task.CompletedTask;
            }

            public Task SignOutAsync(HttpContext context, string? scheme, AuthenticationProperties? properties)
            {
                ctx.RecordSignOut();
                return Task.CompletedTask;
            }
        }

        private sealed class StubTokenRefreshService(TestContext ctx) : ITokenRefreshService
        {
            public Task<RefreshTokenResult> RefreshAsync(string refreshToken, CancellationToken cancellationToken = default)
            {
                ctx.RecordRefresh(cancellationToken);
                if (ctx.RefreshThrows is { } toThrow)
                {
                    throw toThrow;
                }
                var result = ctx.RefreshResult is { } response
                    ? RefreshTokenResult.Success(response)
                    : ctx.RefreshFailure == RefreshFailureReason.InvalidGrant
                        ? RefreshTokenResult.InvalidGrant()
                        : RefreshTokenResult.Transient();
                return Task.FromResult(result);
            }

            public Task<RefreshTokenResult> RefreshAsync(string refreshToken, TokenRefreshOptions options, CancellationToken cancellationToken = default)
                => RefreshAsync(refreshToken, cancellationToken);
        }

        public sealed class StubSessionManagementService : ISessionManagementService
        {
            public List<(string SessionId, string? EncryptedRefreshToken)> UpdateRefreshTokenCalls { get; } = new();

            public Task RegisterSessionAsync(string sessionId, string userId, string? email = null, string? ipAddress = null, string? userAgent = null, string? encryptedRefreshToken = null)
                => Task.CompletedTask;

            public Task UpdateRefreshTokenAsync(string sessionId, string? encryptedRefreshToken)
            {
                UpdateRefreshTokenCalls.Add((sessionId, encryptedRefreshToken));
                return Task.CompletedTask;
            }

            // Round-trip identity is fine for tests - we just need a non-null, deterministic
            // value so we can assert what got handed to UpdateRefreshTokenAsync.
            public string? ProtectRefreshToken(string? refreshToken)
                => string.IsNullOrEmpty(refreshToken) ? null : "ENC(" + refreshToken + ")";

            public Task<IReadOnlyList<SessionInfo>> GetSessionsByEmailAsync(string email, CancellationToken cancellationToken = default)
                => Task.FromResult<IReadOnlyList<SessionInfo>>(Array.Empty<SessionInfo>());

            public Task<bool> TerminateSessionAsync(string sessionId, bool revokeTokens = true, CancellationToken cancellationToken = default, string reason = "unspecified")
                => Task.FromResult(false);

            public Task<int> TerminateSessionsByEmailAsync(string email, bool revokeTokens = true, CancellationToken cancellationToken = default, string reason = "unspecified")
                => Task.FromResult(0);

            public Task<int> TerminateSessionsBySubjectAsync(string subject, bool revokeTokens = true, CancellationToken cancellationToken = default, string reason = "unspecified")
                => Task.FromResult(0);

            public Task TouchSessionAsync(string sessionId) => Task.CompletedTask;
        }

        private sealed class StubApiTokenService(TestContext ctx) : IApiTokenService
        {
            public Task<string?> GetApiTokenAsync(HttpContext context, ApiConfiguration apiConfig, string? accessToken, CancellationToken cancellationToken = default)
                => Task.FromResult<string?>(null);
            public Task<string?> GetApiTokenAsync(HttpContext context, ApiConfiguration apiConfig, string? accessToken, ApiTokenCacheOptions cacheOptions, CancellationToken cancellationToken = default)
                => Task.FromResult<string?>(null);
            public Task InvalidateApiTokensAsync(HttpContext context, CancellationToken cancellationToken = default)
            {
                ctx.RecordApiTokenInvalidation();
                return Task.CompletedTask;
            }
            public Task InvalidateApiTokensAsync(HttpContext context, ApiTokenCacheOptions cacheOptions, CancellationToken cancellationToken = default)
                => InvalidateApiTokensAsync(context, cancellationToken);
        }

        private sealed class NullSchemeProvider : IAuthenticationSchemeProvider
        {
            public Task<AuthenticationScheme?> GetDefaultAuthenticateSchemeAsync() => Task.FromResult<AuthenticationScheme?>(null);
            public Task<AuthenticationScheme?> GetDefaultChallengeSchemeAsync() => Task.FromResult<AuthenticationScheme?>(null);
            public Task<AuthenticationScheme?> GetDefaultForbidSchemeAsync() => Task.FromResult<AuthenticationScheme?>(null);
            public Task<AuthenticationScheme?> GetDefaultSignInSchemeAsync() => Task.FromResult<AuthenticationScheme?>(null);
            public Task<AuthenticationScheme?> GetDefaultSignOutSchemeAsync() => Task.FromResult<AuthenticationScheme?>(null);
            public Task<IEnumerable<AuthenticationScheme>> GetAllSchemesAsync() => Task.FromResult(Enumerable.Empty<AuthenticationScheme>());
            public Task<AuthenticationScheme?> GetSchemeAsync(string name) => Task.FromResult<AuthenticationScheme?>(null);
            public Task<IEnumerable<AuthenticationScheme>> GetRequestHandlerSchemesAsync() => Task.FromResult(Enumerable.Empty<AuthenticationScheme>());
            public void AddScheme(AuthenticationScheme scheme) { }
            public void RemoveScheme(string name) { }
        }

        private sealed class NullHandlerProvider : IAuthenticationHandlerProvider
        {
            public Task<IAuthenticationHandler?> GetHandlerAsync(HttpContext context, string authenticationScheme)
                => Task.FromResult<IAuthenticationHandler?>(null);
        }

        private sealed class TestMeterFactory : IMeterFactory
        {
            public Meter Create(MeterOptions options) => new(options);
            public void Dispose() { }
        }
    }
}
