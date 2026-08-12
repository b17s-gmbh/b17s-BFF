using System.Net.Http.Json;
using System.Net.Mime;

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Hosting;

namespace b17s.Porta.Tests.Integration;

/// <summary>
/// Suite 4 of the E2E plan: inbound reference-token (opaque token) authentication. Drives the BFF
/// as a black box over <see cref="PortaTestHost"/> with a TestServer-hosted <see cref="FakeIdp"/>
/// (now serving an RFC 7662 introspection endpoint) and <see cref="FakeBackend"/>.
/// <para>
/// Reference tokens here are opaque handles the IdP issues; Porta does NOT mint or decrypt them.
/// On each request Porta resolves the inbound <c>Authorization: Bearer &lt;opaque&gt;</c> by POSTing
/// to the IdP's introspection endpoint and applies the audience/issuer binding checks. Every test
/// asserts on BOTH sides: Porta's response AND whether the request actually reached the fake backend
/// / whether the IdP was introspected.
/// </para>
/// <para>
/// Because reference-token requests carry no cookie, the ASP.NET principal is never populated, so the
/// endpoint can't gate on it (<c>RequireAuth()</c> would 401 before introspection runs - and forwarding
/// the inbound token via a <c>BearerToken</c> policy, which requires that principal, is therefore not
/// applicable to the opaque-token path). The endpoint is instead mapped
/// <c>AllowAnonymousWithOptionalAuth()</c> - the middle rung that resolves credentials when present
/// (plain <c>AllowAnonymous()</c> is credential-blind and would never introspect) - with a <c>None</c>
/// backend policy (so no credential is forwarded), and gated by a transformer whose
/// <c>RequiresAuthentication</c> is true - it returns 401 when the introspected <c>sub</c> is absent.
/// </para>
/// </summary>
public sealed class ReferenceTokenE2ETests
{
    private const string BackendBase = "http://backend.test";

    [Fact]
    public async Task ValidReferenceToken_Introspected_AuthenticatesAndForwardsToBackend()
    {
        // The happy path: an IdP-issued opaque token is introspected (active=true, sub=user-1,
        // aud "api", iss=authority, client_id=test-client), passes binding, authenticates the
        // request, and the authenticated call flows through to the backend.
        using var idp = new FakeIdp();
        using var backend = new FakeBackend(BackendBase);
        backend.MapGet("/data", WriteOk);

        using var bff = await StartAsync(idp, backend);

        var token = idp.IssueReferenceToken();
        var response = await GetWithTokenAsync(bff, "/api/data", token);
        response.EnsureSuccessStatusCode();

        var body = await response.Content.ReadFromJsonAsync<BackendPayload>(TestContext.Current.CancellationToken);
        Assert.Equal("ok", body!.Value);

        // Porta resolved the opaque token by actually calling the IdP.
        Assert.True(idp.IntrospectionCallCount >= 1);
        var recorded = Assert.Single(backend.ReceivedRequests);
        // None backend policy: the BFF authenticates the caller but does not forward the opaque
        // token (or any credential) downstream - the backend sees no Authorization header.
        Assert.Null(recorded.Authorization);
    }

    [Fact]
    public async Task UnknownReferenceToken_Returns401_BackendNeverCalled()
    {
        // A random string the IdP never issued introspects as active=false. The transformer's
        // auth gate rejects it (no sub -> 401) before any backend call is attempted.
        using var idp = new FakeIdp();
        using var backend = new FakeBackend(BackendBase);
        backend.MapGet("/data", WriteOk);

        using var bff = await StartAsync(idp, backend);

        var response = await GetWithTokenAsync(bff, "/api/data", "not-a-real-token");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Empty(backend.ReceivedRequests);
    }

    [Fact]
    public async Task RevokedReferenceToken_Returns401_BackendNeverCalled()
    {
        // A token the IdP issued but then revoked introspects as active=false, so it no longer
        // authenticates and nothing reaches the backend.
        //
        // Note on caching: the rejection is observed immediately here because this token was never
        // positively cached. A token already cached as active keeps authenticating until its short
        // introspection cache entry expires - the documented availability/freshness tradeoff of
        // reference-token caching, not a bug.
        using var idp = new FakeIdp();
        using var backend = new FakeBackend(BackendBase);
        backend.MapGet("/data", WriteOk);

        using var bff = await StartAsync(idp, backend);

        var token = idp.IssueReferenceToken();
        idp.Revoke(token);

        var response = await GetWithTokenAsync(bff, "/api/data", token);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Empty(backend.ReceivedRequests);
        Assert.True(idp.WasRevoked(token));
        // Porta asked the IdP and was told the token is inactive - it didn't reject blindly.
        Assert.True(idp.IntrospectionCallCount >= 1);
    }

    [Fact]
    public async Task ReferenceToken_WithNoSessionCookie_StillAuthenticates()
    {
        // Reference-token auth is stateless: there is no OIDC login, no session, no cookie. The
        // bearer alone authenticates, and it keeps working across independent clients that share
        // nothing but the token - i.e. it outlives any browser session because there isn't one.
        using var idp = new FakeIdp();
        using var backend = new FakeBackend(BackendBase);
        backend.MapGet("/data", WriteOk);

        using var bff = await StartAsync(idp, backend);

        var token = idp.IssueReferenceToken();

        var first = await GetWithTokenAsync(bff, "/api/data", token);
        first.EnsureSuccessStatusCode();
        // The BFF issues no session cookie - nothing is persisted client-side to carry forward.
        Assert.False(first.Headers.Contains("Set-Cookie"));

        // A brand-new client (no cookie jar, no prior request) carrying only the same token still
        // authenticates, proving the token - not a session - is the sole credential.
        var second = await GetWithTokenAsync(bff, "/api/data", token);
        second.EnsureSuccessStatusCode();

        Assert.Equal(2, backend.ReceivedRequests.Count);
    }

    // Standard reference-token host: introspection wired to the FakeIdp, a single pass-through
    // endpoint with a None backend policy, gated by an auth-requiring transformer.
    // AllowAnonymousWithOptionalAuth() at the routing layer (no ASP.NET principal exists for
    // reference tokens, and plain AllowAnonymous() is credential-blind - it would never run
    // introspection); the transformer's RequiresAuthentication gate is the real check, keyed on
    // the introspected sub.
    private static Task<IHost> StartAsync(FakeIdp idp, FakeBackend backend) =>
        new PortaTestHost()
            .WithReferenceToken(idp)
            .WithBackend(backend)
            .ConfigureServices(s => s.AddTransformer<AuthGatedPassThrough>())
            .MapEndpoints(endpoints => endpoints
                .MapTransformer<AuthGatedPassThrough, BackendPayload>()
                .FromGet("/api/data")
                .ToBackend("GET", $"{BackendBase}/data")
                .AllowAnonymousWithOptionalAuth()
                .Build())
            .StartAsync();

    // Each call uses a fresh, cookie-less client so the bearer token is the only credential in play.
    private static Task<HttpResponseMessage> GetWithTokenAsync(IHost bff, string path, string token)
    {
        var client = bff.CreateAuthenticatedClient();
        var request = new HttpRequestMessage(HttpMethod.Get, path);
        request.Headers.TryAddWithoutValidation("Authorization", $"Bearer {token}");
        return client.SendAsync(request, TestContext.Current.CancellationToken);
    }

    private static async Task WriteOk(HttpContext ctx)
    {
        ctx.Response.ContentType = MediaTypeNames.Application.Json;
        await ctx.Response.WriteAsJsonAsync(new BackendPayload { Value = "ok" });
    }

    // Gates on the introspected identity at the transformer level (returns 401 when UserId/sub is
    // absent). Uses the property override rather than the [RequiresAuthentication] attribute so the
    // startup authorization validator permits AllowAnonymous() + a None backend policy.
    private sealed class AuthGatedPassThrough : PassThroughTransformer<BackendPayload>
    {
        protected override bool RequiresAuthentication => true;
    }

    private sealed class BackendPayload
    {
        public string Value { get; set; } = string.Empty;
    }
}
