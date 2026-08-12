using System.Diagnostics;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Encodings.Web;

using b17s.Porta.Auth.Providers;
using b17s.Porta.Telemetry;
using b17s.Porta.Tests.Fixtures;
using b17s.Porta.Transformers;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace b17s.Porta.Tests.Transformers;

/// <summary>
/// Exercises the public fluent surface of <see cref="TransformerExtensions.MapTransformer{T, R}"/>
/// (and the underlying <see cref="TransformerEndpointBuilderBase{TTransformer, TBuilder}"/>) by
/// spinning up a real BFF, hitting the endpoint, and inspecting the <see cref="BackendRequest"/>
/// that the framework hands to <see cref="IBackendCaller"/>. The fluent setters store into
/// private fields and surface only through the BackendRequest the handler builds at call time,
/// so this is the only meaningful way to assert they wire up correctly without breaking encapsulation.
/// </summary>
[Collection(PortaActivitySourceCollection.Name)]
public sealed class TransformerEndpointBuilderFluentTests
{
    [Fact]
    public async Task ToGraphQL_SetsPostMethod_AndStoresBackendUrl()
    {
        // ToGraphQL is documented as forcing POST regardless of the From verb. If a future
        // change drops the method-coercion, GET-mounted GraphQL endpoints would silently
        // start GET-ing the GraphQL backend - which most servers reject.
        var backend = new MockBackendCaller()
            .SetupResponse("https://backend.test/graphql", new EchoResponse { Echoed = "ok" });
        using var bff = await CreateBffAsync(endpoints => endpoints
            .MapTransformer<RecordingTransformer, EchoResponse>()
            .FromPost("/api/gql")
            .ToGraphQL("https://backend.test/graphql")
            .AllowAnonymous()
            .Build(), backend);

        var client = bff.GetTestServer().CreateClient();
        var response = await client.PostAsync("/api/gql", content: null, TestContext.Current.CancellationToken);

        response.EnsureSuccessStatusCode();
        var recorded = Assert.Single(backend.RecordedCalls);
        Assert.Equal("POST", recorded.Request.Method);
        Assert.Equal("https://backend.test/graphql", recorded.Request.Url);
    }

    [Fact]
    public async Task WithTokenExchange_PopulatesAudienceAndFlag_OnBackendRequest()
    {
        // WithTokenExchange is the public on-ramp to per-API token exchange. The two private
        // fields it sets show up on BackendRequest.UseTokenExchange and TokenExchangeAudience
        // - and downstream auth handlers branch on those values. Endpoint authorization
        // validator requires RequireAuth() when token-exchange is configured (token exchange
        // is meaningless without a user identity to exchange), so we wire up a stub auth
        // scheme to satisfy that.
        var backend = new MockBackendCaller()
            .SetupResponse("https://backend.test/orders", new EchoResponse { Echoed = "ok" });
        using var bff = await CreateBffAsync(endpoints => endpoints
            .MapTransformer<RecordingTransformer, EchoResponse>()
            .FromGet("/api/orders")
            .ToBackend("GET", "https://backend.test/orders")
            .WithTokenExchange("orders-api")
            .RequireAuth()
            .Build(), backend, withStubAuthScheme: true, authenticated: true);

        var client = bff.GetTestServer().CreateClient();
        var response = await client.GetAsync("/api/orders", TestContext.Current.CancellationToken);

        response.EnsureSuccessStatusCode();
        var recorded = Assert.Single(backend.RecordedCalls);
        Assert.True(recorded.Request.UseTokenExchange);
        Assert.Equal("orders-api", recorded.Request.TokenExchangeAudience);
    }

    [Fact]
    public async Task WithBackendAuth_PropagatesPolicyName_OnBackendRequest()
    {
        // WithBackendAuth selects which IBackendAuthHandler runs (Basic, Bearer, None, etc.).
        // The handler reads BackendAuthPolicy off the BackendRequest at call time.
        var backend = new MockBackendCaller()
            .SetupResponse("https://backend.test/things", new EchoResponse { Echoed = "ok" });
        using var bff = await CreateBffAsync(endpoints => endpoints
            .MapTransformer<RecordingTransformer, EchoResponse>()
            .FromGet("/api/things")
            .ToBackend("GET", "https://backend.test/things")
            .WithBackendAuth("BasicAuth")
            .AllowAnonymous()
            .Build(), backend);

        var client = bff.GetTestServer().CreateClient();
        var response = await client.GetAsync("/api/things", TestContext.Current.CancellationToken);

        response.EnsureSuccessStatusCode();
        var recorded = Assert.Single(backend.RecordedCalls);
        Assert.Equal("BasicAuth", recorded.Request.BackendAuthPolicy);
    }

    [Fact]
    public async Task WithTimeout_PropagatesTimeout_OnBackendRequest()
    {
        var backend = new MockBackendCaller()
            .SetupResponse("https://backend.test/slow", new EchoResponse { Echoed = "ok" });
        using var bff = await CreateBffAsync(endpoints => endpoints
            .MapTransformer<RecordingTransformer, EchoResponse>()
            .FromGet("/api/slow")
            .ToBackend("GET", "https://backend.test/slow")
            .WithTimeout(TimeSpan.FromSeconds(7))
            .AllowAnonymous()
            .Build(), backend);

        var client = bff.GetTestServer().CreateClient();
        var response = await client.GetAsync("/api/slow", TestContext.Current.CancellationToken);

        response.EnsureSuccessStatusCode();
        var recorded = Assert.Single(backend.RecordedCalls);
        Assert.Equal(TimeSpan.FromSeconds(7), recorded.Request.Timeout);
    }

    [Fact]
    public async Task WithRetries_PropagatesEnabledFlagAndAttemptCount_OnBackendRequest()
    {
        var backend = new MockBackendCaller()
            .SetupResponse("https://backend.test/flaky", new EchoResponse { Echoed = "ok" });
        using var bff = await CreateBffAsync(endpoints => endpoints
            .MapTransformer<RecordingTransformer, EchoResponse>()
            .FromGet("/api/flaky")
            .ToBackend("GET", "https://backend.test/flaky")
            .WithRetries(maxAttempts: 5)
            .AllowAnonymous()
            .Build(), backend);

        var client = bff.GetTestServer().CreateClient();
        var response = await client.GetAsync("/api/flaky", TestContext.Current.CancellationToken);

        response.EnsureSuccessStatusCode();
        var recorded = Assert.Single(backend.RecordedCalls);
        Assert.True(recorded.Request.EnableRetries);
        Assert.Equal(5, recorded.Request.MaxRetryAttempts);
    }

    [Fact]
    public async Task AllowAnonymousWithOptionalAuth_AllowsUnauthenticated_AndPopulatesContextWhenPresent()
    {
        // AllowAnonymousWithOptionalAuth lets the request through unauthenticated but still
        // calls TryGetAuthContextAsync so authenticated callers get a populated AuthContext
        // (typical use: same endpoint personalizes when known, falls back to generic otherwise).
        // No backend auth is needed for this transformer-only use of optional auth.
        var backend = new MockBackendCaller()
            .SetupResponse("https://backend.test/maybe", new EchoResponse { Echoed = "ok" });
        var transformer = new RecordingTransformer();
        using var bff = await CreateBffAsync(endpoints => endpoints
            .MapTransformer<RecordingTransformer, EchoResponse>()
            .FromGet("/api/maybe")
            .ToBackend("GET", "https://backend.test/maybe")
            .AllowAnonymousWithOptionalAuth()
            .Build(), backend, transformer: transformer, authenticated: true);

        var client = bff.GetTestServer().CreateClient();
        var response = await client.GetAsync("/api/maybe", TestContext.Current.CancellationToken);

        response.EnsureSuccessStatusCode();
        // Authenticated stub returns an access token - if AllowAnonymousWithOptionalAuth had
        // accidentally used the anonymous path, the auth context would be empty.
        Assert.NotNull(transformer.LastAuthContext);
        Assert.True(transformer.LastAuthContext!.IsAuthenticated);
    }

    [Fact]
    public async Task OptionalBearerTokenBackend_ForwardsPolicyAndToken_WhenAuthenticated()
    {
        // The optional-auth combination: WithBackendAuth(..., optional: true) on an
        // AllowAnonymousWithOptionalAuth endpoint applies the policy for authenticated callers,
        // so their token reaches the backend.
        var backend = new MockBackendCaller()
            .SetupResponse("https://backend.test/maybe", new EchoResponse { Echoed = "ok" });
        using var bff = await CreateBffAsync(endpoints => endpoints
            .MapTransformer<RecordingTransformer, EchoResponse>()
            .FromGet("/api/maybe")
            .ToBackend("GET", "https://backend.test/maybe")
            .WithBackendAuth(BackendAuthPolicies.BearerToken, optional: true)
            .AllowAnonymousWithOptionalAuth()
            .Build(), backend, authenticated: true);

        var client = bff.GetTestServer().CreateClient();
        var response = await client.GetAsync("/api/maybe", TestContext.Current.CancellationToken);

        response.EnsureSuccessStatusCode();
        var recorded = Assert.Single(backend.RecordedCalls);
        Assert.Equal(BackendAuthPolicies.BearerToken, recorded.Request.BackendAuthPolicy);
        Assert.Equal("user-access-token", recorded.Request.AccessToken);
    }

    [Fact]
    public async Task OptionalBearerTokenBackend_DowngradesToNone_WhenAnonymous()
    {
        // Anonymous callers on an optional-auth endpoint have no token to forward, so the
        // optional-flagged policy is downgraded to None instead of warning (BearerToken) or
        // failing the request (TokenExchange).
        var backend = new MockBackendCaller()
            .SetupResponse("https://backend.test/maybe", new EchoResponse { Echoed = "ok" });
        using var bff = await CreateBffAsync(endpoints => endpoints
            .MapTransformer<RecordingTransformer, EchoResponse>()
            .FromGet("/api/maybe")
            .ToBackend("GET", "https://backend.test/maybe")
            .WithBackendAuth(BackendAuthPolicies.BearerToken, optional: true)
            .AllowAnonymousWithOptionalAuth()
            .Build(), backend);

        var client = bff.GetTestServer().CreateClient();
        var response = await client.GetAsync("/api/maybe", TestContext.Current.CancellationToken);

        response.EnsureSuccessStatusCode();
        var recorded = Assert.Single(backend.RecordedCalls);
        Assert.Equal(BackendAuthPolicies.None, recorded.Request.BackendAuthPolicy);
        Assert.Null(recorded.Request.AccessToken);
    }

    [Fact]
    public async Task OptionalTokenExchange_AppliedWhenAuthenticated_DisabledWhenAnonymous()
    {
        // Token exchange follows the same optional rule: exchanged for authenticated callers,
        // switched off (not failed) for anonymous ones.
        var backend = new MockBackendCaller()
            .SetupResponse("https://backend.test/orders", new EchoResponse { Echoed = "ok" });
        using var authenticatedBff = await CreateBffAsync(endpoints => endpoints
            .MapTransformer<RecordingTransformer, EchoResponse>()
            .FromGet("/api/orders")
            .ToBackend("GET", "https://backend.test/orders")
            .WithTokenExchange("orders-api", optional: true)
            .AllowAnonymousWithOptionalAuth()
            .Build(), backend, authenticated: true);

        var response = await authenticatedBff.GetTestServer().CreateClient()
            .GetAsync("/api/orders", TestContext.Current.CancellationToken);

        response.EnsureSuccessStatusCode();
        var recorded = Assert.Single(backend.RecordedCalls);
        Assert.True(recorded.Request.UseTokenExchange);
        Assert.Equal("orders-api", recorded.Request.TokenExchangeAudience);

        var anonymousBackend = new MockBackendCaller()
            .SetupResponse("https://backend.test/orders", new EchoResponse { Echoed = "ok" });
        using var anonymousBff = await CreateBffAsync(endpoints => endpoints
            .MapTransformer<RecordingTransformer, EchoResponse>()
            .FromGet("/api/orders")
            .ToBackend("GET", "https://backend.test/orders")
            .WithTokenExchange("orders-api", optional: true)
            .AllowAnonymousWithOptionalAuth()
            .Build(), anonymousBackend);

        var anonymousResponse = await anonymousBff.GetTestServer().CreateClient()
            .GetAsync("/api/orders", TestContext.Current.CancellationToken);

        anonymousResponse.EnsureSuccessStatusCode();
        var anonymousRecorded = Assert.Single(anonymousBackend.RecordedCalls);
        Assert.False(anonymousRecorded.Request.UseTokenExchange);
        Assert.Null(anonymousRecorded.Request.AccessToken);
    }

    [Fact]
    public async Task AllowAnonymousWithOptionalAuth_PolicyPassed_GetsAuthenticatedTreatment()
    {
        // AllowAnonymousWithOptionalAuth(policy): the authenticated treatment is gated on the
        // authorization policy, evaluated against HttpContext.User (hence the stub scheme).
        var backend = new MockBackendCaller()
            .SetupResponse("https://backend.test/maybe", new EchoResponse { Echoed = "ok" });
        using var bff = await CreateBffAsync(endpoints => endpoints
            .MapTransformer<RecordingTransformer, EchoResponse>()
            .FromGet("/api/maybe")
            .ToBackend("GET", "https://backend.test/maybe")
            .WithBackendAuth(BackendAuthPolicies.BearerToken, optional: true)
            .AllowAnonymousWithOptionalAuth("KnownUser")
            .Build(), backend, authenticated: true, withStubAuthScheme: true,
            configureAuthorization: options => options.AddPolicy(
                "KnownUser", p => p.RequireClaim(ClaimTypes.NameIdentifier)));

        var response = await bff.GetTestServer().CreateClient()
            .GetAsync("/api/maybe", TestContext.Current.CancellationToken);

        response.EnsureSuccessStatusCode();
        var recorded = Assert.Single(backend.RecordedCalls);
        Assert.Equal(BackendAuthPolicies.BearerToken, recorded.Request.BackendAuthPolicy);
        Assert.Equal("user-access-token", recorded.Request.AccessToken);
    }

    [Fact]
    public async Task AllowAnonymousWithOptionalAuth_PolicyFailed_ServedAnonymousView()
    {
        // A credentialed caller that fails the policy is downgraded to the anonymous view, not
        // 403'd: anonymous access is allowed anyway, so a failing credential only removes
        // privilege - it must never make the caller worse off than sending no credential.
        var backend = new MockBackendCaller()
            .SetupResponse("https://backend.test/maybe", new EchoResponse { Echoed = "ok" });
        var transformer = new RecordingTransformer();
        using var bff = await CreateBffAsync(endpoints => endpoints
            .MapTransformer<RecordingTransformer, EchoResponse>()
            .FromGet("/api/maybe")
            .ToBackend("GET", "https://backend.test/maybe")
            .WithBackendAuth(BackendAuthPolicies.BearerToken, optional: true)
            .AllowAnonymousWithOptionalAuth("AdminOnly")
            .Build(), backend, transformer: transformer, authenticated: true, withStubAuthScheme: true,
            configureAuthorization: options => options.AddPolicy(
                "AdminOnly", p => p.RequireClaim("admin")));

        var response = await bff.GetTestServer().CreateClient()
            .GetAsync("/api/maybe", TestContext.Current.CancellationToken);

        response.EnsureSuccessStatusCode();
        var recorded = Assert.Single(backend.RecordedCalls);
        Assert.Equal(BackendAuthPolicies.None, recorded.Request.BackendAuthPolicy);
        Assert.Null(recorded.Request.AccessToken);
        Assert.NotNull(transformer.LastAuthContext);
        Assert.False(transformer.LastAuthContext!.IsAuthenticated);
    }

    [Fact]
    public async Task AllowAnonymous_BearerTokenBackend_FailsAtStartup()
    {
        // Plain AllowAnonymous() must keep rejecting user-identity backend policies at startup:
        // the endpoint never guarantees a token, and the caller did not opt into the
        // downgrade-to-None behavior of AllowAnonymousWithOptionalAuth().
        var backend = new MockBackendCaller();

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => CreateBffAsync(endpoints => endpoints
            .MapTransformer<RecordingTransformer, EchoResponse>()
            .FromGet("/api/anon")
            .ToBackend("GET", "https://backend.test/anon")
            .WithBackendAuth(BackendAuthPolicies.BearerToken)
            .AllowAnonymous()
            .Build(), backend));

        Assert.Contains("AllowAnonymousWithOptionalAuth", ex.Message);
    }

    [Fact]
    public async Task AllowAnonymousWithOptionalAuth_MandatoryIdentityBackend_FailsAtStartup()
    {
        // A NON-optional user-identity policy promises the backend an identity that anonymous
        // callers do not have. The optional endpoint must not silently downgrade a mandatory
        // promise - the policy has to be declared optional explicitly.
        var backend = new MockBackendCaller();

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => CreateBffAsync(endpoints => endpoints
            .MapTransformer<RecordingTransformer, EchoResponse>()
            .FromGet("/api/maybe")
            .ToBackend("GET", "https://backend.test/maybe")
            .WithBackendAuth(BackendAuthPolicies.BearerToken)
            .AllowAnonymousWithOptionalAuth()
            .Build(), backend));

        Assert.Contains("optional: true", ex.Message);
    }

    [Fact]
    public async Task OptionalBackendAuth_OnRequireAuthEndpoint_FailsAtStartup()
    {
        // optional: true on a RequireAuth endpoint is dead configuration - identity is always
        // present, so the flag can never change behavior. Fail loud instead of misleading readers.
        var backend = new MockBackendCaller();

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => CreateBffAsync(endpoints => endpoints
            .MapTransformer<RecordingTransformer, EchoResponse>()
            .FromGet("/api/orders")
            .ToBackend("GET", "https://backend.test/orders")
            .WithBackendAuth(BackendAuthPolicies.BearerToken, optional: true)
            .RequireAuth()
            .Build(), backend, withStubAuthScheme: true));

        Assert.Contains("AllowAnonymousWithOptionalAuth", ex.Message);
    }

    [Fact]
    public async Task OptionalBackendAuth_OnNonIdentityPolicy_FailsAtStartup()
    {
        // BasicAuth uses the BFF's own credentials - there is no caller identity to apply
        // optionally, so the flag is a misconfiguration.
        var backend = new MockBackendCaller();

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => CreateBffAsync(endpoints => endpoints
            .MapTransformer<RecordingTransformer, EchoResponse>()
            .FromGet("/api/things")
            .ToBackend("GET", "https://backend.test/things")
            .WithBackendAuth(BackendAuthPolicies.BasicAuth, optional: true)
            .AllowAnonymousWithOptionalAuth()
            .Build(), backend));

        Assert.Contains("never carries", ex.Message);
    }

    [Fact]
    public async Task AllowAnonymous_IsCredentialBlind_EvenWhenCredentialsPresent()
    {
        // AllowAnonymous() endpoints never resolve credentials: the transformer always sees an
        // empty AuthContext, even when the caller sent valid credentials (data minimization - an
        // endpoint declared anonymous never handles tokens). Use AllowAnonymousWithOptionalAuth()
        // to personalize opportunistically.
        var backend = new MockBackendCaller()
            .SetupResponse("https://backend.test/open", new EchoResponse { Echoed = "ok" });
        var transformer = new RecordingTransformer();
        using var bff = await CreateBffAsync(endpoints => endpoints
            .MapTransformer<RecordingTransformer, EchoResponse>()
            .FromGet("/api/open")
            .ToBackend("GET", "https://backend.test/open")
            .AllowAnonymous()
            .Build(), backend, transformer: transformer, authenticated: true);

        var client = bff.GetTestServer().CreateClient();
        var response = await client.GetAsync("/api/open", TestContext.Current.CancellationToken);

        response.EnsureSuccessStatusCode();
        Assert.NotNull(transformer.LastAuthContext);
        Assert.False(transformer.LastAuthContext!.IsAuthenticated);
        var recorded = Assert.Single(backend.RecordedCalls);
        Assert.Null(recorded.Request.AccessToken);
    }

    [Fact]
    public async Task AllowAnonymous_ThrowingAuthProvider_StillServesRequest()
    {
        // AllowAnonymous() is credential-blind, so a provider that throws on missing/invalid
        // credentials can never fail the request - it is not even consulted.
        var backend = new MockBackendCaller()
            .SetupResponse("https://backend.test/open", new EchoResponse { Echoed = "ok" });
        var transformer = new RecordingTransformer();
        using var bff = await CreateBffAsync(endpoints => endpoints
            .MapTransformer<RecordingTransformer, EchoResponse>()
            .FromGet("/api/open")
            .ToBackend("GET", "https://backend.test/open")
            .AllowAnonymous()
            .Build(), backend, transformer: transformer, authProvider: new ThrowingAuthProvider());

        var client = bff.GetTestServer().CreateClient();
        var response = await client.GetAsync("/api/open", TestContext.Current.CancellationToken);

        response.EnsureSuccessStatusCode();
        Assert.NotNull(transformer.LastAuthContext);
        Assert.False(transformer.LastAuthContext!.IsAuthenticated);
    }

    [Fact]
    public async Task AllowAnonymousWithOptionalAuth_ThrowingAuthProvider_DegradesToAnonymous_InsteadOf500()
    {
        // The optional rung resolves via TryGetAuthContextAsync: a custom provider that throws on
        // a missing/invalid credential must degrade the request to anonymous, not 500 it (and an
        // anonymous hit must not be counted as an authentication failure).
        var backend = new MockBackendCaller()
            .SetupResponse("https://backend.test/open", new EchoResponse { Echoed = "ok" });
        var transformer = new RecordingTransformer();
        using var bff = await CreateBffAsync(endpoints => endpoints
            .MapTransformer<RecordingTransformer, EchoResponse>()
            .FromGet("/api/open")
            .ToBackend("GET", "https://backend.test/open")
            .AllowAnonymousWithOptionalAuth()
            .Build(), backend, transformer: transformer, authProvider: new ThrowingAuthProvider());

        var client = bff.GetTestServer().CreateClient();
        var response = await client.GetAsync("/api/open", TestContext.Current.CancellationToken);

        response.EnsureSuccessStatusCode();
        Assert.NotNull(transformer.LastAuthContext);
        Assert.False(transformer.LastAuthContext!.IsAuthenticated);
    }

    [Fact]
    public async Task ToAny_ForwardsIncomingMethod_OnBackendRequest()
    {
        // ToAny is the method-preserving proxy: backend method follows the inbound request.
        // Captured _backendMethod is "*"; the handler must resolve to the request's actual verb.
        var backend = new MockBackendCaller()
            .SetupResponse("https://backend.test/proxy", new EchoResponse { Echoed = "ok" });
        using var bff = await CreateBffAsync(endpoints => endpoints
            .MapTransformer<RecordingTransformer, EchoResponse>()
            .FromAny("/proxy/{**path}")
            .ToAny("https://backend.test/proxy")
            .AllowAnonymous()
            .Build(), backend);

        var client = bff.GetTestServer().CreateClient();
        var response = await client.DeleteAsync("/proxy/widgets/42", TestContext.Current.CancellationToken);

        response.EnsureSuccessStatusCode();
        var recorded = Assert.Single(backend.RecordedCalls);
        Assert.Equal("DELETE", recorded.Request.Method);
    }

    [Theory]
    [InlineData("GET")]
    [InlineData("POST")]
    [InlineData("PUT")]
    [InlineData("DELETE")]
    [InlineData("PATCH")]
    public async Task ToVerbSugar_SetsBackendMethod_MirroringFromVerbSugar(string verb)
    {
        // The To{Verb} helpers are thin wrappers over ToBackend("VERB", ...), symmetric with the
        // From{Verb} incoming sugar. The backend method is independent of the inbound verb (here
        // always GET), so a wrong delegation would surface as a mismatched recorded method.
        var backend = new MockBackendCaller()
            .SetupResponse("https://backend.test/sugar", new EchoResponse { Echoed = "ok" });
        using var bff = await CreateBffAsync(endpoints =>
        {
            var builder = endpoints
                .MapTransformer<RecordingTransformer, EchoResponse>()
                .FromGet("/api/sugar");
            builder = verb switch
            {
                "GET" => builder.ToGet("https://backend.test/sugar"),
                "POST" => builder.ToPost("https://backend.test/sugar"),
                "PUT" => builder.ToPut("https://backend.test/sugar"),
                "DELETE" => builder.ToDelete("https://backend.test/sugar"),
                "PATCH" => builder.ToPatch("https://backend.test/sugar"),
                _ => throw new ArgumentOutOfRangeException(nameof(verb)),
            };
            builder.AllowAnonymous().Build();
        }, backend);

        var client = bff.GetTestServer().CreateClient();
        var response = await client.GetAsync("/api/sugar", TestContext.Current.CancellationToken);

        response.EnsureSuccessStatusCode();
        var recorded = Assert.Single(backend.RecordedCalls);
        Assert.Equal(verb, recorded.Request.Method);
        Assert.Equal("https://backend.test/sugar", recorded.Request.Url);
    }

    [Fact]
    public async Task ToVerbSugar_PassesContentTypeThrough()
    {
        // The optional contentType parameter on the To{Verb} helpers must reach the BackendRequest,
        // same as ToBackend's third argument.
        var backend = new MockBackendCaller()
            .SetupResponse("https://backend.test/sugar-form", new EchoResponse { Echoed = "ok" });
        using var bff = await CreateBffAsync(endpoints => endpoints
            .MapTransformer<RecordingTransformer, EchoResponse>()
            .FromPost("/api/sugar-form")
            .ToPost("https://backend.test/sugar-form", ContentType.FormUrlEncoded)
            .AllowAnonymous()
            .Build(), backend);

        var client = bff.GetTestServer().CreateClient();
        var response = await client.PostAsync("/api/sugar-form", content: null, TestContext.Current.CancellationToken);

        response.EnsureSuccessStatusCode();
        var recorded = Assert.Single(backend.RecordedCalls);
        Assert.Equal(ContentType.FormUrlEncoded, recorded.Request.RequestContentType);
    }

    [Fact]
    public async Task ToBackend_DefaultsBackendRequestContentTypeToJson()
    {
        // The default ContentType.Json on ToBackend should land on the BackendRequest so the
        // caller serializes bodies as JSON unless overridden.
        var backend = new MockBackendCaller()
            .SetupResponse("https://backend.test/json", new EchoResponse { Echoed = "ok" });
        using var bff = await CreateBffAsync(endpoints => endpoints
            .MapTransformer<RecordingTransformer, EchoResponse>()
            .FromGet("/api/json")
            .ToBackend("GET", "https://backend.test/json")
            .AllowAnonymous()
            .Build(), backend);

        var client = bff.GetTestServer().CreateClient();
        var response = await client.GetAsync("/api/json", TestContext.Current.CancellationToken);

        response.EnsureSuccessStatusCode();
        var recorded = Assert.Single(backend.RecordedCalls);
        Assert.Equal(ContentType.Json, recorded.Request.RequestContentType);
    }

    [Fact]
    public async Task ToBackend_PreservesNonDefaultContentType()
    {
        var backend = new MockBackendCaller()
            .SetupResponse("https://backend.test/form", new EchoResponse { Echoed = "ok" });
        using var bff = await CreateBffAsync(endpoints => endpoints
            .MapTransformer<RecordingTransformer, EchoResponse>()
            .FromGet("/api/form")
            .ToBackend("GET", "https://backend.test/form", ContentType.FormUrlEncoded)
            .AllowAnonymous()
            .Build(), backend);

        var client = bff.GetTestServer().CreateClient();
        var response = await client.GetAsync("/api/form", TestContext.Current.CancellationToken);

        response.EnsureSuccessStatusCode();
        var recorded = Assert.Single(backend.RecordedCalls);
        Assert.Equal(ContentType.FormUrlEncoded, recorded.Request.RequestContentType);
    }

    [Fact]
    public async Task Build_FromRouteInterpolatesRouteValuesIntoBackendUrl()
    {
        // {id} in the backend URL template should be substituted with the matched route value
        // before the BackendRequest is built - otherwise downstream code would call the literal
        // ".../widgets/{id}" URL and 404.
        var backend = new MockBackendCaller()
            .SetupResponse("https://backend.test/widgets/42", new EchoResponse { Echoed = "ok" });
        using var bff = await CreateBffAsync(endpoints => endpoints
            .MapTransformer<RecordingTransformer, EchoResponse>()
            .FromGet("/api/widgets/{id}")
            .ToBackend("GET", "https://backend.test/widgets/{id}")
            .AllowAnonymous()
            .Build(), backend);

        var client = bff.GetTestServer().CreateClient();
        var response = await client.GetAsync("/api/widgets/42", TestContext.Current.CancellationToken);

        response.EnsureSuccessStatusCode();
        var recorded = Assert.Single(backend.RecordedCalls);
        Assert.Equal("https://backend.test/widgets/42", recorded.Request.Url);
    }

    [Fact]
    public void Build_WithoutFromRoute_Throws()
    {
        // Build() is the only place we can catch missing config at startup time; the error
        // must be clear (not an NRE deep in routing).
        var ex = Assert.Throws<InvalidOperationException>(() =>
        {
            using var app = WebApplication.CreateBuilder().Build();
            app.MapTransformer<RecordingTransformer, EchoResponse>()
                .ToBackend("GET", "https://backend.test/x")
                .AllowAnonymous()
                .Build();
        });
        Assert.Contains("FromRoute", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Build_WithoutBackend_Throws()
    {
        var ex = Assert.Throws<InvalidOperationException>(() =>
        {
            using var app = WebApplication.CreateBuilder().Build();
            app.MapTransformer<RecordingTransformer, EchoResponse>()
                .FromGet("/api/x")
                .AllowAnonymous()
                .Build();
        });
        Assert.Contains("Backend", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Build_Throws_WhenAllowForwardingHeadersUsed_WithoutSingleBackend()
    {
        // AllowForwardingHeaders() rides on the single-backend BackendRequest the endpoint
        // handler builds. Named backend legs construct their own requests inside the
        // transformer, where the allow-list is invisible - that must fail the boot instead of
        // silently forwarding nothing.
        var ex = Assert.Throws<InvalidOperationException>(() =>
        {
            using var app = WebApplication.CreateBuilder().Build();
            app.MapTransformer<RecordingTransformer, EchoResponse>()
                .FromGet("/api/x")
                .ToBackends(NamedBackendEndpoint.FromTuple("Data", "GET", "https://backend.test/data"))
                .AllowForwardingHeaders(["X-Request-Id"])
                .AllowAnonymous()
                .Build();
        });
        Assert.Contains("AllowForwardingHeaders", ex.Message);
    }

    [Fact]
    public void ToBackends_AppliesBackendAuthFallback_RegardlessOfCallOrder()
    {
        // The WithBackendAuth() default must reach named backends whether it's chained before or
        // after ToBackends(). Order-dependence here silently left backends unauthenticated.
        using var app1 = WebApplication.CreateBuilder().Build();
        var policyThenBackends = app1.MapTransformer<RecordingTransformer, EchoResponse>()
            .FromGet("/a")
            .WithBackendAuth("BasicAuth")
            .ToBackends(NamedBackendEndpoint.FromTuple("Data", "GET", "https://backend.test/data"))
            .ResolveNamedBackendsForTesting();

        using var app2 = WebApplication.CreateBuilder().Build();
        var backendsThenPolicy = app2.MapTransformer<RecordingTransformer, EchoResponse>()
            .FromGet("/b")
            .ToBackends(NamedBackendEndpoint.FromTuple("Data", "GET", "https://backend.test/data"))
            .WithBackendAuth("BasicAuth")
            .ResolveNamedBackendsForTesting();

        Assert.True(policyThenBackends.TryGet("Data", out var ep1));
        Assert.True(backendsThenPolicy.TryGet("Data", out var ep2));
        Assert.Equal("BasicAuth", ep1!.BackendAuthPolicy);
        Assert.Equal("BasicAuth", ep2!.BackendAuthPolicy); // was null before the fix (order-dependent)
    }

    [Fact]
    public void ToBackends_LambdaOverload_WiresEndpointsAndAppliesBackendAuthFallback()
    {
        // The configure(=>) overload must funnel through the same array overload, so named backends
        // are registered and the WithBackendAuth() default still fills the per-backend gap.
        using var app = WebApplication.CreateBuilder().Build();
        var resolved = app.MapTransformer<RecordingTransformer, EchoResponse>()
            .FromGet("/dash")
            .WithBackendAuth("BasicAuth")
            .ToBackends(b => b
                .ToGet("UserInfo", "https://backend.test/userinfo")
                .ToPost("Orders", "https://backend.test/orders").WithTokenExchange("order-api"))
            .ResolveNamedBackendsForTesting();

        Assert.True(resolved.TryGet("UserInfo", out var userInfo));
        Assert.Equal("GET", userInfo!.Method);
        Assert.Equal("BasicAuth", userInfo.BackendAuthPolicy); // filled by the WithBackendAuth fallback

        Assert.True(resolved.TryGet("Orders", out var orders));
        Assert.Equal("POST", orders!.Method);
        Assert.True(orders.UseTokenExchange); // explicit per-backend config preserved
        Assert.Equal("order-api", orders.TokenExchangeAudience);
    }

    [Fact]
    public void ToBackends_DoesNotOverrideExplicitPerBackendPolicy()
    {
        // A backend that set its own policy must keep it; the builder default only fills the gap.
        using var app = WebApplication.CreateBuilder().Build();
        var resolved = app.MapTransformer<RecordingTransformer, EchoResponse>()
            .FromGet("/c")
            .WithBackendAuth("BasicAuth")
            .ToBackends(NamedBackendEndpoint.FromTuple("Data", "GET", "https://backend.test/data", "BearerToken"))
            .ResolveNamedBackendsForTesting();

        Assert.True(resolved.TryGet("Data", out var ep));
        Assert.Equal("BearerToken", ep!.BackendAuthPolicy);
    }

    [Fact]
    public async Task ResponseSerializationFailure_Returns500_NotClient400()
    {
        // A JsonException while serializing the RESPONSE is a server bug; it must surface as 500,
        // not be misattributed to the client as a 400 "Invalid request body".
        var hostBuilder = new HostBuilder().ConfigureWebHost(webHost =>
        {
            webHost.UseTestServer();
            webHost.ConfigureServices(services =>
            {
                services.AddRouting();
                services.AddAuthorization();
                services.AddSingleton<IAuthenticationProvider, AnonymousAuthProvider>();
                services.AddSingleton<IBackendCaller>(new MockBackendCaller());
                services.AddSingleton<CyclicResponseTransformer>();
            });
            webHost.Configure(app =>
            {
                app.UseRouting();
                app.UseAuthorization();
                app.UseEndpoints(endpoints => endpoints
                    .MapTransformer<CyclicResponseTransformer, CyclicResponse>()
                    .FromGet("/api/cyclic")
                    .ToBackend("GET", "https://backend.test/x")
                    .AllowAnonymous()
                    .Build());
            });
        });
        using var host = await hostBuilder.StartAsync(TestContext.Current.CancellationToken);

        var client = host.GetTestServer().CreateClient();
        var response = await client.GetAsync("/api/cyclic", TestContext.Current.CancellationToken);

        Assert.Equal(500, (int)response.StatusCode);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Contains("Internal server error", body);
        Assert.DoesNotContain("Invalid request body", body);
    }

    [Fact]
    public async Task SelfWritten4xx_RecordsErrorSpan_NotGreen()
    {
        // Span-status contract (§1.5): a transformer that produces its own 4xx must NOT leave a
        // green span behind. Here the transformer sets a 403 status code without faulting, so the
        // happy-path span-status branch is the only thing that can flip the span to Error.
        //
        // The listener is process-global and fires ActivityStopped from whichever thread disposes
        // the span - including spans from other transformer tests running in parallel. Capturing the
        // one span we care about into a TaskCompletionSource (rather than List.Add, which is not
        // thread-safe under concurrent callbacks) and awaiting it also closes the race between the
        // client GetAsync completing and the server-side `using var activity` dispose running.
        var spanStopped = new TaskCompletionSource<Activity>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var listener = new ActivityListener
        {
            ShouldListenTo = source => source.Name == PortaActivitySource.Source.Name,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = a =>
            {
                // The span now carries a fixed category name; disambiguate from other parallel
                // transformer tests by the bff.transformation.strategy tag, not the activity name.
                if (a.OperationName == PortaActivitySource.Activities.Transformation
                    && (string?)a.GetTagItem(PortaActivitySource.Tags.TransformationStrategy) == nameof(SelfWritten4xxTransformer))
                {
                    spanStopped.TrySetResult(a);
                }
            },
        };
        ActivitySource.AddActivityListener(listener);

        var hostBuilder = new HostBuilder().ConfigureWebHost(webHost =>
        {
            webHost.UseTestServer();
            webHost.ConfigureServices(services =>
            {
                services.AddRouting();
                services.AddAuthorization();
                services.AddSingleton<IAuthenticationProvider, AnonymousAuthProvider>();
                services.AddSingleton<IBackendCaller>(new MockBackendCaller());
                services.AddSingleton<SelfWritten4xxTransformer>();
            });
            webHost.Configure(app =>
            {
                app.UseRouting();
                app.UseAuthorization();
                app.UseEndpoints(endpoints => endpoints
                    .MapTransformer<SelfWritten4xxTransformer, EchoResponse>()
                    .FromGet("/api/denied")
                    .ToBackend("GET", "https://backend.test/x")
                    .AllowAnonymous()
                    .Build());
            });
        });
        using var host = await hostBuilder.StartAsync(TestContext.Current.CancellationToken);

        var client = host.GetTestServer().CreateClient();
        var response = await client.GetAsync("/api/denied", TestContext.Current.CancellationToken);

        Assert.Equal(403, (int)response.StatusCode);
        var span = await spanStopped.Task.WaitAsync(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken);
        // Fixed category activity name - the transformer identity lives on the
        // bff.transformation.strategy tag, never baked into the span name.
        Assert.Equal(PortaActivitySource.Activities.Transformation, span.OperationName);
        Assert.Equal(nameof(SelfWritten4xxTransformer), span.GetTagItem(PortaActivitySource.Tags.TransformationStrategy));
        Assert.Equal(ActivityStatusCode.Error, span.Status);
        Assert.Equal(403, span.GetTagItem(PortaActivitySource.Tags.HttpStatusCode));
    }

    [Fact]
    public void When_NullPredicate_Throws()
    {
        // Defensive: a null predicate would NRE inside WhenPredicateMatcherPolicy at request
        // time. Catch it at build time with a clear ArgumentNullException.
        using var app = WebApplication.CreateBuilder().Build();
        var builder = app.MapTransformer<RecordingTransformer, EchoResponse>();

        Assert.Throws<ArgumentNullException>(() => builder.When(null!));
    }

    [Fact]
    public void AddTransformer_RegistersScopedService()
    {
        // AddTransformer<T>() registers the transformer scoped so it can pick up scoped deps
        // (e.g., DbContext). If this regresses to singleton it would break per-request state.
        var services = new ServiceCollection();
        services.AddTransformer<RecordingTransformer>();

        using var provider = services.BuildServiceProvider();
        using var scope1 = provider.CreateScope();
        using var scope2 = provider.CreateScope();

        var a = scope1.ServiceProvider.GetRequiredService<RecordingTransformer>();
        var b = scope2.ServiceProvider.GetRequiredService<RecordingTransformer>();
        var aAgain = scope1.ServiceProvider.GetRequiredService<RecordingTransformer>();

        Assert.NotSame(a, b);
        Assert.Same(a, aAgain);
    }

    [Fact]
    public void AddTransformerTypes_RegistersAllTypes_AsScoped()
    {
        var services = new ServiceCollection();
        services.AddTransformerTypes(typeof(RecordingTransformer), typeof(SecondTransformer));

        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();
        Assert.NotNull(scope.ServiceProvider.GetRequiredService<RecordingTransformer>());
        Assert.NotNull(scope.ServiceProvider.GetRequiredService<SecondTransformer>());
    }

    private static async Task<IHost> CreateBffAsync(
        Action<IEndpointRouteBuilder> configureEndpoints,
        IBackendCaller backend,
        RecordingTransformer? transformer = null,
        bool authenticated = false,
        bool withStubAuthScheme = false,
        IAuthenticationProvider? authProvider = null,
        Action<Microsoft.AspNetCore.Authorization.AuthorizationOptions>? configureAuthorization = null)
    {
        transformer ??= new RecordingTransformer();
        var hostBuilder = new HostBuilder()
            .ConfigureWebHost(webHost =>
            {
                webHost.UseTestServer();
                webHost.ConfigureServices(services =>
                {
                    services.AddRouting();
                    if (withStubAuthScheme)
                    {
                        services.AddAuthentication(StubAuthHandler.SchemeName)
                            .AddScheme<AuthenticationSchemeOptions, StubAuthHandler>(StubAuthHandler.SchemeName, _ => { });
                    }
                    services.AddAuthorization(configureAuthorization ?? (_ => { }));
                    if (authProvider is not null)
                    {
                        services.AddSingleton(authProvider);
                    }
                    else if (authenticated)
                    {
                        services.AddSingleton<IAuthenticationProvider>(new StubAuthProvider(authenticated: true));
                    }
                    else
                    {
                        services.AddSingleton<IAuthenticationProvider, AnonymousAuthProvider>();
                    }
                    services.AddSingleton(backend);
                    services.AddSingleton(transformer);
                });
                webHost.Configure(app =>
                {
                    app.UseRouting();
                    if (withStubAuthScheme)
                    {
                        app.UseAuthentication();
                    }
                    app.UseAuthorization();
                    app.UseEndpoints(configureEndpoints);
                });
            });
        return await hostBuilder.StartAsync();
    }

    public sealed class RecordingTransformer : ITransformer<EchoResponse>
    {
        public AuthenticationContext? LastAuthContext { get; private set; }
        public TransformerContext? LastContext { get; private set; }
        public BackendRequest? LastBackendRequest { get; private set; }

        public async Task<EchoResponse> TransformAsync(TransformerContext context)
        {
            LastContext = context;
            LastAuthContext = context.AuthContext;

            // Mirror what the typical user-written transformer does: pull the framework-built
            // BackendRequest out of Properties and dispatch it through IBackendCaller. This is
            // how the fluent settings actually reach the caller in real apps.
            if (context.Properties.TryGetValue("BackendRequest", out var raw) && raw is BackendRequest req)
            {
                LastBackendRequest = req;
                var result = await context.BackendCaller.CallAsync<EchoResponse>(req, context.CancellationToken);
                if (result.IsSuccess)
                {
                    return result.Value!;
                }
            }
            return new EchoResponse { Echoed = "ok" };
        }
    }

    public sealed class SecondTransformer : ITransformer<EchoResponse>
    {
        public Task<EchoResponse> TransformAsync(TransformerContext context)
            => Task.FromResult(new EchoResponse { Echoed = "ok" });
    }

    // Returns a self-referencing object so System.Text.Json throws a cycle JsonException while
    // serializing the response - used to prove that's a 500, not a client-blamed 400.
    public sealed class CyclicResponseTransformer : ITransformer<CyclicResponse>
    {
        public Task<CyclicResponse> TransformAsync(TransformerContext context)
        {
            var response = new CyclicResponse();
            response.Self = response;
            return Task.FromResult(response);
        }
    }

    public sealed class CyclicResponse
    {
        public CyclicResponse? Self { get; set; }
    }

    // Sets a 4xx status code without faulting or writing the body itself, so the framework still
    // serializes the response - the "self-written 4xx" happy-path branch the span-status contract covers.
    public sealed class SelfWritten4xxTransformer : ITransformer<EchoResponse>
    {
        public Task<EchoResponse> TransformAsync(TransformerContext context)
        {
            context.HttpContext.Response.StatusCode = 403;
            return Task.FromResult(new EchoResponse { Echoed = "denied" });
        }
    }

    public sealed class EchoResponse
    {
        public string Echoed { get; set; } = "";
    }

    private sealed class AnonymousAuthProvider : IAuthenticationProvider
    {
        public Task<AuthenticationContext> GetAuthContextAsync(HttpContext context, CancellationToken cancellationToken = default)
            => Task.FromResult(AuthenticationContext.Unauthenticated());

        public Task<AuthenticationContext?> RefreshAsync(AuthenticationContext current, CancellationToken cancellationToken = default)
            => Task.FromResult<AuthenticationContext?>(null);

        public Task InvalidateAsync(HttpContext context, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }

    // Models a custom provider that throws instead of returning an unauthenticated context
    // (the interface asks providers not to throw, but the optional path must tolerate it).
    private sealed class ThrowingAuthProvider : IAuthenticationProvider
    {
        public Task<AuthenticationContext> GetAuthContextAsync(HttpContext context, CancellationToken cancellationToken = default)
            => throw new InvalidOperationException("no credential");

        public Task<AuthenticationContext?> RefreshAsync(AuthenticationContext current, CancellationToken cancellationToken = default)
            => Task.FromResult<AuthenticationContext?>(null);

        public Task InvalidateAsync(HttpContext context, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }

    /// <summary>
    /// Always-authenticated authentication scheme so endpoints marked RequireAuth()
    /// can be exercised under the TestHost without wiring real OIDC.
    /// </summary>
    private sealed class StubAuthHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory loggerFactory,
        UrlEncoder encoder)
        : AuthenticationHandler<AuthenticationSchemeOptions>(options, loggerFactory, encoder)
    {
        public const string SchemeName = "Stub";

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var identity = new ClaimsIdentity(authenticationType: SchemeName);
            identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, "user-1"));
            var principal = new ClaimsPrincipal(identity);
            var ticket = new AuthenticationTicket(principal, SchemeName);
            return Task.FromResult(AuthenticateResult.Success(ticket));
        }
    }

    private sealed class StubAuthProvider(bool authenticated) : IAuthenticationProvider
    {
        public Task<AuthenticationContext> GetAuthContextAsync(HttpContext context, CancellationToken cancellationToken = default)
        {
            var ctx = authenticated
                ? new AuthenticationContext { AccessToken = "user-access-token" }
                : AuthenticationContext.Unauthenticated();
            return Task.FromResult(ctx);
        }

        public Task<AuthenticationContext?> RefreshAsync(AuthenticationContext current, CancellationToken cancellationToken = default)
            => Task.FromResult<AuthenticationContext?>(null);

        public Task InvalidateAsync(HttpContext context, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }
}
