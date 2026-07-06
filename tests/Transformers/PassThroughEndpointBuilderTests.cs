using System.Reflection;
using System.Security.Claims;
using System.Text.Encodings.Web;

using b17s.Porta.Auth.Providers;
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
/// Exercises the public <see cref="PassThroughEndpointBuilder{TResponse}"/> fluent surface
/// via <see cref="PassThroughExtensions.MapPassThrough{TResponse}(IEndpointRouteBuilder)"/>.
/// PassThrough is the zero-code on-ramp — most production callers use it instead of writing
/// a transformer — so each chain method needs an end-to-end assertion that the resulting
/// endpoint actually behaves the way the docs promise.
///
/// The builder delegates everything to <see cref="TransformerEndpointBuilder{TTransformer, TResponse}"/>,
/// but that delegation is exactly the regression risk: a missing-or-misnamed override would
/// silently drop a fluent setting on PassThrough endpoints while the underlying
/// <c>MapTransformer&lt;&gt;</c> path keeps working.
/// </summary>
public sealed class PassThroughEndpointBuilderTests
{
    public sealed class Routing
    {
        [Theory]
        [InlineData("GET")]
        [InlineData("POST")]
        [InlineData("PUT")]
        [InlineData("DELETE")]
        [InlineData("PATCH")]
        public async Task FromVerb_RegistersEndpoint_ForThatHttpMethod(string method)
        {
            // Each From* convenience method must map the route under the matching verb. A
            // dropped delegate would surface as a 404/405 rather than a wrong-body, so test
            // by hitting the endpoint.
            var backend = new MockBackendCaller()
                .SetupResponse("https://backend.test/x", new EchoResponse { Echoed = "ok" });
            using var bff = await CreateBffAsync(endpoints =>
            {
                var builder = endpoints.MapPassThrough<EchoResponse>();
                _ = method switch
                {
                    "GET" => builder.FromGet("/api/x"),
                    "POST" => builder.FromPost("/api/x"),
                    "PUT" => builder.FromPut("/api/x"),
                    "DELETE" => builder.FromDelete("/api/x"),
                    "PATCH" => builder.FromPatch("/api/x"),
                    _ => throw new InvalidOperationException(),
                };
                builder.ToBackend(method, "https://backend.test/x")
                    .AllowAnonymous()
                    .Build();
            }, backend);

            using var request = new HttpRequestMessage(new HttpMethod(method), "/api/x");
            var response = await bff.GetTestServer().CreateClient().SendAsync(request, TestContext.Current.CancellationToken);

            response.EnsureSuccessStatusCode();
            var recorded = Assert.Single(backend.RecordedCalls);
            Assert.Equal(method, recorded.Request.Method);
        }

        [Fact]
        public async Task FromRoute_RegistersCustomMethod()
        {
            var backend = new MockBackendCaller()
                .SetupResponse("https://backend.test/x", new EchoResponse { Echoed = "ok" });
            using var bff = await CreateBffAsync(endpoints => endpoints
                .MapPassThrough<EchoResponse>()
                .FromRoute("POST", "/api/x")
                .ToBackend("POST", "https://backend.test/x")
                .AllowAnonymous()
                .Build(), backend);

            var response = await bff.GetTestServer().CreateClient()
                .PostAsync("/api/x", content: null, TestContext.Current.CancellationToken);

            response.EnsureSuccessStatusCode();
        }

        [Fact]
        public async Task FromAny_MatchesArbitraryMethods()
        {
            // FromAny is the catch-all — any HTTP verb on the route should route to the
            // endpoint. Doubly important because the underlying TransformerEndpointBuilder
            // FromAny path is exercised here, but the PassThrough wrapper has its own
            // delegation that must not drop the call.
            var backend = new MockBackendCaller()
                .SetupResponse("https://backend.test/x", new EchoResponse { Echoed = "ok" });
            using var bff = await CreateBffAsync(endpoints => endpoints
                .MapPassThrough<EchoResponse>()
                .FromAny("/api/x")
                .ToAny("https://backend.test/x")
                .AllowAnonymous()
                .Build(), backend);

            var client = bff.GetTestServer().CreateClient();
            var get = await client.GetAsync("/api/x", TestContext.Current.CancellationToken);
            var put = await client.PutAsync("/api/x", content: null, TestContext.Current.CancellationToken);

            get.EnsureSuccessStatusCode();
            put.EnsureSuccessStatusCode();
            Assert.Equal(2, backend.RecordedCalls.Count);
            Assert.Contains(backend.RecordedCalls, c => c.Request.Method == "GET");
            Assert.Contains(backend.RecordedCalls, c => c.Request.Method == "PUT");
        }

        [Fact]
        public async Task FromHead_FromOptions_AreRoutable()
        {
            // Less commonly used than the JSON verbs but listed in the public API surface,
            // so they deserve a lock-in.
            var backend = new MockBackendCaller()
                .SetupResponse("https://backend.test/x", new EchoResponse { Echoed = "ok" });
            using var bff = await CreateBffAsync(endpoints =>
            {
                endpoints.MapPassThrough<EchoResponse>()
                    .FromHead("/api/head")
                    .ToBackend("HEAD", "https://backend.test/x")
                    .AllowAnonymous()
                    .Build();
                endpoints.MapPassThrough<EchoResponse>()
                    .FromOptions("/api/options")
                    .ToBackend("OPTIONS", "https://backend.test/x")
                    .AllowAnonymous()
                    .Build();
            }, backend);

            var client = bff.GetTestServer().CreateClient();
            var head = await client.SendAsync(new HttpRequestMessage(HttpMethod.Head, "/api/head"), TestContext.Current.CancellationToken);
            var options = await client.SendAsync(new HttpRequestMessage(HttpMethod.Options, "/api/options"), TestContext.Current.CancellationToken);

            head.EnsureSuccessStatusCode();
            options.EnsureSuccessStatusCode();
            Assert.Equal(2, backend.RecordedCalls.Count);
        }
    }

    public sealed class BackendDispatch
    {
        [Fact]
        public async Task ToBackend_SetsMethodAndUrl_OnBackendRequest()
        {
            var backend = new MockBackendCaller()
                .SetupResponse("https://backend.test/orders", new EchoResponse { Echoed = "ok" });
            using var bff = await CreateBffAsync(endpoints => endpoints
                .MapPassThrough<EchoResponse>()
                .FromGet("/api/orders")
                .ToBackend("GET", "https://backend.test/orders")
                .AllowAnonymous()
                .Build(), backend);

            await bff.GetTestServer().CreateClient().GetAsync("/api/orders", TestContext.Current.CancellationToken);

            var recorded = Assert.Single(backend.RecordedCalls);
            Assert.Equal("GET", recorded.Request.Method);
            Assert.Equal("https://backend.test/orders", recorded.Request.Url);
        }

        [Theory]
        [InlineData("GET")]
        [InlineData("POST")]
        [InlineData("PUT")]
        [InlineData("DELETE")]
        [InlineData("PATCH")]
        public async Task ToVerb_SetsBackendMethodAndUrl_OnBackendRequest(string method)
        {
            // The To* shorthands are what the README and docs use on every MapPassThrough
            // example. They were missing from the wrapper once (only ToBackend/ToAny/ToGraphQL
            // were re-exposed), so each verb gets an end-to-end lock-in.
            var backend = new MockBackendCaller()
                .SetupResponse("https://backend.test/x", new EchoResponse { Echoed = "ok" });
            using var bff = await CreateBffAsync(endpoints =>
            {
                var builder = endpoints.MapPassThrough<EchoResponse>().FromRoute(method, "/api/x");
                _ = method switch
                {
                    "GET" => builder.ToGet("https://backend.test/x"),
                    "POST" => builder.ToPost("https://backend.test/x"),
                    "PUT" => builder.ToPut("https://backend.test/x"),
                    "DELETE" => builder.ToDelete("https://backend.test/x"),
                    "PATCH" => builder.ToPatch("https://backend.test/x"),
                    _ => throw new InvalidOperationException(),
                };
                builder.AllowAnonymous().Build();
            }, backend);

            using var request = new HttpRequestMessage(new HttpMethod(method), "/api/x");
            var response = await bff.GetTestServer().CreateClient().SendAsync(request, TestContext.Current.CancellationToken);

            response.EnsureSuccessStatusCode();
            var recorded = Assert.Single(backend.RecordedCalls);
            Assert.Equal(method, recorded.Request.Method);
            Assert.Equal("https://backend.test/x", recorded.Request.Url);
        }

        [Fact]
        public async Task ToAny_ForwardsInboundMethod_ToBackend()
        {
            // ToAny is "same verb as the request". A regression that hard-codes the verb to
            // GET (or the empty string) would silently break PUT/DELETE flows.
            var backend = new MockBackendCaller()
                .SetupResponse("https://backend.test/x", new EchoResponse { Echoed = "ok" });
            using var bff = await CreateBffAsync(endpoints => endpoints
                .MapPassThrough<EchoResponse>()
                .FromAny("/api/x")
                .ToAny("https://backend.test/x")
                .AllowAnonymous()
                .Build(), backend);

            await bff.GetTestServer().CreateClient()
                .DeleteAsync("/api/x", TestContext.Current.CancellationToken);

            var recorded = Assert.Single(backend.RecordedCalls);
            Assert.Equal("DELETE", recorded.Request.Method);
            Assert.Equal("https://backend.test/x", recorded.Request.Url);
        }

        [Fact]
        public async Task ToGraphQL_ForcesPostMethod()
        {
            // Inherited behavior from TransformerEndpointBuilder: ToGraphQL coerces to POST
            // regardless of the inbound verb. Locked in so a future refactor of the
            // PassThrough wrapper doesn't accidentally bypass the underlying coercion.
            var backend = new MockBackendCaller()
                .SetupResponse("https://backend.test/graphql", new EchoResponse { Echoed = "ok" });
            using var bff = await CreateBffAsync(endpoints => endpoints
                .MapPassThrough<EchoResponse>()
                .FromPost("/api/gql")
                .ToGraphQL("https://backend.test/graphql")
                .AllowAnonymous()
                .Build(), backend);

            await bff.GetTestServer().CreateClient()
                .PostAsync("/api/gql", content: null, TestContext.Current.CancellationToken);

            var recorded = Assert.Single(backend.RecordedCalls);
            Assert.Equal("POST", recorded.Request.Method);
            Assert.Equal("https://backend.test/graphql", recorded.Request.Url);
        }
    }

    public sealed class AuthAndTimeout
    {
        [Fact]
        public async Task WithBackendAuth_PropagatesPolicyName_OnBackendRequest()
        {
            // WithBackendAuth selects the handler that runs against this backend. Confirms
            // the PassThrough wrapper forwards the policy to the inner builder.
            var backend = new MockBackendCaller()
                .SetupResponse("https://backend.test/x", new EchoResponse { Echoed = "ok" });
            using var bff = await CreateBffAsync(endpoints => endpoints
                .MapPassThrough<EchoResponse>()
                .FromGet("/api/x")
                .ToBackend("GET", "https://backend.test/x")
                .WithBackendAuth("BasicAuth")
                .AllowAnonymous()
                .Build(), backend);

            await bff.GetTestServer().CreateClient().GetAsync("/api/x", TestContext.Current.CancellationToken);

            var recorded = Assert.Single(backend.RecordedCalls);
            Assert.Equal("BasicAuth", recorded.Request.BackendAuthPolicy);
        }

        [Fact]
        public async Task WithTokenExchange_PopulatesAudienceAndFlag_OnBackendRequest()
        {
            // Token exchange requires an authenticated user (else there's nothing to
            // exchange), and the validator enforces RequireAuth(). Wire up a stub scheme so
            // the endpoint can actually run.
            var backend = new MockBackendCaller()
                .SetupResponse("https://backend.test/x", new EchoResponse { Echoed = "ok" });
            using var bff = await CreateBffAsync(endpoints => endpoints
                .MapPassThrough<EchoResponse>()
                .FromGet("/api/x")
                .ToBackend("GET", "https://backend.test/x")
                .WithTokenExchange("orders-api")
                .RequireAuth()
                .Build(), backend, withStubAuthScheme: true, authenticated: true);

            await bff.GetTestServer().CreateClient().GetAsync("/api/x", TestContext.Current.CancellationToken);

            var recorded = Assert.Single(backend.RecordedCalls);
            Assert.True(recorded.Request.UseTokenExchange);
            Assert.Equal("orders-api", recorded.Request.TokenExchangeAudience);
        }

        [Fact]
        public async Task WithTimeout_PropagatesTimeout_OnBackendRequest()
        {
            var backend = new MockBackendCaller()
                .SetupResponse("https://backend.test/slow", new EchoResponse { Echoed = "ok" });
            using var bff = await CreateBffAsync(endpoints => endpoints
                .MapPassThrough<EchoResponse>()
                .FromGet("/api/slow")
                .ToBackend("GET", "https://backend.test/slow")
                .WithTimeout(TimeSpan.FromSeconds(7))
                .AllowAnonymous()
                .Build(), backend);

            await bff.GetTestServer().CreateClient().GetAsync("/api/slow", TestContext.Current.CancellationToken);

            var recorded = Assert.Single(backend.RecordedCalls);
            Assert.Equal(TimeSpan.FromSeconds(7), recorded.Request.Timeout);
        }

        [Fact]
        public async Task WithRetries_EnablesRetriesAndCapsAttempts_OnBackendRequest()
        {
            var backend = new MockBackendCaller()
                .SetupResponse("https://backend.test/x", new EchoResponse { Echoed = "ok" });
            using var bff = await CreateBffAsync(endpoints => endpoints
                .MapPassThrough<EchoResponse>()
                .FromGet("/api/x")
                .ToBackend("GET", "https://backend.test/x")
                .WithRetries(5)
                .AllowAnonymous()
                .Build(), backend);

            await bff.GetTestServer().CreateClient().GetAsync("/api/x", TestContext.Current.CancellationToken);

            var recorded = Assert.Single(backend.RecordedCalls);
            Assert.True(recorded.Request.EnableRetries);
            Assert.Equal(5, recorded.Request.MaxRetryAttempts);
        }

        [Fact]
        public async Task AllowAnonymousWithOptionalAuth_Dispatches_WhenUnauthenticated()
        {
            // AllowAnonymousWithOptionalAuth differs from AllowAnonymous() in that an
            // authenticated user's credentials still flow through. The unauthenticated case
            // is the easy-to-regress one: it must still dispatch (no 401).
            var backend = new MockBackendCaller()
                .SetupResponse("https://backend.test/x", new EchoResponse { Echoed = "ok" });
            using var bff = await CreateBffAsync(endpoints => endpoints
                .MapPassThrough<EchoResponse>()
                .FromGet("/api/x")
                .ToBackend("GET", "https://backend.test/x")
                .AllowAnonymousWithOptionalAuth()
                .Build(), backend);

            var response = await bff.GetTestServer().CreateClient()
                .GetAsync("/api/x", TestContext.Current.CancellationToken);

            response.EnsureSuccessStatusCode();
            Assert.Single(backend.RecordedCalls);
        }
    }

    public sealed class HeaderForwarding
    {
        [Fact]
        public async Task Default_ForwardsNoClientHeaders()
        {
            // The typed pipeline builds its backend request from scratch; without an explicit
            // allow-list, ambient client headers (User-Agent, tracing noise, cookies) must not
            // leak to the backend.
            var backend = new MockBackendCaller()
                .SetupResponse("https://backend.test/x", new EchoResponse { Echoed = "ok" });
            using var bff = await CreateBffAsync(endpoints => endpoints
                .MapPassThrough<EchoResponse>()
                .FromGet("/api/x")
                .ToGet("https://backend.test/x")
                .AllowAnonymous()
                .Build(), backend);

            var client = bff.GetTestServer().CreateClient();
            client.DefaultRequestHeaders.Add("X-Request-Id", "req-1");
            await client.GetAsync("/api/x", TestContext.Current.CancellationToken);

            var recorded = Assert.Single(backend.RecordedCalls);
            Assert.Null(recorded.Request.Headers);
        }

        [Fact]
        public async Task AllowForwardingHeaders_CopiesListedHeaders_AndOnlyThose()
        {
            var backend = new MockBackendCaller()
                .SetupResponse("https://backend.test/x", new EchoResponse { Echoed = "ok" });
            using var bff = await CreateBffAsync(endpoints => endpoints
                .MapPassThrough<EchoResponse>()
                .FromGet("/api/x")
                .ToGet("https://backend.test/x")
                .AllowForwardingHeaders(["X-Request-Id"])
                .AllowAnonymous()
                .Build(), backend);

            var client = bff.GetTestServer().CreateClient();
            client.DefaultRequestHeaders.Add("X-Request-Id", "req-1");
            client.DefaultRequestHeaders.Add("Accept-Language", "de-DE");
            await client.GetAsync("/api/x", TestContext.Current.CancellationToken);

            var recorded = Assert.Single(backend.RecordedCalls);
            Assert.NotNull(recorded.Request.Headers);
            var header = Assert.Single(recorded.Request.Headers!);
            Assert.Equal("X-Request-Id", header.Key);
            Assert.Equal("req-1", header.Value);
        }

        [Fact]
        public async Task AllowForwardingHeaders_MatchesHeaderNames_CaseInsensitively()
        {
            var backend = new MockBackendCaller()
                .SetupResponse("https://backend.test/x", new EchoResponse { Echoed = "ok" });
            using var bff = await CreateBffAsync(endpoints => endpoints
                .MapPassThrough<EchoResponse>()
                .FromGet("/api/x")
                .ToGet("https://backend.test/x")
                .AllowForwardingHeaders(["x-request-id"])
                .AllowAnonymous()
                .Build(), backend);

            var client = bff.GetTestServer().CreateClient();
            client.DefaultRequestHeaders.Add("X-Request-Id", "req-1");
            await client.GetAsync("/api/x", TestContext.Current.CancellationToken);

            var recorded = Assert.Single(backend.RecordedCalls);
            Assert.NotNull(recorded.Request.Headers);
            Assert.Equal("req-1", Assert.Single(recorded.Request.Headers!).Value);
        }

        [Fact]
        public async Task AllowForwardingHeaders_FoldsMultiValueHeaders_WithComma()
        {
            var backend = new MockBackendCaller()
                .SetupResponse("https://backend.test/x", new EchoResponse { Echoed = "ok" });
            using var bff = await CreateBffAsync(endpoints => endpoints
                .MapPassThrough<EchoResponse>()
                .FromGet("/api/x")
                .ToGet("https://backend.test/x")
                .AllowForwardingHeaders(["X-Custom"])
                .AllowAnonymous()
                .Build(), backend);

            var client = bff.GetTestServer().CreateClient();
            using var request = new HttpRequestMessage(HttpMethod.Get, "/api/x");
            request.Headers.Add("X-Custom", ["a", "b"]);
            await client.SendAsync(request, TestContext.Current.CancellationToken);

            var recorded = Assert.Single(backend.RecordedCalls);
            Assert.Equal("a,b", Assert.Single(recorded.Request.Headers!).Value);
        }

        [Fact]
        public async Task AllowForwardingHeaders_SkipsForwarding_WhenDestinationHostNotInScope()
        {
            // Host scoping mirrors raw-forward's AllowedDestinationHosts: a non-matching backend
            // host means the allow-list does not apply and nothing is forwarded.
            var backend = new MockBackendCaller()
                .SetupResponse("https://backend.test/x", new EchoResponse { Echoed = "ok" });
            using var bff = await CreateBffAsync(endpoints => endpoints
                .MapPassThrough<EchoResponse>()
                .FromGet("/api/x")
                .ToGet("https://backend.test/x")
                .AllowForwardingHeaders(["X-Request-Id"], destinationHosts: ["other.test"])
                .AllowAnonymous()
                .Build(), backend);

            var client = bff.GetTestServer().CreateClient();
            client.DefaultRequestHeaders.Add("X-Request-Id", "req-1");
            await client.GetAsync("/api/x", TestContext.Current.CancellationToken);

            var recorded = Assert.Single(backend.RecordedCalls);
            Assert.Null(recorded.Request.Headers);
        }

        [Fact]
        public async Task AllowForwardingHeaders_Forwards_WhenDestinationHostInScope()
        {
            var backend = new MockBackendCaller()
                .SetupResponse("https://backend.test/x", new EchoResponse { Echoed = "ok" });
            using var bff = await CreateBffAsync(endpoints => endpoints
                .MapPassThrough<EchoResponse>()
                .FromGet("/api/x")
                .ToGet("https://backend.test/x")
                .AllowForwardingHeaders(["X-Request-Id"], destinationHosts: ["BACKEND.test"])
                .AllowAnonymous()
                .Build(), backend);

            var client = bff.GetTestServer().CreateClient();
            client.DefaultRequestHeaders.Add("X-Request-Id", "req-1");
            await client.GetAsync("/api/x", TestContext.Current.CancellationToken);

            var recorded = Assert.Single(backend.RecordedCalls);
            Assert.Equal("req-1", Assert.Single(recorded.Request.Headers!).Value);
        }

        [Theory]
        [InlineData("Host")]           // hop-by-hop
        [InlineData("Content-Length")] // framing
        [InlineData("Content-Type")]   // entity header; the typed path serializes its own body
        public void AllowForwardingHeaders_RejectsNeverForwardableHeaders_AtConfigurationTime(string header)
        {
            using var app = WebApplication.CreateBuilder().Build();
            var builder = app.MapPassThrough<EchoResponse>()
                .FromGet("/api/x")
                .ToGet("https://backend.test/x");

            Assert.Throws<ArgumentException>(() => builder.AllowForwardingHeaders([header]));
        }

        [Fact]
        public void Build_Throws_WhenForwardedAuthorization_WouldBeOverwrittenByBackendAuth()
        {
            // BackendCaller merges custom headers before applying backend auth, and the built-in
            // policies assign Authorization outright - the forwarded client value would silently
            // vanish. That contradiction must fail the boot, not ship.
            var ex = Assert.Throws<InvalidOperationException>(() =>
            {
                using var app = WebApplication.CreateBuilder().Build();
                app.MapPassThrough<EchoResponse>()
                    .FromGet("/api/x")
                    .ToGet("https://backend.test/x")
                    .WithBackendAuth(BackendAuthPolicies.BearerToken)
                    .AllowForwardingHeaders(["Authorization"])
                    .RequireAuth()
                    .Build();
            });
            Assert.Contains("Authorization", ex.Message);
        }

        [Fact]
        public async Task AllowForwardingHeaders_ForwardsAuthorization_WhenNoBackendAuthPolicySet()
        {
            // Listing Authorization is an explicit opt-in (mirroring raw-forward) and is legal
            // when no backend-auth policy competes for the header.
            var backend = new MockBackendCaller()
                .SetupResponse("https://backend.test/x", new EchoResponse { Echoed = "ok" });
            using var bff = await CreateBffAsync(endpoints => endpoints
                .MapPassThrough<EchoResponse>()
                .FromGet("/api/x")
                .ToGet("https://backend.test/x")
                .AllowForwardingHeaders(["Authorization"])
                .AllowAnonymous()
                .Build(), backend);

            var client = bff.GetTestServer().CreateClient();
            client.DefaultRequestHeaders.Add("Authorization", "Bearer client-token");
            await client.GetAsync("/api/x", TestContext.Current.CancellationToken);

            var recorded = Assert.Single(backend.RecordedCalls);
            Assert.Equal("Bearer client-token", Assert.Single(recorded.Request.Headers!).Value);
        }
    }

    public sealed class Predicate
    {
        [Fact]
        public async Task When_PredicateFalse_Returns404()
        {
            // The When() predicate gates whether the endpoint matches at all. A false
            // predicate must produce a 404 from routing, not silently dispatch. Confirms
            // the PassThrough wrapper actually forwards the predicate to the inner builder.
            var backend = new MockBackendCaller()
                .SetupResponse("https://backend.test/x", new EchoResponse { Echoed = "ok" });
            using var bff = await CreateBffAsync(endpoints => endpoints
                .MapPassThrough<EchoResponse>()
                .FromGet("/api/x")
                .When(_ => false)
                .ToBackend("GET", "https://backend.test/x")
                .AllowAnonymous()
                .Build(), backend);

            var response = await bff.GetTestServer().CreateClient()
                .GetAsync("/api/x", TestContext.Current.CancellationToken);

            Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
            Assert.Empty(backend.RecordedCalls);
        }

        [Fact]
        public async Task When_PredicateTrue_Dispatches()
        {
            var backend = new MockBackendCaller()
                .SetupResponse("https://backend.test/x", new EchoResponse { Echoed = "ok" });
            using var bff = await CreateBffAsync(endpoints => endpoints
                .MapPassThrough<EchoResponse>()
                .FromGet("/api/x")
                .When(_ => true)
                .ToBackend("GET", "https://backend.test/x")
                .AllowAnonymous()
                .Build(), backend);

            var response = await bff.GetTestServer().CreateClient()
                .GetAsync("/api/x", TestContext.Current.CancellationToken);

            response.EnsureSuccessStatusCode();
            Assert.Single(backend.RecordedCalls);
        }
    }

    public sealed class VocabularyParity
    {
        [Fact]
        public void PassThroughBuilder_ReExposes_EveryFluentMethod_OfTheInnerBuilder()
        {
            // PassThroughEndpointBuilder wraps TransformerEndpointBuilder via hand-written
            // delegation rather than inheritance, so every fluent method added to the inner
            // builder must be re-exposed manually. This has regressed before: the docs used
            // ToGet/ToPost/... on MapPassThrough while the wrapper only had ToBackend, so the
            // README's front-page example didn't compile.
            string[] intentionallyAbsent =
            [
                // Named multi-backend aggregation needs a transformer to merge results;
                // a zero-code pass-through has exactly one backend.
                "ToBackends",
            ];

            var fluentNames = new[] { typeof(BffEndpointBuilderBase<>), typeof(TransformerEndpointBuilderBase<,>) }
                .SelectMany(t => t.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly))
                .Where(m => m.ReturnType.IsGenericParameter && m.ReturnType.Name == "TBuilder")
                .Select(m => m.Name)
                .Distinct()
                .Except(intentionallyAbsent);

            var passThroughNames = typeof(PassThroughEndpointBuilder<>)
                .GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
                .Select(m => m.Name)
                .ToHashSet();

            var missing = fluentNames.Where(name => !passThroughNames.Contains(name)).ToList();
            Assert.True(missing.Count == 0,
                $"PassThroughEndpointBuilder is missing fluent methods documented on the inner builder: {string.Join(", ", missing)}. " +
                "Add delegating shorthands (or list them in intentionallyAbsent with a reason).");
        }
    }

    private static async Task<IHost> CreateBffAsync(
        Action<IEndpointRouteBuilder> configureEndpoints,
        IBackendCaller backend,
        bool authenticated = false,
        bool withStubAuthScheme = false)
    {
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
                    services.AddAuthorization();
                    if (authenticated)
                    {
                        services.AddSingleton<IAuthenticationProvider>(new StubAuthProvider(authenticated: true));
                    }
                    else
                    {
                        services.AddSingleton<IAuthenticationProvider, AnonymousAuthProvider>();
                    }
                    services.AddSingleton(backend);
                    // BackendForwardingTransformer is the synthetic transformer behind every
                    // MapPassThrough endpoint. Production code registers it via AddPortaCore;
                    // these tests register the open generic directly to keep the test setup
                    // narrow.
                    services.AddTransient(typeof(BackendForwardingTransformer<>));
                    // WhenPredicateMatcherPolicy evaluates When() predicates during endpoint
                    // selection; without it, the predicate metadata is stored but never read,
                    // so the endpoint matches regardless of the predicate result.
                    services.AddSingleton<Microsoft.AspNetCore.Routing.MatcherPolicy, WhenPredicateMatcherPolicy>();
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
}
