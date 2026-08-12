using System.Net;
using System.Text;

using b17s.Porta.Auth.Providers;
using b17s.Porta.Extensions;
using b17s.Porta.Transformers;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace b17s.Porta.Tests.Transformers;

/// <summary>
/// Raw-forward endpoints sit on the same three-rung auth ladder as typed endpoints:
/// <c>RequireAuth()</c> (mandatory), <c>AllowAnonymousWithOptionalAuth()</c> (resolve when
/// present; user-identity backend auth only with <c>optional: true</c>), <c>AllowAnonymous()</c>
/// (credential-blind). These tests drive a real <see cref="BackendCaller"/> with a capturing
/// primary handler, so the Authorization header the backend actually receives is asserted -
/// not just the BackendRequest configuration.
/// </summary>
public sealed class RawForwardOptionalAuthTests
{
    [Fact]
    public async Task OptionalBearerToken_ForwardsToken_WhenAuthenticated()
    {
        var capture = new RequestCaptureHandler();
        using var bff = await CreateBffAsync(capture, builder => builder
            .FromGet("/proxy/data")
            .ToBackend("GET", "https://backend.test/data")
            .WithBackendAuth(BackendAuthPolicies.BearerToken, optional: true)
            .AllowAnonymousWithOptionalAuth(), authenticated: true);

        var response = await bff.GetTestServer().CreateClient()
            .GetAsync("/proxy/data", TestContext.Current.CancellationToken);

        response.EnsureSuccessStatusCode();
        Assert.Equal("Bearer user-access-token", capture.LastAuthorization);
    }

    [Fact]
    public async Task OptionalBearerToken_SendsNoAuth_WhenAnonymous()
    {
        var capture = new RequestCaptureHandler();
        using var bff = await CreateBffAsync(capture, builder => builder
            .FromGet("/proxy/data")
            .ToBackend("GET", "https://backend.test/data")
            .WithBackendAuth(BackendAuthPolicies.BearerToken, optional: true)
            .AllowAnonymousWithOptionalAuth(), authenticated: false);

        var response = await bff.GetTestServer().CreateClient()
            .GetAsync("/proxy/data", TestContext.Current.CancellationToken);

        response.EnsureSuccessStatusCode();
        Assert.Null(capture.LastAuthorization);
    }

    [Fact]
    public async Task AllowAnonymousWithOptionalAuth_PopulatesTransformerContext_WhenAuthenticated()
    {
        var capture = new RequestCaptureHandler();
        var recorder = new RecordingRawTransformer();
        using var bff = await CreateBffAsync(capture, builder => builder
            .FromGet("/proxy/data")
            .ToBackend("GET", "https://backend.test/data")
            .AllowAnonymousWithOptionalAuth(), authenticated: true, transformer: recorder);

        var response = await bff.GetTestServer().CreateClient()
            .GetAsync("/proxy/data", TestContext.Current.CancellationToken);

        response.EnsureSuccessStatusCode();
        Assert.NotNull(recorder.LastAuthContext);
        Assert.True(recorder.LastAuthContext!.IsAuthenticated);
    }

    [Fact]
    public async Task AllowAnonymous_IsCredentialBlind_EvenWhenCredentialsPresent()
    {
        // Same rule as typed endpoints: a raw-forward endpoint declared AllowAnonymous() never
        // resolves credentials, so its transformer hooks always see an empty AuthContext.
        var capture = new RequestCaptureHandler();
        var recorder = new RecordingRawTransformer();
        using var bff = await CreateBffAsync(capture, builder => builder
            .FromGet("/proxy/data")
            .ToBackend("GET", "https://backend.test/data")
            .AllowAnonymous(), authenticated: true, transformer: recorder);

        var response = await bff.GetTestServer().CreateClient()
            .GetAsync("/proxy/data", TestContext.Current.CancellationToken);

        response.EnsureSuccessStatusCode();
        Assert.NotNull(recorder.LastAuthContext);
        Assert.False(recorder.LastAuthContext!.IsAuthenticated);
        Assert.Null(capture.LastAuthorization);
    }

    [Fact]
    public async Task MandatoryBearerToken_OnOptionalEndpoint_FailsAtStartup()
    {
        var capture = new RequestCaptureHandler();

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => CreateBffAsync(capture, builder => builder
            .FromGet("/proxy/data")
            .ToBackend("GET", "https://backend.test/data")
            .WithBackendAuth(BackendAuthPolicies.BearerToken)
            .AllowAnonymousWithOptionalAuth(), authenticated: true));

        Assert.Contains("optional: true", ex.Message);
    }

    [Fact]
    public async Task OptionalFlag_OnRequireAuthRawForward_FailsAtStartup()
    {
        var capture = new RequestCaptureHandler();

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => CreateBffAsync(capture, builder => builder
            .FromGet("/proxy/data")
            .ToBackend("GET", "https://backend.test/data")
            .WithBackendAuth(BackendAuthPolicies.BearerToken, optional: true)
            .RequireAuth(), authenticated: true));

        Assert.Contains("AllowAnonymousWithOptionalAuth", ex.Message);
    }

    private static async Task<IHost> CreateBffAsync(
        RequestCaptureHandler captureHandler,
        Action<RawForwardEndpointBuilder<RecordingRawTransformer>> configure,
        bool authenticated,
        RecordingRawTransformer? transformer = null)
    {
        transformer ??= new RecordingRawTransformer();
        var hostBuilder = new HostBuilder()
            .ConfigureWebHost(webHost =>
            {
                webHost.UseTestServer();
                webHost.ConfigureServices(services =>
                {
                    services.AddRouting();
                    // BearerToken forwards the user's token, so the backend host must clear the
                    // trusted-host allow-list - same requirement as production configuration.
                    services.AddPortaCore(options => options.TrustedHosts = ["https://backend.test"]);
                    services.AddSingleton<IAuthenticationProvider>(new StubAuthProvider(authenticated));
                    services.AddSingleton(transformer);
                    services.AddHttpClient(BackendCaller.HttpClientName)
                        .ConfigurePrimaryHttpMessageHandler(() => captureHandler);
                });
                webHost.Configure(app =>
                {
                    app.UseRouting();
                    app.UseEndpoints(endpoints =>
                    {
                        var builder = endpoints.MapRawForward<RecordingRawTransformer>();
                        configure(builder);
                        builder.Build();
                    });
                });
            });

        return await hostBuilder.StartAsync();
    }

    public sealed class RecordingRawTransformer : IRawTransformer
    {
        public AuthenticationContext? LastAuthContext { get; private set; }

        public void ModifyRequest(HttpRequestMessage request, TransformerContext context)
            => LastAuthContext = context.AuthContext;
    }

    private sealed class RequestCaptureHandler : HttpMessageHandler
    {
        public string? LastAuthorization { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            LastAuthorization = request.Headers.Authorization?.ToString();
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"ok\":true}", Encoding.UTF8, "application/json"),
            });
        }
    }

    private sealed class StubAuthProvider(bool authenticated) : IAuthenticationProvider
    {
        public Task<AuthenticationContext> GetAuthContextAsync(HttpContext context, CancellationToken cancellationToken = default)
            => Task.FromResult(authenticated
                ? new AuthenticationContext { AccessToken = "user-access-token" }
                : AuthenticationContext.Unauthenticated());

        public Task<AuthenticationContext?> RefreshAsync(AuthenticationContext current, CancellationToken cancellationToken = default)
            => Task.FromResult<AuthenticationContext?>(null);

        public Task InvalidateAsync(HttpContext context, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }
}
