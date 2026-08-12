using System.Net;
using System.Text;

using b17s.Porta.Configuration;
using b17s.Porta.Transformers;

using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace b17s.Porta.Tests.Transformers;

/// <summary>
/// BackendCaller's mint-fresh-on-401 path for the ClientCredentials policy: exactly one retry
/// with <see cref="BackendAuthContext.ForceFreshCredential"/> set, no retry storm on a second
/// 401, no retry at all when the opt-out flag is set or a different policy is in play.
/// </summary>
public sealed class BackendCallerClientCredentialsRetryTests
{
    [Fact]
    public async Task BackendReturns401_RetriesOnce_WithForceFreshCredential()
    {
        var backend = new SequenceHandler(HttpStatusCode.Unauthorized, HttpStatusCode.OK);
        var auth = new RecordingAuthHandler(BackendAuthPolicies.ClientCredentials);
        using var caller = CreateCaller(auth, backend);

        var result = await caller.CallAsync(Request(BackendAuthPolicies.ClientCredentials), TestContext.Current.CancellationToken);

        Assert.True(result.IsSuccess);
        Assert.Equal(2, backend.CallCount);
        Assert.Equal([false, true], auth.ForceFreshFlags);
    }

    [Fact]
    public async Task RetryAlso401_NoThirdAttempt_FailureSurfaced()
    {
        // A fresh token being rejected means the problem is not staleness - exactly two attempts,
        // then the (mapped) failure surfaces. No loop.
        var backend = new SequenceHandler(HttpStatusCode.Unauthorized, HttpStatusCode.Unauthorized);
        var auth = new RecordingAuthHandler(BackendAuthPolicies.ClientCredentials);
        using var caller = CreateCaller(auth, backend);

        var result = await caller.CallAsync(Request(BackendAuthPolicies.ClientCredentials), TestContext.Current.CancellationToken);

        Assert.False(result.IsSuccess);
        Assert.Equal(2, backend.CallCount);
        Assert.Equal(BackendErrorType.AuthenticationError, result.ErrorType);
    }

    [Fact]
    public async Task RefreshOn401Disabled_SingleAttempt()
    {
        var backend = new SequenceHandler(HttpStatusCode.Unauthorized, HttpStatusCode.OK);
        var auth = new RecordingAuthHandler(BackendAuthPolicies.ClientCredentials);
        using var caller = CreateCaller(auth, backend, opts => opts.RefreshBackendTokenOn401 = false);

        var result = await caller.CallAsync(Request(BackendAuthPolicies.ClientCredentials), TestContext.Current.CancellationToken);

        Assert.False(result.IsSuccess);
        Assert.Equal(1, backend.CallCount);
    }

    [Fact]
    public async Task NonClientCredentialsPolicy_DoesNotUseMintFreshPath()
    {
        // BasicAuth 401s must not trigger the retry - re-minting cannot fix static credentials.
        var backend = new SequenceHandler(HttpStatusCode.Unauthorized, HttpStatusCode.OK);
        var auth = new RecordingAuthHandler(BackendAuthPolicies.BasicAuth);
        using var caller = CreateCaller(auth, backend);

        var result = await caller.CallAsync(Request(BackendAuthPolicies.BasicAuth), TestContext.Current.CancellationToken);

        Assert.False(result.IsSuccess);
        Assert.Equal(1, backend.CallCount);
    }

    private static BackendRequest Request(string policy) => new()
    {
        Method = "GET",
        Url = "https://backend.test/data",
        BackendAuthPolicy = policy,
    };

    private static BackendCaller CreateCaller(
        IBackendAuthHandler authHandler,
        HttpMessageHandler backend,
        Action<PortaCoreOptions>? configure = null)
    {
        var registry = new BackendAuthHandlerRegistry();
        registry.Register(authHandler);
        var options = new PortaCoreOptions();
        configure?.Invoke(options);

        return new BackendCaller(
            new SingleHandlerHttpClientFactory(backend),
            registry,
            new ContentSerializer(),
            metrics: null,
            logger: NullLogger<BackendCaller>.Instance,
            coreOptions: Options.Create(options));
    }

    private sealed class RecordingAuthHandler(string policyName) : IBackendAuthHandler
    {
        public List<bool> ForceFreshFlags { get; } = [];

        public string PolicyName => policyName;

        public Task ApplyAuthAsync(HttpRequestMessage request, BackendAuthContext context)
        {
            ForceFreshFlags.Add(context.ForceFreshCredential);
            return Task.CompletedTask;
        }
    }

    /// <summary>Returns the given statuses in order; repeats the last one when exhausted.</summary>
    private sealed class SequenceHandler(params HttpStatusCode[] statuses) : HttpMessageHandler
    {
        private int _calls;

        public int CallCount => _calls;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var call = Interlocked.Increment(ref _calls);
            var status = statuses[Math.Min(call - 1, statuses.Length - 1)];
            return Task.FromResult(new HttpResponseMessage(status)
            {
                Content = new StringContent("{}", Encoding.UTF8, "application/json"),
            });
        }
    }

    private sealed class SingleHandlerHttpClientFactory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(handler, disposeHandler: false);
    }
}
