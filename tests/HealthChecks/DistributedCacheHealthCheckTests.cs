using System.Collections.Concurrent;
using System.Diagnostics;

using b17s.Porta.Configuration;
using b17s.Porta.HealthChecks;
using b17s.Porta.Telemetry;

using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace b17s.Porta.Tests.HealthChecks;

// Emits activities through the shared Porta ActivitySource, so it must not run in
// parallel with tests that attach a global listener and count spans.
[Collection(PortaActivitySourceCollection.Name)]
public sealed class DistributedCacheHealthCheckTests
{
    [Fact]
    public async Task RoundTrip_IsHealthy_RemovesProbeKey_AndReportsImplementation()
    {
        var cache = new DictionaryCache();
        var provider = BuildProvider(cache);
        var check = new DistributedCacheHealthCheck(provider, new PortaHealthCheckOptions());

        var result = await RunAsync(check);

        Assert.Equal(HealthStatus.Healthy, result.Status);
        Assert.Equal(nameof(DictionaryCache), result.Data["implementation"]);
        Assert.True(result.Data.ContainsKey("duration_ms"));
        Assert.Empty(cache.Store);
    }

    [Fact]
    public async Task MemoryDistributedCache_IsHealthySkipped_AndWarnsOncePerAppLifetime()
    {
        var loggerProvider = new CapturingLoggerProvider();
        var provider = BuildProvider(
            new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions())),
            services => services.AddLogging(b => b.AddProvider(loggerProvider)));
        var options = new PortaHealthCheckOptions();

        // Fresh check instance per execution, exactly like the registration factory behaves;
        // the warn-once flag lives on the PortaHealthCheckState singleton.
        var first = await RunAsync(new DistributedCacheHealthCheck(provider, options));
        var second = await RunAsync(new DistributedCacheHealthCheck(provider, options));

        Assert.Equal(HealthStatus.Healthy, first.Status);
        Assert.Contains("not shared across instances", first.Description);
        Assert.Equal(HealthStatus.Healthy, second.Status);
        Assert.Single(loggerProvider.Entries, e => e.EventId.Id == 14800 && e.Level == LogLevel.Warning);
    }

    [Fact]
    public async Task NoCacheRegistered_AutoMode_IsHealthySkipped()
    {
        var provider = BuildProvider(cache: null);
        var check = new DistributedCacheHealthCheck(provider, new PortaHealthCheckOptions());

        var result = await RunAsync(check);

        Assert.Equal(HealthStatus.Healthy, result.Status);
        Assert.Contains("skipped", result.Description);
    }

    [Fact]
    public async Task NoCacheRegistered_CheckRequired_ReportsFailureStatus()
    {
        var provider = BuildProvider(cache: null);
        var check = new DistributedCacheHealthCheck(
            provider, new PortaHealthCheckOptions { CheckDistributedCache = true });

        var result = await RunAsync(check, HealthStatus.Unhealthy);

        Assert.Equal(HealthStatus.Unhealthy, result.Status);
        Assert.Contains("no IDistributedCache", result.Description);
    }

    [Fact]
    public async Task ThrowingCache_ReportsFailureStatus_WithException()
    {
        var provider = BuildProvider(new ThrowingCache());
        var check = new DistributedCacheHealthCheck(provider, new PortaHealthCheckOptions());

        var result = await RunAsync(check, HealthStatus.Unhealthy);

        Assert.Equal(HealthStatus.Unhealthy, result.Status);
        Assert.IsType<TimeoutException>(result.Exception);
        Assert.Contains(nameof(ThrowingCache), result.Description);
    }

    [Fact]
    public async Task StallPastProbeTimeout_ReportsFailureStatus_MentioningTimeout()
    {
        var provider = BuildProvider(new StallingCache());
        var check = new DistributedCacheHealthCheck(
            provider, new PortaHealthCheckOptions { ProbeTimeout = TimeSpan.FromMilliseconds(100) });

        var result = await RunAsync(check, HealthStatus.Unhealthy);

        Assert.Equal(HealthStatus.Unhealthy, result.Status);
        Assert.Contains("timed out", result.Description);
    }

    [Fact]
    public async Task ExternalCancellation_PropagatesInsteadOfReportingFailure()
    {
        var provider = BuildProvider(new StallingCache());
        var check = new DistributedCacheHealthCheck(provider, new PortaHealthCheckOptions());

        using var cts = new CancellationTokenSource();
        cts.CancelAfter(TimeSpan.FromMilliseconds(50));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => RunAsync(check, ct: cts.Token));
    }

    [Fact]
    public async Task EmitsHealthCheckSpan_WithComponentAndDependencyTags()
    {
        var stopped = new ConcurrentBag<Activity>();
        using var listener = CreateListener(stopped);
        var provider = BuildProvider(new DictionaryCache());
        var check = new DistributedCacheHealthCheck(provider, new PortaHealthCheckOptions());

        await RunAsync(check);

        var span = Assert.Single(stopped);
        Assert.Equal(PortaActivitySource.Activities.HealthCheck, span.OperationName);
        Assert.Equal(ActivityKind.Client, span.Kind);
        Assert.Equal("health_check", span.GetTagItem(PortaActivitySource.Tags.Component));
        Assert.Equal("distributed-cache", span.GetTagItem(PortaActivitySource.Tags.BackendService));
        Assert.Contains(span.Events, e => e.Name == PortaActivitySource.Events.HealthCheckPerformed);
        Assert.Equal(ActivityStatusCode.Ok, span.Status);
    }

    [Fact]
    public async Task EnableTelemetryFalse_SuppressesTheSpan()
    {
        var stopped = new ConcurrentBag<Activity>();
        using var listener = CreateListener(stopped);
        var provider = BuildProvider(
            new DictionaryCache(),
            services => services.Configure<PortaCoreOptions>(o => o.EnableTelemetry = false));
        var check = new DistributedCacheHealthCheck(provider, new PortaHealthCheckOptions());

        var result = await RunAsync(check);

        Assert.Equal(HealthStatus.Healthy, result.Status);
        Assert.Empty(stopped);
    }

    private static ActivityListener CreateListener(ConcurrentBag<Activity> stopped)
    {
        // The Porta ActivitySource is process-global, so this listener also sees spans from
        // whatever else is running concurrently (auth, token-refresh, ...). Capture only the
        // health-check span the check under test emits, otherwise Assert.Single / Assert.Empty
        // race against unrelated cross-collection tests. See PortaActivitySourceCollection.
        var listener = new ActivityListener
        {
            ShouldListenTo = source => source.Name == PortaActivitySource.Source.Name,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = activity =>
            {
                if (activity.OperationName == PortaActivitySource.Activities.HealthCheck)
                {
                    stopped.Add(activity);
                }
            },
        };
        ActivitySource.AddActivityListener(listener);
        return listener;
    }

    private static ServiceProvider BuildProvider(
        IDistributedCache? cache, Action<IServiceCollection>? configureServices = null)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<PortaHealthCheckState>();
        if (cache is not null)
        {
            services.AddSingleton(cache);
        }
        configureServices?.Invoke(services);
        return services.BuildServiceProvider();
    }

    private static Task<HealthCheckResult> RunAsync(
        IHealthCheck check,
        HealthStatus failureStatus = HealthStatus.Unhealthy,
        CancellationToken? ct = null)
        => check.CheckHealthAsync(new HealthCheckContext
        {
            Registration = new HealthCheckRegistration("test", check, failureStatus, tags: null),
        }, ct ?? TestContext.Current.CancellationToken);

    private sealed class DictionaryCache : IDistributedCache
    {
        public ConcurrentDictionary<string, byte[]> Store { get; } = new();

        public byte[]? Get(string key) => Store.TryGetValue(key, out var value) ? value : null;
        public Task<byte[]?> GetAsync(string key, CancellationToken token = default) => Task.FromResult(Get(key));
        public void Set(string key, byte[] value, DistributedCacheEntryOptions options) => Store[key] = value;
        public Task SetAsync(string key, byte[] value, DistributedCacheEntryOptions options, CancellationToken token = default)
        {
            Set(key, value, options);
            return Task.CompletedTask;
        }
        public void Refresh(string key) { }
        public Task RefreshAsync(string key, CancellationToken token = default) => Task.CompletedTask;
        public void Remove(string key) => Store.TryRemove(key, out _);
        public Task RemoveAsync(string key, CancellationToken token = default)
        {
            Remove(key);
            return Task.CompletedTask;
        }
    }

    private sealed class ThrowingCache : IDistributedCache
    {
        public byte[]? Get(string key) => throw new TimeoutException("store down");
        public Task<byte[]?> GetAsync(string key, CancellationToken token = default) => throw new TimeoutException("store down");
        public void Set(string key, byte[] value, DistributedCacheEntryOptions options) => throw new TimeoutException("store down");
        public Task SetAsync(string key, byte[] value, DistributedCacheEntryOptions options, CancellationToken token = default)
            => throw new TimeoutException("store down");
        public void Refresh(string key) => throw new TimeoutException("store down");
        public Task RefreshAsync(string key, CancellationToken token = default) => throw new TimeoutException("store down");
        public void Remove(string key) => throw new TimeoutException("store down");
        public Task RemoveAsync(string key, CancellationToken token = default) => throw new TimeoutException("store down");
    }

    private sealed class StallingCache : IDistributedCache
    {
        public byte[]? Get(string key) => null;
        public async Task<byte[]?> GetAsync(string key, CancellationToken token = default)
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, token);
            return null;
        }
        public void Set(string key, byte[] value, DistributedCacheEntryOptions options) { }
        public Task SetAsync(string key, byte[] value, DistributedCacheEntryOptions options, CancellationToken token = default)
            => Task.Delay(Timeout.InfiniteTimeSpan, token);
        public void Refresh(string key) { }
        public Task RefreshAsync(string key, CancellationToken token = default) => Task.CompletedTask;
        public void Remove(string key) { }
        public Task RemoveAsync(string key, CancellationToken token = default) => Task.CompletedTask;
    }

    private sealed class CapturingLoggerProvider : ILoggerProvider
    {
        public ConcurrentBag<(LogLevel Level, EventId EventId, string Message)> Entries { get; } = [];

        public ILogger CreateLogger(string categoryName) => new CapturingLogger(Entries);
        public void Dispose() { }

        private sealed class CapturingLogger(
            ConcurrentBag<(LogLevel, EventId, string)> entries) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
            public bool IsEnabled(LogLevel logLevel) => true;
            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
                Func<TState, Exception?, string> formatter)
                => entries.Add((logLevel, eventId, formatter(state, exception)));
        }
    }
}
