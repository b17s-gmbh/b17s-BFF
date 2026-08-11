using System.Diagnostics.Metrics;

using b17s.Porta.Telemetry;

namespace b17s.Porta.Tests.Telemetry;

/// <summary>
/// Tests for <see cref="PortaMetrics"/>. The class is just a thin wrapper over
/// <see cref="Meter"/> instruments, but the conditional tag-set logic (provider tag
/// only when supplied, error counter only on 4xx/5xx, etc.) is where regressions hide.
/// A <see cref="MeterListener"/> captures emitted measurements so we can assert both
/// the values and the tags.
/// </summary>
public sealed class PortaMetricsTests
{
    // -----------------------------
    // Authentication counters: conditional tag inclusion
    // -----------------------------

    [Fact]
    public void RecordAuthenticationFailure_AlwaysIncludesReason_ProviderTagOptional()
    {
        // Both calls record the reason tag; the second adds a provider tag. The
        // branch is "if (provider != null) tags.Add(provider)" - regressing it would
        // either always include a null provider or always omit a valid one.
        using var harness = MetricsHarness.Create();

        harness.Metrics.RecordAuthenticationFailure("invalid_token");
        harness.Metrics.RecordAuthenticationFailure("invalid_token", provider: "oidc");

        var emissions = harness.Drain("bff.auth.failures");
        Assert.Equal(2, emissions.Count);
        Assert.Equal(1L, emissions[0].Value);
        Assert.Equal("invalid_token", emissions[0].Tags["reason"]);
        Assert.False(emissions[0].Tags.ContainsKey("provider"));

        Assert.Equal("invalid_token", emissions[1].Tags["reason"]);
        Assert.Equal("oidc", emissions[1].Tags["provider"]);
    }

    [Fact]
    public void RecordAuthenticationSuccess_ProviderTagOptional()
    {
        using var harness = MetricsHarness.Create();

        harness.Metrics.RecordAuthenticationSuccess();
        harness.Metrics.RecordAuthenticationSuccess(provider: "session");

        var emissions = harness.Drain("bff.auth.successes");
        Assert.Equal(2, emissions.Count);
        Assert.False(emissions[0].Tags.ContainsKey("provider"));
        Assert.Equal("session", emissions[1].Tags["provider"]);
    }

    [Fact]
    public void RecordAuthenticationChallenge_IncludesOutcome()
    {
        using var harness = MetricsHarness.Create();

        harness.Metrics.RecordAuthenticationChallenge("unauthorized");

        var emission = Assert.Single(harness.Drain("bff.auth.challenges"));
        Assert.Equal(1L, emission.Value);
        Assert.Equal("unauthorized", emission.Tags["outcome"]);
    }

    // -----------------------------
    // Token metrics — success/failure routed to different counters
    // -----------------------------

    [Fact]
    public void RecordTokenRefresh_SuccessAndFailure_RouteToDifferentCounters()
    {
        // The success-bool branch picks between two counters. A regression that
        // swapped the polarity would invert refresh dashboards silently.
        using var harness = MetricsHarness.Create();

        harness.Metrics.RecordTokenRefresh(success: true);
        harness.Metrics.RecordTokenRefresh(success: false, reason: "invalid_grant");

        Assert.Single(harness.Drain("bff.token.refreshes"));
        var failures = harness.Drain("bff.token.refresh_failures");
        Assert.Single(failures);
        Assert.Equal("invalid_grant", failures[0].Tags["reason"]);
    }

    [Fact]
    public void RecordTokenRefresh_ReasonTagOptional()
    {
        using var harness = MetricsHarness.Create();

        harness.Metrics.RecordTokenRefresh(success: true);
        harness.Metrics.RecordTokenRefresh(success: true, reason: "rotation");

        var emissions = harness.Drain("bff.token.refreshes");
        Assert.Equal(2, emissions.Count);
        Assert.False(emissions[0].Tags.ContainsKey("reason"));
        Assert.Equal("rotation", emissions[1].Tags["reason"]);
    }

    // -----------------------------
    // Backend metrics — error counter only on 4xx/5xx
    // -----------------------------

    [Fact]
    public void RecordBackendRequest_2xxStatus_DoesNotIncrementErrorCounter()
    {
        // The `if (statusCode >= 400)` branch is the critical one: a regression that
        // dropped the guard would inflate bff.backend.errors with every successful
        // request. Anchor it for both 2xx and 3xx.
        using var harness = MetricsHarness.Create();

        harness.Metrics.RecordBackendRequest("user-svc", "http", 200);
        harness.Metrics.RecordBackendRequest("user-svc", "http", 304);

        Assert.Equal(2, harness.Drain("bff.backend.requests").Count);
        Assert.Empty(harness.Drain("bff.backend.errors"));
    }

    [Fact]
    public void RecordBackendRequest_4xxAnd5xx_IncrementBothCounters()
    {
        using var harness = MetricsHarness.Create();

        harness.Metrics.RecordBackendRequest("user-svc", "http", 404);
        harness.Metrics.RecordBackendRequest("user-svc", "http", 503);

        Assert.Equal(2, harness.Drain("bff.backend.requests").Count);
        var errors = harness.Drain("bff.backend.errors");
        Assert.Equal(2, errors.Count);

        Assert.Equal("user-svc", errors[0].Tags["service"]);
        Assert.Equal("http", errors[0].Tags["protocol"]);
        Assert.Equal(404, Convert.ToInt32(errors[0].Tags["status_code"]));
    }

    [Fact]
    public void RecordBackendCallDuration_EmitsHistogramWithServiceAndProtocolTags()
    {
        using var harness = MetricsHarness.Create();

        harness.Metrics.RecordBackendCallDuration(42.5, "user-svc", "http");

        var emissions = harness.DrainDouble("bff.backend.duration");
        Assert.Single(emissions);
        Assert.Equal(42.5, emissions[0].Value);
        Assert.Equal("user-svc", emissions[0].Tags["service"]);
        Assert.Equal("http", emissions[0].Tags["protocol"]);
    }

    // -----------------------------
    // Session metrics — composite counter+up-down-counter behavior
    // -----------------------------

    [Fact]
    public void RecordSessionCreated_IncrementsCounterAndActiveSessions()
    {
        // The composite call MUST hit both meters atomically - if the counter
        // bumped without the active-sessions gauge, gauges drift over a long run.
        using var harness = MetricsHarness.Create();

        harness.Metrics.RecordSessionCreated();

        Assert.Single(harness.Drain("bff.session.created"));
        var actives = harness.Drain("bff.sessions.active");
        Assert.Single(actives);
        Assert.Equal(1L, actives[0].Value);
    }

    [Fact]
    public void RecordSessionInvalidated_TagsReasonOnCounterOnly_DecrementsActiveSessionsUntagged()
    {
        using var harness = MetricsHarness.Create();

        harness.Metrics.RecordSessionInvalidated("logout");

        // The reason belongs on the invalidation counter.
        var invalidated = harness.Drain("bff.session.invalidated");
        Assert.Single(invalidated);
        Assert.Equal("logout", invalidated[0].Tags["reason"]);

        // The active-sessions gauge must decrement untagged so it nets against the untagged
        // increment on creation. A reason tag here would split the gauge into per-reason
        // series that never reconcile with the (untagged) created series.
        var actives = harness.Drain("bff.sessions.active");
        Assert.Single(actives);
        Assert.Equal(-1L, actives[0].Value);
        Assert.DoesNotContain("reason", actives[0].Tags.Keys);
    }

    // -----------------------------
    // Active-request gauge
    // -----------------------------

    [Fact]
    public void IncrementAndDecrementActiveRequests_EmitOppositeDeltas()
    {
        using var harness = MetricsHarness.Create();

        harness.Metrics.IncrementActiveRequests();
        harness.Metrics.DecrementActiveRequests();

        var emissions = harness.Drain("bff.requests.active");
        Assert.Equal(2, emissions.Count);
        Assert.Equal(1L, emissions[0].Value);
        Assert.Equal(-1L, emissions[1].Value);
    }

    // -----------------------------
    // Lock cleanup — staleLocksCleaned counter only when > 0
    // -----------------------------

    [Fact]
    public void RecordLockCleanup_ZeroStaleLocks_OnlyIncrementsRunsCounter()
    {
        // The conditional `if (staleLocksCleaned > 0)` branch keeps the
        // stale_locks_cleaned counter accurate as a rate (we never record 0).
        using var harness = MetricsHarness.Create();

        harness.Metrics.RecordLockCleanup(staleLocksCleaned: 0);

        Assert.Single(harness.Drain("bff.session.lock_cleanup_runs"));
        Assert.Empty(harness.Drain("bff.session.stale_locks_cleaned"));
    }

    [Fact]
    public void RecordLockCleanup_NonZeroStaleLocks_IncrementsBothCounters()
    {
        using var harness = MetricsHarness.Create();

        harness.Metrics.RecordLockCleanup(staleLocksCleaned: 3);

        Assert.Single(harness.Drain("bff.session.lock_cleanup_runs"));
        var stale = harness.Drain("bff.session.stale_locks_cleaned");
        Assert.Single(stale);
        Assert.Equal(3L, stale[0].Value);
    }

    // -----------------------------
    // CSRF + per-request histograms — happy-path tag-set coverage
    // -----------------------------

    [Fact]
    public void RecordCsrfValidationFailure_TagsByReason()
    {
        using var harness = MetricsHarness.Create();

        harness.Metrics.RecordCsrfValidationFailure("missing_token");

        var emissions = harness.Drain("bff.csrf.validation_failures");
        Assert.Single(emissions);
        Assert.Equal("missing_token", emissions[0].Tags["reason"]);
    }

    [Fact]
    public void RecordRequestDuration_TagsMethodRouteStatus()
    {
        using var harness = MetricsHarness.Create();

        harness.Metrics.RecordRequestDuration(12.3, "GET", "/api/users", 200);

        var emissions = harness.DrainDouble("bff.request.duration");
        Assert.Single(emissions);
        Assert.Equal(12.3, emissions[0].Value);
        Assert.Equal("GET", emissions[0].Tags["method"]);
        Assert.Equal("/api/users", emissions[0].Tags["route"]);
        Assert.Equal(200, Convert.ToInt32(emissions[0].Tags["status_code"]));
    }

    [Fact]
    public void RecordTransformationDuration_TagsByStrategy()
    {
        using var harness = MetricsHarness.Create();

        harness.Metrics.RecordTransformationDuration(7.0, "aggregator");

        var emissions = harness.DrainDouble("bff.transformation.duration");
        Assert.Single(emissions);
        Assert.Equal("aggregator", emissions[0].Tags["strategy"]);
    }

    [Fact]
    public void RecordAuthenticationDuration_TagsByProvider()
    {
        using var harness = MetricsHarness.Create();

        harness.Metrics.RecordAuthenticationDuration(3.0, "session");

        var emissions = harness.DrainDouble("bff.auth.duration");
        Assert.Single(emissions);
        Assert.Equal("session", emissions[0].Tags["provider"]);
    }

    [Fact]
    public void RecordRequestSize_TagsByMethod()
    {
        using var harness = MetricsHarness.Create();

        harness.Metrics.RecordRequestSize(2048, "POST");

        var emissions = harness.DrainLong("bff.request.size");
        Assert.Single(emissions);
        Assert.Equal(2048L, emissions[0].Value);
        Assert.Equal("POST", emissions[0].Tags["method"]);
    }

    [Fact]
    public void RecordResponseSize_TagsByStatusCode()
    {
        using var harness = MetricsHarness.Create();

        harness.Metrics.RecordResponseSize(4096, 200);

        var emissions = harness.DrainLong("bff.response.size");
        Assert.Single(emissions);
        Assert.Equal(4096L, emissions[0].Value);
        Assert.Equal(200, Convert.ToInt32(emissions[0].Tags["status_code"]));
    }

    // -----------------------------
    // Harness — captures meter emissions per instrument name
    // -----------------------------

    private sealed class MetricsHarness : IDisposable
    {
        public PortaMetrics Metrics { get; }
        private readonly MeterListener _listener;
        private readonly System.Collections.Concurrent.ConcurrentDictionary<string, System.Collections.Concurrent.ConcurrentQueue<Measurement>> _measurements = new();

        private MetricsHarness(PortaMetrics metrics, MeterListener listener)
        {
            Metrics = metrics;
            _listener = listener;
        }

        public static MetricsHarness Create()
        {
            var factory = new TestMeterFactory();
            var metrics = new PortaMetrics(factory);

            // Match this harness's OWN meter by reference, not by name. Every PortaMetrics instance
            // (including those built by other tests running in parallel) shares the meter name
            // PortaActivitySource.ActivitySourceName, so a name filter would capture their emissions
            // too and inflate the counts asserted here.
            var listener = new MeterListener
            {
                InstrumentPublished = (instrument, l) =>
                {
                    if (factory.Created.Contains(instrument.Meter))
                    {
                        l.EnableMeasurementEvents(instrument);
                    }
                }
            };

            var harness = new MetricsHarness(metrics, listener);
            listener.SetMeasurementEventCallback<long>(harness.OnLong);
            listener.SetMeasurementEventCallback<double>(harness.OnDouble);
            listener.Start();
            return harness;
        }

        private void OnLong(Instrument instrument, long value, ReadOnlySpan<KeyValuePair<string, object?>> tags, object? state)
            => Record(instrument.Name, value, tags);

        private void OnDouble(Instrument instrument, double value, ReadOnlySpan<KeyValuePair<string, object?>> tags, object? state)
            => Record(instrument.Name, value, tags);

        private void Record(string name, object value, ReadOnlySpan<KeyValuePair<string, object?>> tags)
        {
            var dict = new Dictionary<string, object?>(tags.Length);
            foreach (var t in tags)
            {
                dict[t.Key] = t.Value;
            }
            var queue = _measurements.GetOrAdd(name, _ => new());
            queue.Enqueue(new Measurement(value, dict));
        }

        public IReadOnlyList<Measurement> Drain(string instrumentName)
        {
            if (!_measurements.TryGetValue(instrumentName, out var queue))
            {
                return Array.Empty<Measurement>();
            }
            var snapshot = new List<Measurement>();
            while (queue.TryDequeue(out var m))
            {
                snapshot.Add(m);
            }
            return snapshot;
        }

        public IReadOnlyList<Measurement> DrainDouble(string instrumentName) => Drain(instrumentName);
        public IReadOnlyList<Measurement> DrainLong(string instrumentName) => Drain(instrumentName);

        public void Dispose() => _listener.Dispose();
    }

    private sealed record Measurement(object Value, IReadOnlyDictionary<string, object?> Tags);

    private sealed class TestMeterFactory : IMeterFactory
    {
        // Track the meters this factory hands out so the harness's listener can scope itself to
        // them by reference (the meter NAME is shared across all PortaMetrics instances).
        public List<Meter> Created { get; } = [];

        public Meter Create(MeterOptions options)
        {
            var meter = new Meter(options);
            Created.Add(meter);
            return meter;
        }

        public void Dispose() { }
    }
}
