using System.Diagnostics;
using System.Diagnostics.Metrics;

namespace b17s.Porta.Telemetry;

/// <summary>
/// Central metrics for BFF business insights using OpenTelemetry-compatible Meter API
/// </summary>
public sealed class PortaMetrics
{
    private static readonly double[] LatencyBucketsMs =
    [
        0.5, 1, 2.5, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000
    ];

    private static readonly long[] SizeBucketsBytes =
    [
        256, 1024, 4096, 16384, 65536, 262144, 1048576, 4194304,
        16777216, 67108864, 268435456
    ];

    private readonly Meter _meter;

    // Counters
    private readonly Counter<long> _authenticationFailures;
    private readonly Counter<long> _authenticationSuccesses;
    private readonly Counter<long> _authenticationChallenges;
    private readonly Counter<long> _tokenRefreshes;
    private readonly Counter<long> _tokenRefreshFailures;
    private readonly Counter<long> _backendRequests;
    private readonly Counter<long> _backendErrors;
    private readonly Counter<long> _csrfValidationFailures;
    private readonly Counter<long> _sessionCreated;
    private readonly Counter<long> _sessionInvalidated;
    private readonly Counter<long> _lockCleanupRuns;
    private readonly Counter<long> _staleLocksCleaned;

    // Histograms
    private readonly Histogram<double> _requestDuration;
    private readonly Histogram<double> _backendCallDuration;
    private readonly Histogram<double> _transformationDuration;
    private readonly Histogram<double> _authenticationDuration;
    private readonly Histogram<long> _requestSize;
    private readonly Histogram<long> _responseSize;

    // UpDownCounters
    private readonly UpDownCounter<long> _activeSessions;
    private readonly UpDownCounter<long> _activeRequests;

    /// <summary>
    /// Initializes a new <see cref="PortaMetrics"/> instance, creating the underlying
    /// <see cref="Meter"/> and all BFF counters, histograms, and up-down counters.
    /// </summary>
    /// <param name="meterFactory">
    /// The meter factory used to create the BFF <see cref="Meter"/> (named after
    /// <see cref="PortaActivitySource.ActivitySourceName"/> and versioned with
    /// <see cref="PortaActivitySource.Version"/>).
    /// </param>
    public PortaMetrics(IMeterFactory meterFactory)
    {
        _meter = meterFactory.Create(PortaActivitySource.ActivitySourceName, PortaActivitySource.Version);

        // Initialize counters
        _authenticationFailures = _meter.CreateCounter<long>(
            "bff.auth.failures",
            description: "Number of authentication failures");

        _authenticationSuccesses = _meter.CreateCounter<long>(
            "bff.auth.successes",
            description: "Number of successful authentications");

        _authenticationChallenges = _meter.CreateCounter<long>(
            "bff.auth.challenges",
            description: "Number of authentication challenges by response outcome");

        _tokenRefreshes = _meter.CreateCounter<long>(
            "bff.token.refreshes",
            description: "Number of token refreshes");

        _tokenRefreshFailures = _meter.CreateCounter<long>(
            "bff.token.refresh_failures",
            description: "Number of token refresh failures");

        _backendRequests = _meter.CreateCounter<long>(
            "bff.backend.requests",
            description: "Number of backend requests");

        _backendErrors = _meter.CreateCounter<long>(
            "bff.backend.errors",
            description: "Number of backend errors");

        _csrfValidationFailures = _meter.CreateCounter<long>(
            "bff.csrf.validation_failures",
            description: "Number of CSRF validation failures");

        _sessionCreated = _meter.CreateCounter<long>(
            "bff.session.created",
            description: "Number of sessions created");

        _sessionInvalidated = _meter.CreateCounter<long>(
            "bff.session.invalidated",
            description: "Number of sessions invalidated");

        _lockCleanupRuns = _meter.CreateCounter<long>(
            "bff.session.lock_cleanup_runs",
            description: "Number of stale lock cleanup timer executions");

        _staleLocksCleaned = _meter.CreateCounter<long>(
            "bff.session.stale_locks_cleaned",
            description: "Number of stale user refresh locks cleaned up");

        // Initialize histograms.
        //
        // Bucket boundaries follow the same shape OpenTelemetry uses for
        // `http.server.request.duration` (translated to ms): sub-ms resolution
        // at the fast end so in-process and same-AZ backend calls don't all
        // collapse into the lowest bucket, with a high tail for long-poll /
        // streaming-like paths. Body-size histograms use a byte-scale set
        // covering 256 B → 256 MiB so both API payloads and the
        // large-attachment cap (MaxBackendResponseBytes = 10 MiB,
        // MaxRawForwardResponseBytes = 100 MiB) land in real buckets with
        // headroom above the cap.
        _requestDuration = _meter.CreateHistogram<double>(
            "bff.request.duration",
            unit: "ms",
            description: "Request processing duration",
            advice: new InstrumentAdvice<double> { HistogramBucketBoundaries = LatencyBucketsMs });

        _backendCallDuration = _meter.CreateHistogram<double>(
            "bff.backend.duration",
            unit: "ms",
            description: "Backend call duration",
            advice: new InstrumentAdvice<double> { HistogramBucketBoundaries = LatencyBucketsMs });

        _transformationDuration = _meter.CreateHistogram<double>(
            "bff.transformation.duration",
            unit: "ms",
            description: "Transformation processing duration",
            advice: new InstrumentAdvice<double> { HistogramBucketBoundaries = LatencyBucketsMs });

        _authenticationDuration = _meter.CreateHistogram<double>(
            "bff.auth.duration",
            unit: "ms",
            description: "Authentication processing duration",
            advice: new InstrumentAdvice<double> { HistogramBucketBoundaries = LatencyBucketsMs });

        _requestSize = _meter.CreateHistogram<long>(
            "bff.request.size",
            unit: "bytes",
            description: "Request body size in bytes",
            advice: new InstrumentAdvice<long> { HistogramBucketBoundaries = SizeBucketsBytes });

        _responseSize = _meter.CreateHistogram<long>(
            "bff.response.size",
            unit: "bytes",
            description: "Response body size in bytes",
            advice: new InstrumentAdvice<long> { HistogramBucketBoundaries = SizeBucketsBytes });

        // Initialize up-down counters
        _activeSessions = _meter.CreateUpDownCounter<long>(
            "bff.sessions.active",
            description: "Number of active sessions");

        _activeRequests = _meter.CreateUpDownCounter<long>(
            "bff.requests.active",
            description: "Number of active requests");
    }

    // Authentication metrics

    /// <summary>
    /// Increments the <c>bff.auth.failures</c> counter to record a failed authentication attempt.
    /// </summary>
    /// <param name="reason">The reason the authentication failed, recorded as the <c>reason</c> tag.</param>
    /// <param name="provider">The authentication provider, recorded as the <c>provider</c> tag when supplied.</param>
    public void RecordAuthenticationFailure(string reason, string? provider = null)
    {
        var tags = new TagList
        {
            { "reason", reason }
        };
        if (provider != null)
            tags.Add("provider", provider);

        _authenticationFailures.Add(1, tags);
    }

    /// <summary>
    /// Increments the <c>bff.auth.successes</c> counter to record a successful authentication.
    /// </summary>
    /// <param name="provider">The authentication provider, recorded as the <c>provider</c> tag when supplied.</param>
    public void RecordAuthenticationSuccess(string? provider = null)
    {
        var tags = new TagList();
        if (provider != null)
            tags.Add("provider", provider);

        _authenticationSuccesses.Add(1, tags);
    }

    /// <summary>Records the outcome of a default authentication challenge.</summary>
    public void RecordAuthenticationChallenge(string outcome)
        => _authenticationChallenges.Add(1, new KeyValuePair<string, object?>("outcome", outcome));

    // Token metrics

    /// <summary>
    /// Records a token refresh outcome, incrementing <c>bff.token.refreshes</c> on success
    /// or <c>bff.token.refresh_failures</c> on failure.
    /// </summary>
    /// <param name="success"><see langword="true"/> if the refresh succeeded; otherwise <see langword="false"/>.</param>
    /// <param name="reason">An optional reason, recorded as the <c>reason</c> tag when supplied.</param>
    public void RecordTokenRefresh(bool success, string? reason = null)
    {
        var tags = new TagList();
        if (reason != null)
            tags.Add("reason", reason);

        if (success)
            _tokenRefreshes.Add(1, tags);
        else
            _tokenRefreshFailures.Add(1, tags);
    }

    // Backend metrics

    /// <summary>
    /// Increments the <c>bff.backend.requests</c> counter for a backend request, and additionally
    /// increments <c>bff.backend.errors</c> when the status code indicates an error (>= 400).
    /// </summary>
    /// <param name="service">The backend service name, recorded as the <c>service</c> tag.</param>
    /// <param name="protocol">The protocol used to reach the backend, recorded as the <c>protocol</c> tag.</param>
    /// <param name="statusCode">The response status code, recorded as the <c>status_code</c> tag.</param>
    public void RecordBackendRequest(string service, string protocol, int statusCode)
    {
        var tags = new TagList
        {
            { "service", service },
            { "protocol", protocol },
            { "status_code", statusCode }
        };

        _backendRequests.Add(1, tags);

        if (statusCode >= 400)
        {
            _backendErrors.Add(1, tags);
        }
    }

    /// <summary>
    /// Records the duration of a backend call on the <c>bff.backend.duration</c> histogram.
    /// </summary>
    /// <param name="durationMs">The backend call duration in milliseconds.</param>
    /// <param name="service">The backend service name, recorded as the <c>service</c> tag.</param>
    /// <param name="protocol">The protocol used to reach the backend, recorded as the <c>protocol</c> tag.</param>
    public void RecordBackendCallDuration(double durationMs, string service, string protocol)
    {
        var tags = new TagList
        {
            { "service", service },
            { "protocol", protocol }
        };

        _backendCallDuration.Record(durationMs, tags);
    }

    // CSRF metrics

    /// <summary>
    /// Increments the <c>bff.csrf.validation_failures</c> counter to record a CSRF validation failure.
    /// </summary>
    /// <param name="reason">The reason validation failed, recorded as the <c>reason</c> tag.</param>
    public void RecordCsrfValidationFailure(string reason)
    {
        var tags = new TagList
        {
            { "reason", reason }
        };

        _csrfValidationFailures.Add(1, tags);
    }

    // Session metrics

    /// <summary>
    /// Records creation of a session: increments the <c>bff.session.created</c> counter and the
    /// <c>bff.sessions.active</c> up-down counter.
    /// </summary>
    public void RecordSessionCreated()
    {
        _sessionCreated.Add(1);
        _activeSessions.Add(1);
    }

    /// <summary>
    /// Records invalidation of a session: increments the <c>bff.session.invalidated</c> counter
    /// (tagged with the reason) and decrements the untagged <c>bff.sessions.active</c> up-down counter.
    /// </summary>
    /// <param name="reason">The reason the session was invalidated, recorded as the <c>reason</c> tag on the counter.</param>
    public void RecordSessionInvalidated(string reason)
    {
        var tags = new TagList
        {
            { "reason", reason }
        };

        _sessionInvalidated.Add(1, tags);
        // The active-sessions gauge is incremented untagged on creation, so it must be
        // decremented untagged too. The invalidation reason lives on _sessionInvalidated;
        // attaching it here would split the gauge into per-reason series that never net
        // back to the created (untagged) series.
        _activeSessions.Add(-1);
    }

    // Request metrics

    /// <summary>
    /// Records the end-to-end processing duration of a request on the <c>bff.request.duration</c> histogram.
    /// </summary>
    /// <param name="durationMs">The request processing duration in milliseconds.</param>
    /// <param name="method">
    /// The HTTP method, recorded as the <c>method</c> tag. The caller must supply a <strong>bounded</strong>
    /// value: servers accept arbitrary token methods, so pass the raw method only after collapsing
    /// nonstandard verbs to <c>_OTHER</c> (the OTel <c>http.request.method</c> convention), as
    /// <c>PortaTelemetryMiddleware</c> does.
    /// </param>
    /// <param name="routeTemplate">
    /// The <strong>low-cardinality route template</strong> (e.g. <c>/api/users/{id}</c>), recorded as the
    /// <c>route</c> tag. Pass the route <em>template</em>, never the concrete request path: a per-request
    /// value such as <c>/api/users/12345</c> creates an unbounded tag set, which explodes time-series
    /// cardinality in the metrics backend (memory/cost blow-up). The caller is responsible for supplying a
    /// bounded value.
    /// </param>
    /// <param name="statusCode">The response status code.</param>
    public void RecordRequestDuration(double durationMs, string method, string routeTemplate, int statusCode)
    {
        var tags = new TagList
        {
            { "method", method },
            { "route", routeTemplate },
            { "status_code", statusCode }
        };

        _requestDuration.Record(durationMs, tags);
    }

    /// <summary>
    /// Records transformation processing duration on the <c>bff.transformation.duration</c> histogram.
    /// </summary>
    /// <param name="durationMs">The transformation processing duration in milliseconds.</param>
    /// <param name="strategy">The transformation strategy, recorded as the <c>strategy</c> tag.</param>
    public void RecordTransformationDuration(double durationMs, string strategy)
    {
        var tags = new TagList
        {
            { "strategy", strategy }
        };

        _transformationDuration.Record(durationMs, tags);
    }

    /// <summary>
    /// Records authentication processing duration on the <c>bff.auth.duration</c> histogram.
    /// </summary>
    /// <param name="durationMs">The authentication processing duration in milliseconds.</param>
    /// <param name="provider">The authentication provider, recorded as the <c>provider</c> tag.</param>
    public void RecordAuthenticationDuration(double durationMs, string provider)
    {
        var tags = new TagList
        {
            { "provider", provider }
        };

        _authenticationDuration.Record(durationMs, tags);
    }

    /// <summary>
    /// Records the request body size on the <c>bff.request.size</c> histogram.
    /// </summary>
    /// <param name="bytes">The request body size in bytes.</param>
    /// <param name="method">
    /// The HTTP method, recorded as the <c>method</c> tag. Must be a bounded value — see
    /// <see cref="RecordRequestDuration"/> for the cardinality contract.
    /// </param>
    public void RecordRequestSize(long bytes, string method)
    {
        var tags = new TagList
        {
            { "method", method }
        };

        _requestSize.Record(bytes, tags);
    }

    /// <summary>
    /// Records the response body size on the <c>bff.response.size</c> histogram.
    /// </summary>
    /// <param name="bytes">The response body size in bytes.</param>
    /// <param name="statusCode">The response status code, recorded as the <c>status_code</c> tag.</param>
    public void RecordResponseSize(long bytes, int statusCode)
    {
        var tags = new TagList
        {
            { "status_code", statusCode }
        };

        _responseSize.Record(bytes, tags);
    }

    // Active request tracking

    /// <summary>
    /// Increments the <c>bff.requests.active</c> up-down counter to track an in-flight request.
    /// </summary>
    public void IncrementActiveRequests() => _activeRequests.Add(1);

    /// <summary>
    /// Decrements the <c>bff.requests.active</c> up-down counter when an in-flight request completes.
    /// </summary>
    public void DecrementActiveRequests() => _activeRequests.Add(-1);

    // Lock cleanup metrics

    /// <summary>
    /// Records a stale-lock cleanup run: increments the <c>bff.session.lock_cleanup_runs</c> counter,
    /// and increments <c>bff.session.stale_locks_cleaned</c> by the number of locks removed when greater than zero.
    /// </summary>
    /// <param name="staleLocksCleaned">The number of stale user refresh locks cleaned up during this run.</param>
    public void RecordLockCleanup(int staleLocksCleaned)
    {
        _lockCleanupRuns.Add(1);
        if (staleLocksCleaned > 0)
        {
            _staleLocksCleaned.Add(staleLocksCleaned);
        }
    }

}
