using b17s.Porta.Transformers;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace b17s.Porta.Extensions;

/// <summary>
/// Extension methods for registering and mapping transformer endpoints.
/// Core service registration (HttpClient, registry, metrics, etc.) lives in
/// <see cref="PortaServiceExtensions.AddPortaCore(IServiceCollection, Action{b17s.Porta.Configuration.PortaCoreOptions})"/>.
/// </summary>
public static class TransformerExtensions
{
    /// <summary>
    /// Maps a transformer to an endpoint with fluent configuration.
    /// </summary>
    /// <typeparam name="TTransformer">The transformer type</typeparam>
    /// <typeparam name="TRequest">The request body type</typeparam>
    /// <typeparam name="TResponse">The response body type</typeparam>
    /// <param name="endpoints">The endpoint route builder</param>
    /// <returns>A fluent builder for configuring the transformer endpoint</returns>
    public static TransformerEndpointBuilder<TTransformer, TRequest, TResponse> MapTransformer<TTransformer, TRequest, TResponse>(
        this IEndpointRouteBuilder endpoints)
        where TTransformer : class, ITransformer<TRequest, TResponse>
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        // Note: Transformer registration is validated at request time, not at startup
        // Transformers must be registered beforehand via AddTransformer<T>()
        return new(endpoints, endpoints.ServiceProvider);
    }

    /// <summary>
    /// Maps a transformer with no request body (for GET, DELETE, etc.).
    /// </summary>
    /// <typeparam name="TTransformer">The transformer type</typeparam>
    /// <typeparam name="TResponse">The response body type</typeparam>
    /// <param name="endpoints">The endpoint route builder</param>
    /// <returns>A fluent builder for configuring the transformer endpoint</returns>
    public static TransformerEndpointBuilder<TTransformer, TResponse> MapTransformer<TTransformer, TResponse>(
        this IEndpointRouteBuilder endpoints)
        where TTransformer : class, ITransformer<TResponse>
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        return new(endpoints, endpoints.ServiceProvider);
    }

    /// <summary>
    /// Registers a transformer in the DI container.
    /// Call this in your service configuration before calling MapTransformer.
    /// </summary>
    /// <typeparam name="TTransformer">
    /// The transformer type to register as a scoped service. Must implement
    /// <see cref="ITransformer{TRequest, TResponse}"/> or <see cref="ITransformer{TResponse}"/>
    /// (both extend the <see cref="ITransformer"/> marker). Raw forwarding transformers are
    /// registered via <see cref="RawForwardExtensions.AddRawForwardTransformer{TTransformer}"/> instead.
    /// </typeparam>
    /// <param name="services">The service collection.</param>
    /// <returns>The service collection for chaining.</returns>
    public static IServiceCollection AddTransformer<TTransformer>(this IServiceCollection services)
        where TTransformer : class, ITransformer
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddScoped<TTransformer>();
        return services;
    }

    /// <summary>
    /// Registers multiple transformer types at once. Equivalent to calling
    /// <see cref="AddTransformer{TTransformer}"/> for each type.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="transformerTypes">
    /// The transformer types to register as scoped services. Each must implement
    /// <see cref="ITransformer{TRequest, TResponse}"/> or <see cref="ITransformer{TResponse}"/>.
    /// </param>
    /// <returns>The service collection for chaining.</returns>
    /// <exception cref="ArgumentException">A type does not implement a transformer interface.</exception>
    public static IServiceCollection AddTransformerTypes(this IServiceCollection services, params Type[] transformerTypes)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(transformerTypes);

        foreach (var type in transformerTypes)
        {
            // Mirror the compile-time bound on AddTransformer<T>: catching a non-transformer
            // here turns a request-time resolution surprise into a registration-time error.
            if (!typeof(ITransformer).IsAssignableFrom(type))
            {
                throw new ArgumentException(
                    $"Type {type.Name} does not implement ITransformer<TRequest, TResponse> or ITransformer<TResponse>",
                    nameof(transformerTypes));
            }

            services.AddScoped(type);
        }
        return services;
    }
}

/// <summary>
/// Fluent builder for creating zero-code pass-through endpoints.
/// Use when you just need to forward requests to a backend without transformation.
/// Internally delegates to <see cref="TransformerEndpointBuilder{TTransformer, TResponse}"/>
/// with a synthetic <see cref="BackendForwardingTransformer{TResponse}"/>, so pass-through
/// endpoints inherit telemetry, <c>When</c>-predicate routing, and the post-Build()
/// anonymous-smuggling recheck.
/// </summary>
/// <typeparam name="TResponse">The response type from the backend</typeparam>
public sealed class PassThroughEndpointBuilder<TResponse>
{
    private readonly TransformerEndpointBuilder<BackendForwardingTransformer<TResponse>, TResponse> _inner;

    internal PassThroughEndpointBuilder(IEndpointRouteBuilder endpoints, IServiceProvider services)
        => _inner = new TransformerEndpointBuilder<BackendForwardingTransformer<TResponse>, TResponse>(endpoints, services);

    /// <summary>Specifies the incoming HTTP method and route pattern.</summary>
    public PassThroughEndpointBuilder<TResponse> FromRoute(string method, string routePattern)
    {
        _inner.FromRoute(method, routePattern);
        return this;
    }

    /// <summary>Specifies a GET route pattern.</summary>
    public PassThroughEndpointBuilder<TResponse> FromGet(string routePattern) => FromRoute("GET", routePattern);

    /// <summary>Specifies a POST route pattern.</summary>
    public PassThroughEndpointBuilder<TResponse> FromPost(string routePattern) => FromRoute("POST", routePattern);

    /// <summary>Specifies a PUT route pattern.</summary>
    public PassThroughEndpointBuilder<TResponse> FromPut(string routePattern) => FromRoute("PUT", routePattern);

    /// <summary>Specifies a DELETE route pattern.</summary>
    public PassThroughEndpointBuilder<TResponse> FromDelete(string routePattern) => FromRoute("DELETE", routePattern);

    /// <summary>Specifies a PATCH route pattern.</summary>
    public PassThroughEndpointBuilder<TResponse> FromPatch(string routePattern) => FromRoute("PATCH", routePattern);

    /// <summary>Specifies a HEAD route pattern.</summary>
    public PassThroughEndpointBuilder<TResponse> FromHead(string routePattern) => FromRoute("HEAD", routePattern);

    /// <summary>Specifies an OPTIONS route pattern.</summary>
    public PassThroughEndpointBuilder<TResponse> FromOptions(string routePattern) => FromRoute("OPTIONS", routePattern);

    /// <summary>Matches any HTTP method on the specified route pattern.</summary>
    public PassThroughEndpointBuilder<TResponse> FromAny(string routePattern)
    {
        _inner.FromAny(routePattern);
        return this;
    }

    /// <summary>
    /// Adds a runtime predicate that must return true for this endpoint to handle the request.
    /// See <see cref="TransformerEndpointBuilderBase{TTransformer, TBuilder}.When"/>.
    /// </summary>
    public PassThroughEndpointBuilder<TResponse> When(Func<HttpContext, bool> predicate)
    {
        _inner.When(predicate);
        return this;
    }

    /// <summary>Specifies the backend HTTP method and URL.</summary>
    public PassThroughEndpointBuilder<TResponse> ToBackend(string method, string url, ContentType contentType = ContentType.Json)
    {
        _inner.ToBackend(method, url, contentType);
        return this;
    }

    /// <summary>Specifies a GET backend URL.</summary>
    /// <param name="url">Backend URL (supports Kubernetes service names: http://user-service/api/users)</param>
    /// <param name="contentType">Content type for serializing request body. Default: JSON</param>
    public PassThroughEndpointBuilder<TResponse> ToGet(string url, ContentType contentType = ContentType.Json) => ToBackend("GET", url, contentType);

    /// <summary>Specifies a POST backend URL.</summary>
    /// <param name="url">Backend URL (supports Kubernetes service names: http://user-service/api/users)</param>
    /// <param name="contentType">Content type for serializing request body. Default: JSON</param>
    public PassThroughEndpointBuilder<TResponse> ToPost(string url, ContentType contentType = ContentType.Json) => ToBackend("POST", url, contentType);

    /// <summary>Specifies a PUT backend URL.</summary>
    /// <param name="url">Backend URL (supports Kubernetes service names: http://user-service/api/users)</param>
    /// <param name="contentType">Content type for serializing request body. Default: JSON</param>
    public PassThroughEndpointBuilder<TResponse> ToPut(string url, ContentType contentType = ContentType.Json) => ToBackend("PUT", url, contentType);

    /// <summary>Specifies a DELETE backend URL.</summary>
    /// <param name="url">Backend URL (supports Kubernetes service names: http://user-service/api/users)</param>
    /// <param name="contentType">Content type for serializing request body. Default: JSON</param>
    public PassThroughEndpointBuilder<TResponse> ToDelete(string url, ContentType contentType = ContentType.Json) => ToBackend("DELETE", url, contentType);

    /// <summary>Specifies a PATCH backend URL.</summary>
    /// <param name="url">Backend URL (supports Kubernetes service names: http://user-service/api/users)</param>
    /// <param name="contentType">Content type for serializing request body. Default: JSON</param>
    public PassThroughEndpointBuilder<TResponse> ToPatch(string url, ContentType contentType = ContentType.Json) => ToBackend("PATCH", url, contentType);

    /// <summary>Forwards to backend using the same HTTP method as the incoming request.</summary>
    public PassThroughEndpointBuilder<TResponse> ToAny(string url)
    {
        _inner.ToAny(url);
        return this;
    }

    /// <summary>Configures the backend as a GraphQL endpoint (POST).</summary>
    public PassThroughEndpointBuilder<TResponse> ToGraphQL(string url)
    {
        _inner.ToGraphQL(url);
        return this;
    }

    /// <summary>Requires authentication with an optional policy.</summary>
    public PassThroughEndpointBuilder<TResponse> RequireAuth(string? policy = null)
    {
        _inner.RequireAuth(policy);
        return this;
    }

    /// <summary>Allows anonymous access.</summary>
    public PassThroughEndpointBuilder<TResponse> AllowAnonymous()
    {
        _inner.AllowAnonymous();
        return this;
    }

    /// <summary>
    /// Allows anonymous access while still authenticating the backend call when the caller
    /// presented credentials: a user-identity backend-auth policy (BearerToken / TokenExchange)
    /// is applied for authenticated callers and downgraded to None for anonymous ones. An optional
    /// authorization policy gates the authenticated treatment - callers failing it get the
    /// anonymous view. See
    /// <see cref="TransformerEndpointBuilderBase{TTransformer, TBuilder}.AllowAnonymousWithOptionalAuth"/>.
    /// </summary>
    public PassThroughEndpointBuilder<TResponse> AllowAnonymousWithOptionalAuth(string? policy = null)
    {
        _inner.AllowAnonymousWithOptionalAuth(policy);
        return this;
    }

    /// <summary>Sets a timeout for the backend call.</summary>
    public PassThroughEndpointBuilder<TResponse> WithTimeout(TimeSpan timeout)
    {
        _inner.WithTimeout(timeout);
        return this;
    }

    /// <summary>Specifies the backend authentication policy.</summary>
    /// <param name="policy">The backend authentication policy name.</param>
    /// <param name="optional">
    /// When true, the policy is applied only for callers that authenticated (requires a
    /// user-identity policy and an <c>AllowAnonymousWithOptionalAuth()</c> endpoint).
    /// </param>
    public PassThroughEndpointBuilder<TResponse> WithBackendAuth(string policy, bool optional = false)
    {
        _inner.WithBackendAuth(policy, optional);
        return this;
    }

    /// <summary>
    /// Uses RFC 8693 token exchange to obtain a backend-specific token for the given audience.
    /// </summary>
    /// <param name="audience">The target audience for the exchanged token.</param>
    /// <param name="optional">
    /// When true, the exchange runs only for callers that authenticated (requires an
    /// <c>AllowAnonymousWithOptionalAuth()</c> endpoint).
    /// </param>
    public PassThroughEndpointBuilder<TResponse> WithTokenExchange(string audience, bool optional = false)
    {
        _inner.WithTokenExchange(audience, optional);
        return this;
    }

    /// <summary>Enables automatic retries for transient failures.</summary>
    public PassThroughEndpointBuilder<TResponse> WithRetries(int maxAttempts = 3)
    {
        _inner.WithRetries(maxAttempts);
        return this;
    }

    /// <summary>
    /// Forwards the listed client request headers onto the backend call. By default a pass-through
    /// endpoint forwards no client headers. See
    /// <see cref="TransformerEndpointBuilderBase{TTransformer, TBuilder}.AllowForwardingHeaders"/>
    /// for the filtering rules and the security implications of listing sensitive headers.
    /// </summary>
    public PassThroughEndpointBuilder<TResponse> AllowForwardingHeaders(
        IEnumerable<string> headers,
        IEnumerable<string>? destinationHosts = null)
    {
        _inner.AllowForwardingHeaders(headers, destinationHosts);
        return this;
    }

    /// <summary>Builds and registers the pass-through endpoint.</summary>
    public RouteHandlerBuilder Build() => _inner.Build();
}

/// <summary>
/// Extension methods for zero-code pass-through endpoints.
/// </summary>
public static class PassThroughExtensions
{
    /// <summary>
    /// Creates a zero-code pass-through endpoint that forwards requests to a backend and returns the response as-is.
    /// No transformer class needed - just configure and build.
    /// </summary>
    /// <typeparam name="TResponse">The response type from the backend</typeparam>
    /// <param name="endpoints">The endpoint route builder</param>
    /// <returns>A fluent builder for configuring the pass-through endpoint</returns>
    /// <example>
    /// <code>
    /// // Zero-code endpoint - no transformer class needed!
    /// app.MapPassThrough&lt;ProductsResponse&gt;()
    ///     .FromRoute("GET", "/api/products")
    ///     .ToBackend("GET", $"{backendUrl}/products")
    ///     .WithBackendAuth(BackendAuthPolicies.BasicAuth)
    ///     .Build();
    /// </code>
    /// </example>
    public static PassThroughEndpointBuilder<TResponse> MapPassThrough<TResponse>(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        return new(endpoints, endpoints.ServiceProvider);
    }
}
