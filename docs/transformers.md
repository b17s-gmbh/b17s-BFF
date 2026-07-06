# Writing Transformers

Transformers handle the transformation between client-facing endpoints and backend service calls. The framework provides several base classes to minimize boilerplate.

## Transformer Hierarchy

| Base Class | Use Case | Lines of Code |
|------------|----------|---------------|
| `MapPassThrough<T>()` | Zero-code pass-through endpoint | 0 (config only) |
| `PassThroughTransformer<T>` | Simple pass-through with optional auth | 1 line |
| `AuthenticatedTransformer<T>` | Authenticated pass-through (no request body) | 1 line |
| `AuthenticatedTransformer<TReq, TRes>` | Auth + creates backend request body | 2-3 lines |
| `AggregatingTransformer<T>` | Multi-backend parallel aggregation with declarative `Configure(AggregatorBuilder)` | ~15 lines |
| `MultiBackendTransformer<T>` / `MultiBackendTransformer<TReq, T>` | Manual multi-backend control (parent of `AggregatingTransformer`). Use when you need explicit `CallBackendsInParallelAsync` / `CallNamedBackendAsync` orchestration instead of the aggregator's declarative builder. | ~25 lines |
| `TransformerBase<T>` / `TransformerBase<TReq, T>` | Full custom control (root of the hierarchy) | Varies |

## Level 1: Zero-Code Pass-Through

For simple endpoints that just forward to a backend and return the response as-is, use `MapPassThrough` - no transformer class needed:

```csharp
// No transformer class required!
app.MapPassThrough<ProductsResponse>()
    .FromGet("/api/products")
    .ToGet("https://backend.internal/products")
    .WithBackendAuth(BackendAuthPolicies.BasicAuth)
    .AllowAnonymous()
    .Build();
```

`MapPassThrough` exposes the same fluent vocabulary as `MapTransformer` - `FromGet/Post/Put/Delete/Patch/Head/Options/Any`, `ToBackend/ToGet/ToPost/ToPut/ToDelete/ToPatch/ToAny/ToGraphQL`, `.When(...)`, `RequireAuth`, `WithTokenExchange`, `WithRetries`, etc. - and inherits telemetry, the `[RequiresAuthentication]` fold, and the anonymous-smuggling recheck for free. The only thing it doesn't support is `ToBackends(...)`; if you need to fan out to multiple backends, write an `AggregatingTransformer<T>` instead.

`ToBackend("GET", url)` also has verb shorthands that mirror the `FromGet/FromPost/...` incoming sugar, so you don't have to pass the method as a string:

```csharp
app.MapPassThrough<ProductsResponse>()
    .FromGet("/api/products")
    .ToGet("https://backend.internal/products")   // == .ToBackend("GET", ...)
    .AllowAnonymous()
    .Build();
```

`ToGet`, `ToPost`, `ToPut`, `ToDelete`, and `ToPatch` are available, each taking the URL plus the optional `ContentType` argument.

Or inherit from `PassThroughTransformer<TResponse>` for minimal code:

```csharp
public class ProductsTransformer : PassThroughTransformer<ProductsResponse>;
```

## Level 2: Authenticated Endpoints

For endpoints that require authentication but don't need to create a request body:

```csharp
// Simple authenticated pass-through - no request body needed
public class MyDataTransformer : AuthenticatedTransformer<MyData>;
```

For endpoints that require authentication and send a request body to the backend (but receive no body from the client):

```csharp
public class UserInfoTransformer : AuthenticatedTransformer<BackendUserRequest, UserInfo>
{
    protected override BackendUserRequest CreateBackendRequest(TransformerContext context)
        => new() { UserId = context.UserId! };
}
```

The base class handles:
- Authentication check (returns 401 if `UserId` is null)
- Backend call execution
- Error handling and response mapping

## Level 3: Multi-Backend Aggregation

For endpoints that call multiple backends in parallel and combine the results:

```csharp
public class EnrichedUserProfileTransformer : AggregatingTransformer<EnrichedUserProfile>
{
    protected override void Configure(AggregatorBuilder builder)
    {
        builder.Backend<UserInfo>("UserInfo")
            .WithBody(ctx => new BackendUserRequest { UserId = ctx.UserId! });

        builder.Backend<UserProductInfo>("ProductInfo")
            .WithBody(ctx => new BackendUserRequest { UserId = ctx.UserId! });
    }

    protected override EnrichedUserProfile MapResults(AggregatorResults results, TransformerContext context)
    {
        return new EnrichedUserProfile
        {
            UserInfo = results.Get<UserInfo>("UserInfo") ?? new(),
            ProductInfo = results.Get<UserProductInfo>("ProductInfo") ?? new(),
            IsFullyEnriched = results.AllSucceeded("UserInfo", "ProductInfo")
        };
    }
}
```

### Minimal API Setup

The transformer's `Configure(AggregatorBuilder)` declares *which* named backends it consumes; the endpoint registration declares *where* those names point. Register the transformer, then map the endpoint with `ToBackends(...)` - the `Name` of each `NamedBackendEndpoint` must match the name used in `builder.Backend<T>("...")`:

```csharp
// 1. Register the transformer (scoped, so it can use scoped dependencies)
builder.Services.AddTransformer<EnrichedUserProfileTransformer>();

// 2. Map the endpoint and wire each named backend to its URL (fluent configure lambda)
app.MapTransformer<EnrichedUserProfileTransformer, EnrichedUserProfile>()
    .FromGet("/api/profile")
    .ToBackends(b => b
        .ToGet("UserInfo", "https://users.internal/userinfo")
        .ToGet("ProductInfo", "https://products.internal/products"))
    .RequireAuth()
    .WithBackendAuth(BackendAuthPolicies.BearerToken)
    .Build();
```

`ToBackends(...)` is the multi-backend counterpart to `ToBackend(...)` and is only available on `MapTransformer` (not `MapPassThrough`). The backends are called in parallel; the user's access token is forwarded to each when `WithBackendAuth(BackendAuthPolicies.BearerToken)` is set.

#### Declaring named backends fluently

The `ToBackends(configure => ...)` overload takes a builder whose `ToGet/ToPost/ToPut/ToDelete/ToPatch(name, url)` methods add a backend, mirroring the `ToGet/FromGet` verb sugar. Per-backend overrides chain off each one and apply to the backend they follow, so the configuration reads top-to-bottom without any object initializers:

```csharp
.ToBackends(b => b
    .ToGet("UserInfo", "https://users.internal/userinfo")
        .WithAuth(BackendAuthPolicies.BearerToken)
    .ToPost("Orders", "https://orders.internal/orders")
        .WithTokenExchange("order-api")
        .WithRetries(3))
```

Available per-backend modifiers: `.WithAuth(policy)`, `.WithUserToken()`, `.WithTokenExchange(audience)`, `.WithTimeout(...)`, `.WithRetries(...)`. Use `.ToBackend(method, name, url)` for verbs without a shorthand (e.g. `HEAD`). `.WithRetries(n)` is per-backend - each backend retries the count it declares, capped at the app-wide `PortaCore:MaxRetryAttempts` ceiling (effective count `min(n, ceiling)`).

`ToBackends(...)` also accepts `NamedBackendEndpoint` values directly - the fluent builder above is sugar over this overload. Use it when you build the endpoints yourself, e.g. programmatically from configuration or a loop, via the object initializer or the `(name, method, url).WithAuth(...)` tuple extensions (see [Endpoints](endpoints.md#multi-backend-endpoints)):

```csharp
.ToBackends(
    ("UserInfo", "GET", "https://users.internal/userinfo").WithAuth(BackendAuthPolicies.BearerToken),
    new NamedBackendEndpoint { Name = "Orders", Method = "POST", UrlTemplate = "https://orders.internal/orders" })
```

## Level 4: Custom Logic

For complex transformations, extend `TransformerBase<TResponse>` directly:

```csharp
public class CustomTransformer : TransformerBase<MyResponse>
{
    public override async Task<MyResponse> TransformAsync(TransformerContext context)
    {
        // Full control over the transformation logic
        var result = await CallBackendAsync(context);
        // Custom processing...
        return transformedResult;
    }
}
```

## Accessing Request Data

Transformers have helper methods to access request data and set response headers:

```csharp
public class MyTransformer : TransformerBase<MyResponse>
{
    public override async Task<MyResponse> TransformAsync(TransformerContext context)
    {
        // Read single-value query parameter
        var productId = GetQueryParameter(context, "productId");

        // Read multi-value query parameters: ?tags=a&tags=b&tags=c
        var tags = GetQueryValues(context, "tags").ToList();  // ["a", "b", "c"]

        // Read request headers
        var correlationId = GetRequestHeader(context, "X-Correlation-Id");
        var acceptLanguages = GetRequestHeaders(context, "Accept-Language").ToList();

        // Set response headers
        SetResponseHeader(context, "X-Request-Id", Guid.NewGuid().ToString());
        AddResponseHeader(context, "X-Custom-Header", "value");
        RemoveResponseHeader(context, "X-Internal-Debug");

        // ... transformation logic
        return result;
    }
}
```

### Helper Methods Reference

| Method | Description |
|--------|-------------|
| `GetQueryParameter(context, key)` | Get single query parameter value (first if multiple) |
| `GetQueryValues(context, key)` | Get all values for a multi-value query parameter |
| `GetRequestHeader(context, headerName)` | Get single request header value |
| `GetRequestHeaders(context, headerName)` | Get all values for a multi-value header |
| `SetResponseHeader(context, name, value)` | Set/replace a response header |
| `AddResponseHeader(context, name, value)` | Append to a response header |
| `RemoveResponseHeader(context, name)` | Remove a response header |

### Direct Context Access

For advanced scenarios, you can access the raw data directly:

```csharp
// Query parameters as StringValues (supports multi-value)
context.QueryParameters["tags"]  // Returns StringValues

// Request headers as StringValues
context.RequestHeaders["X-Custom-Header"]  // Returns StringValues

// Full HttpContext access
context.HttpContext.Request.Headers
context.HttpContext.Response.Headers
```

## Error Handling

### Writing Error Responses

```csharp
// Simple error response
await WriteErrorResponseAsync(context, 400, "Invalid request");

// Forward backend error
await WriteBackendErrorResponseAsync(context, backendResult);
```

### Error Mapping

Backend 401/403 errors are mapped to 502 Bad Gateway by default. This prevents clients from misinterpreting backend auth failures as user session expiration.

Implement `IBackendErrorMapper` to customize:

```csharp
public class MyErrorMapper : IBackendErrorMapper
{
    public (int StatusCode, string Message) MapError(
        int backendStatusCode,
        string? backendError,
        BackendRequest request)
    {
        // Pass through auth errors for specific backends
        if (request.Url.Contains("trusted-internal-api"))
            return (backendStatusCode, backendError ?? "Request failed");

        // Default behavior
        return backendStatusCode switch
        {
            401 => (502, "Backend service authentication failed"),
            403 => (502, "Backend service authorization failed"),
            _ => (backendStatusCode, backendError ?? "Request failed")
        };
    }
}

// Registration
services.AddSingleton<IBackendErrorMapper, MyErrorMapper>();
```

## Content Type Serialization

The library supports multiple content types for backend communication.

### Available Content Types

| Content Type | Usage |
|--------------|-------|
| `ContentType.Json` | Default - `application/json` |
| `ContentType.Xml` | XML APIs - `application/xml` |
| `ContentType.FormUrlEncoded` | Form data - `application/x-www-form-urlencoded` |

### Builder Configuration

```csharp
// Specify request content type for backend (the optional 2nd arg on the verb helpers)
app.MapTransformer<LegacyTransformer, LegacyRequest, LegacyResponse>()
    .FromPost("/api/legacy")
    .ToPost("https://legacy.internal/soap-endpoint", ContentType.Xml)
    .Build();
```

### XML Serialization

For legacy SOAP/XML backends, use the `IContentSerializer` service:

```csharp
public class LegacyApiTransformer : TransformerBase<LegacyResponse>
{
    private readonly IContentSerializer _serializer;

    public LegacyApiTransformer(IContentSerializer serializer)
    {
        _serializer = serializer;
    }

    public override async Task<LegacyResponse> TransformAsync(TransformerContext context)
    {
        // Serialize request to XML
        var xmlRequest = _serializer.Serialize(requestObj, ContentType.Xml);

        // Deserialize XML response
        var response = _serializer.Deserialize<LegacyResponse>(xmlContent, ContentType.Xml);

        return response;
    }
}
```
