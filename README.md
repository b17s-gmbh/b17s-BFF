# b17s.Porta

[![CI](https://github.com/b17s-gmbh/b17s-Porta/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/b17s-gmbh/b17s-Porta/actions/workflows/ci.yml)
[![NuGet](https://img.shields.io/nuget/v/b17s.Porta.svg)](https://www.nuget.org/packages/b17s.Porta/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Docs](https://img.shields.io/badge/docs-b17s.net-0a7ea4.svg)](https://b17s.net/docs/porta)

Porta is your way to create completely customizable, easy-to-implement, boiler-plate code free Backend-For-Frontend (BFF) services with opinionated, sensible defaults.
Its architecture hooks into ASP.Net Core's minimal API design, and extends it via transformer-based API aggregation with multi-frontend/backend authentication support.

> **IMPORTANT** Porta is not yet battle-hardened. For this reason it is advised to not use it on edge yet, but have a reverse proxy in front of it.

## Features

- **Transformer Pattern**: Clean separation between API contracts and backend calls
- **Multi-Backend Aggregation**: Combine data from multiple backends in a single endpoint
- **Per-Backend Authentication**: Configure different auth policies for each backend
- **Startup Validation**: Catch configuration errors at application startup, not runtime
- **OIDC Endpoints**: Opt-in login, logout, and back-channel logout middleware
- **Session Administration**: Opt-in REST endpoints for session management
- **Raw Forwarding**: Zero-code proxy endpoints for binary content, files, and non-JSON APIs
- **GraphQL Support**: REST facade over GraphQL backends
- **OpenTelemetry**: Automatic distributed tracing for all transformers and backend calls
- **Health Checks**: Opt-in readiness checks for the IdP, session store, and Data Protection keys

## Installation

```bash
dotnet add package b17s.Porta
```

## Quick Start

### Minimal Setup (Mapped Passthrough; No Auth)

```csharp
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddPortaCore();

var app = builder.Build();

app.MapPassThrough<ProductsResponse>()
    .FromGet("/api/products")
    .ToGet("https://products-api.internal/products")
    .AllowAnonymous()
    .Build();

app.Run();
```

> **Note**: endpoints require authorization by default (`PortaCoreOptions.RequireAuthorizationByDefault = true`). Drop `.AllowAnonymous()` only when you've configured an authentication scheme. Flip the option to `false` to invert the default if you'd rather opt *into* auth per endpoint.

### With OIDC Authentication

Same pass-through endpoint as above, but now it requires a logged-in user and forwards their
access token to the backend. The only new ingredients are the OIDC pipeline registration
(`AddPortaAuthentication`, bound from configuration) and dropping `.AllowAnonymous()` in favour of
`.RequireAuth()`. See the [OIDC Endpoints](docs/oidc.md) guide for the login/logout middleware.

```csharp
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddPortaCore(options => {
    options.TrustedHosts = ["https://products-api.internal"];
});

// Wire up the OIDC pipeline (cookie + OIDC handler + ticket store) from configuration.
builder.Services.AddPortaAuthentication(builder.Configuration);

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapPassThrough<ProductsResponse>()
    .FromGet("/api/products")
    .ToGet("https://products-api.internal/products")
    .RequireAuth()                                      // 401 unless the user is logged in
    .WithBackendAuth(BackendAuthPolicies.BearerToken)   // forward the user's token to the backend
    .Build();

app.Run();
```

### Raw Passthrough (Binary, Files, Non-JSON)

When you don't want to parse or reshape the response — file downloads, streaming, XML — use
`MapRawForward()`. The body is streamed straight through; no response type is needed. See
[Raw Forwarding](docs/raw-forwarding.md) for header handling and size/timeout limits.

```csharp
app.MapRawForward()
    .FromGet("/api/files/{id}")
    .ToGet("https://files-api.internal/files/{id}")
    .RequireAuth()
    .WithBackendAuth(BackendAuthPolicies.BearerToken)
    .Build();
```

> **Catch-all routes must use catch-all syntax on _both_ sides.** A plain `{name}`
> placeholder is encoded as a single path segment — any `/` in the value becomes
> `%2F` (secure by default, so a route value can't introduce new path segments).
> To proxy a multi-segment subtree, use `{**name}` in **both** the route pattern
> and the backend URL. Mixing them (catch-all route, plain backend placeholder)
> encodes the slashes and 404s at the backend:
>
> ```csharp
> app.MapRawForward()
>     .FromGet("/files/{**rest}")
>     .ToGet("https://files-api.internal/files/{**rest}")  // not {rest}
>     .Build();
> // /files/a/b/c.pdf  ->  https://files-api.internal/files/a/b/c.pdf
> ```

### Introducing a Transformer

A transformer is where you reshape the backend response. Inherit a base class (here
`PassThroughTransformer<T>`, overriding `TransformResponse` to strip an internal field), register it
with `AddTransformer<T>()`, then map it with `MapTransformer<,>()`. See
[Transformers](docs/transformers.md) for the full hierarchy.

```csharp
public class ProductsTransformer : PassThroughTransformer<ProductsResponse>
{
    // Strip the internal cost price the frontend should never see.
    protected override ProductsResponse TransformResponse(ProductsResponse response, TransformerContext context)
        => response with { Items = response.Items.Select(i => i with { CostPrice = null }).ToList() };
}
```

```csharp
builder.Services.AddTransformer<ProductsTransformer>();

app.MapTransformer<ProductsTransformer, ProductsResponse>()
    .FromGet("/api/products")
    .ToGet("https://products-api.internal/products")
    .AllowAnonymous()
    .Build();
```

## Documentation

| Topic | Description |
|-------|-------------|
| [Configuration](docs/configuration.md) | Service registration, options, and production settings |
| [Transformers](docs/transformers.md) | Writing transformers, base classes, and error handling |
| [Endpoints](docs/endpoints.md) | Endpoint builder, routing, and authorization |
| [Authentication](docs/authentication.md) | User auth providers and backend auth handlers |
| [OIDC Endpoints](docs/oidc.md) | Login, logout, back-channel logout, and session admin |
| [Raw Forwarding](docs/raw-forwarding.md) | Binary content, file proxying, and streaming |
| [Caching](docs/caching.md) | Output caching endpoints, distributed (HA) cache, and per-leg aggregation caching |
| [GraphQL](docs/graphql.md) | Calling GraphQL backends from REST endpoints |
| [Telemetry](docs/telemetry.md) | OpenTelemetry traces and metrics |
| [Health Checks](docs/health-checks.md) | Readiness checks for the IdP, distributed cache, and Data Protection |
| [HA Deployment](docs/ha-deployment.md) | Running multiple replicas behind a load balancer without sticky sessions |
| [API Gateway Use](docs/api-gateway.md) | When to use this library as a gateway, and when to pick something else |
| [Advanced](docs/advanced.md) | API versioning, MapGroup, OpenAPI metadata, and composing framework features |

## Try it (runnable demo)

A self-contained, run-out-of-the-box demo lives in [demo/](demo/README.md). One command brings up a
complete BFF topology against **two** identity providers — Keycloak and Zitadel — orchestrated by
.NET Aspire, plus end-to-end login tests against both:

```bash
cd demo
aspire run          # or: dotnet run --project Demo.AppHost
```

A container runtime (Docker Desktop or Podman) is the only prerequisite — the IdPs, database, and
seeded test users are provisioned automatically. See [demo/README.md](demo/README.md) for the topology,
seeded credentials, exposed endpoints, and how to run the functional/E2E suite.

## Transformer Hierarchy

Choose the right base class for your use case. Each links to its guide and a worked example:

| Base Class | Use Case | Code Required |
|------------|----------|---------------|
| [`MapPassThrough<T>()`](docs/transformers.md#level-1-zero-code-pass-through) | Zero-code pass-through | Config only |
| [`PassThroughTransformer<T>`](docs/transformers.md#level-1-zero-code-pass-through) | Simple pass-through | 1 line |
| [`AuthenticatedTransformer<T>`](docs/transformers.md#level-2-authenticated-endpoints) | Auth required, no request body | 1 line |
| [`AuthenticatedTransformer<TReq, TRes>`](docs/transformers.md#level-2-authenticated-endpoints) | Auth + backend request body | 2-3 lines |
| [`AggregatingTransformer<T>`](docs/transformers.md#level-3-multi-backend-aggregation) | Multi-backend aggregation | ~15 lines |
| [`TransformerBase<T>`](docs/transformers.md#level-4-custom-logic) | Full custom control | Varies |

## Backend Authentication

Built-in policies:

| Policy | Description | Requires User |
|--------|-------------|---------------|
| `None` | No authentication | No |
| `BasicAuth` | HTTP Basic auth from config | No |
| `BearerToken` | Forward user's token | Yes |
| `TokenExchange` | Exchange for backend token (needs an audience - see [Authentication](docs/authentication.md#backend-authentication)) | Yes |
| *Custom* | Anything else (HMAC, API keys, client credentials) — implement `IBackendAuthHandler` | Depends |

Per-backend configuration:

```csharp
app.MapTransformer<MyTransformer, Response>()
    .FromGet("/api/data")
    .ToBackends(b => b
        .ToGet("Users", "https://users.internal/api").WithAuth(BackendAuthPolicies.BearerToken)
        .ToGet("Products", "https://products.internal/api").WithAuth(BackendAuthPolicies.BasicAuth))
    .Build();
```

### Custom Policies

The built-in policies aren't a closed set. Implement `IBackendAuthHandler` to add your own (HMAC
signing, API keys, client-credentials, etc.). The handler exposes a `PolicyName`, and `ApplyAuthAsync`
mutates the outgoing request — add headers, sign the body, attach a token. Register it with
`AddPortaAuthHandler<T>()`, then reference it by name via `WithBackendAuth("...")`:

```csharp
public class HmacAuthHandler : IBackendAuthHandler
{
    public string PolicyName => "HmacAuth";

    public Task ApplyAuthAsync(HttpRequestMessage request, BackendAuthContext context)
    {
        request.Headers.Add("X-Signature", ComputeHmacSignature(request));
        request.Headers.Add("X-Timestamp", DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString());
        return Task.CompletedTask;
    }
}

// Registration
builder.Services.AddPortaAuthHandler<HmacAuthHandler>();

// Usage — reference the custom handler by its PolicyName
app.MapPassThrough<Response>()
    .FromGet("/api/partner-data")
    .ToGet("https://partner-api.example.com/data")
    .WithBackendAuth("HmacAuth")
    .Build();
```

See [Authentication](docs/authentication.md#custom-backend-auth-handler) for the full `BackendAuthContext`
contract and registering multiple handlers.
