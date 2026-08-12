using System.Net.Http.Headers;
using System.Text;

using b17s.Porta.Auth.Tokens;
using b17s.Porta.Configuration;
using b17s.Porta.Transformers;

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace b17s.Porta.Tests.Transformers;

/// <summary>
/// Unit tests for the six built-in <see cref="IBackendAuthHandler"/> implementations.
/// These handlers sit on the security-critical path between the BFF and every backend,
/// so each branch — including the "no credentials configured" fallbacks — needs explicit
/// coverage to lock in fail-safe behavior.
/// </summary>
public sealed class DefaultAuthHandlersTests
{
    private static BackendAuthContext Context(
        string? accessToken = null,
        string? backendName = null,
        string? tokenExchangeAudience = null) => new()
        {
            AccessToken = accessToken,
            BackendRequest = new BackendRequest
            {
                Method = "GET",
                Url = "https://backend.test/resource",
                BackendName = backendName,
                TokenExchangeAudience = tokenExchangeAudience,
            },
            CancellationToken = TestContext.Current.CancellationToken,
        };

    public sealed class NoneHandler
    {
        [Fact]
        public void PolicyName_IsNone() =>
            Assert.Equal(BackendAuthPolicies.None, new NoneAuthHandler().PolicyName);

        [Fact]
        public async Task ApplyAuthAsync_DoesNotSetAuthorizationHeader()
        {
            var handler = new NoneAuthHandler();
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://backend.test/resource");

            await handler.ApplyAuthAsync(request, Context(accessToken: "would-be-forwarded"));

            Assert.Null(request.Headers.Authorization);
        }
    }

    public sealed class BearerToken
    {
        [Fact]
        public void PolicyName_IsBearerToken() =>
            Assert.Equal(
                BackendAuthPolicies.BearerToken,
                new BearerTokenAuthHandler(NullLogger<BearerTokenAuthHandler>.Instance).PolicyName);

        [Fact]
        public async Task WithAccessToken_SetsBearerAuthorizationHeader()
        {
            var handler = new BearerTokenAuthHandler(NullLogger<BearerTokenAuthHandler>.Instance);
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://backend.test/resource");

            await handler.ApplyAuthAsync(request, Context(accessToken: "user-token"));

            Assert.NotNull(request.Headers.Authorization);
            Assert.Equal("Bearer", request.Headers.Authorization!.Scheme);
            Assert.Equal("user-token", request.Headers.Authorization.Parameter);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public async Task WithoutAccessToken_DoesNotSetHeader(string? token)
        {
            // Fail open here would forward `Authorization: Bearer ` (empty value), which
            // many backends interpret as anonymous — silently downgrading permissions.
            // The handler instead leaves the header unset and logs a warning.
            var handler = new BearerTokenAuthHandler(NullLogger<BearerTokenAuthHandler>.Instance);
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://backend.test/resource");

            await handler.ApplyAuthAsync(request, Context(accessToken: token));

            Assert.Null(request.Headers.Authorization);
        }
    }

    public sealed class BasicAuth
    {
        [Fact]
        public void PolicyName_IsBasicAuth()
        {
            var handler = new BasicAuthHandler(
                Options.Create(new BackendServiceOptions()),
                NullLogger<BasicAuthHandler>.Instance);
            Assert.Equal(BackendAuthPolicies.BasicAuth, handler.PolicyName);
        }

        [Fact]
        public async Task DefaultCredentials_AreApplied_WhenNoBackendName()
        {
            var options = new BackendServiceOptions
            {
                BasicAuth = new BasicAuthOptions { Username = "svc", Password = "p@ss" },
            };
            var handler = new BasicAuthHandler(Options.Create(options), NullLogger<BasicAuthHandler>.Instance);
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://backend.test/resource");

            await handler.ApplyAuthAsync(request, Context());

            AssertBasic(request, "svc", "p@ss");
        }

        [Fact]
        public async Task PerBackendCredentials_OverrideDefault_WhenBackendNameMatches()
        {
            var options = new BackendServiceOptions
            {
                BasicAuth = new BasicAuthOptions { Username = "default-user", Password = "default-pw" },
                Backends =
                {
                    ["orders"] = new BasicAuthOptions { Username = "orders-user", Password = "orders-pw" },
                },
            };
            var handler = new BasicAuthHandler(Options.Create(options), NullLogger<BasicAuthHandler>.Instance);
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://backend.test/resource");

            await handler.ApplyAuthAsync(request, Context(backendName: "orders"));

            AssertBasic(request, "orders-user", "orders-pw");
        }

        [Fact]
        public async Task BackendName_LookupIsCaseInsensitive()
        {
            // Dictionary is built with OrdinalIgnoreCase; covers the case where developers
            // register `Orders` but a transformer sets `orders`.
            var options = new BackendServiceOptions
            {
                Backends =
                {
                    ["Orders"] = new BasicAuthOptions { Username = "u", Password = "p" },
                },
            };
            var handler = new BasicAuthHandler(Options.Create(options), NullLogger<BasicAuthHandler>.Instance);
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://backend.test/resource");

            await handler.ApplyAuthAsync(request, Context(backendName: "orders"));

            AssertBasic(request, "u", "p");
        }

        [Fact]
        public async Task UnknownBackendName_FailsClosed_DoesNotLeakGlobalDefault()
        {
            // A request that names a backend with no per-backend entry must NOT silently receive
            // the global default credentials (which may belong to a different host). Fail closed.
            var options = new BackendServiceOptions
            {
                BasicAuth = new BasicAuthOptions { Username = "default-user", Password = "default-pw" },
                Backends =
                {
                    ["orders"] = new BasicAuthOptions { Username = "orders-user", Password = "orders-pw" },
                },
            };
            var handler = new BasicAuthHandler(Options.Create(options), NullLogger<BasicAuthHandler>.Instance);
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://backend.test/resource");

            await handler.ApplyAuthAsync(request, Context(backendName: "unknown"));

            Assert.Null(request.Headers.Authorization);
        }

        [Fact]
        public async Task UnknownBackendName_WithFallbackOptIn_UsesGlobalDefault()
        {
            // Opt-in restores the legacy shared-global behaviour for consumers who want it.
            var options = new BackendServiceOptions
            {
                AllowGlobalBasicAuthFallback = true,
                BasicAuth = new BasicAuthOptions { Username = "default-user", Password = "default-pw" },
                Backends =
                {
                    ["orders"] = new BasicAuthOptions { Username = "orders-user", Password = "orders-pw" },
                },
            };
            var handler = new BasicAuthHandler(Options.Create(options), NullLogger<BasicAuthHandler>.Instance);
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://backend.test/resource");

            await handler.ApplyAuthAsync(request, Context(backendName: "unknown"));

            AssertBasic(request, "default-user", "default-pw");
        }

        [Fact]
        public async Task PerBackendWithEmptyUsername_FailsClosed()
        {
            // A placeholder per-backend entry (no username) is not authoritative. With a backend
            // name present and no real per-backend credentials, fail closed rather than leak the
            // global default.
            var options = new BackendServiceOptions
            {
                BasicAuth = new BasicAuthOptions { Username = "default-user", Password = "default-pw" },
                Backends =
                {
                    ["orders"] = new BasicAuthOptions { Username = "", Password = "orphan" },
                },
            };
            var handler = new BasicAuthHandler(Options.Create(options), NullLogger<BasicAuthHandler>.Instance);
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://backend.test/resource");

            await handler.ApplyAuthAsync(request, Context(backendName: "orders"));

            Assert.Null(request.Headers.Authorization);
        }

        [Fact]
        public async Task UsernameWithEmptyPassword_StillSends_ButWarns()
        {
            var capture = new ListLogger<BasicAuthHandler>();
            var options = new BackendServiceOptions
            {
                BasicAuth = new BasicAuthOptions { Username = "svc", Password = "" },
            };
            var handler = new BasicAuthHandler(Options.Create(options), capture);
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://backend.test/resource");

            await handler.ApplyAuthAsync(request, Context());

            AssertBasic(request, "svc", "");
            Assert.Contains(capture.Entries, e => e.Level == LogLevel.Warning && e.Message.Contains("empty password"));
        }

        [Fact]
        public async Task NoCredentialsConfigured_LeavesHeaderUnset()
        {
            // Same fail-closed motivation as the BearerToken handler — sending
            // `Authorization: Basic <base64 of ":">` is a valid header that some backends
            // would treat as the anonymous user.
            var handler = new BasicAuthHandler(
                Options.Create(new BackendServiceOptions()),
                NullLogger<BasicAuthHandler>.Instance);
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://backend.test/resource");

            await handler.ApplyAuthAsync(request, Context(backendName: "anything"));

            Assert.Null(request.Headers.Authorization);
        }

        private static void AssertBasic(HttpRequestMessage request, string username, string password)
        {
            Assert.NotNull(request.Headers.Authorization);
            Assert.Equal("Basic", request.Headers.Authorization!.Scheme);

            var expected = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{username}:{password}"));
            Assert.Equal(expected, request.Headers.Authorization.Parameter);
        }
    }

    public sealed class ApiKey
    {
        private static ApiKeyAuthHandler Handler(BackendServiceOptions options, ILogger<ApiKeyAuthHandler>? logger = null)
            => new(Options.Create(options), logger ?? NullLogger<ApiKeyAuthHandler>.Instance);

        [Fact]
        public void PolicyName_IsApiKey() =>
            Assert.Equal(BackendAuthPolicies.ApiKey, Handler(new BackendServiceOptions()).PolicyName);

        [Fact]
        public async Task DefaultOptions_SendBearerAuthorization()
        {
            var handler = Handler(new BackendServiceOptions
            {
                ApiKey = new ApiKeyOptions { Token = "s3cret" },
            });
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://backend.test/resource");

            await handler.ApplyAuthAsync(request, Context());

            Assert.Equal("Bearer", request.Headers.Authorization!.Scheme);
            Assert.Equal("s3cret", request.Headers.Authorization.Parameter);
        }

        [Fact]
        public async Task CustomScheme_SendsConfiguredScheme()
        {
            var handler = Handler(new BackendServiceOptions
            {
                ApiKey = new ApiKeyOptions { Token = "s3cret", Scheme = "Token" },
            });
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://backend.test/resource");

            await handler.ApplyAuthAsync(request, Context());

            Assert.Equal("Token", request.Headers.Authorization!.Scheme);
            Assert.Equal("s3cret", request.Headers.Authorization.Parameter);
        }

        [Theory]
        [InlineData("")]
        [InlineData("   ")]
        public async Task BlankScheme_FallsBackToBearer(string scheme)
        {
            // A config entry that clears the scheme must not produce a malformed header.
            var handler = Handler(new BackendServiceOptions
            {
                ApiKey = new ApiKeyOptions { Token = "s3cret", Scheme = scheme },
            });
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://backend.test/resource");

            await handler.ApplyAuthAsync(request, Context());

            Assert.Equal("Bearer", request.Headers.Authorization!.Scheme);
        }

        [Fact]
        public async Task HeaderName_SendsRawCustomHeader_InsteadOfAuthorization()
        {
            var handler = Handler(new BackendServiceOptions
            {
                ApiKey = new ApiKeyOptions { Token = "s3cret", HeaderName = "X-Api-Key" },
            });
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://backend.test/resource");

            await handler.ApplyAuthAsync(request, Context());

            Assert.Null(request.Headers.Authorization);
            Assert.Equal("s3cret", Assert.Single(request.Headers.GetValues("X-Api-Key")));
        }

        [Fact]
        public async Task HeaderName_ReplacesPreexistingHeader_NeverAppends()
        {
            // A client-forwarded header of the same name must not ride alongside the configured
            // key - the backend would see two values and might honour the attacker-controlled one.
            var handler = Handler(new BackendServiceOptions
            {
                ApiKey = new ApiKeyOptions { Token = "s3cret", HeaderName = "X-Api-Key" },
            });
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://backend.test/resource");
            request.Headers.TryAddWithoutValidation("X-Api-Key", "client-smuggled");

            await handler.ApplyAuthAsync(request, Context());

            Assert.Equal("s3cret", Assert.Single(request.Headers.GetValues("X-Api-Key")));
        }

        [Fact]
        public async Task PerBackendKey_OverridesDefault_WhenBackendNameMatches()
        {
            var handler = Handler(new BackendServiceOptions
            {
                ApiKey = new ApiKeyOptions { Token = "global" },
                ApiKeys = { ["orders"] = new ApiKeyOptions { Token = "orders-key", Scheme = "ApiKey" } },
            });
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://backend.test/resource");

            await handler.ApplyAuthAsync(request, Context(backendName: "orders"));

            Assert.Equal("ApiKey", request.Headers.Authorization!.Scheme);
            Assert.Equal("orders-key", request.Headers.Authorization.Parameter);
        }

        [Fact]
        public async Task UnknownBackendName_FailsClosed_DoesNotLeakGlobalDefault()
        {
            var handler = Handler(new BackendServiceOptions
            {
                ApiKey = new ApiKeyOptions { Token = "global" },
                ApiKeys = { ["orders"] = new ApiKeyOptions { Token = "orders-key" } },
            });
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://backend.test/resource");

            await handler.ApplyAuthAsync(request, Context(backendName: "unknown"));

            Assert.Null(request.Headers.Authorization);
        }

        [Fact]
        public async Task UnknownBackendName_WithFallbackOptIn_UsesGlobalDefault()
        {
            var handler = Handler(new BackendServiceOptions
            {
                AllowGlobalApiKeyFallback = true,
                ApiKey = new ApiKeyOptions { Token = "global" },
                ApiKeys = { ["orders"] = new ApiKeyOptions { Token = "orders-key" } },
            });
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://backend.test/resource");

            await handler.ApplyAuthAsync(request, Context(backendName: "unknown"));

            Assert.Equal("global", request.Headers.Authorization!.Parameter);
        }

        [Fact]
        public async Task PerBackendWithEmptyToken_FailsClosed()
        {
            // A placeholder per-backend entry (no token) is not authoritative; with a backend
            // name present it must not fall through to the global key.
            var handler = Handler(new BackendServiceOptions
            {
                ApiKey = new ApiKeyOptions { Token = "global" },
                ApiKeys = { ["orders"] = new ApiKeyOptions { Token = "" } },
            });
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://backend.test/resource");

            await handler.ApplyAuthAsync(request, Context(backendName: "orders"));

            Assert.Null(request.Headers.Authorization);
        }

        [Fact]
        public async Task NoTokenConfigured_LeavesHeaderUnset_AndWarns()
        {
            // Same fail-closed motivation as BearerToken/BasicAuth: an empty Bearer value is a
            // valid header some backends treat as anonymous.
            var capture = new ListLogger<ApiKeyAuthHandler>();
            var handler = Handler(new BackendServiceOptions(), capture);
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://backend.test/resource");

            await handler.ApplyAuthAsync(request, Context());

            Assert.Null(request.Headers.Authorization);
            Assert.Contains(capture.Entries, e => e.Level == LogLevel.Warning && e.Message.Contains("no token"));
        }
    }

    public sealed class ClientCredentials
    {
        private static ClientCredentialsAuthHandler Handler(
            BackendServiceOptions options,
            FakeClientCredentialsTokenService? tokenService = null)
            => new(
                Options.Create(options),
                tokenService ?? new FakeClientCredentialsTokenService(),
                NullLogger<ClientCredentialsAuthHandler>.Instance);

        private static BackendServiceOptions OptionsWithGlobal(string? scope = null, string? audience = null) => new()
        {
            ClientCredentials = new ClientCredentialsOptions
            {
                TokenEndpoint = "https://idp.test/connect/token",
                ClientId = "bff-m2m",
                ClientSecret = "s3cret",
                Scope = scope,
                Audience = audience,
            },
        };

        [Fact]
        public void PolicyName_IsClientCredentials() =>
            Assert.Equal(BackendAuthPolicies.ClientCredentials, Handler(new BackendServiceOptions()).PolicyName);

        [Fact]
        public async Task GlobalConfig_MintsToken_AndSendsBearer()
        {
            var tokenService = new FakeClientCredentialsTokenService(token: "minted-token");
            var handler = Handler(OptionsWithGlobal(scope: "orders.read", audience: "orders-api"), tokenService);
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://backend.test/resource");

            await handler.ApplyAuthAsync(request, Context());

            Assert.Equal("Bearer", request.Headers.Authorization!.Scheme);
            Assert.Equal("minted-token", request.Headers.Authorization.Parameter);
            Assert.Equal("https://idp.test/connect/token", tokenService.LastRequest!.TokenEndpoint);
            Assert.Equal("bff-m2m", tokenService.LastRequest.ClientId);
            Assert.Equal("s3cret", tokenService.LastRequest.ClientSecret);
            Assert.Equal("orders.read", tokenService.LastRequest.Scope);
            Assert.Equal("orders-api", tokenService.LastRequest.Audience);
        }

        [Theory]
        [InlineData(null, "id", "secret", "TokenEndpoint")]
        [InlineData("https://idp.test/token", null, "secret", "ClientId")]
        [InlineData("https://idp.test/token", "id", null, "ClientSecret")]
        public async Task IncompleteConfig_ThrowsConfigurationError(
            string? endpoint, string? clientId, string? clientSecret, string expectedMissing)
        {
            // Missing client-credentials config is operator misconfiguration (5xx-class), never a
            // user credential rejection - and the message names exactly what is missing.
            var handler = Handler(new BackendServiceOptions
            {
                ClientCredentials = new ClientCredentialsOptions
                {
                    TokenEndpoint = endpoint ?? "",
                    ClientId = clientId ?? "",
                    ClientSecret = clientSecret ?? "",
                },
            });
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://backend.test/resource");

            var ex = await Assert.ThrowsAsync<BackendAuthConfigurationException>(
                () => handler.ApplyAuthAsync(request, Context()));

            Assert.Contains(expectedMissing, ex.Message);
            Assert.Null(request.Headers.Authorization);
        }

        [Fact]
        public async Task PerBackendConfig_OverridesGlobal_WhenBackendNameMatches()
        {
            var tokenService = new FakeClientCredentialsTokenService();
            var options = OptionsWithGlobal();
            options.ClientCredentialsBackends["orders"] = new ClientCredentialsOptions
            {
                TokenEndpoint = "https://idp.test/connect/token",
                ClientId = "orders-m2m",
                ClientSecret = "orders-secret",
                Scope = "orders.write",
            };
            var handler = Handler(options, tokenService);
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://backend.test/resource");

            await handler.ApplyAuthAsync(request, Context(backendName: "orders"));

            Assert.Equal("orders-m2m", tokenService.LastRequest!.ClientId);
            Assert.Equal("orders.write", tokenService.LastRequest.Scope);
        }

        [Fact]
        public async Task UnknownBackendName_FailsClosed_AsConfigurationError()
        {
            // The global client's scopes may grant more than this backend should receive -
            // and unlike BasicAuth/ApiKey the failure is loud (the call cannot succeed anyway).
            var handler = Handler(OptionsWithGlobal());
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://backend.test/resource");

            var ex = await Assert.ThrowsAsync<BackendAuthConfigurationException>(
                () => handler.ApplyAuthAsync(request, Context(backendName: "unknown")));

            Assert.Contains("AllowGlobalClientCredentialsFallback", ex.Message);
            Assert.Null(request.Headers.Authorization);
        }

        [Fact]
        public async Task UnknownBackendName_WithFallbackOptIn_UsesGlobalDefault()
        {
            var tokenService = new FakeClientCredentialsTokenService();
            var options = OptionsWithGlobal();
            options.AllowGlobalClientCredentialsFallback = true;
            var handler = Handler(options, tokenService);
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://backend.test/resource");

            await handler.ApplyAuthAsync(request, Context(backendName: "unknown"));

            Assert.Equal("bff-m2m", tokenService.LastRequest!.ClientId);
            Assert.NotNull(request.Headers.Authorization);
        }

        [Fact]
        public async Task ForceFreshCredential_IsPassedThrough_ToTokenService()
        {
            // BackendCaller's mint-fresh-on-401 retry sets ForceFreshCredential; the handler must
            // forward it so the token cache is bypassed on exactly that attempt.
            var tokenService = new FakeClientCredentialsTokenService();
            var handler = Handler(OptionsWithGlobal(), tokenService);
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://backend.test/resource");
            var context = new BackendAuthContext
            {
                BackendRequest = new BackendRequest { Method = "GET", Url = "https://backend.test/resource" },
                ForceFreshCredential = true,
                CancellationToken = TestContext.Current.CancellationToken,
            };

            await handler.ApplyAuthAsync(request, context);

            Assert.True(tokenService.LastForceRefresh);
        }

        [Fact]
        public async Task TokenAcquisitionFailure_Propagates_AndLeavesHeaderUnset()
        {
            // Fail closed: an IdP failure must not send an unauthenticated request downstream.
            var tokenService = new FakeClientCredentialsTokenService(
                onCall: _ => throw new InvalidOperationException("Client-credentials token request failed: 500"));
            var handler = Handler(OptionsWithGlobal(), tokenService);
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://backend.test/resource");

            await Assert.ThrowsAsync<InvalidOperationException>(
                () => handler.ApplyAuthAsync(request, Context()));
            Assert.Null(request.Headers.Authorization);
        }

        private sealed class FakeClientCredentialsTokenService(
            string token = "fake-token",
            Func<ClientCredentialsTokenRequest, string>? onCall = null) : IClientCredentialsTokenService
        {
            public ClientCredentialsTokenRequest? LastRequest { get; private set; }
            public bool LastForceRefresh { get; private set; }

            public Task<string> GetTokenAsync(ClientCredentialsTokenRequest request, bool forceRefresh = false, CancellationToken cancellationToken = default)
            {
                LastRequest = request;
                LastForceRefresh = forceRefresh;
                return Task.FromResult(onCall?.Invoke(request) ?? token);
            }
        }
    }

    public sealed class TokenExchange
    {
        [Fact]
        public void PolicyName_IsTokenExchange()
        {
            var handler = new TokenExchangeAuthHandler(
                Options.Create(new BackendServiceOptions()),
                NullLogger<TokenExchangeAuthHandler>.Instance);
            Assert.Equal(BackendAuthPolicies.TokenExchange, handler.PolicyName);
        }

        [Fact]
        public async Task MissingApiTokenService_Throws()
        {
            // Documented contract: the handler resolves IApiTokenService from the request scope.
            // When it's absent (e.g. token exchange not wired up) the handler must throw rather than
            // send an unauthenticated request.
            var handler = new TokenExchangeAuthHandler(
                Options.Create(new BackendServiceOptions { DefaultTokenExchangeAudience = "api" }),
                NullLogger<TokenExchangeAuthHandler>.Instance,
                httpContextAccessor: new HttpContextAccessor
                {
                    HttpContext = new DefaultHttpContext { RequestServices = new ServiceCollection().BuildServiceProvider() },
                });
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://backend.test/resource");

            var ex = await Assert.ThrowsAsync<BackendAuthConfigurationException>(
                () => handler.ApplyAuthAsync(request, Context(accessToken: "u")));
            Assert.Contains("IApiTokenService", ex.Message);
            Assert.Null(request.Headers.Authorization);
        }

        [Fact]
        public async Task MissingHttpContext_Throws()
        {
            var handler = new TokenExchangeAuthHandler(
                Options.Create(new BackendServiceOptions { DefaultTokenExchangeAudience = "api" }),
                NullLogger<TokenExchangeAuthHandler>.Instance,
                httpContextAccessor: new HttpContextAccessor()); // HttpContext is null
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://backend.test/resource");

            var ex = await Assert.ThrowsAsync<BackendAuthConfigurationException>(
                () => handler.ApplyAuthAsync(request, Context(accessToken: "u")));
            Assert.Contains("HttpContext", ex.Message);
        }

        [Fact]
        public async Task NoAudienceConfigured_Throws_WithoutCallingTokenService()
        {
            var apiTokenService = new FakeApiTokenService(_ => "unused");
            var handler = new TokenExchangeAuthHandler(
                Options.Create(new BackendServiceOptions()),
                NullLogger<TokenExchangeAuthHandler>.Instance,
                new HttpContextAccessor { HttpContext = ContextWith(apiTokenService) });
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://backend.test/resource");

            var ex = await Assert.ThrowsAsync<BackendAuthConfigurationException>(
                () => handler.ApplyAuthAsync(request, Context(accessToken: "u")));
            Assert.Contains("audience", ex.Message, StringComparison.OrdinalIgnoreCase);
            Assert.Equal(0, apiTokenService.CallCount);
        }

        [Fact]
        public async Task AudiencePrecedence_RequestOverridesPerBackendAndDefault()
        {
            ApiConfiguration? captured = null;
            var apiTokenService = new FakeApiTokenService(cfg => { captured = cfg; return "out"; });
            var options = new BackendServiceOptions
            {
                DefaultTokenExchangeAudience = "default-aud",
                TokenExchangeAudiences = { ["orders"] = "per-backend-aud" },
            };
            var handler = new TokenExchangeAuthHandler(
                Options.Create(options),
                NullLogger<TokenExchangeAuthHandler>.Instance,
                new HttpContextAccessor { HttpContext = ContextWith(apiTokenService) });
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://backend.test/resource");

            await handler.ApplyAuthAsync(
                request,
                Context(accessToken: "u", backendName: "orders", tokenExchangeAudience: "inline-aud"));

            Assert.NotNull(captured);
            Assert.Equal("inline-aud", captured!.ApiAudience);
        }

        [Fact]
        public async Task AudiencePrecedence_PerBackendOverridesDefault()
        {
            ApiConfiguration? captured = null;
            var apiTokenService = new FakeApiTokenService(cfg => { captured = cfg; return "out"; });
            var options = new BackendServiceOptions
            {
                DefaultTokenExchangeAudience = "default-aud",
                TokenExchangeAudiences = { ["orders"] = "per-backend-aud" },
            };
            var handler = new TokenExchangeAuthHandler(
                Options.Create(options),
                NullLogger<TokenExchangeAuthHandler>.Instance,
                new HttpContextAccessor { HttpContext = ContextWith(apiTokenService) });
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://backend.test/resource");

            await handler.ApplyAuthAsync(request, Context(accessToken: "u", backendName: "orders"));

            Assert.NotNull(captured);
            Assert.Equal("per-backend-aud", captured!.ApiAudience);
        }

        [Fact]
        public async Task AudiencePrecedence_FallsBackToDefault_WhenNoPerBackendMatch()
        {
            ApiConfiguration? captured = null;
            var apiTokenService = new FakeApiTokenService(cfg => { captured = cfg; return "out"; });
            var options = new BackendServiceOptions
            {
                DefaultTokenExchangeAudience = "default-aud",
                TokenExchangeAudiences = { ["orders"] = "per-backend-aud" },
            };
            var handler = new TokenExchangeAuthHandler(
                Options.Create(options),
                NullLogger<TokenExchangeAuthHandler>.Instance,
                new HttpContextAccessor { HttpContext = ContextWith(apiTokenService) });
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://backend.test/resource");

            await handler.ApplyAuthAsync(request, Context(accessToken: "u", backendName: "unknown"));

            Assert.NotNull(captured);
            Assert.Equal("default-aud", captured!.ApiAudience);
        }

        [Fact]
        public async Task PerBackendWithEmptyAudience_FallsBackToDefault()
        {
            // ResolveAudience checks `!string.IsNullOrEmpty` on the per-backend entry. A
            // blank value (e.g. config key present but value missing) must not stick.
            ApiConfiguration? captured = null;
            var apiTokenService = new FakeApiTokenService(cfg => { captured = cfg; return "out"; });
            var options = new BackendServiceOptions
            {
                DefaultTokenExchangeAudience = "default-aud",
                TokenExchangeAudiences = { ["orders"] = "" },
            };
            var handler = new TokenExchangeAuthHandler(
                Options.Create(options),
                NullLogger<TokenExchangeAuthHandler>.Instance,
                new HttpContextAccessor { HttpContext = ContextWith(apiTokenService) });
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://backend.test/resource");

            await handler.ApplyAuthAsync(request, Context(accessToken: "u", backendName: "orders"));

            Assert.NotNull(captured);
            Assert.Equal("default-aud", captured!.ApiAudience);
        }

        [Fact]
        public async Task SuccessfulExchange_SetsBearerAuthorization_AndForwardsContextToTokenService()
        {
            ApiConfiguration? captured = null;
            string? capturedAccessToken = null;
            HttpContext? capturedHttpContext = null;
            var apiTokenService = new FakeApiTokenService((cfg, ctx, accessToken) =>
            {
                captured = cfg;
                capturedHttpContext = ctx;
                capturedAccessToken = accessToken;
                return "exchanged-token";
            });
            var httpContext = ContextWith(apiTokenService);
            var handler = new TokenExchangeAuthHandler(
                Options.Create(new BackendServiceOptions { DefaultTokenExchangeAudience = "api" }),
                NullLogger<TokenExchangeAuthHandler>.Instance,
                new HttpContextAccessor { HttpContext = httpContext });
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://backend.test/resource");

            await handler.ApplyAuthAsync(request, Context(accessToken: "user-token"));

            Assert.NotNull(request.Headers.Authorization);
            Assert.Equal("Bearer", request.Headers.Authorization!.Scheme);
            Assert.Equal("exchanged-token", request.Headers.Authorization.Parameter);

            Assert.Equal("api", captured!.ApiAudience);
            Assert.Equal("https://backend.test/resource", captured.ApiPath);
            Assert.Equal("user-token", capturedAccessToken);
            Assert.Same(httpContext, capturedHttpContext);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public async Task FailedExchange_Throws_AndLeavesHeaderUnset(string? exchangedToken)
        {
            // Fail closed: empty/null exchange result must not forward
            // `Authorization: Bearer ` to the backend.
            var apiTokenService = new FakeApiTokenService(_ => exchangedToken);
            var handler = new TokenExchangeAuthHandler(
                Options.Create(new BackendServiceOptions { DefaultTokenExchangeAudience = "api" }),
                NullLogger<TokenExchangeAuthHandler>.Instance,
                new HttpContextAccessor { HttpContext = ContextWith(apiTokenService) });
            using var request = new HttpRequestMessage(HttpMethod.Get, "https://backend.test/resource");

            await Assert.ThrowsAsync<InvalidOperationException>(
                () => handler.ApplyAuthAsync(request, Context(accessToken: "u")));
            Assert.Null(request.Headers.Authorization);
        }

        // The handler resolves IApiTokenService from HttpContext.RequestServices (it's a singleton
        // and must not capture the scoped service), so register the fake there.
        private static DefaultHttpContext ContextWith(IApiTokenService apiTokenService)
            => new()
            {
                RequestServices = new ServiceCollection().AddSingleton(apiTokenService).BuildServiceProvider(),
            };

        private sealed class FakeApiTokenService : IApiTokenService
        {
            private readonly Func<ApiConfiguration, HttpContext, string?, string?> _onCall;

            public int CallCount { get; private set; }

            public FakeApiTokenService(Func<ApiConfiguration, string?> onCall)
                : this((cfg, _, _) => onCall(cfg)) { }

            public FakeApiTokenService(Func<ApiConfiguration, HttpContext, string?, string?> onCall)
            {
                _onCall = onCall;
            }

            public Task<string?> GetApiTokenAsync(
                HttpContext context,
                ApiConfiguration apiConfig,
                string? accessToken,
                CancellationToken cancellationToken = default)
            {
                CallCount++;
                return Task.FromResult(_onCall(apiConfig, context, accessToken));
            }

            public Task<string?> GetApiTokenAsync(
                HttpContext context,
                ApiConfiguration apiConfig,
                string? accessToken,
                ApiTokenCacheOptions cacheOptions,
                CancellationToken cancellationToken = default) =>
                GetApiTokenAsync(context, apiConfig, accessToken, cancellationToken);

            public Task InvalidateApiTokensAsync(HttpContext context, CancellationToken cancellationToken = default) =>
                Task.CompletedTask;

            public Task InvalidateApiTokensAsync(
                HttpContext context,
                ApiTokenCacheOptions cacheOptions,
                CancellationToken cancellationToken = default) =>
                Task.CompletedTask;
        }
    }

    /// <summary>Minimal in-memory logger that records formatted entries for assertions.</summary>
    private sealed class ListLogger<T> : ILogger<T>
    {
        public List<(LogLevel Level, string Message)> Entries { get; } = [];

        public IDisposable BeginScope<TState>(TState state) where TState : notnull => NullScope.Instance;
        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
            => Entries.Add((logLevel, formatter(state, exception)));

        private sealed class NullScope : IDisposable
        {
            public static readonly NullScope Instance = new();
            public void Dispose() { }
        }
    }
}
