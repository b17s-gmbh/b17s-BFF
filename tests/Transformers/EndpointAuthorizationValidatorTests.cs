using b17s.Porta.Transformers;

namespace b17s.Porta.Tests.Transformers;

/// <summary>
/// Exercises every branch of <see cref="EndpointAuthorizationValidator"/>. The validator
/// is the startup-time gate that prevents a misconfigured endpoint from silently
/// forwarding (or failing to forward) user credentials to a backend — a class of bug
/// you only catch at first request without this check. Each "requires identity" source
/// (token exchange, backend-auth policy that names a user, <c>ForwardUserToken</c>, and
/// the <see cref="RequiresAuthenticationAttribute"/>) needs a dedicated assertion so a
/// future refactor cannot accidentally drop one without breaking a test.
/// </summary>
public sealed class EndpointAuthorizationValidatorTests
{
    private sealed class FakeAuthHandler(string policyName) : IBackendAuthHandler
    {
        public string PolicyName { get; } = policyName;
        public Task ApplyAuthAsync(HttpRequestMessage request, BackendAuthContext context) => Task.CompletedTask;
    }

    private static BackendAuthHandlerRegistry RegistryWith(params string[] policies)
    {
        var registry = new BackendAuthHandlerRegistry();
        foreach (var p in policies)
        {
            registry.Register(new FakeAuthHandler(p));
        }
        return registry;
    }

    [RequiresAuthentication]
    private sealed class AuthRequiredTransformer { }

    private sealed class AnonymousTransformer { }

    public sealed class ValidatePolicyRegistered
    {
        [Fact]
        public void NullPolicy_NoOp()
        {
            // Null is the documented "no backend auth policy" sentinel; must not throw.
            var ex = Record.Exception(() =>
                EndpointAuthorizationValidator.ValidatePolicyRegistered(
                    policy: null,
                    registry: new BackendAuthHandlerRegistry(),
                    context: "endpoint '/api/x'"));

            Assert.Null(ex);
        }

        [Fact]
        public void EmptyPolicy_NoOp()
        {
            var ex = Record.Exception(() =>
                EndpointAuthorizationValidator.ValidatePolicyRegistered(
                    policy: "",
                    registry: new BackendAuthHandlerRegistry(),
                    context: "endpoint '/api/x'"));

            Assert.Null(ex);
        }

        [Fact]
        public void NullRegistry_NoOp()
        {
            // No registry means we can't validate — the caller may be in a context where
            // the registry isn't wired (e.g. tests). The validator must not throw a NRE.
            var ex = Record.Exception(() =>
                EndpointAuthorizationValidator.ValidatePolicyRegistered(
                    policy: "BasicAuth",
                    registry: null,
                    context: "endpoint '/api/x'"));

            Assert.Null(ex);
        }

        [Fact]
        public void RegisteredPolicy_NoOp()
        {
            var registry = RegistryWith("BasicAuth", "BearerToken");

            var ex = Record.Exception(() =>
                EndpointAuthorizationValidator.ValidatePolicyRegistered(
                    policy: "BasicAuth",
                    registry: registry,
                    context: "endpoint '/api/x'"));

            Assert.Null(ex);
        }

        [Fact]
        public void UnregisteredPolicy_ThrowsWithRegisteredList()
        {
            // The error message lists the registered policies so the user can spot a typo.
            // (The registry itself is case-insensitive, so the typo must be a real typo —
            // case alone does not register as unknown.)
            var registry = RegistryWith("BasicAuth", "BearerToken");

            var ex = Assert.Throws<InvalidOperationException>(() =>
                EndpointAuthorizationValidator.ValidatePolicyRegistered(
                    policy: "BasiqAuth",
                    registry: registry,
                    context: "endpoint '/api/x'"));

            Assert.Contains("BasiqAuth", ex.Message);
            Assert.Contains("endpoint '/api/x'", ex.Message);
            Assert.Contains("BasicAuth", ex.Message);
            Assert.Contains("BearerToken", ex.Message);
        }

        [Fact]
        public void RegisteredPolicy_CaseInsensitive_NoOp()
        {
            // The registry is case-insensitive — "BasicAuth" and "basicauth" resolve to the
            // same handler. Lock this in so a future refactor doesn't quietly tighten the
            // comparison and break existing configs.
            var registry = RegistryWith("BasicAuth");

            var ex = Record.Exception(() =>
                EndpointAuthorizationValidator.ValidatePolicyRegistered(
                    policy: "basicauth",
                    registry: registry,
                    context: "endpoint '/api/x'"));

            Assert.Null(ex);
        }
    }

    public sealed class Validate
    {
        [Fact]
        public void NoIdentitySources_NoAuthRequired_NoOp()
        {
            // Pure happy path: nothing needs identity, endpoint allows anonymous — fine.
            var ex = Record.Exception(() =>
                EndpointAuthorizationValidator.Validate(
                    routePattern: "/api/public",
                    backendAuthPolicy: null,
                    useTokenExchange: false,
                    tokenExchangeAudience: null,
                    namedBackends: new NamedBackendEndpoints(),
                    effectiveRequireAuth: false));

            Assert.Null(ex);
        }

        [Fact]
        public void IdentityRequired_AuthEnabled_NoOp()
        {
            var ex = Record.Exception(() =>
                EndpointAuthorizationValidator.Validate(
                    routePattern: "/api/orders",
                    backendAuthPolicy: BackendAuthPolicies.BearerToken,
                    useTokenExchange: false,
                    tokenExchangeAudience: null,
                    namedBackends: new NamedBackendEndpoints(),
                    effectiveRequireAuth: true,
                    authHandlerRegistry: RegistryWith(BackendAuthPolicies.BearerToken)));

            Assert.Null(ex);
        }

        [Fact]
        public void TokenExchange_WithoutRequireAuth_Throws()
        {
            var ex = Assert.Throws<InvalidOperationException>(() =>
                EndpointAuthorizationValidator.Validate(
                    routePattern: "/api/orders",
                    backendAuthPolicy: null,
                    useTokenExchange: true,
                    tokenExchangeAudience: "orders-api",
                    namedBackends: new NamedBackendEndpoints(),
                    effectiveRequireAuth: false));

            Assert.Contains("/api/orders", ex.Message);
            Assert.Contains("AllowAnonymous", ex.Message);
            Assert.Contains("orders-api", ex.Message);
        }

        [Fact]
        public void BearerTokenPolicy_WithoutRequireAuth_Throws()
        {
            // BearerToken at the top-level policy means "forward the user's token". An
            // anonymous endpoint here would forward nothing — silent breakage instead of
            // an early loud failure.
            var ex = Assert.Throws<InvalidOperationException>(() =>
                EndpointAuthorizationValidator.Validate(
                    routePattern: "/api/me",
                    backendAuthPolicy: BackendAuthPolicies.BearerToken,
                    useTokenExchange: false,
                    tokenExchangeAudience: null,
                    namedBackends: new NamedBackendEndpoints(),
                    effectiveRequireAuth: false,
                    authHandlerRegistry: RegistryWith(BackendAuthPolicies.BearerToken)));

            Assert.Contains(BackendAuthPolicies.BearerToken, ex.Message);
        }

        [Fact]
        public void NonIdentityPolicy_WithoutRequireAuth_NoOp()
        {
            // BasicAuth uses the BFF's own credentials, not the user's — so AllowAnonymous
            // is fine for it. This is the canonical "anonymous endpoint hitting a backend
            // with shared creds" case.
            var ex = Record.Exception(() =>
                EndpointAuthorizationValidator.Validate(
                    routePattern: "/api/catalog",
                    backendAuthPolicy: BackendAuthPolicies.BasicAuth,
                    useTokenExchange: false,
                    tokenExchangeAudience: null,
                    namedBackends: new NamedBackendEndpoints(),
                    effectiveRequireAuth: false,
                    authHandlerRegistry: RegistryWith(BackendAuthPolicies.BasicAuth)));

            Assert.Null(ex);
        }

        [Fact]
        public void TransformerWithRequiresAuthentication_WithoutRequireAuth_Throws()
        {
            var ex = Assert.Throws<InvalidOperationException>(() =>
                EndpointAuthorizationValidator.Validate(
                    routePattern: "/api/secure",
                    backendAuthPolicy: null,
                    useTokenExchange: false,
                    tokenExchangeAudience: null,
                    namedBackends: new NamedBackendEndpoints(),
                    effectiveRequireAuth: false,
                    transformerType: typeof(AuthRequiredTransformer)));

            Assert.Contains(nameof(AuthRequiredTransformer), ex.Message);
            Assert.Contains("RequiresAuthentication", ex.Message);
        }

        [Fact]
        public void TransformerWithoutAttribute_NoOp()
        {
            var ex = Record.Exception(() =>
                EndpointAuthorizationValidator.Validate(
                    routePattern: "/api/secure",
                    backendAuthPolicy: null,
                    useTokenExchange: false,
                    tokenExchangeAudience: null,
                    namedBackends: new NamedBackendEndpoints(),
                    effectiveRequireAuth: false,
                    transformerType: typeof(AnonymousTransformer)));

            Assert.Null(ex);
        }

        [Fact]
        public void NamedBackend_ForwardUserToken_WithoutRequireAuth_Throws()
        {
            var backends = new NamedBackendEndpoints();
            backends.Add(new NamedBackendEndpoint
            {
                Name = "user-data",
                Method = "GET",
                UrlTemplate = "https://users.test/api",
                ForwardUserToken = true,
            });

            var ex = Assert.Throws<InvalidOperationException>(() =>
                EndpointAuthorizationValidator.Validate(
                    routePattern: "/api/profile",
                    backendAuthPolicy: null,
                    useTokenExchange: false,
                    tokenExchangeAudience: null,
                    namedBackends: backends,
                    effectiveRequireAuth: false));

            Assert.Contains("user-data", ex.Message);
        }

        [Fact]
        public void NamedBackend_TokenExchange_WithoutRequireAuth_Throws()
        {
            var backends = new NamedBackendEndpoints();
            backends.Add(new NamedBackendEndpoint
            {
                Name = "orders",
                Method = "GET",
                UrlTemplate = "https://orders.test/api",
                UseTokenExchange = true,
                TokenExchangeAudience = "orders-api",
            });

            var ex = Assert.Throws<InvalidOperationException>(() =>
                EndpointAuthorizationValidator.Validate(
                    routePattern: "/api/profile",
                    backendAuthPolicy: null,
                    useTokenExchange: false,
                    tokenExchangeAudience: null,
                    namedBackends: backends,
                    effectiveRequireAuth: false));

            Assert.Contains("orders", ex.Message);
        }

        [Fact]
        public void NamedBackend_BearerTokenPolicy_WithoutRequireAuth_Throws()
        {
            var backends = new NamedBackendEndpoints();
            backends.Add(new NamedBackendEndpoint
            {
                Name = "me",
                Method = "GET",
                UrlTemplate = "https://me.test/api",
                BackendAuthPolicy = BackendAuthPolicies.BearerToken,
            });

            var ex = Assert.Throws<InvalidOperationException>(() =>
                EndpointAuthorizationValidator.Validate(
                    routePattern: "/api/profile",
                    backendAuthPolicy: null,
                    useTokenExchange: false,
                    tokenExchangeAudience: null,
                    namedBackends: backends,
                    effectiveRequireAuth: false,
                    authHandlerRegistry: RegistryWith(BackendAuthPolicies.BearerToken)));

            Assert.Contains("me", ex.Message);
        }

        [Fact]
        public void NamedBackend_NonIdentityPolicy_WithoutRequireAuth_NoOp()
        {
            // Belt-and-braces: a named backend that uses BasicAuth (BFF creds) shouldn't trip
            // the validator regardless of the endpoint's anonymous flag.
            var backends = new NamedBackendEndpoints();
            backends.Add(new NamedBackendEndpoint
            {
                Name = "catalog",
                Method = "GET",
                UrlTemplate = "https://catalog.test/api",
                BackendAuthPolicy = BackendAuthPolicies.BasicAuth,
            });

            var ex = Record.Exception(() =>
                EndpointAuthorizationValidator.Validate(
                    routePattern: "/api/things",
                    backendAuthPolicy: null,
                    useTokenExchange: false,
                    tokenExchangeAudience: null,
                    namedBackends: backends,
                    effectiveRequireAuth: false,
                    authHandlerRegistry: RegistryWith(BackendAuthPolicies.BasicAuth)));

            Assert.Null(ex);
        }

        [Fact]
        public void UnknownTopLevelPolicy_Throws_BeforeIdentityChecks()
        {
            // Policy validation runs first — even if other checks would also fire, the user
            // hears about the typo immediately rather than chasing a misleading second
            // error.
            var registry = RegistryWith(BackendAuthPolicies.BasicAuth);

            var ex = Assert.Throws<InvalidOperationException>(() =>
                EndpointAuthorizationValidator.Validate(
                    routePattern: "/api/x",
                    backendAuthPolicy: "BasiqAuth",
                    useTokenExchange: false,
                    tokenExchangeAudience: null,
                    namedBackends: new NamedBackendEndpoints(),
                    effectiveRequireAuth: true,
                    authHandlerRegistry: registry));

            Assert.Contains("BasiqAuth", ex.Message);
            Assert.Contains("BasicAuth", ex.Message);
        }

        [Fact]
        public void UnknownNamedBackendPolicy_Throws()
        {
            var backends = new NamedBackendEndpoints();
            backends.Add(new NamedBackendEndpoint
            {
                Name = "orders",
                Method = "GET",
                UrlTemplate = "https://orders.test/api",
                BackendAuthPolicy = "DoesNotExist",
            });
            var registry = RegistryWith(BackendAuthPolicies.BasicAuth);

            var ex = Assert.Throws<InvalidOperationException>(() =>
                EndpointAuthorizationValidator.Validate(
                    routePattern: "/api/x",
                    backendAuthPolicy: null,
                    useTokenExchange: false,
                    tokenExchangeAudience: null,
                    namedBackends: backends,
                    effectiveRequireAuth: true,
                    authHandlerRegistry: registry));

            Assert.Contains("DoesNotExist", ex.Message);
            Assert.Contains("orders", ex.Message);
        }

        [Fact]
        public void OptionalBearerTokenPolicy_OptionalUserIdentity_NoOp()
        {
            // The sanctioned combination: an optional-flagged user-identity policy on an
            // AllowAnonymousWithOptionalAuth() endpoint - applied for authenticated callers,
            // downgraded to None for anonymous ones.
            var ex = Record.Exception(() =>
                EndpointAuthorizationValidator.Validate(
                    routePattern: "/api/me",
                    backendAuthPolicy: BackendAuthPolicies.BearerToken,
                    useTokenExchange: false,
                    tokenExchangeAudience: null,
                    namedBackends: new NamedBackendEndpoints(),
                    effectiveRequireAuth: false,
                    authHandlerRegistry: RegistryWith(BackendAuthPolicies.BearerToken),
                    optionalUserIdentity: true,
                    backendAuthOptional: true));

            Assert.Null(ex);
        }

        [Fact]
        public void OptionalTokenExchange_OptionalUserIdentity_NoOp()
        {
            var ex = Record.Exception(() =>
                EndpointAuthorizationValidator.Validate(
                    routePattern: "/api/orders",
                    backendAuthPolicy: null,
                    useTokenExchange: true,
                    tokenExchangeAudience: "orders-api",
                    namedBackends: new NamedBackendEndpoints(),
                    effectiveRequireAuth: false,
                    optionalUserIdentity: true,
                    backendAuthOptional: true));

            Assert.Null(ex);
        }

        [Fact]
        public void OptionalNamedBackendIdentity_OptionalUserIdentity_NoOp()
        {
            var backends = new NamedBackendEndpoints();
            backends.Add(new NamedBackendEndpoint
            {
                Name = "user-data",
                Method = "GET",
                UrlTemplate = "https://users.test/api",
                ForwardUserToken = true,
                OptionalAuth = true,
            });

            var ex = Record.Exception(() =>
                EndpointAuthorizationValidator.Validate(
                    routePattern: "/api/profile",
                    backendAuthPolicy: null,
                    useTokenExchange: false,
                    tokenExchangeAudience: null,
                    namedBackends: backends,
                    effectiveRequireAuth: false,
                    optionalUserIdentity: true));

            Assert.Null(ex);
        }

        [Fact]
        public void OptionalUserIdentity_NoBackendAuth_NoOp()
        {
            // Transformer-only optional auth: the endpoint personalizes on the optionally
            // resolved AuthContext without ever authenticating a backend call. Valid.
            var ex = Record.Exception(() =>
                EndpointAuthorizationValidator.Validate(
                    routePattern: "/api/maybe",
                    backendAuthPolicy: null,
                    useTokenExchange: false,
                    tokenExchangeAudience: null,
                    namedBackends: new NamedBackendEndpoints(),
                    effectiveRequireAuth: false,
                    optionalUserIdentity: true));

            Assert.Null(ex);
        }

        [Fact]
        public void MandatoryIdentityPolicy_OptionalUserIdentity_Throws()
        {
            // A non-optional user-identity policy promises the backend an identity that anonymous
            // callers do not have - the optional endpoint must not silently downgrade it. The
            // developer has to declare the optionality on the policy itself.
            var ex = Assert.Throws<InvalidOperationException>(() =>
                EndpointAuthorizationValidator.Validate(
                    routePattern: "/api/me",
                    backendAuthPolicy: BackendAuthPolicies.BearerToken,
                    useTokenExchange: false,
                    tokenExchangeAudience: null,
                    namedBackends: new NamedBackendEndpoints(),
                    effectiveRequireAuth: false,
                    authHandlerRegistry: RegistryWith(BackendAuthPolicies.BearerToken),
                    optionalUserIdentity: true));

            Assert.Contains("optional: true", ex.Message);
        }

        [Fact]
        public void OptionalFlag_WithoutOptionalEndpoint_Throws()
        {
            // optional: true is dead configuration on RequireAuth() (identity always present) and
            // meaningless on AllowAnonymous() (credentials never resolved) - both fail loud.
            var ex = Assert.Throws<InvalidOperationException>(() =>
                EndpointAuthorizationValidator.Validate(
                    routePattern: "/api/orders",
                    backendAuthPolicy: BackendAuthPolicies.BearerToken,
                    useTokenExchange: false,
                    tokenExchangeAudience: null,
                    namedBackends: new NamedBackendEndpoints(),
                    effectiveRequireAuth: true,
                    authHandlerRegistry: RegistryWith(BackendAuthPolicies.BearerToken),
                    optionalUserIdentity: false,
                    backendAuthOptional: true));

            Assert.Contains("AllowAnonymousWithOptionalAuth", ex.Message);
        }

        [Fact]
        public void OptionalFlag_OnNonIdentityPolicy_Throws()
        {
            // BasicAuth never carries the caller's identity - there is nothing to apply
            // optionally, so the flag is a misconfiguration even on an optional endpoint.
            var ex = Assert.Throws<InvalidOperationException>(() =>
                EndpointAuthorizationValidator.Validate(
                    routePattern: "/api/things",
                    backendAuthPolicy: BackendAuthPolicies.BasicAuth,
                    useTokenExchange: false,
                    tokenExchangeAudience: null,
                    namedBackends: new NamedBackendEndpoints(),
                    effectiveRequireAuth: false,
                    authHandlerRegistry: RegistryWith(BackendAuthPolicies.BasicAuth),
                    optionalUserIdentity: true,
                    backendAuthOptional: true));

            Assert.Contains("never carries", ex.Message);
        }

        [Fact]
        public void OptionalFlag_OnNamedLeg_WithoutOptionalEndpoint_Throws()
        {
            var backends = new NamedBackendEndpoints();
            backends.Add(new NamedBackendEndpoint
            {
                Name = "user-data",
                Method = "GET",
                UrlTemplate = "https://users.test/api",
                BackendAuthPolicy = BackendAuthPolicies.BearerToken,
                OptionalAuth = true,
            });

            var ex = Assert.Throws<InvalidOperationException>(() =>
                EndpointAuthorizationValidator.Validate(
                    routePattern: "/api/profile",
                    backendAuthPolicy: null,
                    useTokenExchange: false,
                    tokenExchangeAudience: null,
                    namedBackends: backends,
                    effectiveRequireAuth: true,
                    authHandlerRegistry: RegistryWith(BackendAuthPolicies.BearerToken)));

            Assert.Contains("user-data", ex.Message);
            Assert.Contains("AllowAnonymousWithOptionalAuth", ex.Message);
        }

        [Fact]
        public void MandatoryNamedLeg_BesideOptionalLeg_OptionalUserIdentity_Throws()
        {
            // Mixed named backends: the optional-flagged leg is fine, but the mandatory identity
            // leg still needs a guaranteed identity and must be reported.
            var backends = new NamedBackendEndpoints();
            backends.Add(new NamedBackendEndpoint
            {
                Name = "personalization",
                Method = "GET",
                UrlTemplate = "https://users.test/api",
                BackendAuthPolicy = BackendAuthPolicies.BearerToken,
                OptionalAuth = true,
            });
            backends.Add(new NamedBackendEndpoint
            {
                Name = "orders",
                Method = "GET",
                UrlTemplate = "https://orders.test/api",
                UseTokenExchange = true,
                TokenExchangeAudience = "orders-api",
            });

            var ex = Assert.Throws<InvalidOperationException>(() =>
                EndpointAuthorizationValidator.Validate(
                    routePattern: "/api/profile",
                    backendAuthPolicy: null,
                    useTokenExchange: false,
                    tokenExchangeAudience: null,
                    namedBackends: backends,
                    effectiveRequireAuth: false,
                    authHandlerRegistry: RegistryWith(BackendAuthPolicies.BearerToken),
                    optionalUserIdentity: true));

            Assert.Contains("orders", ex.Message);
            Assert.DoesNotContain("personalization", ex.Message);
        }

        [Fact]
        public void RequiresAuthenticationAttribute_OptionalUserIdentity_StillThrows()
        {
            // The attribute declares the TRANSFORMER cannot run without an identity - optional
            // mode cannot honor that for anonymous callers, so the combination stays invalid.
            var ex = Assert.Throws<InvalidOperationException>(() =>
                EndpointAuthorizationValidator.Validate(
                    routePattern: "/api/secure",
                    backendAuthPolicy: BackendAuthPolicies.BearerToken,
                    useTokenExchange: false,
                    tokenExchangeAudience: null,
                    namedBackends: new NamedBackendEndpoints(),
                    effectiveRequireAuth: false,
                    authHandlerRegistry: RegistryWith(BackendAuthPolicies.BearerToken),
                    transformerType: typeof(AuthRequiredTransformer),
                    optionalUserIdentity: true,
                    backendAuthOptional: true));

            Assert.Contains(nameof(AuthRequiredTransformer), ex.Message);
            Assert.Contains("RequiresAuthentication", ex.Message);
        }

        [Fact]
        public void ValidateSingleBackend_OptionalFlag_OptionalEndpoint_NoOp()
        {
            // Raw forwarding sits on the same ladder: optional identity policy + optional-auth
            // endpoint is the sanctioned combination.
            var ex = Record.Exception(() =>
                EndpointAuthorizationValidator.ValidateSingleBackend(
                    routePattern: "/proxy/{**path}",
                    backendAuthPolicy: BackendAuthPolicies.BearerToken,
                    effectiveRequireAuth: false,
                    optionalUserIdentity: true,
                    backendAuthOptional: true));

            Assert.Null(ex);
        }

        [Fact]
        public void ValidateSingleBackend_OptionalFlag_WithoutOptionalEndpoint_Throws()
        {
            var ex = Assert.Throws<InvalidOperationException>(() =>
                EndpointAuthorizationValidator.ValidateSingleBackend(
                    routePattern: "/proxy/{**path}",
                    backendAuthPolicy: BackendAuthPolicies.BearerToken,
                    effectiveRequireAuth: true,
                    backendAuthOptional: true));

            Assert.Contains("AllowAnonymousWithOptionalAuth", ex.Message);
        }

        [Fact]
        public void ValidateSingleBackend_MandatoryIdentity_OptionalEndpoint_Throws()
        {
            // Same rule as typed endpoints: a mandatory identity policy cannot ride an
            // anonymous-capable endpoint - the optionality must be declared on the policy.
            var ex = Assert.Throws<InvalidOperationException>(() =>
                EndpointAuthorizationValidator.ValidateSingleBackend(
                    routePattern: "/proxy/{**path}",
                    backendAuthPolicy: BackendAuthPolicies.BearerToken,
                    effectiveRequireAuth: false,
                    optionalUserIdentity: true));

            Assert.Contains("optional: true", ex.Message);
        }

        [Fact]
        public void MultipleIdentitySources_AllReportedInMessage()
        {
            // The combined error message lists every source so the developer can fix them
            // in one round-trip instead of one per recompile.
            var backends = new NamedBackendEndpoints();
            backends.Add(new NamedBackendEndpoint
            {
                Name = "orders",
                Method = "GET",
                UrlTemplate = "https://orders.test/api",
                ForwardUserToken = true,
            });

            var ex = Assert.Throws<InvalidOperationException>(() =>
                EndpointAuthorizationValidator.Validate(
                    routePattern: "/api/profile",
                    backendAuthPolicy: BackendAuthPolicies.BearerToken,
                    useTokenExchange: true,
                    tokenExchangeAudience: "orders-api",
                    namedBackends: backends,
                    effectiveRequireAuth: false,
                    authHandlerRegistry: RegistryWith(BackendAuthPolicies.BearerToken),
                    transformerType: typeof(AuthRequiredTransformer)));

            Assert.Contains(BackendAuthPolicies.BearerToken, ex.Message);
            Assert.Contains("orders-api", ex.Message);
            Assert.Contains("orders", ex.Message);
            Assert.Contains(nameof(AuthRequiredTransformer), ex.Message);
        }
    }
}
