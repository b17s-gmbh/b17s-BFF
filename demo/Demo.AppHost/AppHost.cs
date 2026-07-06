// ===========================================================================
// b17s.Porta end-to-end demo — Aspire AppHost
//
// Brings up, with one command, a full BFF topology against TWO identity providers:
//
//   keycloak (container)          - realm + client imported from JSON (zero-touch)
//   valkey   (container)          - shared distributed cache (Redis-protocol); both BFFs'
//                                   session/ticket store, so sessions survive across replicas
//   postgres (container)          - database for Zitadel
//   zitadel  (container)          - second IdP; first-instance seeded with a service account
//   zitadel-provisioner (project) - creates Zitadel's OIDC app at runtime, writes its
//                                   client id/secret to a file the BFF reads
//   backend  (project)            - sample downstream API the BFF forwards to
//   bff-keycloak (project)        - b17s.Porta BFF pointed at Keycloak
//   bff-zitadel  (project)        - the SAME b17s.Porta BFF pointed at Zitadel
//
// Fixed host ports are used so OIDC redirect URIs are stable (the imported Keycloak realm
// and the Zitadel app both register http://127.0.0.1:510x/signin-oidc).
//
// Requires a container runtime (Docker Desktop / Podman). Everything runs over plain HTTP
// on 127.0.0.1 for demo simplicity — the BFFs run in the Development environment, which is
// the only environment in which Porta permits the relaxed cookie/HTTPS settings used here.
// ===========================================================================

// Fixed host ports — keep these in sync with the Keycloak realm JSON and the Zitadel
// provisioner redirect URIs below.
const int BackendPort = 51100;
const int BffKeycloakPort = 51101;
const int BffZitadelPort = 51102;
const int KeycloakPort = 58080;
const int ZitadelPort = 58081;

const string BackendUrl = "http://127.0.0.1:51100";
const string KeycloakRealm = "porta-demo";

// Service credentials the BFF presents to the backend's Basic-auth-protected /internal endpoint
// (BackendAuthPolicies.BasicAuth). The same pair is handed to the backend (which validates it)
// and to both BFFs (which present it) so the machine-to-machine call succeeds end to end.
const string BackendBasicUser = "bff-service";
const string BackendBasicPassword = "porta-basic-demo-secret";

// Precomputed URL strings. (Built as plain strings so they bind to WithEnvironment's
// string overload — an interpolated string containing an int otherwise binds to Aspire's
// ReferenceExpression interpolation handler, which only accepts resource value-providers.)
// IdP authorities use 127.0.0.1 (NOT 127.0.0.1) deliberately. The IdP containers run under
// rootless Podman, which publishes their host ports on IPv4 127.0.0.1 ONLY (no [::1]). On
// Windows + WSL2 NAT networking the browser resolves "127.0.0.1" to ::1 first, so a browser
// navigation to http://127.0.0.1:5808x (the OIDC authorize redirect) hits an IPv6 address
// with no listener -> ERR_CONNECTION_REFUSED. Forcing the authority host to 127.0.0.1 keeps
// both the browser redirect and the back-channel calls on IPv4, which WSL2 forwards. The BFF
// itself is dual-stack, so its redirect URIs below stay on "127.0.0.1" — and MUST, because
// the OIDC correlation cookie is set for the host you browse the BFF on (127.0.0.1). The user
// only detours to 127.0.0.1 for the IdP. (Equivalent under Docker Desktop / WSL mirrored mode.)
var zitadelApiUrl = $"http://127.0.0.1:{ZitadelPort}";
var zitadelExternalPort = ZitadelPort.ToString();
var zitadelRedirectUri = $"http://127.0.0.1:{BffZitadelPort}/signin-oidc";
var zitadelPostLogoutUri = $"http://127.0.0.1:{BffZitadelPort}/signout-callback-oidc";
var keycloakAuthority = $"http://127.0.0.1:{KeycloakPort}/realms/{KeycloakRealm}";
var zitadelAuthority = zitadelApiUrl;

// Zitadel master key MUST be exactly 32 characters (encrypts secrets at rest).
const string ZitadelMasterKey = "MasterkeyNeedsToHave32Characters";

var builder = DistributedApplication.CreateBuilder(args);

// Aspire labels every published host-port endpoint with the literal host "localhost" in the
// dashboard's URLs column. Rewrite those to 127.0.0.1 so the displayed links match the IdP
// authorities AND are actually clickable: under rootless Podman + WSL2 NAT the IdP containers
// are only reachable via IPv4 127.0.0.1 (a "localhost" link resolves to ::1 and is refused).
Action<Aspire.Hosting.ApplicationModel.ResourceUrlsCallbackContext> useLoopbackUrls = context =>
{
    foreach (var url in context.Urls)
    {
        url.Url = url.Url.Replace("localhost", "127.0.0.1");
    }
};

// Shared folder for Zitadel <-> provisioner hand-off (service-account key in, client
// credentials out). Wiped on every run so a fresh Zitadel instance is always reprovisioned
// and stale credentials never linger. Git-ignored via demo/.gitignore.
var sharedDir = Path.Combine(builder.AppHostDirectory, ".zitadel");
if (Directory.Exists(sharedDir))
{
    try { Directory.Delete(sharedDir, recursive: true); } catch { /* best effort */ }
}
Directory.CreateDirectory(sharedDir);

var machineKeyFile = Path.Combine(sharedDir, "zitadel-admin-sa.json");
var zitadelClientFile = Path.Combine(sharedDir, "bff-zitadel-client.json");

// ---------------------------------------------------------------------------
// Keycloak — realm + confidential client imported from JSON (zero-touch).
// ---------------------------------------------------------------------------
var keycloakAdmin = builder.AddParameter("keycloak-admin", "admin");
var keycloakAdminPassword = builder.AddParameter("keycloak-admin-password", "admin", secret: true);

// The positional port binds the container's HTTP endpoint (container 8080) to the fixed
// host port. NOTE: this only stays HTTP because we disable Aspire's automatic developer-
// certificate HTTPS termination (ASPIRE_DEVELOPER_CERTIFICATE_DEFAULT_HTTPS_TERMINATION=false
// in appsettings.json / launchSettings.json). With that default left ON, Aspire.Hosting
// 13.x rewrites the primary HTTP endpoint to terminate TLS with the ASP.NET dev cert — so
// host 58080 maps to container 8443 (HTTPS) instead of 8080. The BFF then speaks plaintext
// HTTP (keycloakAuthority is http://, the demo is all-HTTP on 127.0.0.1) into a TLS listener,
// which fails the OIDC discovery fetch with "The response ended prematurely (ResponseEnded)".
// The injected cert is also untrusted and Keycloak emits HSTS, so an HTTPS path would break
// the browser login redirect outright — plain HTTP is the only sane demo posture here.
var keycloak = builder.AddKeycloak("keycloak", KeycloakPort, keycloakAdmin, keycloakAdminPassword)
    .WithRealmImport("./keycloak/realms")
    // Bind the HTTP endpoint straight to the host (no Aspire DCP proxy hop). Under rootless
    // Podman the DCP proxy — a host process — can't route to the container's internal network
    // (10.89.0.0/24), so a proxied http://127.0.0.1:58080 hop returns empty replies and the
    // BFF's OIDC discovery fetch fails with "response ended prematurely". A non-proxied
    // endpoint is published directly (127.0.0.1:58080 -> container 8080), which IS host-
    // reachable under Podman and is equivalent under Docker.
    .WithEndpoint("http", endpoint => endpoint.IsProxied = false)
    // Ready only once the imported realm answers discovery — a precise readiness probe.
    .WithHttpHealthCheck($"/realms/{KeycloakRealm}/.well-known/openid-configuration")
    .WithUrls(useLoopbackUrls);

// ---------------------------------------------------------------------------
// Postgres + Zitadel — second IdP. Zitadel has no realm import, so a provisioner
// creates the OIDC app at runtime (see below).
// ---------------------------------------------------------------------------
var postgresPassword = builder.AddParameter("postgres-password", "postgres", secret: true);
var postgres = builder.AddPostgres("postgres", password: postgresPassword)
    .WithUrls(useLoopbackUrls);

var zitadel = builder.AddContainer("zitadel", "ghcr.io/zitadel/zitadel", "latest")
    .WithArgs("start-from-init", "--masterkeyFromEnv", "--tlsMode", "disabled")
    // Non-proxied for the same rootless-Podman routing reason as Keycloak above: publish
    // 127.0.0.1:58081 -> container 8080 directly so the BFF and provisioner can reach it.
    .WithHttpEndpoint(port: ZitadelPort, targetPort: 8080, name: "http", isProxied: false)
    .WithEnvironment("ZITADEL_MASTERKEY", ZitadelMasterKey)
    .WithEnvironment("ZITADEL_EXTERNALSECURE", "false")
    .WithEnvironment("ZITADEL_TLS_ENABLED", "false")
    // 127.0.0.1 (not 127.0.0.1) so Zitadel's issuer matches zitadelAuthority/zitadelApiUrl and
    // the browser reaches it over IPv4 — see the authority note above for the WSL2/Podman reason.
    .WithEnvironment("ZITADEL_EXTERNALDOMAIN", "127.0.0.1")
    .WithEnvironment("ZITADEL_EXTERNALPORT", zitadelExternalPort)
    // Zitadel v4 enables Login UI v2 by default (DefaultInstance.Features.LoginV2.Required=true),
    // which runs as a SEPARATE container the demo does not host — so /authorize 302s to
    // /ui/v2/login and 404s ({"code":5,...}), overriding any per-app loginVersion. Disable it so
    // the embedded legacy login (/ui/login) is served. FIRSTINSTANCE is the alias this image
    // honors for the seeded instance (see the ORG_* settings below); set both prefixes to be safe.
    .WithEnvironment("ZITADEL_DEFAULTINSTANCE_FEATURES_LOGINV2_REQUIRED", "false")
    .WithEnvironment("ZITADEL_FIRSTINSTANCE_FEATURES_LOGINV2_REQUIRED", "false")
    // Database wiring (Zitadel reaches postgres by its Aspire resource name on the shared
    // container network; the demo uses the postgres superuser for both connections).
    .WithEnvironment("ZITADEL_DATABASE_POSTGRES_HOST", "postgres")
    .WithEnvironment("ZITADEL_DATABASE_POSTGRES_PORT", "5432")
    .WithEnvironment("ZITADEL_DATABASE_POSTGRES_DATABASE", "zitadel")
    .WithEnvironment("ZITADEL_DATABASE_POSTGRES_USER_USERNAME", "postgres")
    .WithEnvironment("ZITADEL_DATABASE_POSTGRES_USER_PASSWORD", postgresPassword)
    .WithEnvironment("ZITADEL_DATABASE_POSTGRES_USER_SSL_MODE", "disable")
    .WithEnvironment("ZITADEL_DATABASE_POSTGRES_ADMIN_USERNAME", "postgres")
    .WithEnvironment("ZITADEL_DATABASE_POSTGRES_ADMIN_PASSWORD", postgresPassword)
    .WithEnvironment("ZITADEL_DATABASE_POSTGRES_ADMIN_SSL_MODE", "disable")
    // First-instance seed: a demo admin user (login: demo / demo) to mirror Keycloak's test
    // user, plus a machine service account whose JSON key is written for the provisioner.
    // Zitadel's default password policy (8+ chars, upper/lower/number/symbol) would reject
    // "demo", so relax the instance PasswordComplexityPolicy. DomainPolicy.UserLoginMustBeDomain
    // is already false by default, so the login name is just "demo" (no @org-domain suffix).
    .WithEnvironment("ZITADEL_FIRSTINSTANCE_ORG_HUMAN_USERNAME", "demo")
    .WithEnvironment("ZITADEL_FIRSTINSTANCE_ORG_HUMAN_PASSWORD", "demo")
    .WithEnvironment("ZITADEL_FIRSTINSTANCE_ORG_HUMAN_PASSWORDCHANGEREQUIRED", "false")
    // The PasswordComplexityPolicy binds under the canonical DEFAULTINSTANCE prefix (per
    // defaults.yaml), NOT FIRSTINSTANCE — using FIRSTINSTANCE left MinLength at 0 and the
    // 03_default_instance migration failed with Errors.User.PasswordComplexityPolicy.MinLength.
    .WithEnvironment("ZITADEL_DEFAULTINSTANCE_PASSWORDCOMPLEXITYPOLICY_MINLENGTH", "1")
    .WithEnvironment("ZITADEL_DEFAULTINSTANCE_PASSWORDCOMPLEXITYPOLICY_HASLOWERCASE", "false")
    .WithEnvironment("ZITADEL_DEFAULTINSTANCE_PASSWORDCOMPLEXITYPOLICY_HASUPPERCASE", "false")
    .WithEnvironment("ZITADEL_DEFAULTINSTANCE_PASSWORDCOMPLEXITYPOLICY_HASNUMBER", "false")
    .WithEnvironment("ZITADEL_DEFAULTINSTANCE_PASSWORDCOMPLEXITYPOLICY_HASSYMBOL", "false")
    // Allow logging in with the bare username "demo" (no @org-domain suffix). Despite the
    // defaults.yaml showing false, the seeded instance behaves as UserLoginMustBeDomain=true,
    // so set it explicitly under the canonical DEFAULTINSTANCE prefix.
    .WithEnvironment("ZITADEL_DEFAULTINSTANCE_DOMAINPOLICY_USERLOGINMUSTBEDOMAIN", "false")
    .WithEnvironment("ZITADEL_FIRSTINSTANCE_ORG_MACHINE_MACHINE_USERNAME", "demo-provisioner")
    .WithEnvironment("ZITADEL_FIRSTINSTANCE_ORG_MACHINE_MACHINE_NAME", "Demo Provisioner")
    .WithEnvironment("ZITADEL_FIRSTINSTANCE_ORG_MACHINE_MACHINEKEY_TYPE", "1")
    .WithEnvironment("ZITADEL_FIRSTINSTANCE_MACHINEKEYPATH", "/machinekey/zitadel-admin-sa.json")
    .WithBindMount(sharedDir, "/machinekey")
    .WithHttpHealthCheck("/debug/healthz")
    .WaitFor(postgres)
    .WithUrls(useLoopbackUrls);

// One-shot init: creates the Zitadel project + OIDC app, writes client id/secret to a file.
var zitadelProvisioner = builder.AddProject<Projects.Demo_ZitadelProvisioner>("zitadel-provisioner")
    .WithEnvironment("ZITADEL_API", zitadelApiUrl)
    .WithEnvironment("ZITADEL_MACHINE_KEY_FILE", machineKeyFile)
    .WithEnvironment("DEMO_OIDC_CLIENT_FILE", zitadelClientFile)
    .WithEnvironment("DEMO_REDIRECT_URI", zitadelRedirectUri)
    .WithEnvironment("DEMO_POST_LOGOUT_URI", zitadelPostLogoutUri)
    .WithEnvironment("DEMO_PROJECT_NAME", "Porta Demo")
    .WithEnvironment("DEMO_APP_NAME", "Porta BFF (Zitadel)")
    .WaitFor(zitadel);

// ---------------------------------------------------------------------------
// Valkey — the shared distributed cache (Redis-protocol compatible).
//
// This is Porta's first HA prerequisite: the auth ticket store, server-side session store,
// session-metadata index, and refresh lock all live in IDistributedCache. Both BFFs point at
// this ONE container, so a session minted by one replica is visible to the other — exactly the
// no-sticky-sessions posture docs/ha-deployment.md describes. Without it each BFF would fall
// back to its own in-memory cache. Referenced by both BFFs below under the name "cache"; the
// BFF calls builder.AddRedisDistributedCache("cache") to register the client against it.
// (Valkey speaks the Redis wire protocol, so the StackExchange.Redis client integration works
// unchanged.) The demo's /health/ready page surfaces Porta's distributed-cache probe against it.
// ---------------------------------------------------------------------------
var cache = builder.AddValkey("cache")
    .WithUrls(useLoopbackUrls);

// ---------------------------------------------------------------------------
// Sample downstream API the BFFs forward to.
// ---------------------------------------------------------------------------
var backend = builder.AddProject<Projects.Demo_Api>("backend", launchProfileName: null)
    .WithHttpEndpoint(port: BackendPort, isProxied: false, name: "http")
    .WithExternalHttpEndpoints()
    // Credentials the backend expects on its Basic-auth-protected /internal endpoint.
    .WithEnvironment("Demo__BasicAuthUsername", BackendBasicUser)
    .WithEnvironment("Demo__BasicAuthPassword", BackendBasicPassword)
    .WithUrls(useLoopbackUrls);

// ---------------------------------------------------------------------------
// The b17s.Porta BFF, run twice from the SAME project against the two IdPs.
// ---------------------------------------------------------------------------
var bffKeycloak = builder.AddProject<Projects.Demo_Bff>("bff-keycloak", launchProfileName: null)
    .WithHttpEndpoint(port: BffKeycloakPort, isProxied: false, name: "http")
    .WithExternalHttpEndpoints()
    .WithEnvironment("ASPNETCORE_ENVIRONMENT", "Development")
    .WithEnvironment("Demo__ProviderLabel", "Keycloak")
    .WithEnvironment("Demo__BackendUrl", BackendUrl)
    .WithEnvironment("PortaCore__TrustedHosts__0", BackendUrl)
    // Service credentials the BFF presents to the backend (BackendAuthPolicies.BasicAuth).
    .WithEnvironment("BackendService__BasicAuth__Username", BackendBasicUser)
    .WithEnvironment("BackendService__BasicAuth__Password", BackendBasicPassword)
    .WithEnvironment("OidcAuth__Authority", keycloakAuthority)
    .WithEnvironment("OidcAuth__ClientId", "porta-bff")
    .WithEnvironment("OidcAuth__ClientSecret", "porta-bff-secret")
    .WithEnvironment("OidcAuth__Scope", "openid profile email")
    // Injects the "cache" connection string so AddRedisDistributedCache("cache") resolves it.
    .WithReference(cache)
    .WaitFor(cache)
    .WaitFor(keycloak)
    .WaitFor(backend)
    .WithUrls(useLoopbackUrls);

var bffZitadel = builder.AddProject<Projects.Demo_Bff>("bff-zitadel", launchProfileName: null)
    .WithHttpEndpoint(port: BffZitadelPort, isProxied: false, name: "http")
    .WithExternalHttpEndpoints()
    .WithEnvironment("ASPNETCORE_ENVIRONMENT", "Development")
    .WithEnvironment("Demo__ProviderLabel", "Zitadel")
    .WithEnvironment("Demo__BackendUrl", BackendUrl)
    .WithEnvironment("Demo__OidcClientFile", zitadelClientFile)
    .WithEnvironment("PortaCore__TrustedHosts__0", BackendUrl)
    // Service credentials the BFF presents to the backend (BackendAuthPolicies.BasicAuth).
    .WithEnvironment("BackendService__BasicAuth__Username", BackendBasicUser)
    .WithEnvironment("BackendService__BasicAuth__Password", BackendBasicPassword)
    .WithEnvironment("OidcAuth__Authority", zitadelAuthority)
    .WithEnvironment("OidcAuth__Scope", "openid profile email")
    // Injects the "cache" connection string so AddRedisDistributedCache("cache") resolves it.
    .WithReference(cache)
    .WaitFor(cache)
    // ClientId/ClientSecret arrive via the provisioner-written file referenced above.
    .WaitForCompletion(zitadelProvisioner)
    .WaitFor(backend)
    .WithUrls(useLoopbackUrls);

builder.Build().Run();
