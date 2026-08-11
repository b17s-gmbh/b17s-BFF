using System.Text.Json;

using b17s.Porta.Configuration;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace b17s.Porta.Tests.Auth;

public sealed class ChallengeDispatchHandlerTests
{
    [Fact]
    public async Task DefaultChallenge_ForFetch_ReturnsProblem401()
    {
        await using var provider = BuildProvider();
        var context = Context(provider, "GET");
        context.Request.PathBase = "/tenant";
        context.Request.Headers["Sec-Fetch-Mode"] = "cors";

        await context.ChallengeAsync();

        Assert.Equal(401, context.Response.StatusCode);
        Assert.Equal("application/problem+json", context.Response.ContentType);
        Assert.Equal("no-store", context.Response.Headers.CacheControl);
        context.Response.Body.Position = 0;
        using var problem = await JsonDocument.ParseAsync(
            context.Response.Body,
            cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal("urn:porta:session-expired", problem.RootElement.GetProperty("type").GetString());
        Assert.Equal("/tenant/bff/login", problem.RootElement.GetProperty("login").GetString());
    }

    [Fact]
    public async Task DefaultChallenge_ForNavigation_RedirectsToOidc()
    {
        await using var provider = BuildProvider();
        var context = Context(provider, "GET");
        context.Request.Headers["Sec-Fetch-Mode"] = "navigate";
        context.Request.Headers["Sec-Fetch-Dest"] = "document";

        await context.ChallengeAsync();

        Assert.Equal(302, context.Response.StatusCode);
        Assert.StartsWith("https://idp.example.com/authorize", context.Response.Headers.Location.ToString());
    }

    [Fact]
    public async Task ExplicitOidcChallenge_BypassesDispatcherForFetch()
    {
        await using var provider = BuildProvider();
        var context = Context(provider, "POST");
        context.Request.Headers["Sec-Fetch-Mode"] = "cors";

        await context.ChallengeAsync(OpenIdConnectDefaults.AuthenticationScheme);

        Assert.Equal(302, context.Response.StatusCode);
        Assert.StartsWith("https://idp.example.com/authorize", context.Response.Headers.Location.ToString());
    }

    [Fact]
    public async Task Head401_HasNoBody()
    {
        await using var provider = BuildProvider(ChallengeDispatchMode.Unauthorized);
        var context = Context(provider, "HEAD");

        await context.ChallengeAsync();

        Assert.Equal(401, context.Response.StatusCode);
        Assert.Equal(0, context.Response.Body.Length);
    }

    private static ServiceProvider BuildProvider(ChallengeDispatchMode mode = ChallengeDispatchMode.Auto)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddMetrics();
        services.AddPortaAuthentication(options =>
        {
            options.Authority = "https://idp.example.com";
            options.ClientId = "porta";
            options.ClientSecret = "secret";
            options.Challenge.Mode = mode;
        });
        services.PostConfigure<OpenIdConnectOptions>(OpenIdConnectDefaults.AuthenticationScheme, options =>
            options.ConfigurationManager = new StaticConfigurationManager<OpenIdConnectConfiguration>(new OpenIdConnectConfiguration
            {
                AuthorizationEndpoint = "https://idp.example.com/authorize",
            }));
        return services.BuildServiceProvider();
    }

    private static DefaultHttpContext Context(IServiceProvider provider, string method)
    {
        var context = new DefaultHttpContext
        {
            RequestServices = provider,
        };
        context.Request.Scheme = "https";
        context.Request.Host = new HostString("app.example.com");
        context.Request.Method = method;
        context.Response.Body = new MemoryStream();
        return context;
    }
}
