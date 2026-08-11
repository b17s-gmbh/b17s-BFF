using b17s.Porta.Auth.Sessions;
using b17s.Porta.Auth;
using b17s.Porta.Auth.Tokens;
using b17s.Porta.Extensions;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.Metrics;

namespace b17s.Porta.Tests.Extensions;

public class AddPortaAuthenticationTests
{
    [Fact]
    public async Task AddPortaAuthentication_RegistersCookieAndOidcSchemes()
    {
        var services = BuildServices();
        var sp = services.BuildServiceProvider();

        var schemeProvider = sp.GetRequiredService<IAuthenticationSchemeProvider>();
        var cookie = await schemeProvider.GetSchemeAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        var oidc = await schemeProvider.GetSchemeAsync(OpenIdConnectDefaults.AuthenticationScheme);
        var dispatcher = await schemeProvider.GetSchemeAsync(ChallengeDispatchHandler.SchemeName);
        var defaults = sp.GetRequiredService<Microsoft.Extensions.Options.IOptions<AuthenticationOptions>>().Value;

        Assert.NotNull(cookie);
        Assert.NotNull(oidc);
        Assert.NotNull(dispatcher);
        Assert.Equal(ChallengeDispatchHandler.SchemeName, defaults.DefaultChallengeScheme);
        Assert.Equal(ChallengeDispatchHandler.SchemeName, defaults.DefaultForbidScheme);
        Assert.Equal(CookieAuthenticationDefaults.AuthenticationScheme, defaults.DefaultAuthenticateScheme ?? defaults.DefaultScheme);
    }

    [Fact]
    public void AddPortaAuthentication_RegistersTicketStore_AndCookieOptionsUseIt()
    {
        var services = BuildServices();
        var sp = services.BuildServiceProvider();

        var ticketStore = sp.GetRequiredService<ITicketStore>();
        Assert.IsType<DistributedCacheTicketStore>(ticketStore);

        var cookieOptions = sp.GetRequiredService<Microsoft.Extensions.Options.IOptionsMonitor<CookieAuthenticationOptions>>()
            .Get(CookieAuthenticationDefaults.AuthenticationScheme);
        Assert.NotNull(cookieOptions.SessionStore);
        Assert.Same(ticketStore, cookieOptions.SessionStore);
    }

    [Fact]
    public void AddPortaAuthentication_RegistersBffServices()
    {
        var services = BuildServices();
        var sp = services.BuildServiceProvider();

        Assert.NotNull(sp.GetRequiredService<ISessionManagementService>());
        Assert.NotNull(sp.GetRequiredService<IAccessTokenRefreshService>());
        Assert.NotNull(sp.GetRequiredService<IDataProtectionProvider>());
    }

    [Fact]
    public void AddPortaAuthentication_OidcOptionsBoundFromConfig()
    {
        var services = BuildServices();
        var sp = services.BuildServiceProvider();

        var oidcOptions = sp.GetRequiredService<Microsoft.Extensions.Options.IOptionsMonitor<OpenIdConnectOptions>>()
            .Get(OpenIdConnectDefaults.AuthenticationScheme);

        Assert.Equal("https://idp.example.com", oidcOptions.Authority);
        Assert.Equal("test-client", oidcOptions.ClientId);
        Assert.True(oidcOptions.UsePkce);
        Assert.True(oidcOptions.SaveTokens);
        Assert.Contains("openid", oidcOptions.Scope);
        Assert.Contains("email", oidcOptions.Scope);
    }

    private static IServiceCollection BuildServices()
    {
        var dict = new Dictionary<string, string?>
        {
            ["SessionAuthentication:Authority"] = "https://idp.example.com",
            ["SessionAuthentication:ClientId"] = "test-client",
            ["SessionAuthentication:ClientSecret"] = "test-secret",
            ["SessionAuthentication:Scope"] = "openid profile email",
            ["SessionAuthentication:CookieName"] = "TestCookie",
            ["SessionAuthentication:UsePkce"] = "true",
            ["SessionAuthentication:SessionTimeoutInMin"] = "60",
            ["SessionAuthentication:DataProtection:ApplicationName"] = "TestApp",
            ["SessionAuthentication:DataProtection:KeyLifetimeDays"] = "30",
        };
        var config = new ConfigurationBuilder().AddInMemoryCollection(dict).Build();

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddMetrics();
        services.AddPortaAuthentication(config);
        return services;
    }
}
