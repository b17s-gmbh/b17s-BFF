using b17s.Porta.Configuration;
using b17s.Porta.Extensions;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace b17s.Porta.Tests.Extensions;

public class AddPortaOidcAuthOptionsCopyTests
{
    // S5: AddPortaOidcAuth projects the caller's options into both IOptions<OidcAuthOptions>
    // and IOptions<SessionAuthenticationConfiguration>. The mutable sub-objects must be
    // deep-copied so the two registrations don't alias the same instance — otherwise a
    // PostConfigure mutation on one would silently affect the other.

    [Fact]
    public void AddPortaOidcAuth_DeepCopiesSubObjects_AcrossBothOptionsTypes()
    {
        var services = new ServiceCollection();
        services.AddOptions();
        services.AddPortaOidcAuth(o =>
        {
            o.Authority = "https://idp.example.com";
            o.ClientId = "porta";
            o.ClientSecret = "secret";
        });

        var sp = services.BuildServiceProvider();
        var oidc = sp.GetRequiredService<IOptions<OidcAuthOptions>>().Value;
        var session = sp.GetRequiredService<IOptions<SessionAuthenticationConfiguration>>().Value;

        Assert.NotSame(oidc.Cookie, session.Cookie);
        Assert.NotSame(oidc.Challenge, session.Challenge);
        Assert.NotSame(oidc.Resilience, session.Resilience);
        Assert.NotSame(oidc.DataProtection, session.DataProtection);
        Assert.NotSame(oidc.SessionKeys, session.SessionKeys);
    }

    [Fact]
    public void AddPortaOidcAuth_PostConfigureOnOneType_DoesNotAffectTheOther()
    {
        var services = new ServiceCollection();
        services.AddOptions();
        services.AddPortaOidcAuth(o =>
        {
            o.Authority = "https://idp.example.com";
            o.ClientId = "porta";
            o.ClientSecret = "secret";
        });

        // A PostConfigure mutation on the session sub-object must not leak into the
        // OidcAuthOptions registration (and vice versa).
        services.PostConfigure<SessionAuthenticationConfiguration>(o => o.Cookie.SecurePolicy = "None");

        var sp = services.BuildServiceProvider();
        var oidc = sp.GetRequiredService<IOptions<OidcAuthOptions>>().Value;
        var session = sp.GetRequiredService<IOptions<SessionAuthenticationConfiguration>>().Value;

        Assert.Equal("None", session.Cookie.SecurePolicy);
        Assert.Equal("Always", oidc.Cookie.SecurePolicy);
    }
}
