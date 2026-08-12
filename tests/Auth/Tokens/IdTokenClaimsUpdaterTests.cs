using System.Security.Claims;
using System.Text;
using System.Text.Json;

using b17s.Porta.Auth.Tokens;

namespace b17s.Porta.Tests.Auth.Tokens;

/// <summary>
/// Unit tests for <see cref="IdTokenClaimsUpdater"/>: the per-type claims update the token
/// refresh applies to the session principal from a new id_token. Claims are
/// authorization-relevant, so both directions are pinned: what must change (values of a
/// re-asserted type, including removals within the type) and what must never change (types the
/// new token omits, protocol claims, sessions the token does not belong to).
/// </summary>
public sealed class IdTokenClaimsUpdaterTests
{
    private const string Issuer = "https://idp.test";

    [Fact]
    public void ReassertedType_ValuesReplaced_IncludingRemovals()
    {
        // Old session: roles [admin, user]. New id_token: roles [user]. The revoked "admin"
        // must disappear - this is the point of the feature.
        var principal = Principal(("sub", "user-1"), ("role", "admin"), ("role", "user"));
        var newToken = IdToken(("sub", "user-1"), ("role", "user"));

        var updated = IdTokenClaimsUpdater.TryBuildUpdatedPrincipal(principal, IdToken(("sub", "user-1")), newToken);

        Assert.NotNull(updated);
        var roles = updated!.FindAll("role").Select(c => c.Value).ToArray();
        Assert.Equal(["user"], roles);
    }

    [Fact]
    public void AbsentType_IsKept()
    {
        // IdPs commonly issue leaner id_tokens on refresh than at login; absence must not be
        // treated as revocation.
        var principal = Principal(("sub", "user-1"), ("email", "u@test.example"), ("role", "admin"));
        var newToken = IdToken(("sub", "user-1"), ("role", "admin"));

        var updated = IdTokenClaimsUpdater.TryBuildUpdatedPrincipal(principal, IdToken(("sub", "user-1")), newToken);

        Assert.Equal("u@test.example", updated!.FindFirst("email")!.Value);
    }

    [Fact]
    public void NewType_IsAdded()
    {
        var principal = Principal(("sub", "user-1"));
        var newToken = IdToken(("sub", "user-1"), ("department", "sales"));

        var updated = IdTokenClaimsUpdater.TryBuildUpdatedPrincipal(principal, IdToken(("sub", "user-1")), newToken);

        Assert.Equal("sales", updated!.FindFirst("department")!.Value);
    }

    [Fact]
    public void ProtocolClaims_AreNeverCopied()
    {
        var principal = Principal(("sub", "user-1"));
        var newToken = IdToken(
            ("sub", "user-1"), ("nonce", "n-1"), ("at_hash", "h"), ("auth_time", "123"),
            ("amr", "pwd"), ("azp", "client"), ("sid", "sess-1"));

        var updated = IdTokenClaimsUpdater.TryBuildUpdatedPrincipal(principal, IdToken(("sub", "user-1")), newToken);

        Assert.NotNull(updated);
        foreach (var type in new[] { "nonce", "at_hash", "auth_time", "amr", "azp", "sid", "iss", "aud", "exp" })
        {
            Assert.Null(updated!.FindFirst(type));
        }
    }

    [Fact]
    public void MappedPrincipal_RawTokenType_UpdatesMappedType()
    {
        // Principals built by the OIDC handler's default claim mapping carry ClaimTypes.Role, not
        // "role". The raw id_token type must update the mapped type, not add a parallel claim.
        var principal = Principal(("sub", "user-1"), (ClaimTypes.Role, "admin"), (ClaimTypes.Role, "user"));
        var newToken = IdToken(("sub", "user-1"), ("role", "user"));

        var updated = IdTokenClaimsUpdater.TryBuildUpdatedPrincipal(principal, IdToken(("sub", "user-1")), newToken);

        Assert.Equal(["user"], updated!.FindAll(ClaimTypes.Role).Select(c => c.Value).ToArray());
        Assert.Null(updated.FindFirst("role"));
    }

    [Fact]
    public void SubMismatch_AbortsUpdate()
    {
        // OIDC Core 12.2: a refresh id_token for a different subject must never rewrite this
        // session's claims (session-swap protection).
        var principal = Principal(("sub", "user-1"), ("role", "user"));
        var newToken = IdToken(("sub", "user-2"), ("role", "admin"));

        var updated = IdTokenClaimsUpdater.TryBuildUpdatedPrincipal(principal, IdToken(("sub", "user-1")), newToken);

        Assert.Null(updated);
    }

    [Fact]
    public void IssuerMismatch_AbortsUpdate()
    {
        var principal = Principal(("sub", "user-1"));
        var previous = IdToken(("sub", "user-1"));
        var newToken = IdToken("https://evil.test", ("sub", "user-1"));

        var updated = IdTokenClaimsUpdater.TryBuildUpdatedPrincipal(principal, previous, newToken);

        Assert.Null(updated);
    }

    [Fact]
    public void NoPreviousIdToken_FallsBackToPrincipalSubject()
    {
        var principal = Principal(("sub", "user-1"), ("role", "old"));
        var newToken = IdToken(("sub", "user-1"), ("role", "new"));

        var updated = IdTokenClaimsUpdater.TryBuildUpdatedPrincipal(principal, previousIdToken: null, newToken);

        Assert.Equal("new", updated!.FindFirst("role")!.Value);
    }

    [Fact]
    public void NoPreviousIdToken_MappedSubjectOnPrincipal_StillValidates()
    {
        // Default claim mapping stores the subject as ClaimTypes.NameIdentifier - the fallback
        // must find it there too.
        var principal = Principal(("sub", null), (ClaimTypes.NameIdentifier, "user-1"), ("role", "old"));
        var newToken = IdToken(("sub", "user-1"), ("role", "new"));

        var updated = IdTokenClaimsUpdater.TryBuildUpdatedPrincipal(principal, previousIdToken: null, newToken);

        Assert.Equal("new", updated!.FindFirst("role")!.Value);
    }

    [Fact]
    public void NoUsableSubjectReference_AbortsUpdate_FailClosed()
    {
        var principal = Principal(("role", "old")); // no sub, no NameIdentifier
        var newToken = IdToken(("sub", "user-1"), ("role", "new"));

        var updated = IdTokenClaimsUpdater.TryBuildUpdatedPrincipal(principal, previousIdToken: null, newToken);

        Assert.Null(updated);
    }

    [Fact]
    public void UnparsableNewToken_AbortsUpdate()
    {
        var principal = Principal(("sub", "user-1"));

        var updated = IdTokenClaimsUpdater.TryBuildUpdatedPrincipal(principal, previousIdToken: null, "not-a-jwt");

        Assert.Null(updated);
    }

    [Fact]
    public void IdentityMetadata_IsPreserved()
    {
        // IsAuthenticated / IsInRole must not change semantics: authentication type and the
        // name/role claim type configuration survive the rebuild.
        var identity = new ClaimsIdentity(
            [new Claim("sub", "user-1"), new Claim("custom-role", "admin")],
            authenticationType: "Cookies",
            nameType: "name",
            roleType: "custom-role");
        var principal = new ClaimsPrincipal(identity);
        var newToken = IdToken(("sub", "user-1"), ("custom-role", "user"));

        var updated = IdTokenClaimsUpdater.TryBuildUpdatedPrincipal(principal, previousIdToken: null, newToken);

        Assert.NotNull(updated);
        Assert.True(updated!.Identity!.IsAuthenticated);
        Assert.Equal("Cookies", updated.Identity.AuthenticationType);
        Assert.True(updated.IsInRole("user"));
        Assert.False(updated.IsInRole("admin"));
    }

    // -- helpers -------------------------------------------------------------------------------

    private static ClaimsPrincipal Principal(params (string Type, string? Value)[] claims)
    {
        var identity = new ClaimsIdentity(
            claims.Where(c => c.Value is not null).Select(c => new Claim(c.Type, c.Value!)),
            authenticationType: "Cookies");
        return new ClaimsPrincipal(identity);
    }

    /// <summary>
    /// Builds an unsigned ("alg":"none") id_token - IdTokenClaimsUpdater parses without signature
    /// validation (the real token arrives over the client-authenticated TLS token-endpoint channel).
    /// Repeated claim types are folded into a JSON array, as IdPs emit multi-value claims.
    /// </summary>
    private static string IdToken(params (string Type, string Value)[] claims) => IdToken(Issuer, claims);

    private static string IdToken(string issuer, params (string Type, string Value)[] claims)
    {
        var payload = new Dictionary<string, object> { ["iss"] = issuer };
        foreach (var group in claims.GroupBy(c => c.Type))
        {
            var values = group.Select(c => c.Value).ToArray();
            payload[group.Key] = values.Length == 1 ? values[0] : values;
        }

        static string Base64Url(string json) =>
            Convert.ToBase64String(Encoding.UTF8.GetBytes(json)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        var header = Base64Url("""{"alg":"none","typ":"JWT"}""");
        var body = Base64Url(JsonSerializer.Serialize(payload));
        return $"{header}.{body}.";
    }
}
