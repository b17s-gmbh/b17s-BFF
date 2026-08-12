using System.Security.Claims;

using Microsoft.IdentityModel.JsonWebTokens;

namespace b17s.Porta.Auth.Tokens;

/// <summary>
/// Rebuilds the session (cookie) principal's claims from the NEW <c>id_token</c> an IdP returned
/// with a refresh response, so claim changes (roles granted/revoked, renamed users, ...) propagate
/// to the BFF without a re-login. Used by <see cref="AccessTokenRefreshService"/> when
/// <c>PortaCoreOptions.RefreshClaimsFromIdToken</c> is enabled.
/// </summary>
/// <remarks>
/// Update semantics (see the option's XML docs for the rationale):
/// <list type="bullet">
/// <item><description>Per claim TYPE present in the new id_token: replace the session's claims of
/// that type with the new values. Types absent from the new id_token stay untouched.</description></item>
/// <item><description>OIDC protocol / login-time claims are never copied.</description></item>
/// <item><description>The new token's <c>iss</c>/<c>sub</c> must match the previous id_token
/// (OIDC Core §12.2) - falling back to the principal's subject when no previous id_token is on
/// the ticket. Any mismatch or parse failure aborts the update (returns null).</description></item>
/// <item><description>Principals built with the OIDC handler's default inbound claim mapping are
/// handled: a raw id_token type (e.g. <c>role</c>) updates the mapped type
/// (<c>ClaimTypes.Role</c>) when that is what the session carries.</description></item>
/// </list>
/// </remarks>
internal static class IdTokenClaimsUpdater
{
    private static readonly JsonWebTokenHandler JwtHandler = new();

    // Claims that describe the token or the original authentication event, not the user - never
    // copied onto the session principal. `sub` is validated (must match) rather than copied.
    private static readonly HashSet<string> ExcludedClaimTypes = new(StringComparer.Ordinal)
    {
        "iss", "sub", "aud", "exp", "iat", "nbf", "jti", "typ",
        "nonce", "at_hash", "c_hash", "s_hash", "azp",
        "auth_time", "amr", "acr", "sid",
    };

    // Minimal inbound map covering the OIDC standard claims the default ASP.NET claim mapping
    // renames. Used only to FIND the session's existing claim type for a raw id_token type; a
    // type the session does not carry (under either name) is added under its raw name.
    private static readonly Dictionary<string, string> InboundClaimTypeMap = new(StringComparer.Ordinal)
    {
        ["name"] = ClaimTypes.Name,
        ["unique_name"] = ClaimTypes.Name,
        ["given_name"] = ClaimTypes.GivenName,
        ["family_name"] = ClaimTypes.Surname,
        ["email"] = ClaimTypes.Email,
        ["role"] = ClaimTypes.Role,
        ["roles"] = ClaimTypes.Role,
        ["birthdate"] = ClaimTypes.DateOfBirth,
        ["gender"] = ClaimTypes.Gender,
    };

    /// <summary>
    /// Builds a copy of <paramref name="current"/> with its primary identity's claims updated from
    /// <paramref name="newIdToken"/>, or returns <c>null</c> when the update must be skipped: the
    /// new token cannot be parsed, its <c>iss</c>/<c>sub</c> do not match the session, or the
    /// principal carries no <see cref="ClaimsIdentity"/>. The input principal is never mutated -
    /// on <c>null</c> the caller signs the existing principal back in unchanged.
    /// </summary>
    public static ClaimsPrincipal? TryBuildUpdatedPrincipal(
        ClaimsPrincipal current,
        string? previousIdToken,
        string newIdToken)
    {
        if (!TryRead(newIdToken, out var fresh) || current.Identity is not ClaimsIdentity primary)
        {
            return null;
        }

        if (!SubjectAndIssuerMatch(current, previousIdToken, fresh))
        {
            return null;
        }

        // Clone preserves AuthenticationType / NameClaimType / RoleClaimType / actor / label,
        // so authorization behavior (IsAuthenticated, IsInRole) is unchanged by the update.
        var updated = primary.Clone();

        foreach (var group in fresh.Claims
                     .Where(c => !ExcludedClaimTypes.Contains(c.Type))
                     .GroupBy(c => c.Type, StringComparer.Ordinal))
        {
            var targetType = ResolveTargetType(updated, group.Key);

            foreach (var stale in updated.FindAll(targetType).ToArray())
            {
                updated.RemoveClaim(stale);
            }

            foreach (var claim in group)
            {
                updated.AddClaim(new Claim(targetType, claim.Value, claim.ValueType, claim.Issuer));
            }
        }

        // Preserve any additional identities untouched; only the primary is rebuilt.
        return new ClaimsPrincipal(
            current.Identities.Select(identity => ReferenceEquals(identity, primary) ? updated : identity));
    }

    // OIDC Core §12.2: an id_token issued on refresh must carry the same iss and sub as the one
    // issued at authentication time. Compare against the previous id_token when the ticket has
    // one (exact, mapping-independent); otherwise fall back to the principal's subject claim.
    // No usable reference at all fails closed - claims are authorization-relevant.
    private static bool SubjectAndIssuerMatch(ClaimsPrincipal current, string? previousIdToken, JsonWebToken fresh)
    {
        var freshSub = fresh.Subject;
        if (string.IsNullOrEmpty(freshSub))
        {
            return false;
        }

        if (!string.IsNullOrEmpty(previousIdToken) && TryRead(previousIdToken, out var previous))
        {
            return string.Equals(previous.Subject, freshSub, StringComparison.Ordinal)
                && string.Equals(previous.Issuer, fresh.Issuer, StringComparison.Ordinal);
        }

        var currentSub = current.FindFirst("sub")?.Value
            ?? current.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        return !string.IsNullOrEmpty(currentSub)
            && string.Equals(currentSub, freshSub, StringComparison.Ordinal);
    }

    // The raw id_token type updates whatever name the session actually carries: raw name first,
    // then the default-mapping name; a type the session lacks entirely is added under its raw name
    // (matching a mapping-disabled setup, where raw names are what policies check).
    private static string ResolveTargetType(ClaimsIdentity identity, string rawType)
    {
        if (identity.FindFirst(rawType) is not null)
        {
            return rawType;
        }

        if (InboundClaimTypeMap.TryGetValue(rawType, out var mapped) && identity.FindFirst(mapped) is not null)
        {
            return mapped;
        }

        return rawType;
    }

    private static bool TryRead(string token, out JsonWebToken jwt)
    {
        jwt = null!;
        if (string.IsNullOrEmpty(token) || !JwtHandler.CanReadToken(token))
        {
            return false;
        }

        try
        {
            jwt = JwtHandler.ReadJsonWebToken(token);
            return true;
        }
        catch (ArgumentException)
        {
            // Structurally readable but not a well-formed JWT - treat as unusable.
            return false;
        }
    }
}
