using Microsoft.Extensions.Options;

namespace b17s.Porta.Configuration;

/// <summary>
/// Validates <see cref="SessionAuthenticationConfiguration"/> (and its
/// <see cref="OidcAuthOptions"/> subclass) at startup so a misconfigured BFF
/// fails on boot instead of on the first OIDC redirect, where the error
/// surface is just an opaque IdP-side complaint.
///
/// Wired in <see cref="b17s.Porta.Extensions.AuthenticationServiceExtensions"/>
/// via <c>AddSingleton&lt;IValidateOptions&lt;SessionAuthenticationConfiguration&gt;&gt;</c>;
/// the options pipeline runs all registered validators the first time
/// <c>IOptions&lt;T&gt;.Value</c> is resolved, throwing
/// <see cref="OptionsValidationException"/> with the accumulated errors.
/// </summary>
internal sealed class SessionAuthenticationConfigurationValidator
    : IValidateOptions<SessionAuthenticationConfiguration>
{
    public ValidateOptionsResult Validate(string? name, SessionAuthenticationConfiguration options)
    {
        var errors = new List<string>();

        // Authority is treated opaquely: the configured value is what we send to the IdP and
        // compare byte-for-byte against the iss claim (RFC 7519). We do not normalise the
        // trailing slash because IdPs are strict about which form they emit, and silently
        // trimming or appending would shift drift from config-time to token-validation-time.
        // Validate only that the value is parseable as an absolute http(s) URL.
        if (string.IsNullOrWhiteSpace(options.Authority))
        {
            errors.Add("SessionAuthentication.Authority is required.");
        }
        else if (!Uri.TryCreate(options.Authority, UriKind.Absolute, out var authorityUri)
            || (authorityUri.Scheme != Uri.UriSchemeHttp && authorityUri.Scheme != Uri.UriSchemeHttps))
        {
            errors.Add(
                $"SessionAuthentication.Authority must be an absolute http(s) URL. " +
                $"Got: '{options.Authority}'.");
        }

        if (string.IsNullOrWhiteSpace(options.ClientId))
        {
            errors.Add("SessionAuthentication.ClientId is required.");
        }

        // ClientSecret is mandatory for the confidential-client / authorization-code
        // flow that the BFF runs by default. A public client would not be running
        // server-side with a session store, so an empty secret here is always a
        // misconfiguration rather than an intentional public-client choice.
        if (string.IsNullOrWhiteSpace(options.ClientSecret))
        {
            errors.Add("SessionAuthentication.ClientSecret is required for confidential-client flows.");
        }

        if (options.SessionTimeoutInMin <= 0)
        {
            errors.Add(
                $"SessionAuthentication.SessionTimeoutInMin must be > 0. " +
                $"Got: {options.SessionTimeoutInMin}.");
        }

        if (options.Cookie is null)
        {
            errors.Add("SessionAuthentication.Cookie must be set.");
        }

        else
        {
            if (!IsValidSecurePolicy(options.Cookie.SecurePolicy))
            {
                errors.Add(
                    $"SessionAuthentication.Cookie.SecurePolicy '{options.Cookie.SecurePolicy}' " +
                    "is not a valid value. Expected one of: Always, SameAsRequest, None.");
            }
            if (!IsValidSameSite(options.Cookie.SameSite))
            {
                errors.Add(
                    $"SessionAuthentication.Cookie.SameSite '{options.Cookie.SameSite}' " +
                    "is not a valid value. Expected one of: Strict, Lax, None.");
            }
            // SameSite=None requires Secure=Always: browsers silently drop SameSite=None
            // cookies that are not Secure, and any HTTP downgrade would expose the cookie.
            // Validate only when both individual fields are well-formed so consumers don't
            // see both "invalid value" and "incompatible combination" errors at once.
            if (IsValidSameSite(options.Cookie.SameSite)
                && IsValidSecurePolicy(options.Cookie.SecurePolicy)
                && string.Equals(options.Cookie.SameSite, "None", StringComparison.Ordinal)
                && !string.Equals(options.Cookie.SecurePolicy, "Always", StringComparison.Ordinal))
            {
                errors.Add(
                    "SessionAuthentication.Cookie.SameSite='None' requires " +
                    "SessionAuthentication.Cookie.SecurePolicy='Always'. " +
                    $"Got SecurePolicy='{options.Cookie.SecurePolicy}'. Browsers drop " +
                    "SameSite=None cookies that are not marked Secure, and HTTP downgrade " +
                    "would expose the cookie. Either set SecurePolicy=Always or switch " +
                    "SameSite to Lax/Strict.");
            }
            if (options.Cookie.ExpireTimeSpanMinutes <= 0)
            {
                errors.Add(
                    $"SessionAuthentication.Cookie.ExpireTimeSpanMinutes must be > 0. " +
                    $"Got: {options.Cookie.ExpireTimeSpanMinutes}.");
            }
        }

        if (options.Challenge is null)
        {
            errors.Add("SessionAuthentication.Challenge must be set.");
        }
        else
        {
            if (!Enum.IsDefined(options.Challenge.Mode))
            {
                errors.Add($"SessionAuthentication.Challenge.Mode '{options.Challenge.Mode}' is not valid.");
            }

            if (options.Challenge.LoginPath is { } loginPath
                && (!loginPath.StartsWith('/') || loginPath.StartsWith("//", StringComparison.Ordinal)))
            {
                errors.Add("SessionAuthentication.Challenge.LoginPath must be a local absolute path beginning with one '/'.");
            }
        }

        // KeyManagementOptions.NewKeyLifetime rejects lifetimes under one week, but only
        // when the value is applied - deep inside Data Protection key management on the
        // first protect/unprotect. Surface it here instead, where the message can point
        // at the actual config knob.
        if (options.DataProtection is null)
        {
            errors.Add("SessionAuthentication.DataProtection must be set.");
        }
        else if (options.DataProtection.KeyLifetimeDays < 7)
        {
            errors.Add(
                $"SessionAuthentication.DataProtection.KeyLifetimeDays must be >= 7. " +
                $"Got: {options.DataProtection.KeyLifetimeDays}. ASP.NET Core Data Protection " +
                "requires a new-key lifetime of at least one week.");
        }

        if (options.Resilience is not null)
        {
            if (options.Resilience.RequestTimeoutSeconds <= 0)
            {
                errors.Add(
                    $"SessionAuthentication.Resilience.RequestTimeoutSeconds must be > 0. " +
                    $"Got: {options.Resilience.RequestTimeoutSeconds}.");
            }
            // Polly rejects MaxRetryAttempts < 1 when the token pipeline is first
            // built, which would surface as an OptionsValidationException on the
            // first token call instead of at startup. Only validated when retries
            // are enabled - with EnableRetry=false the value is never applied.
            if (options.Resilience.EnableRetry && options.Resilience.MaxRetryAttempts < 1)
            {
                errors.Add(
                    $"SessionAuthentication.Resilience.MaxRetryAttempts must be >= 1 when " +
                    $"EnableRetry is true. Got: {options.Resilience.MaxRetryAttempts}. " +
                    "Set EnableRetry=false to disable retries.");
            }
        }

        return errors.Count == 0
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(errors);
    }

    private static bool IsValidSecurePolicy(string value) =>
        value is "Always" or "SameAsRequest" or "None";

    private static bool IsValidSameSite(string value) =>
        value is "Strict" or "Lax" or "None";
}

/// <summary>
/// Mirror of <see cref="SessionAuthenticationConfigurationValidator"/> for the
/// <see cref="OidcAuthOptions"/> subclass. Required because the options
/// pipeline validates the exact bound type - a validator registered against
/// the base does not run when consumers configure
/// <c>IOptions&lt;OidcAuthOptions&gt;</c> directly.
/// </summary>
internal sealed class OidcAuthOptionsValidator : IValidateOptions<OidcAuthOptions>
{
    private readonly SessionAuthenticationConfigurationValidator _inner = new();

    public ValidateOptionsResult Validate(string? name, OidcAuthOptions options)
        => _inner.Validate(name, options);
}
