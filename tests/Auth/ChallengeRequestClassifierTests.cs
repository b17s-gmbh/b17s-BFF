using b17s.Porta.Auth;

using Microsoft.AspNetCore.Http;

namespace b17s.Porta.Tests.Auth;

public sealed class ChallengeRequestClassifierTests
{
    [Theory]
    [InlineData("GET")]
    [InlineData("HEAD")]
    public void SafeDocumentNavigation_IsInteractive(string method)
    {
        var request = Request(method);
        request.Headers["Sec-Fetch-Mode"] = "navigate";
        request.Headers["Sec-Fetch-Dest"] = "document";

        Assert.True(ChallengeRequestClassifier.IsInteractive(request));
    }

    [Fact]
    public void NavigationPost_IsNotInteractive()
    {
        var request = Request("POST");
        request.Headers["Sec-Fetch-Mode"] = "navigate";
        request.Headers["Sec-Fetch-Dest"] = "document";

        Assert.False(ChallengeRequestClassifier.IsInteractive(request));
    }

    [Theory]
    [InlineData("cors", "empty")]
    [InlineData("same-origin", "empty")]
    [InlineData("no-cors", "image")]
    [InlineData("navigate", "iframe")]
    public void FetchAndEmbeddedRequests_AreNotInteractive(string mode, string destination)
    {
        var request = Request("GET");
        request.Headers["Sec-Fetch-Mode"] = mode;
        request.Headers["Sec-Fetch-Dest"] = destination;

        Assert.False(ChallengeRequestClassifier.IsInteractive(request));
    }

    [Theory]
    [InlineData("text/html", true)]
    [InlineData("text/html;q=0", false)]
    [InlineData("text/*;q=.5", true)]
    [InlineData("*/*", false)]
    [InlineData("application/json, text/html;q=.8", true)]
    public void LegacyRequest_UsesParsedAcceptHeader(string accept, bool expected)
    {
        var request = Request("GET");
        request.Headers.Accept = accept;

        Assert.Equal(expected, ChallengeRequestClassifier.IsInteractive(request));
    }

    [Fact]
    public void AnyFetchMetadata_DisablesLegacyFallback()
    {
        var request = Request("GET");
        request.Headers.Accept = "text/html";
        request.Headers["Sec-Fetch-Site"] = "same-origin";

        Assert.False(ChallengeRequestClassifier.IsInteractive(request));
    }

    private static HttpRequest Request(string method)
    {
        var context = new DefaultHttpContext();
        context.Request.Method = method;
        return context.Request;
    }
}
