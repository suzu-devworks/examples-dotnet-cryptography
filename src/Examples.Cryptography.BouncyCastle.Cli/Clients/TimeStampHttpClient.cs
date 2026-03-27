using System.Net.Http.Headers;
using Org.BouncyCastle.Tsp;

namespace Examples.Cryptography.BouncyCastle.Cli.Clients;

/// <summary>
/// The <see cref="HttpClient" /> for Time stamp request.
/// </summary>
/// <remarks>
/// Initializes a new instance of the <see cref="TimeStampHttpClient" /> class.
/// </remarks>
/// <param name="httpClient">A <see cref="HttpClient" /> instance managed by <see cref="IHttpClientFactory" />.</param>
public class TimeStampHttpClient(HttpClient httpClient)
{
    // https://learn.microsoft.com/en-us/dotnet/core/extensions/httpclient-factory#typed-clients
    private readonly HttpClient _httpClient = httpClient;

    /// <summary>
    /// Requests a timestamp token to The Time Stamping Authority.
    /// </summary>
    /// <param name="requestUri">The Uri the request is sent to.</param>
    /// <param name="request">The <see cref="TimeStampRequest" /> instance.</param>
    /// <param name="timeout">A http request timeout.
    ///   If null is specified, the default value of <see cref="HttpClient" /> will be set.</param>
    /// <param name="cancellationToken">The token to monitor for cancellation requests.
    ///   The default value is None.</param>
    /// <returns>The task object representing the asynchronous operation.
    ///   The value of the type parameter of the value task contains A <see cref="TimeStampResponse" /> instance.</returns>
    public async Task<TimeStampResponse> RequestAsync(
          Uri requestUri,
          TimeStampRequest request,
          TimeSpan? timeout = default,
          CancellationToken cancellationToken = default)
    {
        var base64Encoded = Convert.ToBase64String(request.GetEncoded());
        var content = new StringContent(base64Encoded);
        content.Headers.ContentType = new MediaTypeHeaderValue(@"application/timestamp-query");
        content.Headers.Add("Content-Transfer-Encoding", "base64");

        using var httpResponse = await _httpClient.PostAsync(requestUri, content, cancellationToken)
            .WaitAsync(timeout ?? _httpClient.Timeout, cancellationToken);

        if (!httpResponse.IsSuccessStatusCode)
        {
            var responseContent = await httpResponse.Content.ReadAsStringAsync(cancellationToken);
            throw new HttpRequestException(
                $"Request to '{requestUri}' failed with status code {(int)httpResponse.StatusCode} ({httpResponse.StatusCode}). Response content: {responseContent}",
                inner: null,
                statusCode: httpResponse.StatusCode);
        }

        var bytes = await httpResponse.Content.ReadAsByteArrayAsync(cancellationToken);
        return new TimeStampResponse(bytes);
    }

}
