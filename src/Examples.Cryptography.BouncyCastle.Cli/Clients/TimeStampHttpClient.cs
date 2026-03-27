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
        var content = new ByteArrayContent(request.GetEncoded());
        content.Headers.ContentType = new MediaTypeHeaderValue(@"application/timestamp-query");

        var httpResponse = await _httpClient.PostAsync(requestUri, content, cancellationToken)
            .WaitAsync(timeout ?? _httpClient.Timeout, cancellationToken);

        if (!httpResponse.IsSuccessStatusCode)
        {
            throw new Exception($"{httpResponse.StatusCode}");
        }

        var bytes = await httpResponse.Content.ReadAsByteArrayAsync(cancellationToken);
        return new TimeStampResponse(bytes);
    }

}
