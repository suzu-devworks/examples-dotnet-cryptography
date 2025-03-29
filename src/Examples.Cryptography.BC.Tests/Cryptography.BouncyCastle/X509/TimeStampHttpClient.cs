using System.Net.Http.Headers;
using Org.BouncyCastle.Tsp;

namespace Examples.Cryptography.BouncyCastle.X509;

/// <summary>
/// The <see cref="HttpClient" /> for Time stamp request.
/// </summary>
public class TimeStampHttpClient
{
    // https://learn.microsoft.com/ja-jp/dotnet/fundamentals/networking/http/httpclient-guidelines
    private readonly IHttpClientFactory _httpClientFactory;

    /// <summary>
    /// Initializes a new instance of the <see cref="TimeStampHttpClient" /> class.
    /// </summary>
    /// <param name="httpClientFactory">A class instance that implements <see cref="IHttpClientFactory" />.</param>
    public TimeStampHttpClient(IHttpClientFactory httpClientFactory)
    {
        _httpClientFactory = httpClientFactory;
    }

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
        content.Headers.Add("Content-Transfer-Encoding", "base64");

        TimeStampResponse response;
        using (var client = _httpClientFactory.CreateClient(nameof(TimeStampHttpClient)))
        {
            var httpResponse = await client.PostAsync(requestUri, content, cancellationToken)
                .WaitAsync(timeout ?? client.Timeout, cancellationToken);

            if (!httpResponse.IsSuccessStatusCode)
            {
                throw new Exception($"{httpResponse.StatusCode}");
            }

            var bytes = await httpResponse.Content.ReadAsByteArrayAsync(cancellationToken);
            response = new TimeStampResponse(bytes);
        }

        return response;
    }

}
