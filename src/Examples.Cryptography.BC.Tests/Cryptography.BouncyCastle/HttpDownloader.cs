using Org.BouncyCastle.OpenSsl;

namespace Examples.Cryptography.BouncyCastle;

/// <summary>
/// The <see cref="HttpClient" /> for file download.
/// </summary>
public class HttpDownloader
{
    // https://learn.microsoft.com/ja-jp/dotnet/fundamentals/networking/http/httpclient-guidelines
    private readonly IHttpClientFactory _httpClientFactory;

    /// <summary>
    /// Initializes a new instance of the <see cref="HttpDownloader" /> class.
    /// </summary>
    /// <param name="httpClientFactory">A class instance that implements <see cref="IHttpClientFactory" />.</param>
    public HttpDownloader(IHttpClientFactory httpClientFactory)
    {
        _httpClientFactory = httpClientFactory;
    }

    /// <summary>
    /// Requests file download.
    /// </summary>
    /// <param name="requestUri">The Uri the request is sent to.</param>
    /// <param name="timeout">A http request timeout.
    ///   If null is specified, the default value of <see cref="HttpClient" /> will be set.</param>
    /// <param name="cancellationToken">The token to monitor for cancellation requests.
    ///   The default value is None.</param>
    /// <returns>The task object representing the asynchronous operation.
    ///   The value of the type parameter of the value task contains An array of <c>byte</c>.</returns>
    public async Task<byte[]> DownloadAsync(
        Uri requestUri,
        TimeSpan? timeout = default,
        CancellationToken cancellationToken = default)
    {
        byte[] response;
        using (var client = _httpClientFactory.CreateClient(nameof(HttpDownloader)))
        {
            var httpResponse = await client.GetAsync(requestUri, cancellationToken)
                .WaitAsync(timeout ?? client.Timeout, cancellationToken);

            if (!httpResponse.IsSuccessStatusCode)
            {
                throw new ApplicationException($"{httpResponse.StatusCode}");
            }

            // I couldn't trust it.
            // var contentType = httpResponse.Content.Headers.ContentType?.MediaType;

            using var stream = await httpResponse.Content.ReadAsStreamAsync(cancellationToken);
            using var reader = new PemReader(new StreamReader(stream));
            var pem = reader.ReadPemObject();

            response = pem?.Content
                ?? await httpResponse.Content.ReadAsByteArrayAsync(cancellationToken);
        }

        return response;
    }
}
