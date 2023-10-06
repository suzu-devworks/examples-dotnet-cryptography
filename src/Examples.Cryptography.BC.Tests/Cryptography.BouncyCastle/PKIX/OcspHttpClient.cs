using System.Net.Http.Headers;
using Org.BouncyCastle.Ocsp;

namespace Examples.Cryptography.BouncyCastle.PKIX;

/// <summary>
/// The <see cref="HttpClient" /> for OCSP request.
/// </summary>
public class OcspHttpClient
{
    // https://learn.microsoft.com/ja-jp/dotnet/fundamentals/networking/http/httpclient-guidelines
    private readonly IHttpClientFactory _httpClientFactory;

    /// <summary>
    /// Initializes a new instance of the <see cref="OcspHttpClient" /> class.
    /// </summary>
    /// <param name="httpClientFactory">A class instance that implements <see cref="IHttpClientFactory" />.</param>
    public OcspHttpClient(IHttpClientFactory httpClientFactory)
    {
        _httpClientFactory = httpClientFactory;
    }

    /// <summary>
    /// Requests certificate revocation status to the OCSP responder.
    /// </summary>
    /// <param name="requestUri">The Uri the request is sent to.</param>
    /// <param name="request">The <see cref="OcspReq" /> instance.</param>
    /// <param name="timeout">A http request timeout.
    ///   If null is specified, the default value of <see cref="HttpClient" /> will be set.</param>
    /// <param name="cancellationToken">The token to monitor for cancellation requests.
    ///   The default value is None.</param>
    /// <returns>The task object representing the asynchronous operation.
    ///   The value of the type parameter of the value task contains A <see cref="OcspResp" /> instance.</returns>
    public async Task<OcspResp> RequestAsync(
        Uri requestUri,
        OcspReq request,
        TimeSpan? timeout = default,
        CancellationToken cancellationToken = default)
    {
        var content = new ByteArrayContent(request.GetEncoded());
        content.Headers.ContentType = new MediaTypeHeaderValue(@"application/ocsp-request");

        OcspResp response;
        using (var client = _httpClientFactory.CreateClient(nameof(OcspHttpClient)))
        {
            var httpResponse = await client.PostAsync(requestUri, content, cancellationToken)
                .WaitAsync(timeout ?? client.Timeout, cancellationToken);

            if (!httpResponse.IsSuccessStatusCode)
            {
                throw new Exception($"{httpResponse.StatusCode}");
            }

            var bytes = await httpResponse.Content.ReadAsByteArrayAsync(cancellationToken);
            response = new OcspResp(bytes);
        }

        return response;
    }
}
