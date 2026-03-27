using System.Net.Http.Headers;
using Org.BouncyCastle.Ocsp;

namespace Examples.Cryptography.BouncyCastle.Cli.Clients;

/// <summary>
/// The <see cref="HttpClient" /> for OCSP request.
/// </summary>
/// <remarks>
/// Initializes a new instance of the <see cref="OcspHttpClient" /> class.
/// </remarks>
/// <param name="httpClient">A <see cref="HttpClient" /> instance managed by <see cref="IHttpClientFactory" />.</param>
public class OcspHttpClient(HttpClient httpClient)
{
    // https://learn.microsoft.com/en-us/dotnet/core/extensions/httpclient-factory#typed-clients
    private readonly HttpClient _httpClient = httpClient;

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

        var httpResponse = await _httpClient.PostAsync(requestUri, content, cancellationToken)
            .WaitAsync(timeout ?? _httpClient.Timeout, cancellationToken);

        if (!httpResponse.IsSuccessStatusCode)
        {
            throw new Exception($"{httpResponse.StatusCode}");
        }

        var bytes = await httpResponse.Content.ReadAsByteArrayAsync(cancellationToken);
        return new OcspResp(bytes);
    }

}
