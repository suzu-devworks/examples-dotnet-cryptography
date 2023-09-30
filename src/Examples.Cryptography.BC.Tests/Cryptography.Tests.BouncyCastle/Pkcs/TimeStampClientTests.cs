using System.Net.Http.Headers;
using System.Text;
using Examples.Cryptography.BouncyCastle.Pkcs;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Tsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tsp;

namespace Examples.Cryptography.Tests.BouncyCastle.Pkcs;

public class TimeStampClientTests
{
    private readonly ITestOutputHelper _output;

    public TimeStampClientTests(ITestOutputHelper output)
    {
        /// ```
        /// dotnet test --logger "console;verbosity=detailed"
        /// ```
        _output = output;
    }

    [Fact(Skip = "USE HTTPS.")]
    public async Task WhenRequestTimestampToken_UsingFreeTsaOrg_ResponseOk()
    {
        // I will try to get the TimeStampToken using the actual TSA server(FreeTSA.org).

        // ### Arrange. ###
        var data = Encoding.UTF8.GetBytes("TEST MESSAGE PHRASE");

        //```
        // $ openssl ts -query -data file.png -no_nonce -sha512 -cert -out file.tsq
        //```
        // Make a request as above.
        var algorithm = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha512);
        var digest = DigestUtilities.CalculateDigest(algorithm.Algorithm, data);
        var message = new MessageImprint(algorithm, digest);

        var request = new TimeStampRequestGenerator()
            .Configure(gen => gen.SetCertReq(true))
            .Generate(
                digestAlgorithm: message.HashAlgorithm.Algorithm,
                digest: message.GetHashedMessage()
            );

        // ### Act. ###
        // call FreeTSA.org with HTTPS or dummy.
        var response = await RequestTimestampAsync(request, @"https://freetsa.org/tsr");

        // ### Assert. ###
        response.Status.Is(0);

        var token = response.TimeStampToken;
        token.IsInstanceOf<TimeStampToken>();

        _output.WriteLine($"# TimeStampToken(FreeTSA.org):");
        _output.WriteLine(token.DumpAsString());

        return;
    }

    private static readonly HttpClient HttpClient = new();

    public static async Task<TimeStampResponse> RequestTimestampAsync(TimeStampRequest request, string uri)
    {
        var content = new ByteArrayContent(request.GetEncoded());
        content.Headers.ContentType
            = new MediaTypeHeaderValue(@"application/timestamp-query");

        var httpResponse = await HttpClient.PostAsync(uri, content);

        if (!httpResponse.IsSuccessStatusCode)
        {
            throw new Exception($"{httpResponse.StatusCode}");
        }

        var bytes = await httpResponse.Content.ReadAsByteArrayAsync();
        var response = new TimeStampResponse(bytes);

        return response;
    }
}
