using System.Text;
using ConsoleAppFramework;
using Examples.Cryptography.BouncyCastle.Asn1;
using Examples.Cryptography.BouncyCastle.Cli.Clients;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tsp;

namespace Examples.Cryptography.BouncyCastle.Cli.Commands;

/// <summary>
/// Commands for TSA (Time Stamping Authority) operations.
/// </summary>
[RegisterCommands("tsa")]
public class TsaCommand(TimeStampHttpClient client)
{
    /// <summary>
    /// Requests a timestamp token from a TSA server.
    /// </summary>
    /// <param name="url">-u, TSA server URL.</param>
    /// <param name="data">-d, Data to timestamp as a string. If not specified, uses a default message.</param>
    /// <param name="algorithm">-a, Hash algorithm name (SHA-256, SHA-384, SHA-512). Default: SHA-256.</param>
    /// <param name="output">-o, Output file path to save the DER-encoded timestamp token.</param>
    /// <param name="verbose">-v, Show ASN.1 structure of the response.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    [Command("request")]
    public async Task Request(
        string url,
        string? data = null,
        string algorithm = "SHA-256",
        string? output = null,
        bool verbose = false,
        CancellationToken cancellationToken = default)
    {
        var tsaUri = new Uri(url);
        var messageBytes = data is not null
            ? Encoding.UTF8.GetBytes(data)
            : Encoding.UTF8.GetBytes("timestamp request");

        // Determine hash algorithm OID
        var algOid = GetAlgorithmOid(algorithm);

        // Compute message digest
        var digest = DigestUtilities.CalculateDigest(algOid, messageBytes);

        // Build TSA request
        var requestGenerator = new TimeStampRequestGenerator();
        requestGenerator.SetCertReq(certReq: true);

        var nonce = new BigInteger(64, new SecureRandom());
        var request = requestGenerator.Generate(algOid.Id, digest, nonce);

        // Send TSA request
        Console.Error.WriteLine($"Requesting timestamp from: {tsaUri}");
        var response = await client.RequestAsync(tsaUri, request, cancellationToken: cancellationToken);

        // Validate response against original request
        response.Validate(request);

        var token = response.TimeStampToken;
        var tst = token.TimeStampInfo;

        // Display summary
        Console.WriteLine($"SerialNumber : {tst.SerialNumber}");
        Console.WriteLine($"GenTime      : {tst.GenTime:o}");
        Console.WriteLine($"Policy       : {tst.Policy}");
        Console.WriteLine($"Algorithm    : {tst.MessageImprintAlgOid}");

        // Display ASN.1 structure
        if (verbose)
        {
            Console.WriteLine();
            Console.WriteLine(token.ToStructureString());
        }

        // Save DER-encoded timestamp token to file
        if (output is not null)
        {
            await File.WriteAllBytesAsync(output, token.GetEncoded(), cancellationToken);
            Console.Error.WriteLine($"Timestamp token saved to: {output}");
        }
    }

    private static DerObjectIdentifier GetAlgorithmOid(string name) =>
        name.ToUpperInvariant() switch
        {
            "SHA-256" or "SHA256" => NistObjectIdentifiers.IdSha256,
            "SHA-384" or "SHA384" => NistObjectIdentifiers.IdSha384,
            "SHA-512" or "SHA512" => NistObjectIdentifiers.IdSha512,
            _ => throw new ArgumentException($"Unsupported algorithm: {name}. Supported: SHA-256, SHA-384, SHA-512")
        };
}
