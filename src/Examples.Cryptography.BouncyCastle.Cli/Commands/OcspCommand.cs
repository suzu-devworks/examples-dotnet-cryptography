using ConsoleAppFramework;
using Examples.Cryptography.BouncyCastle.Asn1;
using Examples.Cryptography.BouncyCastle.Cli.Clients;
using Examples.Cryptography.BouncyCastle.X509;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Ocsp;

namespace Examples.Cryptography.BouncyCastle.Cli.Commands;

/// <summary>
/// Commands for OCSP (Online Certificate Status Protocol) certificate status checking.
/// </summary>
[RegisterCommands("ocsp")]
public class OcspCommand(OcspHttpClient client)
{
    /// <summary>
    /// Checks certificate revocation status via OCSP.
    /// </summary>
    /// <param name="cert">-c, Path to the target certificate file (PEM).</param>
    /// <param name="issuer">-i, Path to the issuer certificate file (PEM).</param>
    /// <param name="url">-u, OCSP endpoint URL. If not specified, extracted from the certificate AIA extension.</param>
    /// <param name="output">-o, Output file path to save the DER-encoded OCSP response.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    [Command("check")]
    public async Task Check(
        string cert,
        string issuer,
        string? url = null,
        string? output = null,
        CancellationToken cancellationToken = default)
    {
        // Load certificates
        var targetCertPem = await File.ReadAllTextAsync(cert, cancellationToken);
        var issuerCertPem = await File.ReadAllTextAsync(issuer, cancellationToken);

        var targetCert = X509CertificateLoader.LoadFromPem(targetCertPem);
        var issuerCert = X509CertificateLoader.LoadFromPem(issuerCertPem);

        // Determine OCSP endpoint URL
        Uri ocspUri;
        if (url is not null)
        {
            ocspUri = new Uri(url);
        }
        else
        {
            ocspUri = targetCert.GetAuthorityInfoAccessUri(X509ObjectIdentifiers.OcspAccessMethod)
                ?? throw new InvalidOperationException(
                    "OCSP URL not found in certificate AIA extension. Use --url to specify the endpoint.");
        }

        // Build OCSP request (unsigned with nonce)
        var certId = new CertificateID(CertificateID.DigestSha1, issuerCert, targetCert.SerialNumber);
        var generator = new OcspReqGenerator();
        generator.AddRequest(certId);

        var nonce = new byte[16];
        Random.Shared.NextBytes(nonce);
        generator.AddNonce(nonce);

        var request = generator.Generate();

        // Send OCSP request
        Console.Error.WriteLine($"Requesting OCSP status from: {ocspUri}");
        var response = await client.RequestAsync(ocspUri, request, cancellationToken: cancellationToken);

        // Display certificate status summary
        var basicResp = (BasicOcspResp)response.GetResponseObject();
        var single = basicResp.Responses.First();
        var certStatus = single.GetCertStatus();

        string statusText;
        if (certStatus == CertificateStatus.Good)
        {
            statusText = "GOOD";
        }
        else if (certStatus is RevokedStatus revokedStatus)
        {
            statusText = $"REVOKED (reason: {revokedStatus.RevocationReason}, time: {revokedStatus.RevocationTime:o})";
        }
        else
        {
            statusText = "UNKNOWN";
        }

        Console.WriteLine($"Certificate status: {statusText}");
        Console.WriteLine($"ThisUpdate       : {single.ThisUpdate:o}");
        if (single.NextUpdate != null)
        {
            Console.WriteLine($"NextUpdate       : {single.NextUpdate.Value:o}");
        }
        Console.WriteLine();

        // Display ASN.1 structure
        Console.WriteLine(response.ToStructureString());

        // Save DER-encoded response to file
        if (output is not null)
        {
            await File.WriteAllBytesAsync(output, response.GetEncoded(), cancellationToken);
            Console.Error.WriteLine($"OCSP response saved to: {output}");
        }
    }
}
