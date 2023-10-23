using Examples.Cryptography.BouncyCastle.Utilities;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;

namespace Examples.Cryptography.BouncyCastle.PKCS;

/// <summary>
/// The <see cref="Pkcs10CertificationRequest" /> importer and extension methods for export.
/// </summary>
public static class Pkcs10CertificationRequestAgent
{
    /// <summary>
    /// Exports the certificate request in the <see cref="CertificationRequest" /> format, PEM encoded.
    /// </summary>
    /// <param name="request">A <see cref="Pkcs10CertificationRequest" /> instance.</param>
    /// <returns>A string containing the PEM-encoded PrivateKey.</returns>
    public static string ExportCertificateRequestPem(this Pkcs10CertificationRequest request)
        => PemUtility.ToPemString(request);

    /// <summary>
    /// Imports the certificate request from an <see cref="CertificationRequest" />, replacement for this object.
    /// </summary>
    /// <param name="pem">The PEM text of the key to import.</param>
    /// <returns>The <see cref="Pkcs10CertificationRequest" /> instance
    /// containing the imported certificate request.</returns>
    public static Pkcs10CertificationRequest ImportCertificateRequestPem(string pem)
    {
        using var reader = new PemReader(new StringReader(pem));
        var loaded = reader.ReadObject();

        if (loaded is Pkcs10CertificationRequest request)
        {
            return request;
        }

        throw new NotSupportedException($"type is {loaded.GetType().Name}");
    }


}
