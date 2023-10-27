using Examples.Cryptography.BouncyCastle.Internals;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.X509;

namespace Examples.Cryptography.BouncyCastle.X509;

/// <summary>
/// The <see cref="X509Certificate" /> importer and extension methods for export.
/// </summary>
public static class X509CertificateAgent
{
    /// <summary>
    /// Exports the certificate in the <see cref="X509CertificateStructure" /> format, PEM encoded.
    /// </summary>
    /// <param name="certificate">A <see cref="X509Certificate" /> instance.</param>
    /// <returns>A string containing the PEM-encoded PrivateKey.</returns>
    public static string ExportCertificatePem(this X509Certificate certificate)
    {
        return PemUtility.ToPemString(certificate);
    }

    /// <summary>
    /// Imports the certificate from an <see cref="X509CertificateStructure" />, replacement for this object.
    /// </summary>
    /// <param name="pem">The PEM text of the key to import.</param>
    /// <returns>A <see cref="X509Certificate" /> instance
    /// containing the imported certificate.</returns>
    public static X509Certificate CreateFromPem(string pem)
    {
        using var reader = new PemReader(new StringReader(pem));
        var loaded = reader.ReadObject();

        if (loaded is X509Certificate cert)
        {
            return cert;
        }

        throw new NotSupportedException($"type is {loaded.GetType().Name}");
    }

}
