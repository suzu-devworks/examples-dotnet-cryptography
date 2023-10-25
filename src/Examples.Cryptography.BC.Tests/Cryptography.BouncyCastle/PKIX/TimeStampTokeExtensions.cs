using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Store;

namespace Examples.Cryptography.BouncyCastle.PKIX;

/// <summary>
/// Extension methods for <see cref="TimeStampToken" />.
/// </summary>
public static class TimeStampTokeExtensions
{
    /// <summary>
    /// Find the TSA certificate by <see cref="TimeStampToken" />.
    /// Looks for a certificate with that name if the tsa field is present.
    /// </summary>
    /// <param name="tat">The <see cref="TimeStampToken" /> instance.</param>
    /// <returns>The TSA certificate.</returns>
    public static X509Certificate? FindTSACertificate(this TimeStampToken tat)
    {
        var tsaOption = tat.TimeStampInfo.Tsa;

        X509CertStoreSelector? selector = null;
        if (tsaOption is not null)
        {
            selector = new X509CertStoreSelector
            {
                Subject = X509Name.GetInstance(tsaOption.Name)
            };
        }

        var tsaCert = tat.GetCertificates().EnumerateMatches(selector)
            .FirstOrDefault();

        return tsaCert;
    }

}
