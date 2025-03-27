using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;

namespace Examples.Cryptography.BouncyCastle.X509;

/// <summary>
/// Extension methods for <see cref="X509Certificate" />.
/// </summary>
public static class X509CertificateExtensions
{
    /// <summary>
    /// Gets AuthorityInfoAccess X.509 V3 Certificate extension values.
    /// </summary>
    /// <param name="certificate">The <see cref="X509Certificate" /> instance.</param>
    /// <param name="accessMethod">OID of accessMethod indicating the type and format of the information.</param>
    /// <returns>A <see cref="AccessDescription" /> instance.</returns>
    public static AccessDescription? GetAuthorityInfoAccess(this X509Certificate certificate,
         DerObjectIdentifier accessMethod)
    {
        var value = certificate.GetExtensionValue(X509Extensions.AuthorityInfoAccess);
        if (value is null)
        {
            return null;
        }

        var asn1 = X509ExtensionUtilities.FromExtensionValue(value);
        var aia = AuthorityInformationAccess.GetInstance(asn1);

        var access = aia.GetAccessDescriptions().Where(x => x.AccessMethod.Equals(accessMethod))
            .FirstOrDefault();

        return access;
    }

    /// <summary>
    /// Gets AuthorityInfoAccess X.509 V3 Certificate extension values as a <see cref="Uri" />.
    /// </summary>
    /// <param name="certificate">The <see cref="X509Certificate" /> instance.</param>
    /// <param name="accessMethod">OID of accessMethod indicating the type and format of the information.</param>
    /// <returns>A access location <see cref="Uri" />.</returns>
    public static Uri? GetAuthorityInfoAccessUri(this X509Certificate certificate,
         DerObjectIdentifier accessMethod)
    {
        var access = certificate.GetAuthorityInfoAccess(accessMethod);

        if ((access is null)
            || (access.AccessLocation.TagNo != GeneralName.UniformResourceIdentifier))
        {
            return null;
        }

        return new Uri($"{access.AccessLocation.Name}");
    }

    /// <summary>
    /// Gets CrlDistributionPoints X.509 V3 Certificate extension values.
    /// </summary>
    /// <param name="certificate">The <see cref="X509Certificate" /> instance.</param>
    /// <returns>An <see cref="IEnumerable{T}" /> collection of type <see cref="DistributionPoint" />.</returns>
    public static IEnumerable<DistributionPoint> GetCrlDistributionPoints(this X509Certificate certificate)
    {
        var value = certificate.GetExtensionValue(X509Extensions.CrlDistributionPoints);
        if (value is null)
        {
            return Enumerable.Empty<DistributionPoint>();
        }

        var asn1 = X509ExtensionUtilities.FromExtensionValue(value);
        var crlDp = CrlDistPoint.GetInstance(asn1);
        var dsp = crlDp.GetDistributionPoints();

        return dsp;
    }

    /// <summary>
    /// Gets CrlDistributionPoints X.509 V3 Certificate extension values as a <see cref="Uri" />.
    /// </summary>
    /// <param name="certificate">The <see cref="X509Certificate" /> instance.</param>
    /// <returns>An access location <see cref="Uri" />.</returns>
    public static Uri? GetCrlDistributionPointsUri(this X509Certificate certificate)
    {
        var gName = certificate.GetCrlDistributionPoints()
            .Where(x => x.DistributionPointName.Type == DistributionPointName.FullName)
            .SelectMany(x => GeneralNames.GetInstance(x.DistributionPointName.Name).GetNames())
            .Where(x => x.TagNo == GeneralName.UniformResourceIdentifier)
            .FirstOrDefault();

        if (gName is null)
        {
            return null;
        }

        return new Uri($"{gName.Name}");
    }

}
