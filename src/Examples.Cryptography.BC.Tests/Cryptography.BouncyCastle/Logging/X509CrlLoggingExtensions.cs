using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;

namespace Examples.Cryptography.BouncyCastle.Logging;

/// <summary>
/// Extension methods for <see cref="X509Crl" /> logging.
/// </summary>
public static class X509CrlLoggingExtensions
{
    /// <summary>
    /// Converts the contents of <see cref="X509Crl" /> to a <c>string</c> for log output.
    /// </summary>
    /// <param name="crl">The <see cref="X509Crl" /> instance.</param>
    /// <param name="indent">A indent indent.</param>
    /// <param name="showEntries"></param>
    /// <returns>A <c>string</c> for log output.</returns>
    public static string DumpAsString(this X509Crl crl, int indent = 0,
        bool showEntries = false)
    {
        var builder = new StringBuilder();

        builder.AppendLevelLine(indent, "issuer", $"{crl.IssuerDN}");
        builder.AppendLevelLine(indent, "nextUpdate", $"{crl.NextUpdate}");

        builder.AppendLevelLine(indent, "revokedCertificates", $"[count={crl.GetRevokedCertificates().Count}]");

        if (showEntries)
        {
            foreach (var (entry, index) in crl.GetRevokedCertificates()
                .Select((x, i) => (x, i)))
            {
                var reasonCode = entry.GetExtensionValue(X509Extensions.ReasonCode);
                var reason = new CrlReason(
                    DerEnumerated.GetInstance(
                        X509ExtensionUtilities.FromExtensionValue(reasonCode)));

                _ = entry.GetExtensionValue(X509Extensions.InvalidityDate);

                builder.AppendLevelLine(indent + 1, $"[{index}]", $"[SerialNumber: {entry.SerialNumber}, RevocationDate: {entry.RevocationDate}, {reason}]");
            }
        }

        return builder.ToString();
    }

}
