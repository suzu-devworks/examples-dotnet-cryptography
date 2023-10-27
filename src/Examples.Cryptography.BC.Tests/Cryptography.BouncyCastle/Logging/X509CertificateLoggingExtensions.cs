using System.Text;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;

namespace Examples.Cryptography.BouncyCastle.Logging;

/// <summary>
/// Extension methods for <see cref="X509Certificate" /> logging.
/// </summary>
public static class X509CertificateLoggingExtensions
{
    /// <summary>
    /// Converts the contents of <see cref="X509Certificate" /> to a <c>string</c> for log output.
    /// </summary>
    /// <param name="certificate">The <see cref="X509Certificate" /> instance.</param>
    /// <param name="indent">A indent indent.</param>
    /// <param name="showDetail">If true, output details.</param>
    /// <returns>A <c>string</c> for log output.</returns>
    public static string DumpAsString(this X509Certificate certificate, int indent = 0,
        bool showDetail = false)
    {
        var builder = new StringBuilder();

        builder.AppendLevelLine(indent, "subject", $"{certificate.SubjectDN}");
        builder.AppendLevelLine(indent, "issuer", $"{certificate.IssuerDN}");
        builder.AppendLevelLine(indent, "serialNumber", $"{certificate.SerialNumber}");
        builder.AppendLevelLine(indent, "notAfter", $"{certificate.NotAfter}");

        if (showDetail)
        {
            builder.Append(certificate.ToString());
        }

        return builder.ToString();
    }

    /// <summary>
    /// Converts the contents of <see cref="X509Extensions" /> to a <c>string</c> for log output.
    /// </summary>
    /// <param name="extensions">The <see cref="X509Extensions" /> instance.</param>
    /// <param name="indent">A indent indent.</param>
    /// <returns>A <c>string</c> for log output.</returns>
    public static string? DumpAsString(this X509Extensions extensions, int indent = 0)
    {
        var builder = new StringBuilder();

        foreach (var (oid, index) in extensions.GetExtensionOids()
            .Select((x, i) => (x, i)))
        {
            var ext = extensions.GetExtension(oid);
            builder.AppendLevelLine(indent + 1, $"[{index}]", $"critical({ext.IsCritical}) {oid} value = {ext.Value}");
        }

        return builder.ToString();
    }

}
