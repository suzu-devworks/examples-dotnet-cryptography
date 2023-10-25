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

        builder.AppendLebelLine(indent, "subject", $"{certificate.SubjectDN}");
        builder.AppendLebelLine(indent, "issuer", $"{certificate.IssuerDN}");
        builder.AppendLebelLine(indent, "serialNumber", $"{certificate.SerialNumber}");
        builder.AppendLebelLine(indent, "notAfter", $"{certificate.NotAfter}");

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
            builder.AppendLebelLine(indent + 1, $"[{index}]", $"critical({ext.IsCritical}) {oid} value = {ext.Value}");
        }

        return builder.ToString();
    }

}
