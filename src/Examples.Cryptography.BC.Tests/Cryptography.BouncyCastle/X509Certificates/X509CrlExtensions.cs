using Org.BouncyCastle.X509;

namespace Examples.Cryptography.BouncyCastle.X509Certificates;

/// <summary>
/// Extension methods for <see cref="X509Crl" />.
/// </summary>
public static class X509CrlExtensions
{
    /// <summary>
    /// Converts the contents of <see cref="X509Crl" /> to a <c>string</c> for log output.
    /// </summary>
    /// <param name="crl">The <see cref="X509Crl" /> instance.</param>
    /// <param name="indent">A indent indent.</param>
    /// <returns>A <c>string</c> for log output.</returns>
    public static string DumpAsString(this X509Crl crl, int indent = 0)
    {
        _ = indent;
        return crl.ToString();
    }
}
