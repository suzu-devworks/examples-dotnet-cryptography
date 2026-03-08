using System.Text;
using Org.BouncyCastle.OpenSsl;

namespace Examples.Cryptography.BouncyCastle.Tests.Fixtures;

/// <summary>
/// Utility for converting BouncyCastle objects to PEM format strings.
/// </summary>
public static class PemUtility
{
    /// <summary>
    /// Converts a BouncyCastle encodable object (e.g., private key, public key) to a PEM format string.
    /// </summary>
    /// <param name="encodable"></param>
    /// <returns></returns>
    public static string ToPemString(object encodable)
    {
        var builder = new StringBuilder();
        //using var memory = new MemoryStream();
        //using (var writer = new PemWriter(new StreamWriter(memory, Encoding.ASCII)))
        using (var writer = new PemWriter(new StringWriter(builder)))
        {
            writer.WriteObject(encodable);
        }
        //var pem = Encoding.ASCII.GetString(memory.ToArray()).TrimEnd();
        var pem = builder.ToString().TrimEnd();

        return pem;
    }
}
