using System.Text;
using Org.BouncyCastle.OpenSsl;

namespace Examples.Cryptography.BouncyCastle.Utilities;

/// <summary>
/// Utility for converting BouncyCastle objects to PEM format strings.
/// </summary>
internal static class PemUtility
{
    /// <summary>
    /// Converts a BouncyCastle encodable object (e.g., private key, public key) to a PEM format string.
    /// </summary>
    /// <param name="encodable"></param>
    /// <returns></returns>
    public static string ToPemString(object encodable)
    {
        var builder = new StringBuilder();
        using (var writer = new PemWriter(new StringWriter(builder)))
        {
            writer.WriteObject(encodable);
        }

        return builder.ToString().TrimEnd();
    }

    /// <summary>
    /// Loads a BouncyCastle object from a PEM format string, returning the expected type if successful.
    /// </summary>
    /// <typeparam name="T"></typeparam>
    /// <param name="pem"></param>
    /// <returns></returns>
    /// <exception cref="NotSupportedException">If the loaded object is not of the expected type.</exception>
    public static T LoadFrom<T>(string pem)
    {
        using var reader = new PemReader(new StringReader(pem));
        var loaded = reader.ReadObject();

        if (loaded is T result)
        {
            return result;
        }

        throw new NotSupportedException($"type is {loaded.GetType().Name}");
    }
}
