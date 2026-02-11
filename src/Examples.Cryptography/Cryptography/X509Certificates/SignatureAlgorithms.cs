using System.Security.Cryptography;

namespace Examples.Cryptography.X509Certificates;

/// <summary>
/// Defines OBJECT IDENTIFIER for signature algorithm.
/// </summary>
/// <seealso href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpnap/a48b02b2-2a10-4eb0-bed4-1807a6d2f5ad" />
public static class SignatureAlgorithms
{
    public static readonly Oid Sha1RSA = new("1.2.840.113549.1.1.5");
    public static readonly Oid Sha256RSA = new("1.2.840.113549.1.1.11");
    public static readonly Oid Sha384RSA = new("1.2.840.113549.1.1.12");
    public static readonly Oid Sha512RSA = new("1.2.840.113549.1.1.13");
    public static readonly Oid Sha256ECDSA = new("1.2.840.10045.4.3.2");
    public static readonly Oid Sha384ECDSA = new("1.2.840.10045.4.3.3");
    public static readonly Oid Sha512ECDSA = new("1.2.840.10045.4.3.4");

    private static readonly Dictionary<string, (HashAlgorithmName HashName, string AlgorithmName)> Algorithms = new()
    {
        [Sha1RSA.Value!] = (HashAlgorithmName.SHA1, "sha1WithRSAEncryption"),
        [Sha256RSA.Value!] = (HashAlgorithmName.SHA256, "sha256WithRSAEncryption"),
        [Sha384RSA.Value!] = (HashAlgorithmName.SHA384, "sha384WithRSAEncryption"),
        [Sha512RSA.Value!] = (HashAlgorithmName.SHA512, "sha512WithRSAEncryption"),
        [Sha256ECDSA.Value!] = (HashAlgorithmName.SHA256, "ecdsa-with-SHA256"),
        [Sha384ECDSA.Value!] = (HashAlgorithmName.SHA384, "ecdsa-with-SHA384"),
        [Sha512ECDSA.Value!] = (HashAlgorithmName.SHA512, "ecdsa-with-SHA512"),
    };

    /// <summary>
    /// Converts signature OID to <see cref="HashAlgorithmName"/> entry.
    /// </summary>
    /// <param name="signature">The signature OID.</param>
    /// <returns>A <see cref="HashAlgorithmName" />An entry.</returns>
    public static HashAlgorithmName? GetHashAlgorithmName(Oid signature)
    {
        if (Algorithms.TryGetValue(signature.Value ?? "unknown", out var info))
        {
            return info.HashName;
        }

        return null;
    }

    /// <summary>
    /// Converts signature OID to an algorithm name.
    /// </summary>
    /// <param name="signature">The signature OID.</param>
    /// <returns>The OID-defined algorithm name.</returns>
    public static string? GetAlgorithmName(Oid signature)
    {
        if (Algorithms.TryGetValue(signature.Value ?? "unknown", out var info))
        {
            return info.AlgorithmName;
        }

        return null;
    }

}
