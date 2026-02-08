using System.Security.Cryptography;

namespace Examples.Cryptography.X509Certificates;

/// <summary>
/// Defines OBJECT IDENTIFIER for hash algorithm.
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

    private static readonly Dictionary<string, HashAlgorithmName> HashAlgorithms = new()
    {
        [Sha1RSA.Value!] = HashAlgorithmName.SHA1,
        [Sha256RSA.Value!] = HashAlgorithmName.SHA256,
        [Sha384RSA.Value!] = HashAlgorithmName.SHA384,
        [Sha512RSA.Value!] = HashAlgorithmName.SHA512,
        [Sha256ECDSA.Value!] = HashAlgorithmName.SHA256,
        [Sha384ECDSA.Value!] = HashAlgorithmName.SHA384,
        [Sha512ECDSA.Value!] = HashAlgorithmName.SHA512,
    };

    /// <summary>
    /// Converts signature OID to <see cref="HashAlgorithmName"/> entry.
    /// </summary>
    /// <param name="signature">The signature OID.</param>
    /// <returns>A <see cref="HashAlgorithmName" />An entry.</returns>
    public static HashAlgorithmName? GetHashAlgorithmName(Oid signature)
    {
        if (HashAlgorithms.TryGetValue(signature.Value ?? "unknown", out var hashName))
        {
            return hashName;
        }

        return null;
    }

}
