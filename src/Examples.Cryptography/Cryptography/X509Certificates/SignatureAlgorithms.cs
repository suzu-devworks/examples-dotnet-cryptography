using System.Security.Cryptography;

namespace Examples.Cryptography.X509Certificates;

#pragma warning disable IDE1006

/// <summary>
/// Defines OBJECT IDENTIFIER for hash algorithm.
/// </summary>
/// <seealso href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpnap/a48b02b2-2a10-4eb0-bed4-1807a6d2f5ad" />
public static class SignatureAlgorithms
{
    public static readonly Oid sha1RSA = new("1.2.840.113549.1.1.5");
    public static readonly Oid sha256RSA = new("1.2.840.113549.1.1.11");
    public static readonly Oid sha384RSA = new("1.2.840.113549.1.1.12");
    public static readonly Oid sha512RSA = new("1.2.840.113549.1.1.13");
    public static readonly Oid sha256ECDSA = new("1.2.840.10045.4.3.2");
    public static readonly Oid sha384ECDSA = new("1.2.840.10045.4.3.3");
    public static readonly Oid sha512ECDSA = new("1.2.840.10045.4.3.4");

    private static readonly Dictionary<string, HashAlgorithmName> hashes = new()
    {
        [sha1RSA.Value!] = HashAlgorithmName.SHA1,
        [sha256RSA.Value!] = HashAlgorithmName.SHA256,
        [sha384RSA.Value!] = HashAlgorithmName.SHA384,
        [sha512RSA.Value!] = HashAlgorithmName.SHA512,
        [sha256ECDSA.Value!] = HashAlgorithmName.SHA256,
        [sha384ECDSA.Value!] = HashAlgorithmName.SHA384,
        [sha512ECDSA.Value!] = HashAlgorithmName.SHA512,
    };

    /// <summary>
    /// Converts signature OID to <see cref="HashAlgorithmName"/> entry.
    /// </summary>
    /// <param name="signature">The signature OID.</param>
    /// <returns>A <see cref="HashAlgorithmName" />An entry.</returns>
    public static HashAlgorithmName? GetHashAlgorithmName(Oid signature)
    {
        if (hashes.TryGetValue(signature.Value ?? "unknown", out var hashName))
        {
            return hashName;
        }

        return null;
    }

}
