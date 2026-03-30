using System.Security.Cryptography;

namespace Examples.Cryptography.Xml.XAdES;

/// <summary>
/// Interface for a Time Stamping Authority (TSA) client.
/// Used to obtain RFC 3161 timestamp tokens over a message imprint.
/// </summary>
public interface ITsaClient
{
    /// <summary>
    /// Requests a timestamp token for the given hash.
    /// </summary>
    /// <param name="hash">The hash bytes to timestamp.</param>
    /// <param name="hashAlgorithm">The hash algorithm used to produce <paramref name="hash"/>.</param>
    /// <returns>A DER-encoded RFC 3161 TimeStampToken (CMS SignedData).</returns>
    byte[] GetTimestampToken(byte[] hash, HashAlgorithmName hashAlgorithm);
}
