using System.Security.Cryptography;
using Examples.Cryptography.Xml.XAdES;

namespace Examples.Cryptography.Xml.Tests.XAdES.Fixtures;

/// <summary>
/// A mock <see cref="ITsaClient"/> that returns a fake DER-encoded timestamp token.
/// Used for unit tests where actual TSA communication is not required.
/// </summary>
public sealed class MockTsaClient : ITsaClient
{
    /// <summary>
    /// Returns a minimal fake DER-encoded timestamp token.
    /// The bytes represent an empty ASN.1 SEQUENCE, which is sufficient
    /// for structural XAdES tests that do not perform TSP response validation.
    /// </summary>
    /// <param name="hash">The hash bytes (not used in the mock response).</param>
    /// <param name="hashAlgorithm">The hash algorithm (not used in the mock response).</param>
    /// <returns>A minimal fake timestamp token.</returns>
    public byte[] GetTimestampToken(byte[] hash, HashAlgorithmName hashAlgorithm)
    {
        // Minimal fake DER-encoded CMS ContentInfo wrapping an empty SEQUENCE.
        // Real implementations would request an RFC 3161 TimeStampToken from a TSA here.
        return new byte[] { 0x30, 0x00 };
    }
}
