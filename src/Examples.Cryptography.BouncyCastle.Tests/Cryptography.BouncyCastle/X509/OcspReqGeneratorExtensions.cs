using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Ocsp;

namespace Examples.Cryptography.BouncyCastle.X509;

/// <summary>
/// Extension methods for <see cref="OcspReqGenerator" />.
/// </summary>
public static class OcspReqGeneratorExtensions
{
    /// <summary>
    /// Adds OCSP nonce extension value.
    /// </summary>
    /// <param name="generator">The <see cref="OcspReqGenerator" /> instance.</param>
    /// <param name="nonce">A nonce value.</param>
    /// <returns>The <see cref="OcspReqGenerator" /> Instances for daisy chaining</returns>
    public static OcspReqGenerator AddNonce(this OcspReqGenerator generator,
        byte[] nonce)
    {
        var extensions = new Dictionary<DerObjectIdentifier, X509Extension>
        {
            {
                OcspObjectIdentifiers.PkixOcspNonce,
                    new X509Extension(critical: false, new DerOctetString(nonce))
            }
        };

        generator.SetRequestExtensions(new X509Extensions(extensions));

        return generator;
    }

}
