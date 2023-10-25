using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Ocsp;

namespace Examples.Cryptography.BouncyCastle.PKIX;

/// <summary>
/// Extension methods for <see cref="OcspReqGenerator" />.
/// </summary>
public static class OcspReqGeneratorExtensions
{
    /// <summary>
    /// Call delegate to confine the settings to <see cref="OcspReqGenerator" /> to the function scope.
    /// </summary>
    /// <param name="generator">The <see cref="OcspReqGenerator" /> instance.</param>
    /// <param name="configureAction">A delegate for setting.</param>
    /// <returns>The <see cref="OcspReqGenerator" /> Instances for daisy chaining</returns>
    public static OcspReqGenerator Configure(this OcspReqGenerator generator,
        Action<OcspReqGenerator> configureAction)
    {
        configureAction.Invoke(generator);

        return generator;
    }

    /// <summary>
    /// Adds OCSP nonce extension value.
    /// </summary>
    /// <param name="generator">The <see cref="OcspReqGenerator" /> instance.</param>
    /// <param name="nonce">A nonce value.</param>
    /// <returns>The <see cref="OcspReqGenerator" /> Instances for daisy chaining</returns>
    public static OcspReqGenerator AddNonce(this OcspReqGenerator generator,
        BigInteger nonce)
    {
        var nonceValue = new DerOctetString(
            new DerOctetString(nonce.ToByteArray()));

        var values = new Dictionary<DerObjectIdentifier, X509Extension>
        {
            { OcspObjectIdentifiers.PkixOcspNonce, new X509Extension(critical: false, nonceValue) }
        };

        generator.SetRequestExtensions(new X509Extensions(values));

        return generator;
    }

}
