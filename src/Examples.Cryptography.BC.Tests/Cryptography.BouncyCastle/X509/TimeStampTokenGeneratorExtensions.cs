using Org.BouncyCastle.Asn1.Tsp;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Tsp;

namespace Examples.Cryptography.BouncyCastle.X509;

/// <summary>
/// Extension methods for <see cref="TimeStampTokenGenerator" />.
/// </summary>
public static class TimeStampTokenGeneratorExtensions
{
    /// <summary>
    /// Generates a <see cref="TimeStampToken" /> instance.
    /// </summary>
    /// <param name="generator">The <see cref="TimeStampTokenGenerator" /> instance.</param>
    /// <param name="message"></param>
    /// <param name="nonce"></param>
    /// <param name="serialNumber"></param>
    /// <param name="genTime"></param>
    /// <returns></returns>
    public static TimeStampToken Generate(this TimeStampTokenGenerator generator,
        MessageImprint message,
        BigInteger nonce,
        BigInteger serialNumber,
        DateTime genTime)
    {
        var requestGenerator = new TimeStampRequestGenerator();
        requestGenerator.SetCertReq(true);
        var request = requestGenerator.Generate(
            digestAlgorithmOid: message.HashAlgorithm.Algorithm.Id,
            digest: message.GetHashedMessage(),
            nonce);

        // client --- send --->  TSA server.

        var responseGenerator = new TimeStampResponseGenerator(generator, TspAlgorithms.Allowed);
        var response = responseGenerator.Generate(request, serialNumber, genTime);

        // client <-- recv --- TSA server.

        return response.TimeStampToken;
    }

}
