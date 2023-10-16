using Examples.Fluency;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;

namespace Examples.Cryptography.Tests.BouncyCastle.Algorithms.Hashing;

public class Sha3DigestTests : IClassFixture<LargeDataFixture>
{
    private readonly LargeDataFixture _lob;
    private readonly ITestOutputHelper _output;

    public Sha3DigestTests(LargeDataFixture lob, ITestOutputHelper output)
    {
        _lob = lob;
        _output = output;
    }


    public static IEnumerable<object[]> GenerateDigestData()
    {
        yield return new object[] { new Sha3Digest(), "SHA3-256", 32,
            "X+Qp/elj/YikFAdxFbiGKs1Quimp4o9jqwF2vORxv5I=" };
        yield return new object[] { new Sha3Digest(bitLength: 384), "SHA3-384", 48,
            "V4yg3n/s2On98xRokf9UJpq01+GLHAcd70/QscStvbtu8LWDLC5wrrl+CFgFHetN" };
        yield return new object[] { new Sha3Digest(bitLength: 512), "SHA3-512", 64,
            "URJaJroURp7sRHxiRV6rIRrGk8Dc8KUIfE39ObkWuSm8Qqz3UAfHBtz25ppRcyV+vmrA+cO32A2VdimDHgGqVQ==" };
    }

    [Theory]
    [MemberData(nameof(GenerateDigestData))]
    public void WhenGeneratingDigest_WithSpan(IDigest digest, string name, int size, string expected)
    {
        ReadOnlySpan<byte> input = _lob.MillionSameCharacterData.AsSpan();

        // input data.
        digest.BlockUpdate(input);

        // generate hash.
        Span<byte> buffer = stackalloc byte[digest.GetDigestSize()];
        digest.DoFinal(buffer);
        var output = buffer.ToArray(); //boxing

        digest.AlgorithmName.Is(name);
        digest.GetDigestSize().Is(size);
        output.ToBase64String().Is(expected);

        return;
    }

    [Theory]
    [MemberData(nameof(GenerateDigestData))]
    public void WhenGeneratingDigest_WithByteArray(IDigest digest, string name, int size, string expected)
    {
        byte[] input = _lob.MillionSameCharacterData;

        // input data.
        digest.BlockUpdate(input, 0, input.Length);

        // generate hash.
        byte[] output = new byte[digest.GetDigestSize()];
        digest.DoFinal(output, 0);

        digest.AlgorithmName.Is(name);
        digest.GetDigestSize().Is(size);
        output.ToBase64String().Is(expected);

        // when separated update.
        digest.Reset();
        digest.BlockUpdate(input, 0, (input.Length / 2));
        digest.BlockUpdate(input, (input.Length / 2), (input.Length - (input.Length / 2)));
        byte[] output2 = new byte[digest.GetDigestSize()];
        digest.DoFinal(output2, 0);
        output2.Is(output);

        return;
    }

}
