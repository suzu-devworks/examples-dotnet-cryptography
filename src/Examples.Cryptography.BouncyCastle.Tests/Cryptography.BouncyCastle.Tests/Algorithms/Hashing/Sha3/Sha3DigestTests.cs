using System.Text;
using Examples.Cryptography.Extensions;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;

namespace Examples.Cryptography.BouncyCastle.Tests.Algorithms.Hashing;

public class Sha3DigestTests
{
    private static byte[] LargeData { get; } = Encoding.ASCII.GetBytes(new string('@', count: 1_000_000));

    public static readonly TheoryData<string, int, string> DigestsData = new()
    {
        {
            "SHA3-256", 32,
            // spell-checker: disable-next-line
            "X+Qp/elj/YikFAdxFbiGKs1Quimp4o9jqwF2vORxv5I="
        },
        {
            "SHA3-384", 48,
            // spell-checker: disable-next-line
            "V4yg3n/s2On98xRokf9UJpq01+GLHAcd70/QscStvbtu8LWDLC5wrrl+CFgFHetN"
        },
        {
            "SHA3-512", 64,
            // spell-checker: disable-next-line
            "URJaJroURp7sRHxiRV6rIRrGk8Dc8KUIfE39ObkWuSm8Qqz3UAfHBtz25ppRcyV+vmrA+cO32A2VdimDHgGqVQ=="
        },
    };

    private static IDigest CreateDigest(string name)
    {
        return name switch
        {
            "SHA3-256" => new Sha3Digest(256),
            "SHA3-384" => new Sha3Digest(384),
            "SHA3-512" => new Sha3Digest(512),
            _ => throw new ApplicationException("no expected pattern.")
        };
    }

    [Theory]
    [MemberData(nameof(DigestsData))]
    public void When_LargeDataIsHashed_WithBlockUpdateBySpan_Then_DigestMatchesExpectedValue(string name, int size, string expected)
    {
        ReadOnlySpan<byte> input = LargeData.AsSpan();

        IDigest digest = CreateDigest(name);
        digest.BlockUpdate(input);

        // generate hash.
        Span<byte> buffer = stackalloc byte[digest.GetDigestSize()];
        digest.DoFinal(buffer);
        var output = buffer.ToArray(); //boxing

        // Assert:

        Assert.Equal(name, digest.AlgorithmName);
        Assert.Equal(size, digest.GetDigestSize());
        Assert.Equal(expected, output.ToBase64String());
    }

    [Theory]
    [MemberData(nameof(DigestsData))]
    public void When_LargeDataIsHashed_WithBlockUpdateByByteArray_Then_DigestMatchesExpectedValue(string name, int size, string expected)
    {
        byte[] input = LargeData;

        IDigest digest = CreateDigest(name);
        digest.BlockUpdate(input, 0, input.Length);

        // generate hash.
        byte[] output = new byte[digest.GetDigestSize()];
        digest.DoFinal(output, 0);

        // when separated update.
        digest.Reset();
        digest.BlockUpdate(input, 0, (input.Length / 2));
        digest.BlockUpdate(input, (input.Length / 2), (input.Length - (input.Length / 2)));
        byte[] output2 = new byte[digest.GetDigestSize()];
        digest.DoFinal(output2, 0);

        // Assert:

        Assert.Equal(name, digest.AlgorithmName);
        Assert.Equal(size, digest.GetDigestSize());
        Assert.Equal(expected, output.ToBase64String());

        Assert.Equal(output, output2);
    }
}
