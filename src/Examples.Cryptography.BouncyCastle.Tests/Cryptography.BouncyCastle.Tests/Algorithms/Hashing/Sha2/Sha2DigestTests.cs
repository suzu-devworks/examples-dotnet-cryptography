using System.Text;
using Examples.Cryptography.Extensions;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;

namespace Examples.Cryptography.BouncyCastle.Tests.Algorithms.Hashing;

public class Sha2DigestTests
{
    private static byte[] LargeData { get; } = Encoding.ASCII.GetBytes(new string('@', count: 1_000_000));

    public static readonly TheoryData<string, int, string> DigestsData = new()
    {
        {
            "SHA-256", 32,
            // spell-checker: disable-next-line
            "RBDc0q3nQ5ys+xmRvtn1h8gj7BhrVBHa5cizWcPSEU4="
        },
        {
            "SHA-384", 48,
            // spell-checker: disable-next-line
            "Wr8/YJpm79bM8/RI3dsSHGOYjyv7wAlKcWukPnNenvQHha79Uiv7ZLKPwCClh6Og"
        },
        {
            "SHA-512", 64,
            // spell-checker: disable-next-line
            "5ZA+o2oN4eFwbgzi36FFbP9skakPqy8nDB1YkoJMBgAyMZ832MsdmVIe08I3OJHS9J80Xakf5wm49K+SNybBuw=="
        },
    };

    private static IDigest CreateDigest(string name)
    {
        return name switch
        {
            "SHA-256" => new Sha256Digest(),
            "SHA-384" => new Sha384Digest(),
            "SHA-512" => new Sha512Digest(),
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
        var output = buffer.ToArray(); //boxing ?

        // Assert:

        Assert.Equal(name, digest.AlgorithmName);
        Assert.Equal(size, digest.GetDigestSize());
        Assert.Equal(expected, output.ToBase64String());
    }

    [Theory]
    [MemberData(nameof(DigestsData))]
    public void When_LargeDataIsHashed_WithBlockUpdateByByteArray_Then_DigestMatchesExpectedValue(string name, int size, string expected)
    {
        var input = LargeData;

        IDigest digest = CreateDigest(name);
        digest.BlockUpdate(input);

        // generate hash.
        byte[] output = new byte[digest.GetDigestSize()];
        digest.DoFinal(output, 0);

        // when separated update.
        digest.Reset();
        digest.BlockUpdate(input, 0, input.Length / 2);
        digest.BlockUpdate(input, input.Length / 2, input.Length - (input.Length / 2));
        byte[] output2 = new byte[digest.GetDigestSize()];
        digest.DoFinal(output2, 0);

        // Assert:

        Assert.Equal(name, digest.AlgorithmName);
        Assert.Equal(size, digest.GetDigestSize());
        Assert.Equal(expected, output.ToBase64String());

        Assert.Equal(output, output2);
    }
}
