using Examples.Fluency;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;

namespace Examples.Cryptography.BouncyCastle.Tests.Algorithms.Hashing;

public class Sha2DigestTests : IClassFixture<HashingDataFixture>
{
    private readonly HashingDataFixture _lob;
    private readonly ITestOutputHelper _output;

    public Sha2DigestTests(HashingDataFixture lob, ITestOutputHelper output)
    {
        _lob = lob;
        _output = output;
    }


    public static IEnumerable<object[]> GenerateDigestData()
    {
        yield return new object[] { new Sha256Digest(), "SHA-256", 32,
            "RBDc0q3nQ5ys+xmRvtn1h8gj7BhrVBHa5cizWcPSEU4=" };
        yield return new object[] { new Sha384Digest(), "SHA-384", 48,
            "Wr8/YJpm79bM8/RI3dsSHGOYjyv7wAlKcWukPnNenvQHha79Uiv7ZLKPwCClh6Og" };
        yield return new object[] { new Sha512Digest(), "SHA-512", 64,
            "5ZA+o2oN4eFwbgzi36FFbP9skakPqy8nDB1YkoJMBgAyMZ832MsdmVIe08I3OJHS9J80Xakf5wm49K+SNybBuw==" };
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
        var output = buffer.ToArray(); //boxing ?

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
