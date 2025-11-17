using System.Security.Cryptography;
using System.Text;

namespace Examples.Cryptography.Tests.Algorithms.Hashing;

public class SHA2DigestTests
{
    private static byte[] LargeData { get; } = Encoding.ASCII.GetBytes(new string('@', count: 1_000_000));

    public static readonly TheoryData<string, int, string> DigestsData = new()
    {
        {
            "SHA256",
            SHA256.HashSizeInBytes,
            // spell-checker: disable-next-line
            "RBDc0q3nQ5ys+xmRvtn1h8gj7BhrVBHa5cizWcPSEU4="
        },
        {
            "SHA384",
            SHA384.HashSizeInBytes,
            // spell-checker: disable-next-line
            "Wr8/YJpm79bM8/RI3dsSHGOYjyv7wAlKcWukPnNenvQHha79Uiv7ZLKPwCClh6Og"
        },
        {
            "SHA512",
            SHA512.HashSizeInBytes,
            // spell-checker: disable-next-line
            "5ZA+o2oN4eFwbgzi36FFbP9skakPqy8nDB1YkoJMBgAyMZ832MsdmVIe08I3OJHS9J80Xakf5wm49K+SNybBuw=="
        },
    };

    [Theory]
    [MemberData(nameof(DigestsData))]
    public void When_HashedWithHashData_Then_DigestMatchesExpectedValue(string name, int length, string expected)
    {
        var input = LargeData;

        var actual = name switch
        {
            "SHA256" => SHA256.HashData(input),
            "SHA384" => SHA384.HashData(input),
            "SHA512" => SHA512.HashData(input),
            _ => throw new ApplicationException("no expected pattern.")
        };

        // Assert:

        Assert.Equal(length, actual.Length);
        Assert.Equal(expected, actual.ToBase64String());
    }

    [Theory]
    [MemberData(nameof(DigestsData))]
    public async Task When_HashedWithHashDataAsync_Then_DigestMatchesExpectedValue(string name, int length, string expected)
    {
        var input = LargeData;

        using var stream = new MemoryStream(input);
        Memory<byte> actual = new byte[length];
        var token = TestContext.Current.CancellationToken;
        var task = name switch
        {
            "SHA256" => SHA256.HashDataAsync(stream, actual, token),
            "SHA384" => SHA384.HashDataAsync(stream, actual, token),
            "SHA512" => SHA512.HashDataAsync(stream, actual, token),
            _ => throw new ApplicationException("no expected pattern.")
        };
        var len = await task;

        // Assert:

        Assert.Equal(length, len);
        Assert.Equal(length, actual.Length);
        Assert.Equal(expected, actual.ToArray().ToBase64String());
    }

    [Theory]
    [MemberData(nameof(DigestsData))]
    public async Task When_HashedWithComputeHashAsync_Then_DigestMatchesExpectedValue(string name, int length, string expected)
    {
        var input = LargeData;

        using HashAlgorithm hasher = name switch
        {
            "SHA256" => SHA256.Create(),
            "SHA384" => SHA384.Create(),
            "SHA512" => SHA512.Create(),
            _ => throw new ApplicationException("no expected pattern.")
        };

        using var stream = new MemoryStream(input);
        var actual = await hasher.ComputeHashAsync(stream, TestContext.Current.CancellationToken);

        // Assert:

        Assert.Equal(length, actual.Length);
        Assert.Equal(expected, actual.ToBase64String());
    }

}
