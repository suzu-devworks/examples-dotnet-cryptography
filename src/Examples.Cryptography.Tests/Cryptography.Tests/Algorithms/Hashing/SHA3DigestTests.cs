using System.Security.Cryptography;
using System.Text;

namespace Examples.Cryptography.Tests.Algorithms.Hashing;

/// <summary>
/// Tests for SHA3 digests.
/// </summary>
public class SHA3DigestTests
{
    private static byte[] LargeData { get; } = Encoding.ASCII.GetBytes(new string('@', count: 1_000_000));

    public static readonly TheoryData<string, int, string> DigestsData = new()
    {
        {
            "SHA3_256",
            SHA3_256.HashSizeInBytes,
            // spell-checker: disable-next-line
            "X+Qp/elj/YikFAdxFbiGKs1Quimp4o9jqwF2vORxv5I="
        },
        {
            "SHA3_384",
            SHA3_384.HashSizeInBytes,
            // spell-checker: disable-next-line
            "V4yg3n/s2On98xRokf9UJpq01+GLHAcd70/QscStvbtu8LWDLC5wrrl+CFgFHetN"
        },
        {
            "SHA3_512",
            SHA3_512.HashSizeInBytes,
            // spell-checker: disable-next-line
            "URJaJroURp7sRHxiRV6rIRrGk8Dc8KUIfE39ObkWuSm8Qqz3UAfHBtz25ppRcyV+vmrA+cO32A2VdimDHgGqVQ=="
        },
    };

    [Theory]
    [MemberData(nameof(DigestsData))]
    public void When_HashedWithHashData_Then_DigestMatchesExpectedValue(string name, int length, string expected)
    {
        var input = LargeData;

        var actual = name switch
        {
            "SHA3_256" => SHA3_256.HashData(input),
            "SHA3_384" => SHA3_384.HashData(input),
            "SHA3_512" => SHA3_512.HashData(input),
            _ => throw new ApplicationException("no expected pattern.")
        };

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
            "SHA3_256" => SHA3_256.HashDataAsync(stream, actual, token),
            "SHA3_384" => SHA3_384.HashDataAsync(stream, actual, token),
            "SHA3_512" => SHA3_512.HashDataAsync(stream, actual, token),
            _ => throw new ApplicationException("no expected pattern.")
        };
        var len = await task;

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
            "SHA3_256" => SHA3_256.Create(),
            "SHA3_384" => SHA3_384.Create(),
            "SHA3_512" => SHA3_512.Create(),
            _ => throw new ApplicationException("no expected pattern.")
        };

        using var stream = new MemoryStream(input);
        var actual = await hasher.ComputeHashAsync(stream, TestContext.Current.CancellationToken);

        Assert.Equal(length, actual.Length);
        Assert.Equal(expected, actual.ToBase64String());
    }

}
