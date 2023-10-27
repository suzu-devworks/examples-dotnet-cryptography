using System.Security.Cryptography;
using Examples.Fluency;

namespace Examples.Cryptography.Tests.Algorithms.Hashing;

public class Sha2DigestTests : IClassFixture<HashingDataFixture>
{
    private readonly HashingDataFixture _fixture;

    public Sha2DigestTests(HashingDataFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public void WhenGeneratingDigest_WithByte_ReturnsExpected()
    {
        var largeData = _fixture.MillionSameCharacterData;

        {
            var actual = SHA512.HashData(largeData);
            actual.Length.Is(SHA512.HashSizeInBytes);
            actual.ToBase64String()
                .Is("5ZA+o2oN4eFwbgzi36FFbP9skakPqy8nDB1YkoJMBgAyMZ832MsdmVIe08I3OJHS9J80Xakf5wm49K+SNybBuw==");
        }

        return;
    }

    [Fact]
    public async Task WhenGeneratingDigest_WithStream_ReturnsExpected()
    {
        var largeData = _fixture.MillionSameCharacterData;

        using (var stream = new MemoryStream(largeData))
        using (var sha = SHA512.Create())
        {
            //var actual = sha.ComputeHash(stream);
            var actual = await sha.ComputeHashAsync(stream, CancellationToken.None);
            actual.Length.Is(SHA512.HashSizeInBytes);
            actual.ToBase64String()
                .Is("5ZA+o2oN4eFwbgzi36FFbP9skakPqy8nDB1YkoJMBgAyMZ832MsdmVIe08I3OJHS9J80Xakf5wm49K+SNybBuw==");
        }

        return;
    }

    [Fact]
    public async Task WhenGeneratingDigest_WithMemory_ReturnsExpected()
    {
        var largeData = _fixture.MillionSameCharacterData;

        using (var stream = new MemoryStream(largeData))
        {
            Memory<byte> actual = new byte[SHA256.HashSizeInBytes];
            var len = await SHA256.HashDataAsync(stream, actual, CancellationToken.None);
            len.Is(SHA256.HashSizeInBytes);
            actual.ToArray().ToBase64String()
                .Is("RBDc0q3nQ5ys+xmRvtn1h8gj7BhrVBHa5cizWcPSEU4=");
        }

        using (var stream = new MemoryStream(largeData))
        {
            Memory<byte> actual = new byte[SHA384.HashSizeInBytes];
            var len = await SHA384.HashDataAsync(stream, actual, CancellationToken.None);
            len.Is(SHA384.HashSizeInBytes);
            actual.ToArray().ToBase64String()
                .Is("Wr8/YJpm79bM8/RI3dsSHGOYjyv7wAlKcWukPnNenvQHha79Uiv7ZLKPwCClh6Og");
        }

        using (var stream = new MemoryStream(largeData))
        {
            Memory<byte> actual = new byte[SHA512.HashSizeInBytes];
            var len = await SHA512.HashDataAsync(stream, actual, CancellationToken.None);
            len.Is(SHA512.HashSizeInBytes);
            actual.ToArray().ToBase64String()
                .Is("5ZA+o2oN4eFwbgzi36FFbP9skakPqy8nDB1YkoJMBgAyMZ832MsdmVIe08I3OJHS9J80Xakf5wm49K+SNybBuw==");
        }

        return;
    }

}
