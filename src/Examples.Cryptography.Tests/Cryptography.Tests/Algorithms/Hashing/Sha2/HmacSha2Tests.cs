using System.Security.Cryptography;
using System.Text;

namespace Examples.Cryptography.Tests.Algorithms.Hashing.Sha2;

public class HmacSha2Tests
{
    private static readonly string Message = "This is a test using a larger than block-size key " +
                                             "and a larger than block-size data. The key needs to be hashed " +
                                             "before being used by the HMAC algorithm.";
    private static HMAC CreateHmac(string name, byte[] secretKey)
    {
        return name switch
        {
            "SHA-256" => new HMACSHA256(secretKey),
            "SHA-384" => new HMACSHA384(secretKey),
            "SHA-512" => new HMACSHA512(secretKey),
            _ => throw new ApplicationException("no expected pattern.")
        };
    }

    private static byte[] CreateSecretKey(long bytes)
    {
        byte[] secureRandomBytes = new byte[bytes];
        RandomNumberGenerator.Fill(secureRandomBytes);
        return secureRandomBytes;
    }

    private static async ValueTask<byte[]> ComputeHmacAsync(string name, byte[] message, byte[] secretKey, CancellationToken cancellationToken)
    {
        using HMAC hmac = CreateHmac(name, secretKey);
        using var inStream = new MemoryStream(message);
        return await hmac.ComputeHashAsync(inStream, cancellationToken);
    }

    [Theory]
    [InlineData("SHA-256")]
    [InlineData("SHA-384")]
    [InlineData("SHA-512")]
    public async Task When_HMACGenerated_WithTheSameKey_Then_GetsSameValue(string name)
    {
        var message = Encoding.ASCII.GetBytes(Message);
        var secretKey = CreateSecretKey(64);

        var output = await ComputeHmacAsync(name, message, secretKey, TestContext.Current.CancellationToken);
        var verify = await ComputeHmacAsync(name, message, secretKey, TestContext.Current.CancellationToken);

        // Assert:

        Assert.Equal(output, verify);
    }

    [Theory]
    [InlineData("SHA-256")]
    public async Task When_HMACGenerated_WithDifferentKeys_Then_GetsDifferentValues(string name)
    {
        var message = Encoding.ASCII.GetBytes(Message);
        var secretKey1 = CreateSecretKey(64);
        var secretKey2 = CreateSecretKey(64);

        var output = await ComputeHmacAsync(name, message, secretKey1, TestContext.Current.CancellationToken);
        var verify = await ComputeHmacAsync(name, message, secretKey2, TestContext.Current.CancellationToken);

        // Assert:

        Assert.NotEqual(output, verify);
    }

    [Theory]
    [InlineData("SHA-256")]
    public async Task When_HMACGenerated_WithMessagesAreTampered_Then_GetsDifferentValues(string name)
    {
        var message = Encoding.ASCII.GetBytes(Message);
        var secretKey = CreateSecretKey(64);

        var output = await ComputeHmacAsync(name, message, secretKey, TestContext.Current.CancellationToken);

        // Tamper with the message
        message[0] ^= 0xFF; // Flip the first byte

        var verify = await ComputeHmacAsync(name, message, secretKey, TestContext.Current.CancellationToken);

        // Assert:

        Assert.NotEqual(output, verify);
    }

}
