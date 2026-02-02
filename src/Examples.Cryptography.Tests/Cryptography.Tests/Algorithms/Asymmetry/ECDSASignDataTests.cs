using System.Security.Cryptography;
using System.Text;

namespace Examples.Cryptography.Tests.Algorithms.Asymmetry;

/// <summary>
/// Tests for ECDSA key signing and verification.
/// </summary>
/// <param name="fixture"></param>
public class ECDSASignDataTests(
    ECDSAKeyFixture fixture)
    : IClassFixture<ECDSAKeyFixture>
{
    [Fact]
    public void When_SigningAndVerifying_Then_Success()
    {
        ECDsa keyPair = fixture.KeyPair;

        byte[] data = Encoding.UTF8.GetBytes("Data to Sign");
        byte[] signature = keyPair.SignData(data, HashAlgorithmName.SHA256);

        bool verified = keyPair.VerifyData(data, signature, HashAlgorithmName.SHA256);

        Assert.True(verified);
    }

}
