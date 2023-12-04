using System.Security.Cryptography;
using System.Text;
using Examples.Fluency;

namespace Examples.Cryptography.Tests.Algorithms.Symmetry;

public class AESAEADEncryptionTests
{
    private readonly ITestOutputHelper _output;

    public AESAEADEncryptionTests(ITestOutputHelper output)
    {
        _output = output;
    }

    [Fact]
    public void WhenDecryptingFromEncryptedData_WithGCMMode_ReturnsToBeforeData()
    {
        // Arrange.
        string original = "Here is some data to encrypt!";

        byte[] additionalAuthenticatedData
            = Encoding.UTF8.GetBytes("This message was sent 29th Feb at 11.00am - does not repeat"); // Max 64 byte.

        Span<byte> key = new byte[32];
        RandomNumberGenerator.Fill(key);

        // Act.
        var inputText = Encoding.UTF8.GetBytes(original);
        var (cipherText, nonce, tag) = Encrypt(inputText, key, additionalAuthenticatedData);

        _output.WriteLine("AES-GCM:");
        _output.WriteLine($"\tcipherText: {cipherText.ToArray().ToBase64String()}, {cipherText.Length}");
        _output.WriteLine($"\tnonce: {nonce.ToArray().ToBase64String()}, {nonce.Length}");
        _output.WriteLine($"\ttag {tag.ToArray().ToBase64String()}, {tag.Length}");

        var roundtrip = Decrypt(cipherText, nonce, tag, key, additionalAuthenticatedData);
        var outputText = Encoding.UTF8.GetString(roundtrip);

        // Assert.
        outputText.Is(original);

        return;

        static (byte[] cipherText, byte[] nonce, byte[] tag) Encrypt(
            ReadOnlySpan<byte> plainText,
            ReadOnlySpan<byte> key,
            ReadOnlySpan<byte> aad = default)
        {
            using var aes = new AesGcm(key, tagSizeInBytes: AesGcm.TagByteSizes.MaxSize);

            Span<byte> nonce = new byte[AesGcm.NonceByteSizes.MaxSize]; // 13 byte.
            RandomNumberGenerator.Fill(nonce);

            Span<byte> tag = new Byte[AesGcm.TagByteSizes.MaxSize]; // 16byte.

            Span<byte> cipherText = new byte[plainText.Length];

            aes.Encrypt(nonce, plainText, cipherText, tag, aad);

            return (cipherText.ToArray(), nonce.ToArray(), tag.ToArray());
        }

        static byte[] Decrypt(
            ReadOnlySpan<byte> cipherText,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> tag,
            ReadOnlySpan<byte> key,
            ReadOnlySpan<byte> aad = default)
        {
            using var aes = new AesGcm(key, tagSizeInBytes: AesGcm.TagByteSizes.MaxSize);

            Span<byte> plainText = new byte[cipherText.Length];

            aes.Decrypt(nonce, cipherText, tag, plainText, aad);

            return plainText.ToArray();
        }
    }


    [Fact]
    public void WhenDecryptingFromEncryptedData_WithCCMMode_ReturnsToBeforeData()
    {
        // Arrange.
        string original = "Here is some data to encrypt!";

        byte[] additionalAuthenticatedData
            = Encoding.UTF8.GetBytes("This message was sent 29th Feb at 11.00am - does not repeat"); // Max 64 byte.

        Span<byte> key = new byte[32];
        RandomNumberGenerator.Fill(key);

        // Act.
        var inputText = Encoding.UTF8.GetBytes(original);
        var (cipherText, nonce, tag) = Encrypt(inputText, key, additionalAuthenticatedData);

        _output.WriteLine("AES-CCM:");
        _output.WriteLine($"\tcipherText: {cipherText.ToArray().ToBase64String()}, {cipherText.Length}");
        _output.WriteLine($"\tnonce: {nonce.ToArray().ToBase64String()}, {nonce.Length}");
        _output.WriteLine($"\ttag {tag.ToArray().ToBase64String()}, {tag.Length}");

        var roundtrip = Decrypt(cipherText, nonce, tag, key, additionalAuthenticatedData);
        var outputText = Encoding.UTF8.GetString(roundtrip);

        // Assert.
        outputText.Is(original);

        return;

        static (byte[] cipherText, byte[] nonce, byte[] tag) Encrypt(
            ReadOnlySpan<byte> plainText,
            ReadOnlySpan<byte> key,
            ReadOnlySpan<byte> aad = default)
        {
            using var aes = new AesCcm(key);

            Span<byte> nonce = new byte[AesCcm.NonceByteSizes.MaxSize]; // 13 byte.
            RandomNumberGenerator.Fill(nonce);

            Span<byte> tag = new Byte[AesCcm.TagByteSizes.MaxSize]; // 16byte.

            Span<byte> cipherText = new byte[plainText.Length];

            aes.Encrypt(nonce, plainText, cipherText, tag, aad);

            return (cipherText.ToArray(), nonce.ToArray(), tag.ToArray());
        }

        static byte[] Decrypt(
            ReadOnlySpan<byte> cipherText,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> tag,
            ReadOnlySpan<byte> key,
            ReadOnlySpan<byte> aad = default)
        {
            using var aes = new AesCcm(key);

            Span<byte> plainText = new byte[cipherText.Length];

            aes.Decrypt(nonce, cipherText, tag, plainText, aad);

            return plainText.ToArray();
        }
    }

}
