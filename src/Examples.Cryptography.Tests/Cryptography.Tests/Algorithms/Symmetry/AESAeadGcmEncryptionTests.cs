using System.Security.Cryptography;
using System.Text;

namespace Examples.Cryptography.Tests.Algorithms.Symmetry;

/// <summary>
/// Tests of AES Galois Counter Mode (GCM) Cipher Suites for TLS.
/// </summary>
/// <param name="output"></param>
/// <seealso href="https://datatracker.ietf.org/doc/html/rfc5288"/>
public class AESAeadGcmEncryptionTests
{
    private ITestOutputHelper? Output => TestContext.Current.TestOutputHelper;

    [Fact]
    public void When_EncryptedAndDecrypted_Then_StringIsRestored()
    {
        string original = "Here is some data to encrypt!";

        byte[] additionalAuthenticatedData
            = Encoding.UTF8.GetBytes("This message was sent 29th Feb at 11.00am - does not repeat"); // Max 64 byte.

        Span<byte> key = new byte[32];
        RandomNumberGenerator.Fill(key);

        var inputText = Encoding.UTF8.GetBytes(original);
        var (cipherText, nonce, tag) = Encrypt(inputText, key, additionalAuthenticatedData);

        var roundtrip = Decrypt(cipherText, nonce, tag, key, additionalAuthenticatedData);
        var outputText = Encoding.UTF8.GetString(roundtrip);

        //Display the original data and the decrypted data.
        Output?.WriteLine("Original:   {0}", original);
        Output?.WriteLine("Round Trip: {0}", outputText);

        // Assert:

        Assert.NotSame(original, roundtrip);
        Assert.Equal(original, outputText);

        static (byte[] cipherText, byte[] nonce, byte[] tag) Encrypt(
            ReadOnlySpan<byte> plainText,
            ReadOnlySpan<byte> key,
            ReadOnlySpan<byte> aad = default)
        {
            using var aes = new AesGcm(key, tagSizeInBytes: AesGcm.TagByteSizes.MaxSize);

            Span<byte> nonce = stackalloc byte[AesGcm.NonceByteSizes.MaxSize]; // 13 byte.
            RandomNumberGenerator.Fill(nonce);

            Span<byte> tag = stackalloc byte[AesGcm.TagByteSizes.MaxSize]; // 16byte.

            Span<byte> cipherText = stackalloc byte[plainText.Length];

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

            Span<byte> plainText = stackalloc byte[cipherText.Length];

            aes.Decrypt(nonce, cipherText, tag, plainText, aad);

            return plainText.ToArray();
        }

    }

}
