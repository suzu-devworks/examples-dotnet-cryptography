using System.Text;
using Examples.Cryptography.BouncyCastle.Symmetric;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Xunit.Sdk;

namespace Examples.Cryptography.BouncyCastle.Tests.Algorithms.Symmetric.Aes;

/// <summary>
/// Tests for AES encryption and decryption using BouncyCastle library.
/// </summary>
public class AesEncryptionTests
{
    /// <summary>
    /// When encrypting and then decrypting data, the original data should be restored.
    /// </summary>
    /// <param name="mode"></param>
    /// <param name="keySize"></param>
    [Theory]
    [InlineData(BlockCipherModes.Ecb, 16)]
    [InlineData(BlockCipherModes.Cbc, 16)]
    [InlineData(BlockCipherModes.Cfb, 16)]
    [InlineData(BlockCipherModes.Ofb, 16)]
    [InlineData(BlockCipherModes.Ccm, 16)]
    [InlineData(BlockCipherModes.Ccm, 24)]
    [InlineData(BlockCipherModes.Ccm, 32)]
    [InlineData(BlockCipherModes.Gcm, 16)]
    [InlineData(BlockCipherModes.Gcm, 24)]
    [InlineData(BlockCipherModes.Gcm, 32)]
    public void When_DecryptingAfterEncrypting_Then_OriginalDataIsRestored(BlockCipherModes mode, int keySize)
    {
        var inputText = "Here is some data to encrypt!";

        var algorithm = mode.GetAesAlgorithm(keySize);

        CipherKeyGenerator generator = GeneratorUtilities.GetKeyGenerator(algorithm);
        KeyParameter keyParam = generator.GenerateKeyParameter();

        // It seems like there is no absorption here yet, hmm...
        ICipherParameters cipherParam = GetCipherParameters(algorithm, keyParam);

        // Encrypts or decrypts data in a single-part operation.
        var input = Encoding.UTF8.GetBytes(inputText);
        var encrypted = Encrypt(algorithm, cipherParam, input);

        byte[] decrypted = Decrypt(algorithm, cipherParam, encrypted);
        var outputText = Encoding.UTF8.GetString(decrypted);

        // Assert:

        Assert.Equal(inputText, outputText);

        byte[] encryptionKey = keyParam.GetKey();
        Assert.Equal(keySize, encryptionKey.Length);

        // When generating only the key.
        byte[] otherKey = generator.GenerateKey();
        Assert.Equal(keySize, otherKey.Length);
        Assert.NotEqual(encryptionKey, otherKey); // key are different.

        // When specifying a key.
        KeyParameter specifyKeyParam = ParameterUtilities.CreateKeyParameter(algorithm, encryptionKey);
        Assert.Equal(encryptionKey, specifyKeyParam.GetKey());

        static byte[] Encrypt(DerObjectIdentifier algorithm, ICipherParameters keyParam, byte[] plainTextData)
        {
            IBufferedCipher cipher = CipherUtilities.GetCipher(algorithm);
            cipher.Init(forEncryption: true, keyParam);

            return cipher.DoFinal(plainTextData);
        }

        static byte[] Decrypt(DerObjectIdentifier algorithm, ICipherParameters keyParam, byte[] cipherTextData)
        {
            IBufferedCipher cipher = CipherUtilities.GetCipher(algorithm);
            cipher.Init(forEncryption: false, keyParam);

            return cipher.DoFinal(cipherTextData);
        }

        static ICipherParameters GetCipherParameters(DerObjectIdentifier algorithm, KeyParameter keyParam)
        {
            var random = new SecureRandom();
            var name = CipherUtilities.GetAlgorithmName(algorithm);

            ICipherParameters cipherParam;
            switch (name.Split('/')[1])
            {
                case "ECB":
                    cipherParam = keyParam;
                    break;

                case "CCM":
                    {
                        byte[] nonce = random.GenerateSeed(length: 13); // SIZE(7..13)
                        CcmParameters ccm = new(nonce, icvLen: 12);     // DEFAULT 12
                        cipherParam = ParameterUtilities.GetCipherParameters(algorithm, keyParam, ccm.ToAsn1Object());
                    }
                    break;

                case "GCM":
                    {
                        byte[] nonce = random.GenerateSeed(length: 12); // - recommended size is 12 octets
                        GcmParameters gcm = new(nonce, icvLen: 12);     // DEFAULT 12
                        cipherParam = ParameterUtilities.GetCipherParameters(algorithm, keyParam, gcm.ToAsn1Object());
                    }
                    break;

                default:
                    {
                        byte[] iv = random.GenerateSeed(length: 16); // AES block size.
                        cipherParam = ParameterUtilities.GetCipherParameters(
                            algorithm, keyParam, new DerOctetString(iv).ToAsn1Object());
                    }
                    break;
            }

            return cipherParam;
        }
    }

    /// <summary>
    /// When encrypting and then decrypting data, the original data should be restored.
    /// This test is based on the test code on the official website.
    /// </summary>
    /// <param name="mode"></param>
    /// <param name="keySize"></param>
    /// <seealso href="https://github.com/bcgit/bc-csharp/blob/master/crypto/test/src/test/BaseBlockCipherTest.cs#L27" />
    [Theory]
    [InlineData(BlockCipherModes.Ecb, 16)]
    [InlineData(BlockCipherModes.Cbc, 16)]
    [InlineData(BlockCipherModes.Cfb, 16)]
    [InlineData(BlockCipherModes.Ofb, 16)]
    [InlineData(BlockCipherModes.Ccm, 16)]
    [InlineData(BlockCipherModes.Gcm, 16)]
    public void When_DecryptingAfterEncrypting_WithBlockCipherTest_Then_OriginalDataIsRestored(BlockCipherModes mode, int keySize)
    {
        byte[] data = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };

        var algorithm = mode.GetAesAlgorithm(keySize);
        var name = CipherUtilities.GetAlgorithmName(algorithm);

        // Create the cipher object for AES algorithm.
        IBufferedCipher c1 = CipherUtilities.GetCipher(algorithm.Id);
        IBufferedCipher c2 = CipherUtilities.GetCipher(name);

        // // CipherKeyGenerator is useful for creating random keys.
        CipherKeyGenerator generator = GeneratorUtilities.GetKeyGenerator(algorithm);
        byte[] key = generator.GenerateKey();

        KeyParameter k = ParameterUtilities.CreateKeyParameter(algorithm.Id, key);

        ICipherParameters cp = GetCipherParameters(algorithm, k);

        // Initialize this cipher with a set of algorithm parameters.
        c1.Init(forEncryption: true, cp);
        c2.Init(forEncryption: false, cp);

        // Encrypts or decrypts data in a single-part operation.
        byte[] result = c2.DoFinal(c1.DoFinal(data));

        // Assert:

        Assert.Equal(data, result);
        Assert.Equal(keySize, key.Length);

        static ICipherParameters GetCipherParameters(DerObjectIdentifier algorithm, KeyParameter k)
        {
            var name = CipherUtilities.GetAlgorithmName(algorithm);

            return name switch
            {
                var n when n.Contains("/ECB/") => k,
                var n when n.Contains("/CCM/") => new ParametersWithIV(k, new byte[13]),
                var n when n.Contains("/GCM/") => new ParametersWithIV(k, new byte[12]),
                _ => new ParametersWithIV(k, new byte[16])
            };
        }
    }

    /// <summary>
    /// When encrypting and then decrypting data using CipherStream, the original data should be restored.
    /// This test is based on the test code on the official website.
    /// </summary>
    /// <exception cref="XunitException"></exception>
    /// <exception cref="EndOfStreamException"></exception>
    /// <seealso href="https://github.com/bcgit/bc-csharp/blob/master/crypto/test/src/test/AESTest.cs#L146" />
    [Fact]
    public void When_DecryptingAfterEncrypting_WithCipherStream_Then_OriginalDataIsRestored()
    {
        DoCipherTest(128,
            Convert.FromHexString("000102030405060708090a0b0c0d0e0f"), // 16 bytes
            Convert.FromHexString("00112233445566778899aabbccddeeff"), // 16 bytes
            Convert.FromHexString("69c4e0d86a7b0430d8cdb78070b4c55a")
            );

        DoCipherTest(192,
            Convert.FromHexString("000102030405060708090a0b0c0d0e0f1011121314151617"), // 24 bytes
            Convert.FromHexString("00112233445566778899aabbccddeeff"), // 16 bytes
            Convert.FromHexString("dda97ca4864cdfe06eaf70a0ec0d7191")
            );

        DoCipherTest(256,
            Convert.FromHexString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"), // 32 bytes
            Convert.FromHexString("00112233445566778899aabbccddeeff"), // 16 bytes
            Convert.FromHexString("8ea2b7ca516745bfeafc49904b496089")
            );

        static void DoCipherTest(int strength, byte[] keyBytes, byte[] input, byte[] output)
        {
            _ = strength; // unused, but we want to keep it for readability.

            // Setting up AES encryption Key.
            KeyParameter key = ParameterUtilities.CreateKeyParameter("AES", keyBytes);

            // Create the cipher object for AES algorithm.
            IBufferedCipher inCipher = CipherUtilities.GetCipher("AES/ECB/NoPadding");
            IBufferedCipher outCipher = CipherUtilities.GetCipher("AES/ECB/NoPadding");

            try
            {
                // Initialize this cipher with a set of algorithm parameters.
                outCipher.Init(true, key);
            }
            catch (Exception e)
            {
                throw new XunitException("AES failed initialization - " + e, e);
            }

            try
            {
                // Initialize this cipher with a set of algorithm parameters.
                inCipher.Init(false, key);
            }
            catch (Exception e)
            {
                throw new XunitException("AES failed initialization - " + e, e);
            }

            //
            // encryption pass
            //
            MemoryStream bOut = new();
            CipherStream cOut = new(bOut, null, outCipher);

            try
            {
                for (int i = 0; i != input.Length / 2; i++)
                {
                    cOut.WriteByte(input[i]);
                }
                cOut.Write(input, input.Length / 2, input.Length - input.Length / 2);
                cOut.Close();
            }
            catch (IOException e)
            {
                throw new XunitException("AES failed encryption - " + e, e);
            }

            byte[] bytes = bOut.ToArray();

            Assert.Equal(output, bytes);

            //
            // decryption pass
            //
            MemoryStream bIn = new(bytes, false);
            CipherStream cIn = new(bIn, inCipher, null);

            try
            {
                BinaryReader dIn = new(cIn);

                bytes = new byte[input.Length];

                for (int i = 0; i != input.Length / 2; i++)
                {
                    bytes[i] = dIn.ReadByte();
                }

                int remaining = bytes.Length - input.Length / 2;
                byte[] extra = dIn.ReadBytes(remaining);
                if (extra.Length < remaining)
                    throw new EndOfStreamException();
                extra.CopyTo(bytes, input.Length / 2);
            }
            catch (Exception e)
            {
                throw new XunitException("AES failed decryption - " + e, e);
            }

            Assert.Equal(input, bytes);
        }
    }

    /// <summary>
    /// When encrypting and then decrypting, the original data should be restored.
    /// This test is adapted from a StackOverflow post.
    /// </summary>
    /// <seealso href="https://stackoverflow.com/questions/41005321/unable-to-exchange-aes-256-cbc-pkcs7-between-c-sharp-bouncycastle-and-php-openss"/>
    [Fact]
    public void When_DecryptingAfterEncrypting_WithStackOverflow_Then_OriginalDataIsRestored()
    {
        var inputText = "Here is some data to encrypt!";

        var algorithm = "AES/CBC/PKCS7";

        var random = new SecureRandom();
        byte[] iv = random.GenerateSeed(length: 16);
        byte[] encryptionKey = random.GenerateSeed(length: 32);

        var input = Encoding.UTF8.GetBytes(inputText);
        var encrypted = Encrypt(input, encryptionKey, iv);

        var decrypted = Decrypt(encrypted, encryptionKey, iv);
        var outputText = Encoding.UTF8.GetString(decrypted);

        Assert.Equal(inputText, outputText);

        byte[] Encrypt(byte[] input, byte[] encryptionKey, byte[] iv)
        {
            // Setting up AES encryption Key.
            KeyParameter keyParam = ParameterUtilities.CreateKeyParameter("AES", encryptionKey);

            // Setting up the Initialization Vector.
            ICipherParameters aesParam = new ParametersWithIV(keyParam, iv);

            // Create the cipher object for AES algorithm.
            IBufferedCipher cipher = CipherUtilities.GetCipher(algorithm);
            // Initialize this cipher with a set of algorithm parameters.
            cipher.Init(forEncryption: true, aesParam);
            // Encrypts or decrypts data in a single-part operation.
            byte[] output = cipher.DoFinal(input);

            return output;
        }

        byte[] Decrypt(byte[] input, byte[] encryptionKey, byte[] iv)
        {
            // Setting up AES encryption Key.
            KeyParameter keyParam = ParameterUtilities.CreateKeyParameter("AES", encryptionKey);

            // Setting up the Initialization Vector.
            ICipherParameters aesParam = new ParametersWithIV(keyParam, iv);

            // Create the cipher object for AES algorithm.
            IBufferedCipher cipher = CipherUtilities.GetCipher(algorithm);
            // Initialize this cipher with a set of algorithm parameters.
            cipher.Init(forEncryption: false, aesParam);
            // Encrypts or decrypts data in a single-part operation.
            byte[] output = cipher.DoFinal(input);

            return output;
        }
    }
}
