using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Xunit.Sdk;

namespace Examples.Cryptography.Tests.BouncyCastle.Algorithms.Symmetry;

public class AESEncryptionTests
{

    public static IEnumerable<object[]> GenerateAlgorithmData()
    {
        yield return new object[] { NistObjectIdentifiers.IdAes128Ccm, 16 };
        yield return new object[] { NistObjectIdentifiers.IdAes192Ccm, 24 };
        yield return new object[] { NistObjectIdentifiers.IdAes256Ccm, 32 };

        yield return new object[] { NistObjectIdentifiers.IdAes128Gcm, 16 };
        yield return new object[] { NistObjectIdentifiers.IdAes192Gcm, 24 };
        yield return new object[] { NistObjectIdentifiers.IdAes256Gcm, 32 };

        yield return new object[] { NistObjectIdentifiers.IdAes128Ecb, 16 };
        yield return new object[] { NistObjectIdentifiers.IdAes128Cbc, 16 };
        yield return new object[] { NistObjectIdentifiers.IdAes128Cfb, 16 };
        yield return new object[] { NistObjectIdentifiers.IdAes128Ofb, 16 };
    }

    [Theory]
    [MemberData(nameof(GenerateAlgorithmData))]
    public void WhenDecryptingAfterEncrypting_UsingAnyUtilities(
        DerObjectIdentifier algorithm,
        int keysize)
    {
        // https://github.com/bcgit/bc-csharp/blob/master/crypto/test/src/test/BaseBlockCipherTest.cs#L27

        var inputText = "Here is some data to encrypt!";

        CipherKeyGenerator generator = GeneratorUtilities.GetKeyGenerator(algorithm);
        KeyParameter keyParam = generator.GenerateKeyParameter();
        {
            byte[] encryptionKey = keyParam.GetKey();
            encryptionKey.Length.Is(keysize);

            // When generating only the key.
            byte[] otherKey = generator.GenerateKey();
            otherKey.Length.Is(keysize);
            otherKey.IsNot(encryptionKey); // key are different.

            // When specifying a key.
            KeyParameter specifyKeyParam = ParameterUtilities.CreateKeyParameter(algorithm, encryptionKey);
            specifyKeyParam.IsStructuralEqual(keyParam);
        }

        // It seems like there is no absorption here yet, hmm...
        ICipherParameters cipherParam = GetCipherParameters(algorithm, keyParam);

        // Encrypts or decrypts data in a single-part operation.
        var input = Encoding.UTF8.GetBytes(inputText);
        var encripted = Encrypt(algorithm, cipherParam, input);

        byte[] decripted = Decrypt(algorithm, cipherParam, encripted);
        var outputText = Encoding.UTF8.GetString(decripted);

        outputText.Is(inputText, "failed");

        return;

        static byte[] Encrypt(DerObjectIdentifier algorithm, ICipherParameters keyParam, byte[] plainTextData)
        {
            IBufferedCipher cipher = CipherUtilities.GetCipher(algorithm);
            cipher.Init(true, keyParam);

            return cipher.DoFinal(plainTextData);
        }

        static byte[] Decrypt(DerObjectIdentifier algorithm, ICipherParameters keyParam, byte[] cipherTextData)
        {
            IBufferedCipher cipher = CipherUtilities.GetCipher(algorithm);
            cipher.Init(false, keyParam);

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

                        cipherParam.IsInstanceOf<AeadParameters>().Is(p =>
                            (p.MacSize == (8 * ccm.IcvLen)) && (p.GetNonce().SequenceEqual(nonce)));
                    }
                    break;

                case "GCM":
                    {
                        byte[] nonce = random.GenerateSeed(length: 12); // - recommended size is 12 octets
                        GcmParameters gcm = new(nonce, icvLen: 12);     // DEFAULT 12
                        cipherParam = ParameterUtilities.GetCipherParameters(algorithm, keyParam, gcm.ToAsn1Object());

                        cipherParam.IsInstanceOf<AeadParameters>().Is(p =>
                            (p.MacSize == (8 * gcm.IcvLen)) && (p.GetNonce().SequenceEqual(nonce)));
                    }
                    break;

                default:
                    {
                        byte[] iv = random.GenerateSeed(length: 16); // AES block size.
                        cipherParam = ParameterUtilities.GetCipherParameters(
                            algorithm, keyParam, new DerOctetString(iv).ToAsn1Object());

                        cipherParam.IsInstanceOf<ParametersWithIV>().Is(p =>
                            (p.IVLength == 16) && (p.Parameters == keyParam));
                    }
                    break;
            }

            return cipherParam;
        }
    }

    public static IEnumerable<object[]> GenerateDataForUsingOidTest()
    {
        yield return new object[] { NistObjectIdentifiers.IdAes128Ecb };
        yield return new object[] { NistObjectIdentifiers.IdAes128Cbc };
        yield return new object[] { NistObjectIdentifiers.IdAes128Cfb };
        yield return new object[] { NistObjectIdentifiers.IdAes128Ofb };
    }

    [Theory]
    [MemberData(nameof(GenerateDataForUsingOidTest))]
    public void WhenDecryptingAfterEncrypting_UsingOidTestAsReference(DerObjectIdentifier algorithm)
    {
        // https://github.com/bcgit/bc-csharp/blob/master/crypto/test/src/test/BaseBlockCipherTest.cs#L27

        var inputText = "Here is some data to encrypt!";

        var name = CipherUtilities.GetAlgorithmName(algorithm);

        // Create the cipher object for AES algorithm.
        IBufferedCipher c1 = CipherUtilities.GetCipher(algorithm.Id);
        IBufferedCipher c2 = CipherUtilities.GetCipher(name);

        // // CipherKeyGenerator is useful for creating random keys.
        CipherKeyGenerator kg = GeneratorUtilities.GetKeyGenerator(algorithm);
        byte[] key = kg.GenerateKey();

        KeyParameter k = ParameterUtilities.CreateKeyParameter(algorithm.Id, key);

        ICipherParameters cp = k;
        if (name.IndexOf("/ECB/") < 0)
        {
            cp = new ParametersWithIV(cp, new byte[16]);
        }

        // Initialize this cipher with a set of algorithm parameters.
        c1.Init(true, cp);
        c2.Init(false, cp);

        // Encrypts or decrypts data in a single-part operation.
        var input = Encoding.UTF8.GetBytes(inputText);
        var encripted = c1.DoFinal(input);

        byte[] decripted = c2.DoFinal(encripted);
        var outputText = Encoding.UTF8.GetString(decripted);

        outputText.Is(inputText, "failed");

        return;
    }


    [Fact]
    public void WhenDecryptingAfterEncrypting_UsingDoCipherTest()
    {
        // https://github.com/bcgit/bc-csharp/blob/master/crypto/test/src/test/AESTest.cs#L146

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

        return;

        static void DoCipherTest(int strength, byte[] keyBytes, byte[] input, byte[] output)
        {
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
                throw new XunitException("AES failed initialisation - " + e, e);
            }

            try
            {
                // Initialize this cipher with a set of algorithm parameters.
                inCipher.Init(false, key);
            }
            catch (Exception e)
            {
                throw new XunitException("AES failed initialisation - " + e, e);
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

            bytes.Is(output, $"AES {strength} failed encryption - expected ");

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
                throw new XunitException("AES failed encryption - " + e, e);
            }

            bytes.Is(input, $"AES {strength} failed decryption - expected.");

        }
    }


    [Fact]
    public void WhenDecryptingAfterEncrypting_UsingStackoverflow()
    {
        //https://stackoverflow.com/questions/41005321/unable-to-exchange-aes-256-cbc-pkcs7-between-c-sharp-bouncycastle-and-php-openss

        var inputText = "Here is some data to encrypt!";

        var algorithm = "AES/CBC/PKCS7";

        var random = new SecureRandom();
        byte[] iv = random.GenerateSeed(length: 16);
        byte[] encryptionKey = random.GenerateSeed(length: 32);

        var input = Encoding.UTF8.GetBytes(inputText);
        var encripted = Encrypt(input, encryptionKey, iv);

        var decripted = Decrypt(encripted, encryptionKey, iv);
        var outputText = Encoding.UTF8.GetString(decripted);

        outputText.Is(inputText);
        Encoding.UTF8.GetString(encripted).IsNot(inputText);

        return;

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
