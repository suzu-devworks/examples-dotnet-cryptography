using System.Security.Cryptography;
using System.Text;

namespace Examples.Cryptography.Tests.Algorithms.Asymmetric.Rsa;

/// <summary>
/// Example uses the RSA class to encrypt a string into an array of bytes and then decrypt the bytes back into a string.
/// </summary>
/// <param name="fixture"></param>
/// <seealso href="https:// learn.microsoft.com/ja-jp/dotnet/api/system.security.cryptography.rsacryptoserviceprovider"/>
public class RsaKeyEncryptionTests(RsaKeyFixture fixture) : IClassFixture<RsaKeyFixture>
{
    private ITestOutputHelper? Output => TestContext.Current.TestOutputHelper;

    [Fact]
    public void When_DataIsEncryptedAndDecrypted_Then_OriginalDataIsRestored()
    {
        try
        {
            // Create a UnicodeEncoder to convert between byte array and string.

            UnicodeEncoding converter = new();

            // Create byte arrays to hold original, encrypted, and decrypted data.
            byte[] dataToEncrypt = converter.GetBytes("Data to Encrypt");
            byte[] encryptedData;
            byte[] decryptedData;

            // Create a new instance of RSACryptoServiceProvider to generate
            // public and private key data.
            //# 公開鍵データと秘密鍵データを生成するために、RSACryptoServiceProvider の新しいインスタンスを作成します。
            //# using var rsa = new RSACryptoServiceProvider();
            var rsa = fixture.KeyPair;
            {
                // Pass the data to ENCRYPT, the public key information
                // (using RSACryptoServiceProvider.ExportParameters(false),
                // and a boolean flag specifying no OAEP padding.
                //# ENCRYPT に公開鍵データを渡します.
                encryptedData = RSAEncrypt(dataToEncrypt,
                    rsa.ExportParameters(includePrivateParameters: false),
                    doOAEPPadding: false);

                // Pass the data to DECRYPT, the private key information
                // (using RSACryptoServiceProvider.ExportParameters(true),
                // and a boolean flag specifying no OAEP padding.
                //# DECRYPT に秘密鍵データを渡します。
                decryptedData = RSADecrypt(encryptedData,
                    rsa.ExportParameters(includePrivateParameters: true),
                    doOAEPPadding: false);

                // Display the decrypted plaintext to the console.
                Output?.WriteLine("Decrypted plaintext: {0}", converter.GetString(decryptedData));
            }

            // Assert:

            //# was restored to original.
            Assert.Equal(dataToEncrypt, decryptedData);

        }
        catch (ArgumentNullException)
        {
            // Catch this exception in case the encryption did
            // not succeed.
            Output?.WriteLine("Encryption failed.");

            //# Assert
            Assert.Fail("Encryption failed.");
        }

    }

    private byte[] RSAEncrypt(byte[] dataToEncrypt, RSAParameters rsaKeyInfo, bool doOAEPPadding)
    {
        try
        {
            byte[] encryptedData;
            // Create a new instance of RSACryptoServiceProvider.
            //# using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            using (var rsa = RSA.Create())
            {
                // Import the RSA Key information. This only needs
                // to include the public key information.
                //# 公開鍵をインポートします。
                rsa.ImportParameters(rsaKeyInfo);

                // Encrypt the passed byte array and specify OAEP padding.
                // OAEP padding is only available on Microsoft Windows XP or
                // later.
                //# Explicitly specify not to use SHA-1.
                //# encryptedData = rsa.Encrypt(dataToEncrypt, doOAEPPadding);
                encryptedData = rsa.Encrypt(dataToEncrypt,
                    doOAEPPadding ? RSAEncryptionPadding.OaepSHA256 : RSAEncryptionPadding.Pkcs1);

            }
            return encryptedData;
        }
        // Catch and display a CryptographicException
        // to the console.
        catch (CryptographicException e)
        {
            Output?.WriteLine(e.Message);

            //# return null;
            throw;
        }
    }

    private byte[] RSADecrypt(byte[] dataToDecrypt, RSAParameters rsaKeyInfo, bool doOAEPPadding)
    {
        try
        {
            byte[] decryptedData;
            // Create a new instance of RSACryptoServiceProvider.
            // using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            using (var rsa = RSA.Create())
            {
                // Import the RSA Key information. This needs
                // to include the private key information.
                rsa.ImportParameters(rsaKeyInfo);

                // Decrypt the passed byte array and specify OAEP padding.
                // OAEP padding is only available on Microsoft Windows XP or
                // later.
                //# Explicitly specify not to use SHA-1.
                //# decryptedData = rsa.Decrypt(dataToDecrypt, doOAEPPadding);
                decryptedData = rsa.Decrypt(dataToDecrypt,
                    doOAEPPadding ? RSAEncryptionPadding.OaepSHA256 : RSAEncryptionPadding.Pkcs1);
            }
            return decryptedData;
        }
        // Catch and display a CryptographicException
        // to the console.
        catch (CryptographicException e)
        {
            Output?.WriteLine(e.ToString());

            //# return null;
            throw;
        }
    }

}
