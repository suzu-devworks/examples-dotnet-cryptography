using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace Examples.Cryptography.Tests.Algorithms.Asymmetry;

public class RSAEncryptionTests : IDisposable
{
    private readonly ITestOutputHelper _output;
    private readonly RSA _keyPair;

    public RSAEncryptionTests(ITestOutputHelper output)
    {
        /// ```shell
        /// dotnet test --logger "console;verbosity=detailed"
        /// ```
        _output = output;

        _keyPair = GenerateKeyPair();
    }

    public void Dispose()
    {
        _keyPair?.Dispose();
        GC.SuppressFinalize(this);
    }

    private RSA GenerateKeyPair()
    {
        var sw = Stopwatch.StartNew();

        var key = RSA.Create(keySizeInBits: 2048);

        sw.Stop();
        _output.WriteLine($"RSA generate time {sw.Elapsed}");

        return key;
    }


    [Fact]
    public void WhenDecryptingFromEncryptedData_WorksAsExpected()
    {
        // https://learn.microsoft.com/ja-jp/dotnet/api/system.security.cryptography.rsacryptoserviceprovider?view=net-7.0

        // ### Arrange. ###
        var provider = _keyPair!;

        var input = "Data to Encrypt";
        var actual = (string?)null;
        try
        {
            //Create a UnicodeEncoder to convert between byte array and string.
            //> var converter = new UnicodeEncoding();
            var converter = Encoding.UTF8;

            //Create byte arrays to hold original, encrypted, and decrypted data.
            byte[] dataToEncrypt = converter.GetBytes(input);
            byte[] encryptedData;
            byte[] decryptedData;

            //Create a new instance of RSACryptoServiceProvider to generate
            //public and private key data.
            //> 公開鍵データと秘密鍵データを生成するために、RSACryptoServiceProvider の新しいインスタンスを作成します。
            //> using var rsaProvider = new RSACryptoServiceProvider(2048);
            //using var rsaProvider = RSA.Create(2048);

            //Pass the data to ENCRYPT, the public key information
            //(using RSACryptoServiceProvider.ExportParameters(false),
            //and a boolean flag specifying no OAEP padding.
            //> ENCRYPT に公開鍵データを渡します.
            encryptedData = RSAEncrypt(dataToEncrypt,
                provider.ExportParameters(includePrivateParameters: false),
                doOAEPPadding: false);

            //Pass the data to DECRYPT, the private key information
            //(using RSACryptoServiceProvider.ExportParameters(true),
            //and a boolean flag specifying no OAEP padding.
            //> DECRYPT に秘密鍵データを渡します。
            decryptedData = RSADecrypt(encryptedData,
                provider.ExportParameters(includePrivateParameters: true),
                doOAEPPadding: false);

            actual = converter.GetString(decryptedData);

            //Display the decrypted plaintext to the console.
            _output.WriteLine("Decrypted plaintext: {0}", actual);
        }
        catch (ArgumentNullException)
        {
            //Catch this exception in case the encryption did
            //not succeed.
            _output.WriteLine("Encryption failed.");
            Assert.Fail("Encryption failed.");
        }

        actual.Is(input);
    }

    private byte[] RSAEncrypt(byte[] dataToEncrypt, RSAParameters rsaKeyInfo, bool doOAEPPadding)
    {
        try
        {
            byte[] encryptedData;
            //Create a new instance of RSACryptoServiceProvider.
            //> using (var rsaProvider = new RSACryptoServiceProvider())
            using (var rsaProvider = RSA.Create())
            {
                //Import the RSA Key information. This only needs
                //to include the public key information.
                //公開鍵をインポートします。
                rsaProvider.ImportParameters(rsaKeyInfo);

                //Encrypt the passed byte array and specify OAEP padding.
                //OAEP padding is only available on Microsoft Windows XP or
                //later.
                //> encryptedData = rsaProvider.Encrypt(dataToEncrypt, doOAEPPadding);
                var padding = (doOAEPPadding) ? RSAEncryptionPadding.OaepSHA256 : RSAEncryptionPadding.Pkcs1;
                encryptedData = rsaProvider.Encrypt(dataToEncrypt, padding);

            }
            return encryptedData;
        }
        //Catch and display a CryptographicException
        //to the console.
        catch (CryptographicException e)
        {
            _output.WriteLine(e.Message);
            throw;
            //return null;
        }
    }

    private byte[] RSADecrypt(byte[] dataToDecrypt, RSAParameters rsaKeyInfo, bool doOAEPPadding)
    {
        try
        {
            byte[] decryptedData;
            //Create a new instance of RSACryptoServiceProvider.
            //using (var rsa = new RSACryptoServiceProvider())
            using (var rsa = RSA.Create())
            {
                //Import the RSA Key information. This needs
                //to include the private key information.
                rsa.ImportParameters(rsaKeyInfo);

                //Decrypt the passed byte array and specify OAEP padding.
                //OAEP padding is only available on Microsoft Windows XP or
                //later.
                //> decryptedData = rsa.Decrypt(dataToDecrypt, doOAEPPadding);
                var padding = (doOAEPPadding) ? RSAEncryptionPadding.OaepSHA256 : RSAEncryptionPadding.Pkcs1;
                decryptedData = rsa.Decrypt(dataToDecrypt, padding);
            }
            return decryptedData;
        }
        //Catch and display a CryptographicException
        //to the console.
        catch (CryptographicException e)
        {
            _output.WriteLine(e.ToString());
            throw;
            //return null;
        }
    }


    [Fact]
    public void WhenDataSigning_WorksAsExpected()
    {
        // https://learn.microsoft.com/ja-jp/dotnet/api/system.security.cryptography.rsacryptoserviceprovider.signdata?view=net-7.0

        // ### Arrange. ###
        var provider = _keyPair!;

        try
        {
            // Create a UnicodeEncoder to convert between byte array and string.
            //> var converter = new ASCIIEncoding();
            var converter = Encoding.UTF8;

            var dataString = "Data to Sign";

            // Create byte arrays to hold original, encrypted, and decrypted data.
            byte[] originalData = converter.GetBytes(dataString);
            byte[] signedData;

            // Create a new instance of the RSACryptoServiceProvider class
            // and automatically create a new key-pair.
            //> var provider = new RSACryptoServiceProvider();
            //var provider = RSA.Create(2048);

            // Export the key information to an RSAParameters object.
            // You must pass true to export the private key for signing.
            // However, you do not need to export the private key
            // for verification.
            var key = provider.ExportParameters(true);

            // Hash and sign the data.
            signedData = HashAndSignBytes(originalData, key);

            // Verify the data and display the result to the
            // console.
            if (VerifySignedHash(originalData, signedData, key))
            {
                _output.WriteLine("The data was verified.");
            }
            else
            {
                _output.WriteLine("The data does not match the signature.");
            }
        }
        catch (ArgumentNullException)
        {
            _output.WriteLine("The data was not signed or verified");
            Assert.Fail("The data was not signed or verified.");

        }
    }

    private byte[] HashAndSignBytes(byte[] dataToSign, RSAParameters key)
    {
        try
        {
            // Create a new instance of RSACryptoServiceProvider using the
            // key from RSAParameters.
            //> var rsa = new RSACryptoServiceProvider();
            using var rsa = RSA.Create();

            rsa.ImportParameters(key);

            // Hash and sign the data. Pass a new instance of SHA256
            // to specify the hashing algorithm.
            //> return rsa.SignData(dataToSign, SHA256.Create());
            return rsa.SignData(dataToSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
        catch (CryptographicException e)
        {
            _output.WriteLine(e.Message);

            //return null;
            throw;
        }
    }

    private bool VerifySignedHash(byte[] dataToVerify, byte[] signedData, RSAParameters key)
    {
        try
        {
            // Create a new instance of RSACryptoServiceProvider using the
            // key from RSAParameters.
            //var rsa = new RSACryptoServiceProvider();
            using var rsa = RSA.Create();

            rsa.ImportParameters(key);

            // Verify the data using the signature.  Pass a new instance of SHA256
            // to specify the hashing algorithm.
            //> return rsa.VerifyData(dataToVerify, SHA256.Create(), signedData);
            return rsa.VerifyData(dataToVerify, signedData, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
        catch (CryptographicException e)
        {
            _output.WriteLine(e.Message);

            return false;
        }
    }

}
