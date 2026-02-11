using System.Security.Cryptography;
using System.Text;

namespace Examples.Cryptography.Tests.Algorithms.Asymmetric.Rsa;

/// <summary>
/// Example signs and verifies data.
/// </summary>
/// <param name="fixture"></param>
/// <seealso href="https://learn.microsoft.com/ja-jp/dotnet/api/system.security.cryptography.rsacryptoserviceprovider.signdata"/>
public class RsaKeySigningTests(RsaKeyFixture fixture) : IClassFixture<RsaKeyFixture>
{
    private ITestOutputHelper? Output => TestContext.Current.TestOutputHelper;

    [Fact]
    public void When_DataIsSigned_Then_VerificationSucceeds()
    {
        try
        {
            // Create a UnicodeEncoder to convert between byte array and string.
            ASCIIEncoding converter = new();

            string dataString = "Data to Sign";

            // Create byte arraysっs to hold original, encrypted, and decrypted data.
            byte[] originalData = converter.GetBytes(dataString);
            byte[] signedData;

            // Create a new instance of the RSACryptoServiceProvider class
            // and automatically create a new key-pair.
            //# var rsa = new RSACryptoServiceProvider();
            var rsa = fixture.KeyPair;

            // Export the key information to an RSAParameters object.
            // You must pass true to export the private key for signing.
            // However, you do not need to export the private key
            // for verification.
            RSAParameters key = rsa.ExportParameters(includePrivateParameters: true);

            // Hash and sign the data.
            signedData = HashAndSignBytes(originalData, key);

            // Verify the data and display the result to the
            // console.
            if (VerifySignedHash(originalData, signedData, key))
            {
                Output?.WriteLine("The data was verified.");
            }
            else
            {
                Output?.WriteLine("The data does not match the signature.");
            }
        }
        catch (ArgumentNullException)
        {
            Output?.WriteLine("The data was not signed or verified");
            Assert.Fail("The data was not signed or verified.");
        }
    }

    private byte[] HashAndSignBytes(byte[] dataToSign, RSAParameters key)
    {
        try
        {
            // Create a new instance of RSACryptoServiceProvider using the
            // key from RSAParameters.
            //# RSACryptoServiceProvider rsaAlg = new RSACryptoServiceProvider();
            var rsaAlg = RSA.Create();

            rsaAlg.ImportParameters(key);

            // Hash and sign the data. Pass a new instance of SHA256
            // to specify the hashing algorithm.
            //# return rsa.SignData(dataToSign, SHA256.Create());
            return rsaAlg.SignData(dataToSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
        catch (CryptographicException e)
        {
            Output?.WriteLine(e.Message);

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
            //# RSACryptoServiceProvider rsaAlg = new RSACryptoServiceProvider();
            var rsaAlg = RSA.Create();

            rsaAlg.ImportParameters(key);

            // Verify the data using the signature.  Pass a new instance of SHA256
            // to specify the hashing algorithm.
            //# return rsa.VerifyData(dataToVerify, SHA256.Create(), signedData);
            return rsaAlg.VerifyData(dataToVerify, signedData,
                HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
        catch (CryptographicException e)
        {
            Output?.WriteLine(e.Message);

            return false;
        }
    }

}
