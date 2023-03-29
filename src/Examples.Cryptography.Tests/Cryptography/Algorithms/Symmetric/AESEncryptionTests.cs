using System.Security.Cryptography;
using System.Text;

namespace Examples.Cryptography.Algorithms.Symmetric;

public class AESEncryptionTests
{
    private readonly ITestOutputHelper _output;

    public AESEncryptionTests(ITestOutputHelper output)
    {
        _output = output;
    }

    [Fact]
    public void WhenEncryptAndDecrypy_WithStream()
    {
        // https://learn.microsoft.com/ja-jp/dotnet/api/system.security.cryptography.aes?view=net-7.0

        string original = "Here is some data to encrypt!";

        // Create a new instance of the Aes
        // class.  This generates a new key and initialization
        // vector (IV).
        using var aes = Aes.Create();
        //aes.KeySize = 256; //default.
        //aes.BlockSize = 128; //default.
        //aes.Mode = CipherMode.CBC; //default.
        //aes.Padding = PaddingMode.PKCS7; //default.

        // Encrypt the string to an array of bytes.
        var encrypted = Encrypt(original, aes.Key, aes.IV);

        // Decrypt the bytes to a string.
        var roundtrip = Decrypt(encrypted, aes.Key, aes.IV);

        // Assert.
        roundtrip.Is(original);

        //Display the original data and the decrypted data.
        _output.WriteLine("Original:   {0}", original);
        _output.WriteLine("Round Trip: {0}", roundtrip);

    }

    private static byte[] Encrypt(string plainText, byte[] key, byte[] initialVector)
    {
        byte[] encrypted;

        // Create an Aes object
        // with the specified key and IV.
        using (var aes = Aes.Create())
        {
            aes.Key = key;
            aes.IV = initialVector;

            // Create an encryptor to perform the stream transform.
            var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

            // Create the streams used for encryption.
            using var stream = new MemoryStream();

            using (var cryptoStream = new CryptoStream(stream, encryptor, CryptoStreamMode.Write))
            //> using (var writer = new StreamWriter(cryptoStream))
            using (var writer = new BinaryWriter(cryptoStream))
            {
                //Write all data to the stream.
                //> writer.Write(plainText);
                var bytes = Encoding.UTF8.GetBytes(plainText);
                writer.Write(bytes, 0, bytes.Length);
            }

            encrypted = stream.ToArray();
        }

        // Return the encrypted bytes from the memory stream.
        return encrypted;
    }

    private static string Decrypt(byte[] cipherText, byte[] key, byte[] initialVector)
    {
        // Declare the string used to hold
        // the decrypted text.
        string? plaintext = null;

        // Create an Aes object
        // with the specified key and IV.
        using (var aes = Aes.Create())
        {
            aes.Key = key;
            aes.IV = initialVector;

            // Create a decryptor to perform the stream transform.
            var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

            // Create the streams used for decryption.
            using var stream = new MemoryStream(cipherText);
            using var cryptoStream = new CryptoStream(stream, decryptor, CryptoStreamMode.Read);
            //> using var reader = new StreamReader(cryptoStream);

            // Read the decrypted bytes from the decrypting stream
            // and place them in a string.
            //> plaintext = reader.ReadToEnd();
            using var output = new MemoryStream();
            cryptoStream.CopyTo(output);
            plaintext = Encoding.UTF8.GetString(output.ToArray());
        }

        return plaintext;
    }

    [Fact]
    public void WhenEncryptAndDecrypy_WithTransform()
    {
        string original = "Here is some data to encrypt!";

        using var aes = Aes.Create();

        var encrypted = EncryptWithTransform(original, aes.Key, aes.IV);

        var roundtrip = DecryptWithTransform(encrypted, aes.Key, aes.IV);

        roundtrip.Is(original);
    }

    private static byte[] EncryptWithTransform(string plainText, byte[] key, byte[] iv)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;

        using var encryptor = aes.CreateEncryptor();

        var bytes = Encoding.UTF8.GetBytes(plainText);
        byte[] encrypted = encryptor.TransformFinalBlock(bytes, 0, bytes.Length);

        return encrypted;
    }

    private static string DecryptWithTransform(byte[] ciphertext, byte[] key, byte[] iv)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;

        using var decryptor = aes.CreateDecryptor();

        var bytes = decryptor.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
        var plaintext = Encoding.UTF8.GetString(bytes);

        return plaintext;
    }

}
