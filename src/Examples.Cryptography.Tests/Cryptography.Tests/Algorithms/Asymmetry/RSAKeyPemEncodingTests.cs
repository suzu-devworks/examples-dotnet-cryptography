using System.Security.Cryptography;

namespace Examples.Cryptography.Tests.Algorithms.Asymmetry;

public class RSAKeyPemEncodingTests(
    RSAKeyPemEncodingTests.Fixture fixture,
    ITestOutputHelper output)
    : IClassFixture<RSAKeyPemEncodingTests.Fixture>
{
    public class Fixture : IDisposable
    {
        public Fixture()
        {
            var dir = Environment.GetEnvironmentVariable("TEST_ASSETS_PATH") ?? Environment.CurrentDirectory;
            var path = Path.Combine(dir, "localhost.rsa.key");
            if (!File.Exists(path))
            {
                throw new FileNotFoundException("The PEM file was not found. Please create it using OpenSSL.", path);
            }
            Pem = File.ReadAllText(path);
        }
        public string Pem { get; }

        public void Dispose()
        {
            GC.SuppressFinalize(this);
        }
    }

    [Fact]
    public void When_FindIsUsedOnPemCreatedWithOpenSSL_Then_ParsingSucceeds()
    {
        // Finds the first PEM-encoded data.
        var pem = fixture.Pem;
        var fields = PemEncoding.Find(pem);

        output.WriteLine("DecodedDataLength: {0}", fields.DecodedDataLength);
        output.WriteLine("Location: {0}", fields.Location);
        output.WriteLine("Label: {0}", fields.Label);
        output.WriteLine("Base64Data: {0}", fields.Base64Data);

        output.WriteLine("{0}", pem[fields.Label]);
        output.WriteLine("{0}", pem[fields.Base64Data]);

        // Assert:

        // Gets the size of the decoded base-64 data, in bytes.
        Assert.True(fields.DecodedDataLength is >= 2300 and <= 2400);

        // Gets the location of the PEM-encoded text,
        // including the surrounding encapsulation boundaries.
        Assert.Equal(0, fields.Location.Start);
        Assert.True(fields.Location.End.Value is >= 3200 and <= 3300);

        // Gets the location of the label.
        Assert.Equal(11, fields.Label.Start);
        Assert.Equal(26, fields.Label.End);
        Assert.Equal("RSA PRIVATE KEY", pem[fields.Label]);

        // Gets the location of the base-64 data inside of the PEM.
        Assert.Equal(32, fields.Base64Data.Start);
        Assert.True(fields.Base64Data.End.Value is >= 3200 and <= 3300);

        var data = Convert.FromBase64String(pem[fields.Base64Data]);

        using RSA imported = RSA.Create();
        imported.ImportFromPem(pem);
        var der = imported.ExportRSAPrivateKey();
        Assert.Equal(der, data);
    }

}
