using System.Security.Cryptography;
using Examples.Cryptography.Tests.Fixtures.OpenSsl;

namespace Examples.Cryptography.Tests.Algorithms.Asymmetric.Rsa;

public class RsaKeyPemEncodingTests(RsaKeyOpenSslFixture fixture) : IClassFixture<RsaKeyOpenSslFixture>
{
    private ITestOutputHelper? Output => TestContext.Current.TestOutputHelper;

    [Fact]
    public void When_FindIsUsedOnPemCreatedWithOpenSSL_Then_ParsingSucceeds()
    {
        var pem = fixture.PrivateKeyPem;
        var fields = PemEncoding.Find(pem);

        Output?.WriteLine("DecodedDataLength: {0}", fields.DecodedDataLength);
        Output?.WriteLine("Location: {0}", fields.Location);
        Output?.WriteLine("Label: {0}", fields.Label);
        Output?.WriteLine("Base64Data: {0}", fields.Base64Data);

        Output?.WriteLine("{0}", pem[fields.Label]);
        Output?.WriteLine("{0}", pem[fields.Base64Data]);

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
