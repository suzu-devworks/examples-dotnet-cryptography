using System.Security.Cryptography;

namespace Examples.Cryptography.Tests.Algorithms.Asymmetry;

public class RSAPemEncodingTests(ITestOutputHelper output)
{
    [Fact]
    public void When_FindIsUsedOnPemCreatedWithOpenSSL_Then_ParsingSucceeds()
    {
        var pem = PEM_WITH_OPEN_SSL;

        // Finds the first PEM-encoded data.
        var fields = PemEncoding.Find(pem);

        // Assert:

        // Gets the size of the decoded base-64 data, in bytes.
        Assert.Equal(2349, fields.DecodedDataLength);

        // Gets the location of the PEM-encoded text,
        // including the surrounding encapsulation boundaries.
        Assert.Equal(0, fields.Location.Start);
        Assert.Equal(3242, fields.Location.End);

        // Gets the location of the label.
        Assert.Equal(11, fields.Label.Start);
        Assert.Equal(26, fields.Label.End);
        Assert.Equal("RSA PRIVATE KEY", pem[fields.Label]);
        output.WriteLine("Label:", pem[fields.Label]);

        // Gets the location of the base-64 data inside of the PEM.
        Assert.Equal(32, fields.Base64Data.Start);
        Assert.Equal(3212, fields.Base64Data.End);
        output.WriteLine("Base64Data:", pem[fields.Base64Data]);

        var data = Convert.FromBase64String(pem[fields.Base64Data]);

        using RSA imported = RSA.Create();
        imported.ImportFromPem(pem);
        var der = imported.ExportRSAPrivateKey();
        Assert.Equal(der, data);
    }

    /// <summary>
    /// Example PEM-encoded RSA private key generated with OpenSSL.
    /// </summary>
    // spell-checker: disable
    private const string PEM_WITH_OPEN_SSL = """
        -----BEGIN RSA PRIVATE KEY-----
        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
        -----END RSA PRIVATE KEY-----
        """;
    // spell-checker: enable

}
