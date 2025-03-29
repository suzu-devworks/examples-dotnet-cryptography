using System.Security.Cryptography;

namespace Examples.Cryptography.Tests.Algorithms.Asymmetry;

public class PemEncodingTests
{
    [Fact]
    public void WhenFindingAndExtractingDataFromPem_WithRSA_WorksAsExpected()
    {
        // Arrange.
        using var provider = RSA.Create(2048);
        var der = provider.ExportRSAPrivateKey();
        var pem = provider.ExportRSAPrivateKeyPem();

        // Act.
        var fields = PemEncoding.Find(pem);

        var base64 = pem[fields.Base64Data];
        var bytes = Convert.FromBase64String(base64);

        // Assert.
        fields.DecodedDataLength.Is(der.Length);
        fields.Location.Start.Is(0);
        //field.Location.End.Is(3246);
        fields.Label.Start.Is(11);
        fields.Label.End.Is(26);
        fields.Base64Data.Start.Is(32);
        //field.Base64Data.End.Is(3212);

        bytes.Is(der);
    }
}
