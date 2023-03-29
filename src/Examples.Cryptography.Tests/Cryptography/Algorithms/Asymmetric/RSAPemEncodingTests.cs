using System.Security.Cryptography;

namespace Examples.Cryptography.Algorithms.Asymmetric;

public class RSAPemEncodingTests
{
    [Fact]
    public void WhenFindDataPartsFromPem()
    {
        // Arrange.
        using var provider = RSA.Create(4096);
        var der = provider.ExportRSAPrivateKey();
        var pem = provider.ExportRSAPrivateKeyPem();

        // Act.
        var field = PemEncoding.Find(pem);

        var base64 = pem[field.Base64Data];
        var bytes = Convert.FromBase64String(base64);

        // Assert.
        field.DecodedDataLength.Is(der.Length);
        field.Location.Start.Is(0);
        //field.Location.End.Is(3246);
        field.Label.Start.Is(11);
        field.Label.End.Is(26);
        field.Base64Data.Start.Is(32);
        //field.Base64Data.End.Is(3212);

        bytes.Is(der);
    }
}
