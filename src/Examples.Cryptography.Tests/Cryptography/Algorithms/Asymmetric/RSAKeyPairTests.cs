using System.Security.Cryptography;

namespace Examples.Cryptography.Algorithms.Asymmetric;

public class RSAKeyPairTests
{
    private readonly ITestOutputHelper _output;

    public RSAKeyPairTests(ITestOutputHelper output)
    {
        _output = output;
    }


    [Fact]
    public void WhenExportAndImportPrivateKey()
    {
        // ```sh
        // $ openssl genrsa -out private.key 4096
        // $ openssl rsa -in private.key -inform pem -out private.der -outform der
        // ```

        // Arrange.
        var keySize = 4096;

        // Act.
        using var provider = RSA.Create(keySize);
        var exported = provider.ExportRSAPrivateKey();

        using var otherProvider = RSA.Create();
        otherProvider.ImportRSAPrivateKey(exported, out var readcount);
        var other = otherProvider.ExportRSAPrivateKey();

        // Assert.
        other.Is(exported);
        other.Length.Is(readcount);

        return;
    }


    [Fact]
    public void WhenExportAndImportPrivateKeyPem()
    {
        // ```sh
        // $ openssl genrsa -out private.key 4096
        // ```

        // Arrange.
        var keySize = 4096;

        // Act.
        using var provider = RSA.Create(keySize);
        var pem = provider.ExportRSAPrivateKeyPem();

        //File.WriteAllText(@"private.key", pem);
        _output.WriteLine($"\n{pem}");

        using var otherProvider = RSA.Create();
        otherProvider.ImportFromPem(pem);
        var other = otherProvider.ExportRSAPrivateKeyPem();

        // Assert.
        other.Is(pem);
        pem.Is(x => x.StartsWith("-----BEGIN RSA PRIVATE KEY-----")
                    && x.EndsWith("-----END RSA PRIVATE KEY-----"));

        return;
    }


    [Fact]
    public void WhenExportAndImportPrivateKeyXml()
    {
        // Arrange.
        var keySize = 4096;

        // Act.
        using var provider = RSA.Create(keySize);
        var xml = provider.ToXmlString(includePrivateParameters: true);

        _output.WriteLine($"\n{xml}");

        using var otherProvider = RSA.Create();
        otherProvider.FromXmlString(xml);

        var other = otherProvider.ToXmlString(includePrivateParameters: true);

        // Assert.
        other.Is(xml);

        return;
    }


    [Fact]
    public void WhenExportAndImportPublicKey()
    {
        //```sh
        // $ openssl genrsa -out private.key 4096
        // $ openssl rsa -pubout -in private.key -inform pem -out public.key -outform der
        //```

        // Arrange.
        var keySize = 4096;

        // Act.
        using var provider = RSA.Create(keySize);
        var exported = provider.ExportRSAPublicKey();

        using var otherProvider = RSA.Create();
        otherProvider.ImportRSAPublicKey(exported, out var readcount);
        var other = otherProvider.ExportRSAPublicKey();

        // Assert.
        other.Is(exported);
        other.Length.Is(readcount);
        Assert.Throws<CryptographicException>(() => otherProvider.ExportRSAPrivateKey());

        return;
    }


    [Fact]
    public void WhenExportAndImportPublicKeyPem()
    {
        //```sh
        // $ openssl genrsa -out private.key 4096
        // $ openssl rsa -pubout -in private.key -out public.key
        //```

        // Arrange.
        var keySize = 4096;

        // Act.
        using var provider = RSA.Create(keySize);
        var pem = provider.ExportRSAPublicKeyPem();

        //File.WriteAllText(@"public.key", pem);
        _output.WriteLine($"\n{pem}");

        using var otherProvider = RSA.Create();
        otherProvider.ImportFromPem(pem);
        var other = otherProvider.ExportRSAPublicKeyPem();

        // Assert.
        other.Is(pem);
        pem.Is(x => x.StartsWith("-----BEGIN RSA PUBLIC KEY-----")
                    && x.EndsWith("-----END RSA PUBLIC KEY-----"));

        Assert.Throws<CryptographicException>(() =>
            otherProvider.ExportRSAPrivateKeyPem());

        return;
    }


    [Fact]
    public void WhenExportAndImportPublicKeyXml()
    {
        // Arrange.
        var keySize = 4096;

        // Act.
        using var provider = RSA.Create(keySize);
        var xml = provider.ToXmlString(includePrivateParameters: false);

        _output.WriteLine($"\n{xml}");

        using var otherProvider = RSA.Create();
        otherProvider.FromXmlString(xml);
        var other = otherProvider.ToXmlString(includePrivateParameters: false);

        // Assert.
        other.Is(xml);
        Assert.Throws<CryptographicException>(() =>
            otherProvider.ExportRSAPrivateKeyPem());

        return;
    }


}
