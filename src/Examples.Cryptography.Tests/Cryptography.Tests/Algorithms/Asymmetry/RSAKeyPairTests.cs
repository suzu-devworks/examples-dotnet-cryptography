using System.Security.Cryptography;

namespace Examples.Cryptography.Tests.Algorithms.Asymmetry;

public class RSAKeyPairTests : IDisposable
{
    private readonly ITestOutputHelper _output;
    private readonly RSA _keyPair;

    public RSAKeyPairTests(ITestOutputHelper output)
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

    private static RSA GenerateKeyPair()
        => RSA.Create(keySizeInBits: 2048);


    [Fact]
    public void WhenImportingFromExportRSAPrivateKey_ReturnsToBeforeExport()
    {
        // ```shell
        // $ openssl rsa -in private.key -inform pem -out private.der -outform der
        // ```

        // ### Arrange. ###
        var keyPair = _keyPair!;

        // ### Act. ###
        var exported = keyPair.ExportRSAPrivateKey();

        using var actual = RSA.Create();
        actual.ImportRSAPrivateKey(exported, out var readcount);

        // ### Assert. ###
        // How to check equals?
        actual.IsNot(keyPair);

        // Is it a　success if the arrays are equal?.
        var other = actual.ExportRSAPrivateKey();
        other.Is(exported);
        other.Length.Is(readcount);

        return;
    }


    [Fact]
    public void WhenImportingFromExportPrivateKeyPem_ReturnsToBeforeExport()
    {
        // ```shell
        // $ openssl rsa -in private.der -inform der -out private.key -outform pem
        // ```

        // ### Arrange. ###
        var keyPair = _keyPair!;

        // ### Act. ###
        var pem = keyPair.ExportRSAPrivateKeyPem();

        using var actual = RSA.Create();
        actual.ImportFromPem(pem);

        // ### Assert. ###
        // How to check equals?
        actual.IsNot(keyPair);

        // Is it a　success if the arrays are equal?.
        var other = actual.ExportRSAPrivateKeyPem();
        other.Is(pem);

        // PEM assertions
        pem.Is(x => x.StartsWith("-----BEGIN RSA PRIVATE KEY-----")
                    && x.EndsWith("-----END RSA PRIVATE KEY-----"));

        _output.WriteLine($"{pem}");
        //File.WriteAllText(@"rsa-private.key", pem);

        return;
    }


    [Fact]
    public void WhenImportingFromToXmlString_IncludePrivateKey_ReturnsToBeforeExport()
    {
        // ### Arrange. ###
        var keyPair = (RSA)_keyPair;

        // ### Act. ###
        var xml = keyPair.ToXmlString(includePrivateParameters: true);

        using var actual = RSA.Create();
        actual.FromXmlString(xml);

        // ### Assert. ###
        // How to check equals?
        actual.IsNot(keyPair);

        // Is it a　success if the arrays are equal?.
        var other = actual.ToXmlString(includePrivateParameters: true);
        other.Is(xml);

        _output.WriteLine($"{xml}");
        //File.WriteAllText(@"rsa-private.xml", xml);

        return;
    }


    [Fact]
    public void WhenImportingFromExportRSAPublicKey_ReturnsOnlyPublicKey()
    {
        //```shell
        // $ openssl rsa -pubout -in private.key -inform pem -out public.key -outform der
        //```

        // ### Arrange. ###
        var keyPair = (RSA)_keyPair;

        // ### Act. ###
        var exported = keyPair.ExportRSAPublicKey();

        using var actual = RSA.Create();
        actual.ImportRSAPublicKey(exported, out var readCount);

        // ### Assert. ###
        // How to check equals?
        actual.IsNot(keyPair);

        // Is it a　success if the arrays are equal?.
        var other = actual.ExportRSAPublicKey();
        other.Is(exported);
        other.Length.Is(readCount);

        // Exporting the private key will fail
        // because only the public key has been restored.
        Assert.Throws<CryptographicException>(() =>
            actual.ExportRSAPrivateKey());

        return;
    }


    [Fact]
    public void WhenImportingFromExportRSAPublicKeyPem_ReturnsOnlyPublicKey()
    {
        //```shell
        // $ openssl rsa -pubout -in private.key -out public.key
        //```

        // ### Arrange. ###
        var keyPair = (RSA)_keyPair;

        // ### Act. ###
        var pem = keyPair.ExportRSAPublicKeyPem();

        using var actual = RSA.Create();
        actual.ImportFromPem(pem);

        // ### Assert. ###
        // How to check equals?
        actual.IsNot(keyPair);

        // Is it a　success if the arrays are equal?.
        var other = actual.ExportRSAPublicKeyPem();
        other.Is(pem);

        // PEM assertions
        pem.Is(x => x.StartsWith("-----BEGIN RSA PUBLIC KEY-----")
                    && x.EndsWith("-----END RSA PUBLIC KEY-----"));

        _output.WriteLine($"{pem}");
        //File.WriteAllText(@"rsa-public.key", pem);

        // Exporting the private key will fail
        // because only the public key has been restored.
        Assert.Throws<CryptographicException>(() =>
            actual.ExportRSAPrivateKeyPem());

        return;
    }


    [Fact]
    public void WhenImportingFromToXmlString_WithExcludePrivateKey_ReturnsOnlyPublicKey()
    {
        // ### Arrange. ###
        var keyPair = (RSA)_keyPair;

        // ### Act. ###
        var xml = keyPair.ToXmlString(includePrivateParameters: false);

        using var actual = RSA.Create();
        actual.FromXmlString(xml);

        // ### Assert. ###
        // How to check equals?
        actual.IsNot(keyPair);

        // Is it a　success if the arrays are equal?.
        var other = actual.ToXmlString(includePrivateParameters: false);
        other.Is(xml);

        _output.WriteLine($"{xml}");
        //File.WriteAllText(@"rsa-public.xml", xml);

        // Exporting the private key will fail
        // because only the public key has been restored.
        Assert.Throws<CryptographicException>(() =>
            actual.ToXmlString(includePrivateParameters: true));

        return;
    }

}
