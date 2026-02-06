using System.Security.Cryptography.X509Certificates;

namespace Examples.Cryptography.Tests.PKCS;

/// <summary>
/// PKCS #12: Personal Information Exchange Syntax v1.1.
/// </summary>
/// <param name="fixture"></param>
/// <seealso href="https://datatracker.ietf.org/doc/html/rfc7292" />
public partial class PKCS12PersonalInformationExchangeTests(
    PKCS12PersonalInformationExchangeTests.Fixture fixture)
    : IClassFixture<PKCS12PersonalInformationExchangeTests.Fixture>
{
    [Fact]
    public void When_ExportedAndImported_Then_CertificateIsRestored()
    {
        var privateKey = fixture.PrivateKey;
        var original = fixture.Certificate.CopyWithPrivateKey(privateKey);
        var password = fixture.Secret;

        // spell-checker: disable-next-line
        // TODO Shrouded Keybag: pbeWithSHA1And3-KeyTripleDES-CBC, Iteration 2000
        var exported = original.Export(X509ContentType.Pkcs12, password);
        // File.WriteAllBytes("localhost.pfx", exported);

        using var imported = X509CertificateLoader.LoadPkcs12(
                exported,
                password,
                X509KeyStorageFlags.UserKeySet |
                X509KeyStorageFlags.EphemeralKeySet |
                X509KeyStorageFlags.Exportable);

        // Assert:

        // They are different instances.
        Assert.NotSame(original, imported);

        // The contents should be the same.
        Assert.Equal(original, imported);
        Assert.Equal(original.Thumbprint, imported.Thumbprint);

        // Public keys match
        Assert.Equal(original.GetPublicKey(), imported.GetPublicKey());

        // PKCS #12 can hold private keys
        Assert.True(imported.HasPrivateKey);

        var importedPrivateKey = imported.GetECDsaPrivateKey();

        // They are different instances.
        Assert.NotSame(privateKey, importedPrivateKey);
        Assert.NotEqual(privateKey, importedPrivateKey);   // Maybe calling object.Equals()

        // If the export results are the same, then the restoration is successful.
        Assert.Equal(privateKey.ExportECPrivateKey(), importedPrivateKey!.ExportECPrivateKey());
    }

    [Fact]
    public void When_OpenSSLIsImported_Then_CertificateIsRestored()
    {
        var bytes = fixture.Pkcs12Bytes;
        var password = fixture.Secret;

        using var imported = X509CertificateLoader.LoadPkcs12(
            bytes,
            password,
            X509KeyStorageFlags.UserKeySet |
            X509KeyStorageFlags.EphemeralKeySet |
            X509KeyStorageFlags.Exportable); ;

        // Assert:

        Assert.NotNull(imported);

        // The contents should be the same.
        Assert.Equal("CN=Example Intermediate CA, O=examples, C=JP", imported.IssuerName.Name);
        Assert.Equal("CN=*.ecdsa.example.com, C=JP", imported.SubjectName.Name);

        // PKCS #12 can hold private keys
        Assert.True(imported.HasPrivateKey);
    }
}
