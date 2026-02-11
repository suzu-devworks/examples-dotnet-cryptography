using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Examples.Cryptography.Extensions;
using Examples.Cryptography.Tests.Fixtures.OpenSsl;
using Examples.Cryptography.Tests.Helpers;

namespace Examples.Cryptography.Tests.Pkcs.Pkcs12;

/// <summary>
/// PKCS #12: Personal Information Exchange Syntax v1.1.
/// </summary>
/// <param name="fixture"></param>
/// <seealso href="https://datatracker.ietf.org/doc/html/rfc7292" />
public class Pkcs12PersonalInformationExchangeTests(
    Pkcs12PersonalInformationExchangeTests.Fixture fixture)
    : IClassFixture<Pkcs12PersonalInformationExchangeTests.Fixture>
{
    public class Fixture : IAsyncLifetime
    {
        public async ValueTask InitializeAsync()
        {
            await EcdsaCert.InitializeAsync();
            await Pkcs12.InitializeAsync();
        }

        public async ValueTask DisposeAsync()
        {
            await EcdsaCert.DisposeAsync();
            await Pkcs12.DisposeAsync();
            GC.SuppressFinalize(this);
        }

        public EcdsaCertificateOpenSslFixture EcdsaCert { get; } = new();
        public Pkcs12OpenSslFixture Pkcs12 { get; } = new();

        public ECDsa PrivateKey => EcdsaCert.PrivateKey;
        public X509Certificate2 Certificate => EcdsaCert.Certificate;
        public byte[] Pkcs12Bytes => Pkcs12.Pkcs12Bytes;
        public string Secret => Pkcs12.Secret;
    }

    private TestFileOutputHelper FileOutput => TestFileOutputHelper.Instance;

    [Fact]
    public async Task When_ExportedAndImported_Then_CertificateIsRestored()
    {
        var privateKey = fixture.PrivateKey;
        var original = fixture.Certificate;
        var password = fixture.Secret;

        var builder = new Pkcs12Builder();

        var certContents = new Pkcs12SafeContents();
        certContents.AddCertificate(original);
        builder.AddSafeContentsUnencrypted(certContents);

        var keyContents = new Pkcs12SafeContents();
        keyContents.AddKeyUnencrypted(privateKey);

        var modernPbe = new PbeParameters(
            PbeEncryptionAlgorithm.Aes256Cbc,
            HashAlgorithmName.SHA256,
            iterationCount: 100000);

        builder.AddSafeContentsEncrypted(keyContents, password, modernPbe);

        builder.SealWithMac(password, HashAlgorithmName.SHA256, iterationCount: 2000);

        byte[] exported = builder.Encode();
        await FileOutput.WriteFileAsync("localhost.p12", exported, TestContext.Current.CancellationToken);

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
        Assert.True(privateKey.EqualsParameters(imported.GetECDsaPrivateKey()));
    }

    [Fact]
    public async Task When_ExportedAndImported_WithOlderEnvironments_Then_CertificateIsRestored()
    {
        var privateKey = fixture.PrivateKey;
        var original = fixture.Certificate;
        var password = fixture.Secret;

        /* With OpenSSL use the following command:
        ```shell
        openssl pkcs12 -export -inkey private.key -in localhost.crt -out localhost.pfx
        ```
        */
        // spell-checker: disable-next-line
        // The older encryption type pbeWithSHA1And3-KeyTripleDES-CBC is used internally
        // for compatibility with older environments (Windows 7/8 and older Java versions).
        var exported = original.CopyWithPrivateKey(privateKey).Export(X509ContentType.Pkcs12, password);
        await FileOutput.WriteFileAsync("localhost.p12.old", exported, TestContext.Current.CancellationToken);

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
