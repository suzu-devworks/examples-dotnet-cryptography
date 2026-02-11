using System.Security.Cryptography;
using Examples.Cryptography.Extensions;
using Examples.Cryptography.Tests.Helpers;

namespace Examples.Cryptography.Tests.Pkcs.Pkcs8;

/// <summary>
/// Asymmetric Key Packages.
/// </summary>
/// <param name="fixture">The test fixture.</param>
/// <seealso href="https://datatracker.ietf.org/doc/html/rfc5958"/>
public class Pkcs8AsymmetricKeyPackagesTests(
    Pkcs8AsymmetricKeyPackagesTests.Fixture fixture
    ) : IClassFixture<Pkcs8AsymmetricKeyPackagesTests.Fixture>
{
    public class Fixture : IAsyncLifetime
    {
        public async ValueTask InitializeAsync()
        {
            await Pkcs8.InitializeAsync();
        }

        public async ValueTask DisposeAsync()
        {
            KeyPair.Dispose();
            await Pkcs8.DisposeAsync();
            GC.SuppressFinalize(this);
        }

        public Pkcs8OpenSslFixture Pkcs8 { get; } = new();
        public ECDsa KeyPair { get; } = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        public string Secret => Pkcs8.Secret;
        public string PrivateKeyPem => Pkcs8.PrivateKeyPem;
        public string EncryptedPrivateKeyPem => Pkcs8.EncryptedPrivateKeyPem;
    }

    private ITestOutputHelper? Output => TestContext.Current.TestOutputHelper;
    private TestFileOutputHelper FileOutput => TestFileOutputHelper.Instance;

    [Fact]
    public async Task When_ExportedToPemAndImported_Then_PrivateKeyIsRestored()
    {
        ECDsa original = fixture.KeyPair;

        /* With OpenSSL use the following command:
        ```shell
        openssl pkcs8 -topk8 -nocrypt -in ecdsa.private.key -out ecdsa.private.key.pk8
        ```
        */
        var pem = original.ExportPkcs8PrivateKeyPem();
        Output?.WriteLine($"{pem}");
        await FileOutput.WriteFileAsync("ecdsa.private.key.pk8", pem,
            TestContext.Current.CancellationToken);

        using var importing = ECDsa.Create();
        importing.ImportFromPem(pem.AsSpan());

        // Assert:

        // PEM label as expected.
        Assert.StartsWith("-----BEGIN PRIVATE KEY-----", pem);
        Assert.EndsWith("-----END PRIVATE KEY-----", pem);

        // They are different instances.
        Assert.NotSame(original, importing);

        // The parameters, including the private key, are the same.
        Assert.True(original.EqualsParameters(importing, includePrivateParameters: true));

        // Exporting again gives the same result.
        Assert.Equal(pem, importing.ExportPkcs8PrivateKeyPem());
    }

    [Fact]
    public void When_OpenSSLPemIsImported_Then_PrivateKeyIsRestored()
    {
        var pem = fixture.PrivateKeyPem;

        using var importing = ECDsa.Create();
        importing.ImportFromPem(pem.AsSpan());

        // Assert:

        Assert.Equal(256, importing.KeySize);
        Assert.Equal("ECDsa", importing.SignatureAlgorithm);

        var publicParams = importing.ExportParameters(includePrivateParameters: false);
        Assert.Equal(ECCurve.NamedCurves.nistP256.Oid.Value, publicParams.Curve.Oid.Value);
        Assert.Equal(32, publicParams.Q.X?.Length);
        Assert.Equal(32, publicParams.Q.Y?.Length);

        // Has private key
        var privateParams = importing.ExportParameters(includePrivateParameters: true);
        Assert.Equal(32, privateParams.D?.Length);
    }

    [Fact]
    public async Task When_ExportedToEncryptedPemAndImported_Then_PrivateKeyIsRestored()
    {
        ECDsa original = fixture.KeyPair;
        var password = fixture.Secret;

        /* With OpenSSL use the following command:
        ```shell
        openssl pkcs8 -topk8 -v2 aes-256-cbc -v2prf hmacWithSHA512 \
            -in ecdsa.private.key -out ecdsa-private.key.p8enc
        ```
        */
        // The password-based encryption (PBE) parameters.
        var parameters = new PbeParameters(
                PbeEncryptionAlgorithm.Aes256Cbc,
                HashAlgorithmName.SHA256,
                iterationCount: RandomNumberGenerator.GetInt32(1, 100_000));

        var pem = original.ExportEncryptedPkcs8PrivateKeyPem(password.AsSpan(), parameters);
        Output?.WriteLine($"{pem}");
        await FileOutput.WriteFileAsync("ecdsa.private.key.p8enc", pem,
            TestContext.Current.CancellationToken);

        using var importing = ECDsa.Create();
        importing.ImportFromEncryptedPem(pem.AsSpan(), password.AsSpan());

        // Assert:

        // PEM label as expected.
        Assert.StartsWith("-----BEGIN ENCRYPTED PRIVATE KEY-----", pem);
        Assert.EndsWith("-----END ENCRYPTED PRIVATE KEY-----", pem);

        // They are different instances.
        Assert.NotSame(original, importing);

        // The parameters, including the private key, are the same.
        Assert.True(original.EqualsParameters(importing, includePrivateParameters: true));

        // The salt and IV change each time, so the results are different each time.
        Assert.NotEqual(pem, importing.ExportEncryptedPkcs8PrivateKeyPem(password.AsSpan(), parameters));
    }

    [Fact]
    public void When_OpenSSLEncryptedPemIsImported_Then_PrivateKeyIsRestored()
    {
        var pem = fixture.EncryptedPrivateKeyPem;
        var password = fixture.Secret;

        using var importing = ECDsa.Create();
        importing.ImportFromEncryptedPem(pem.AsSpan(), password.AsSpan());

        // Assert:

        Assert.Equal(256, importing.KeySize);
        Assert.Equal("ECDsa", importing.SignatureAlgorithm);

        var publicParams = importing.ExportParameters(includePrivateParameters: false);
        Assert.Equal(ECCurve.NamedCurves.nistP256.Oid.Value, publicParams.Curve.Oid.Value);
        Assert.Equal(32, publicParams.Q.X?.Length);
        Assert.Equal(32, publicParams.Q.Y?.Length);

        // Has private key
        var privateParams = importing.ExportParameters(includePrivateParameters: true);
        Assert.Equal(32, privateParams.D?.Length);
    }

}
