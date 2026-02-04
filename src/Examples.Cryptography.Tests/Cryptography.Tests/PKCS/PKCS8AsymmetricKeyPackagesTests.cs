using System.Security.Cryptography;

namespace Examples.Cryptography.Tests.PKCS;

/// <summary>
/// Asymmetric Key Packages.
/// </summary>
/// <param name="fixture"></param>
/// <seealso href="https://datatracker.ietf.org/doc/html/rfc5958"/>
public class PKCS8AsymmetricKeyPackagesTests(
    PKCS8AsymmetricKeyPackagesTests.Fixture fixture
    ) : IClassFixture<PKCS8AsymmetricKeyPackagesTests.Fixture>
{
    public class Fixture : IDisposable
    {
        public Fixture()
        {
            var dir = Environment.GetEnvironmentVariable("TEST_ASSETS_PATH") ?? Environment.CurrentDirectory;

            Pem = File.ReadAllText(Path.Combine(dir, "localhost.ecdsa.pk8"));
            Secret = File.ReadAllText(Path.Combine(dir, ".password"));
        }

        public void Dispose()
        {
            KeyPair?.Dispose();
            GC.SuppressFinalize(this);
        }

        public ECDsa KeyPair { get; } = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        public string Pem { get; }
        public string Secret { get; }
    }

    private ITestOutputHelper? Output => TestContext.Current.TestOutputHelper;

    [Fact]
    public void When_ExportedToPemAndImported_Then_PrivateKeyIsRestored()
    {
        ECDsa original = fixture.KeyPair;

        var pem = original.ExportPkcs8PrivateKeyPem();
        Output?.WriteLine($"{pem}");
        //File.WriteAllText(@"private.p8", pem);

        using var importing = ECDsa.Create();
        importing.ImportFromPem(pem.AsSpan());

        // Assert:

        // PEM label as expected.
        Assert.StartsWith("-----BEGIN PRIVATE KEY-----", pem);
        Assert.EndsWith("-----END PRIVATE KEY-----", pem);

        // They are different instances.
        Assert.NotSame(original, importing);
        Assert.NotEqual(original, importing);   // Maybe calling object.Equals()

        // Same if public key is the same
        Assert.Equivalent(original.ExportSubjectPublicKeyInfo(),
                          importing.ExportSubjectPublicKeyInfo());

        // Same if parameters is the same
        Assert.Equivalent(original.ExportParameters(includePrivateParameters: true),
                          importing.ExportParameters(includePrivateParameters: true));

        // Exporting again gives the same result.
        Assert.Equal(pem, importing.ExportPkcs8PrivateKeyPem());
    }

    [Fact]
    public void When_OpenSSLPemIsImported_Then_PrivateKeyIsRestored()
    {
        var pem = fixture.Pem;
        Output?.WriteLine($"{pem}");

        using var importing = ECDsa.Create();
        importing.ImportFromPem(pem.AsSpan());

        // Assert:

        Assert.Equal(256, importing.KeySize);
        Assert.Equal("ECDsa", importing.SignatureAlgorithm);

        var publicKeyParameters = importing.ExportParameters(includePrivateParameters: false);

        Assert.Equal(ECCurve.NamedCurves.nistP256.Oid.Value, publicKeyParameters.Curve.Oid.Value);
        Assert.Equal(32, publicKeyParameters.Q.X?.Length);
        Assert.Equal(32, publicKeyParameters.Q.Y?.Length);
    }

    [Fact]
    public void When_ExportedToEncryptedPemAndImported_Then_PrivateKeyIsRestored()
    {
        ECDsa original = fixture.KeyPair;
        var password = fixture.Secret;

        // he password-based encryption (PBE) parameters.
        var parameters = new PbeParameters(
                PbeEncryptionAlgorithm.Aes256Cbc,
                HashAlgorithmName.SHA256,
                iterationCount: RandomNumberGenerator.GetInt32(1, 100_000));

        var pem = original.ExportEncryptedPkcs8PrivateKeyPem(password.AsSpan(), parameters);
        Output?.WriteLine($"{pem}");
        //File.WriteAllText(@"private.encrypted.p8", pem);

        using var importing = ECDsa.Create();
        importing.ImportFromEncryptedPem(pem.AsSpan(), password.AsSpan());

        // Assert:

        // PEM label as expected.
        Assert.StartsWith("-----BEGIN ENCRYPTED PRIVATE KEY-----", pem);
        Assert.EndsWith("-----END ENCRYPTED PRIVATE KEY-----", pem);

        // They are different instances.
        Assert.NotSame(original, importing);
        Assert.NotEqual(original, importing);   // Maybe calling object.Equals()

        // Same if public key is the same
        Assert.Equivalent(original.ExportSubjectPublicKeyInfo(),
                          importing.ExportSubjectPublicKeyInfo());

        // Same if parameters is the same
        Assert.Equivalent(original.ExportParameters(includePrivateParameters: true),
                          importing.ExportParameters(includePrivateParameters: true));

        // The salt and IV change each time, so the results are different each time.
        Assert.NotEqual(pem, importing.ExportEncryptedPkcs8PrivateKeyPem(password.AsSpan(), parameters));

    }

}
