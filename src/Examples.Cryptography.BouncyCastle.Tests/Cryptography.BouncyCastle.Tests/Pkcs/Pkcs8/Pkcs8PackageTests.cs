using Examples.Cryptography.BouncyCastle.Algorithms;
using Examples.Cryptography.BouncyCastle.Tests.Fixtures;
using Examples.Cryptography.BouncyCastle.Tests.Helpers;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Xunit.Sdk;

namespace Examples.Cryptography.BouncyCastle.Tests.Pkcs.Pkcs8;

public class Pkcs8PackageTests(
    Pkcs8PackageTests.Fixture fixture
    ) : IClassFixture<Pkcs8PackageTests.Fixture>
{
    public class Fixture : IAsyncLifetime
    {
        public async ValueTask InitializeAsync()
        {
            await Pkcs8.InitializeAsync();
        }

        public async ValueTask DisposeAsync()
        {
            await Pkcs8.DisposeAsync();
            GC.SuppressFinalize(this);
        }

        public AsymmetricCipherKeyPair KeyPair => _keyPair.Value;
        private readonly Lazy<AsymmetricCipherKeyPair> _keyPair = new(() =>
        {
            var keyPair = GeneratorUtilities.GetKeyPairGenerator("ECDSA")
                .ConfigureECParameter(CustomNamedCurves.GetByName("P-256"))
                .GenerateKeyPair();

            return keyPair;
        });

        public Pkcs8OpenSslFixture Pkcs8 { get; } = new();

        public string Secret => Pkcs8.Secret;
        public string PrivateKeyPem => Pkcs8.PrivateKeyPem;
        public string EncryptedPrivateKeyPem => Pkcs8.EncryptedPrivateKeyPem;
    }

    private ITestOutputHelper? Output => TestContext.Current.TestOutputHelper;

    private TestFileOutputHelper FileOutput => TestFileOutputHelper.Instance;

    [Fact]
    public async Task When_ExportedToPemAndImported_Then_PrivateKeyIsRestored()
    {
        var keyPair = fixture.KeyPair;

        var pkcs8 = new Pkcs8Generator(keyPair.Private);

        var pem = PemUtility.ToPemString(pkcs8);
        Output?.WriteLine($"{pem}");
        await FileOutput.WriteFileAsync("bc-ecdsa-private.key.pk8", pem,
            TestContext.Current.CancellationToken);

        var imported = AsymmetricCipherKeyPairLoader.LoadFromPem(pem);

        // Assert:

        // PEM label as expected.
        Assert.StartsWith("-----BEGIN PRIVATE KEY-----", pem);
        Assert.EndsWith("-----END PRIVATE KEY-----", pem);

        // They are different instances.
        Assert.NotSame(keyPair, imported);

        // The key is the same.
        Assert.Equal(keyPair.Private, imported.Private);
        Assert.Equal(keyPair.Public, imported.Public);
    }

    [Fact]
    public void When_OpenSSLPemIsImported_Then_PrivateKeyIsRestored()
    {
        var pem = fixture.PrivateKeyPem;

        var imported = AsymmetricCipherKeyPairLoader.LoadFromPem(pem);

        // Assert:

        var privateKey = Assert.IsType<ECPrivateKeyParameters>(imported.Private);
        Assert.Equal(256, privateKey.Parameters.Curve.FieldSize);
        Assert.Equal("EC", privateKey.AlgorithmName);
    }

    [Fact]
    public async Task When_ExportedToEncryptedPemAndImported_WithPkcs8Generator_Then_PrivateKeyIsRestored()
    {
        var keyPair = fixture.KeyPair;
        var password = PasswordGenerator.Generate(12);

        var algorithm = PkcsObjectIdentifiers.PbeWithShaAnd3KeyTripleDesCbc;
        var pkcs8enc = new Pkcs8Generator(keyPair.Private, algorithm.Id)
        {
            SecureRandom = new SecureRandom(),
            Password = password.ToCharArray(),
        }
        .Generate();

        var pem = PemUtility.ToPemString(pkcs8enc);
        Output?.WriteLine($"{pem}");
        await FileOutput.WriteFileAsync("bc-ecdsa-private1.key.pk8e", pem,
            TestContext.Current.CancellationToken);
        await FileOutput.WriteFileAsync("bc-ecdsa-private1.key.pk8e.secret", password,
            TestContext.Current.CancellationToken);

        var imported = AsymmetricCipherKeyPairLoader.LoadFromPem(pem, new PasswordFinder(password));

        // Assert:

        // PEM label as expected.
        Assert.StartsWith("-----BEGIN ENCRYPTED PRIVATE KEY-----", pem);
        Assert.EndsWith("-----END ENCRYPTED PRIVATE KEY-----", pem);

        // They are different instances.
        Assert.NotSame(keyPair, imported);

        // The key is the same.
        Assert.Equal(keyPair.Private, imported.Private);
        Assert.Equal(keyPair.Public, imported.Public);
    }

    [Fact]
    public async Task When_ExportedToEncryptedPemAndImported_WithEncryptedPrivateKeyInfoFactory_Then_PrivateKeyIsRestored()
    {
        var keyPair = fixture.KeyPair!;
        var password = PasswordGenerator.Generate(12);

        var keyAlgorithm = NistObjectIdentifiers.IdAes256Cbc;
        var keyPrfAlgorithm = PkcsObjectIdentifiers.IdHmacWithSha256;

        var random = new SecureRandom();
        var salt = random.GenerateSeed(20);
        var iterationCount = 2048;

        var encInfo = EncryptedPrivateKeyInfoFactory.CreateEncryptedPrivateKeyInfo(
            keyAlgorithm, keyPrfAlgorithm, password.ToCharArray(),
            salt, iterationCount, random, keyPair.Private);
        var encPrivateInfo = new Pkcs8EncryptedPrivateKeyInfo(encInfo);

        var pem = PemUtility.ToPemString(encPrivateInfo);

        Output?.WriteLine($"{pem}");
        await FileOutput.WriteFileAsync("bc-ecdsa-private.key.pk8e", pem,
            TestContext.Current.CancellationToken);
        await FileOutput.WriteFileAsync("bc-ecdsa-private.key.pk8e.secret", password,
            TestContext.Current.CancellationToken);

        using var reader = new PemReader(new StringReader(pem), new PasswordFinder(password));
        var loaded = reader.ReadObject();
        if (loaded is not ECPrivateKeyParameters privateKey)
        {
            throw new XunitException("Failed to read private key from PEM.");
        }

        var publicKey = privateKey.GeneratePublicKey();
        var imported = new AsymmetricCipherKeyPair(publicKey, privateKey);

        // Assert:

        // PEM label as expected.
        Assert.StartsWith("-----BEGIN ENCRYPTED PRIVATE KEY-----", pem);
        Assert.EndsWith("-----END ENCRYPTED PRIVATE KEY-----", pem);

        // They are different instances.
        Assert.NotSame(keyPair, imported);

        // The key is the same.
        Assert.Equal(keyPair.Private, imported.Private);
        Assert.Equal(keyPair.Public, imported.Public);
    }

    [Fact]
    public void When_OpenSSLEncryptedPemIsImported_Then_PrivateKeyIsRestored()
    {
        var pem = fixture.EncryptedPrivateKeyPem;
        var secret = fixture.Secret;

        var imported = AsymmetricCipherKeyPairLoader.LoadFromPem(pem, new PasswordFinder(secret));

        // Assert:

        var privateKey = Assert.IsType<ECPrivateKeyParameters>(imported.Private);
        Assert.Equal(256, privateKey.Parameters.Curve.FieldSize);
        Assert.Equal("EC", privateKey.AlgorithmName);
    }
}
