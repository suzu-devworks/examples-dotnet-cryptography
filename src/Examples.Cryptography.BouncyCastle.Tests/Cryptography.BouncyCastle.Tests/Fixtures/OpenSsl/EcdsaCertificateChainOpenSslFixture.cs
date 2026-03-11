
using Examples.Cryptography.BouncyCastle.Algorithms;
using Examples.Cryptography.BouncyCastle.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;

namespace Examples.Cryptography.BouncyCastle.Tests.Fixtures.OpenSsl;

public class EcdsaCertificateChainOpenSslFixture(bool includePrivateKeys = false) : IAsyncLifetime
{
    public async ValueTask InitializeAsync()
    {
        await _caCertificates.InitializeAsync();

        var dir = Environment.GetEnvironmentVariable("TEST_ASSETS_PATH") ?? Environment.CurrentDirectory;

        EndEntityCertificate = X509CertificateLoader.LoadFromPem(
            await File.ReadAllTextAsync(Path.Combine(dir, "example.ecdsa.crt"),
                TestContext.Current.CancellationToken));

        if (includePrivateKeys)
        {
            EndEntityPrivateKey = AsymmetricCipherKeyPairLoader.LoadFromPem(
                await File.ReadAllTextAsync(Path.Combine(dir, "example.ecdsa.key"),
                    TestContext.Current.CancellationToken));
        }
    }

    public async ValueTask DisposeAsync()
    {
        await _caCertificates.DisposeAsync();
        GC.SuppressFinalize(this);
    }

    private readonly CaCertificatesOpenSslFixture _caCertificates = new(includePrivateKeys);

    public X509Certificate RootCaCertificate => _caCertificates.RootCaCertificate;
    public AsymmetricCipherKeyPair? RootCaPrivateKey => _caCertificates.RootCaPrivateKey;

    public X509Certificate IntermediateCaCertificate => _caCertificates.IntermediateCaCertificate;
    public AsymmetricCipherKeyPair? IntermediateCaPrivateKey => _caCertificates.IntermediateCaPrivateKey;

    public X509Certificate EndEntityCertificate { get; private set; } = default!;
    public AsymmetricCipherKeyPair? EndEntityPrivateKey { get; private set; }

}
