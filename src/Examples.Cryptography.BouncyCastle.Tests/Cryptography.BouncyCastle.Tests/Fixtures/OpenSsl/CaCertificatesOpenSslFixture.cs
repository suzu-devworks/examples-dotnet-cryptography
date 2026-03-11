using Examples.Cryptography.BouncyCastle.Algorithms;
using Examples.Cryptography.BouncyCastle.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;

namespace Examples.Cryptography.BouncyCastle.Tests.Fixtures.OpenSsl;

public class CaCertificatesOpenSslFixture(bool includePrivateKeys = false) : IAsyncLifetime
{
    public async ValueTask InitializeAsync()
    {
        var dir = Environment.GetEnvironmentVariable("TEST_ASSETS_PATH") ?? Environment.CurrentDirectory;

        RootCaCertificate = X509CertificateLoader.LoadFromPem(
            await File.ReadAllTextAsync(Path.Combine(dir, "example.ca-root.crt"),
                TestContext.Current.CancellationToken));

        IntermediateCaCertificate = X509CertificateLoader.LoadFromPem(
            await File.ReadAllTextAsync(Path.Combine(dir, "example.ca-intermediate.crt"),
                TestContext.Current.CancellationToken));

        if (includePrivateKeys)
        {
            RootCaPrivateKey = AsymmetricCipherKeyPairLoader.LoadFromPem(
                await File.ReadAllTextAsync(Path.Combine(dir, "example.ca-root.key"),
                    TestContext.Current.CancellationToken));

            IntermediateCaPrivateKey = AsymmetricCipherKeyPairLoader.LoadFromPem(
                await File.ReadAllTextAsync(Path.Combine(dir, "example.ca-intermediate.key"),
                    TestContext.Current.CancellationToken));
        }
    }

    public ValueTask DisposeAsync()
    {
        GC.SuppressFinalize(this);
        return ValueTask.CompletedTask;
    }

    public X509Certificate RootCaCertificate { get; private set; } = default!;
    public AsymmetricCipherKeyPair? RootCaPrivateKey { get; private set; }

    public X509Certificate IntermediateCaCertificate { get; private set; } = default!;
    public AsymmetricCipherKeyPair? IntermediateCaPrivateKey { get; private set; }
}
