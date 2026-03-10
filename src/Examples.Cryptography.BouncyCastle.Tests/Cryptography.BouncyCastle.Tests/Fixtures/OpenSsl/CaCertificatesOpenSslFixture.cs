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
                File.ReadAllText(Path.Combine(dir, "example.ca-root.crt")));
        IntermediateCaCertificate = X509CertificateLoader.LoadFromPem(
                File.ReadAllText(Path.Combine(dir, "example.ca-intermediate.crt")));

        if (includePrivateKeys)
        {
            RootCaPrivateKey = AsymmetricCipherKeyPairLoader.LoadFromPem(
                File.ReadAllText(Path.Combine(dir, "example.ca-root.key")));

            IntermediateCaPrivateKey = AsymmetricCipherKeyPairLoader.LoadFromPem(
                File.ReadAllText(Path.Combine(dir, "example.ca-intermediate.key")));
        }
    }

    public ValueTask DisposeAsync()
    {
        GC.SuppressFinalize(this);
        return ValueTask.CompletedTask;
    }

    public X509Certificate RootCaCertificate { get; private set; } = default!;
    public X509Certificate IntermediateCaCertificate { get; private set; } = default!;
    public AsymmetricCipherKeyPair? RootCaPrivateKey { get; private set; }
    public AsymmetricCipherKeyPair? IntermediateCaPrivateKey { get; private set; }
}
