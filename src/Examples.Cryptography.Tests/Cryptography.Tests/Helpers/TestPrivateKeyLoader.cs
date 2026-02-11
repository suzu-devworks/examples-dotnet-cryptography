using System.Security.Cryptography;

namespace Examples.Cryptography.Tests.Helpers;

/// <summary>
/// Helper for loading private keys for tests.
/// </summary>
public static class TestPrivateKeyLoader
{
    public static async Task<ECDsa> LoadECDsaPrivateKey(string path, CancellationToken cancellationToken)
    {
        var pem = await File.ReadAllTextAsync(path, cancellationToken);
        var privateKey = ECDsa.Create();
        privateKey.ImportFromPem(pem.AsSpan());
        return privateKey;
    }

    public static async Task<RSA> LoadRsaPrivateKey(string path, CancellationToken cancellationToken)
    {
        var pem = await File.ReadAllTextAsync(path, cancellationToken);
        var privateKey = RSA.Create();
        privateKey.ImportFromPem(pem.AsSpan());
        return privateKey;
    }

}
