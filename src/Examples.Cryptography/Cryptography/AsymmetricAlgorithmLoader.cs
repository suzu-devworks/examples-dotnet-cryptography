using System.Security.Cryptography;

namespace Examples.Cryptography;

/// <summary>
/// Loader for asymmetric algorithms (ECDsa, RSA) from PEM files.
/// </summary>
public static class AsymmetricAlgorithmLoader
{
    /// <summary>
    /// Loads an ECDsa private key from a PEM file asynchronously.
    /// </summary>
    /// <param name="path"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    public static async Task<ECDsa> LoadECDsaPrivateKeyAsync(string path, CancellationToken cancellationToken)
    {
        var pem = await File.ReadAllTextAsync(path, cancellationToken);
        var privateKey = ECDsa.Create();
        privateKey.ImportFromPem(pem.AsSpan());
        return privateKey;
    }

    /// <summary>
    /// Loads an RSA private key from a PEM file asynchronously.
    /// </summary>
    /// <param name="path"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    public static async Task<RSA> LoadRsaPrivateKeyAsync(string path, CancellationToken cancellationToken)
    {
        var pem = await File.ReadAllTextAsync(path, cancellationToken);
        var privateKey = RSA.Create();
        privateKey.ImportFromPem(pem.AsSpan());
        return privateKey;
    }
}
