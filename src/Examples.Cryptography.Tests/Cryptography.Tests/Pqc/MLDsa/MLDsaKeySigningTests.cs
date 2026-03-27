#pragma warning disable SYSLIB5006 // Some MLDsa PKCS#8 methods are experimental in .NET 10.0

using System.Security.Cryptography;
using System.Text;

namespace Examples.Cryptography.Tests.Pqc;

/// <summary>
/// Tests for ML-DSA (Module Lattice Digital Signature Algorithm) signing and verification.
/// </summary>
/// <remarks>
/// ML-DSA is standardized in FIPS 204 as a quantum-resistant digital signature algorithm.
/// It is designed to replace classical signature algorithms such as ECDSA and RSA
/// that are vulnerable to Shor's algorithm running on a quantum computer.
/// <para>
/// Advantages over classical signature algorithms (e.g., ECDSA with P-256):
/// <list type="bullet">
///   <item>Quantum-resistant: secure against attacks by quantum computers.</item>
///   <item>
///     No external hash algorithm parameter: ML-DSA performs hashing internally (FIPS 204 §5),
///     unlike ECDSA which requires explicitly specifying a hash algorithm.
///   </item>
///   <item>
///     Context binding: an optional context byte string (up to 255 bytes) can be used
///     to separate signatures across different protocol contexts, preventing cross-protocol attacks.
///   </item>
/// </list>
/// </para>
/// </remarks>
/// <param name="fixture">Key fixture.</param>
public class MLDsaKeySigningTests(MLDsaKeyFixture fixture) : IClassFixture<MLDsaKeyFixture>
{
    private ITestOutputHelper? Output => TestContext.Current.TestOutputHelper;

    /// <summary>
    /// Verifies that signing and verifying data with the same key succeeds.
    /// </summary>
    [Fact]
    public void When_SigningAndVerifying_Then_Success()
    {
        Assert.SkipUnless(MLDsa.IsSupported,
            "ML-DSA is not supported on this platform. Requires OpenSSL 3.3.0 or later.");

        var keyPair = fixture.KeyPair!;
        byte[] data = Encoding.UTF8.GetBytes("Data to Sign");

        // No HashAlgorithmName parameter needed: ML-DSA hashes the message internally.
        byte[] signature = keyPair.SignData(data, context: []);

        Output?.WriteLine("Algorithm:          {0}", keyPair.Algorithm.Name);
        Output?.WriteLine("Signature size:     {0} bytes", signature.Length);
        Output?.WriteLine("Public key size:    {0} bytes", keyPair.Algorithm.PublicKeySizeInBytes);
        Output?.WriteLine("Private key size:   {0} bytes", keyPair.Algorithm.PrivateKeySizeInBytes);

        bool verified = keyPair.VerifyData(data, signature, Array.Empty<byte>());

        Assert.True(verified);
    }

    /// <summary>
    /// Verifies that an altered signature fails verification.
    /// </summary>
    [Fact]
    public void When_SignatureIsAltered_Then_VerificationFails()
    {
        Assert.SkipUnless(MLDsa.IsSupported,
            "ML-DSA is not supported on this platform. Requires OpenSSL 3.3.0 or later.");

        var keyPair = fixture.KeyPair!;
        byte[] data = Encoding.UTF8.GetBytes("Data to Sign");
        byte[] signature = keyPair.SignData(data, context: []);

        // Flip the first byte of the signature to simulate tampering.
        byte[] tamperedSignature = (byte[])signature.Clone();
        tamperedSignature[0] ^= 0xFF;

        bool verified = keyPair.VerifyData(data, tamperedSignature, Array.Empty<byte>());

        Assert.False(verified);
    }

    /// <summary>
    /// Verifies that a signature produced with one context cannot be verified with a different context.
    /// </summary>
    /// <remarks>
    /// Context binding is a feature unique to FIPS 204/205 algorithms.
    /// It prevents a signature created in one protocol context from being replayed in another,
    /// providing a defense-in-depth against cross-protocol attacks without requiring higher-level mitigations.
    /// </remarks>
    [Fact]
    public void When_SigningWithContext_Then_VerificationWithDifferentContextFails()
    {
        Assert.SkipUnless(MLDsa.IsSupported,
            "ML-DSA is not supported on this platform. Requires OpenSSL 3.3.0 or later.");

        var keyPair = fixture.KeyPair!;
        byte[] data = Encoding.UTF8.GetBytes("Data to Sign");
        byte[] contextA = Encoding.UTF8.GetBytes("protocol-A");
        byte[] contextB = Encoding.UTF8.GetBytes("protocol-B");

        // Sign under context A.
        byte[] signature = keyPair.SignData(data, contextA);

        // Verification under the same context must succeed.
        bool verifiedWithSameContext = keyPair.VerifyData(data, signature, contextA);

        // Verification under a different context must fail.
        bool verifiedWithDifferentContext = keyPair.VerifyData(data, signature, contextB);

        Assert.Multiple(
            () => Assert.True(verifiedWithSameContext),
            () => Assert.False(verifiedWithDifferentContext)
        );
    }

    /// <summary>
    /// Verifies that the key pair can be exported as PKCS#8 and re-imported to verify a signature.
    /// </summary>
    [Fact]
    public void When_Pkcs8PrivateKeyIsExportedAndImported_Then_VerificationSucceeds()
    {
        Assert.SkipUnless(MLDsa.IsSupported,
            "ML-DSA is not supported on this platform. Requires OpenSSL 3.3.0 or later.");

        var original = fixture.KeyPair!;
        byte[] data = Encoding.UTF8.GetBytes("Data to Sign");

        // Sign with the original key.
        byte[] signature = original.SignData(data, context: []);

        // Export and re-import private key as PKCS#8.
        byte[] pkcs8 = original.ExportPkcs8PrivateKey();

        Output?.WriteLine("PKCS#8 size: {0} bytes", pkcs8.Length);

        using var imported = MLDsa.ImportPkcs8PrivateKey(pkcs8);
        bool verified = imported.VerifyData(data, signature, Array.Empty<byte>());

        Assert.True(verified);
    }
}
