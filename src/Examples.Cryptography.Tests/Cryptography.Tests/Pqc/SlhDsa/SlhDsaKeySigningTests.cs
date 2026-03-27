#pragma warning disable SYSLIB5006 // SlhDsa is an experimental API in .NET 10.0

using System.Security.Cryptography;
using System.Text;

namespace Examples.Cryptography.Tests.Pqc;

/// <summary>
/// Tests for SLH-DSA (Stateless Hash-Based Digital Signature Algorithm) signing and verification.
/// </summary>
/// <remarks>
/// SLH-DSA is standardized in FIPS 205 as a quantum-resistant digital signature algorithm.
/// Unlike ML-DSA (which is lattice-based), SLH-DSA is hash-based: its security relies solely
/// on the collision resistance of the underlying hash function (SHA-256 or SHAKE-256).
/// <para>
/// Advantages and characteristics compared to classical and other post-quantum algorithms:
/// <list type="bullet">
///   <item>
///     Quantum-resistant: secure against attacks by quantum computers.
///   </item>
///   <item>
///     Conservative security assumptions: security is based only on hash function properties,
///     which are very well studied, unlike the newer lattice assumptions used by ML-DSA.
///   </item>
///   <item>
///     Tiny public and private keys: the public key is only 32 bytes for 128-bit security —
///     far smaller than ML-DSA-44 (1312 bytes) or RSA-2048 (256 bytes public key).
///   </item>
///   <item>
///     Stateless: unlike XMSS or LMS, no signing state needs to be maintained between operations,
///     making it safe to use in distributed or stateless environments.
///   </item>
///   <item>
///     Trade-off: signatures are large. SLH-DSA-SHA2-128s produces a 7856-byte signature,
///     compared to 64 bytes for ECDSA (P-256) or 2420 bytes for ML-DSA-44.
///   </item>
///   <item>
///     Context binding: same as ML-DSA, an optional context byte string can be specified
///     to prevent cross-protocol signature replay.
///   </item>
/// </list>
/// </para>
/// </remarks>
/// <param name="fixture">Key fixture.</param>
public class SlhDsaKeySigningTests(SlhDsaKeyFixture fixture) : IClassFixture<SlhDsaKeyFixture>
{
    private ITestOutputHelper? Output => TestContext.Current.TestOutputHelper;

    /// <summary>
    /// Verifies that signing and verifying data with the same key succeeds.
    /// </summary>
    [Fact]
    public void When_SigningAndVerifying_Then_Success()
    {
        Assert.SkipUnless(SlhDsa.IsSupported,
            "SLH-DSA is not supported on this platform. Requires OpenSSL 3.3.0 or later.");

        var keyPair = fixture.KeyPair!;
        byte[] data = Encoding.UTF8.GetBytes("Data to Sign");

        // No HashAlgorithmName parameter needed: SLH-DSA hashes the message internally.
        byte[] signature = keyPair.SignData(data, context: []);

        Output?.WriteLine("Algorithm:          {0}", keyPair.Algorithm.Name);
        Output?.WriteLine("Signature size:     {0} bytes", signature.Length);
        Output?.WriteLine("Public key size:    {0} bytes", keyPair.Algorithm.PublicKeySizeInBytes);
        Output?.WriteLine("Private key size:   {0} bytes", keyPair.Algorithm.PrivateKeySizeInBytes);
        Output?.WriteLine("  [Note] SLH-DSA has tiny keys ({0}/{1} bytes) but large signatures ({2} bytes).",
            keyPair.Algorithm.PublicKeySizeInBytes,
            keyPair.Algorithm.PrivateKeySizeInBytes,
            keyPair.Algorithm.SignatureSizeInBytes);

        bool verified = keyPair.VerifyData(data, signature, Array.Empty<byte>());

        Assert.True(verified);
    }

    /// <summary>
    /// Verifies that an altered signature fails verification.
    /// </summary>
    [Fact]
    public void When_SignatureIsAltered_Then_VerificationFails()
    {
        Assert.SkipUnless(SlhDsa.IsSupported,
            "SLH-DSA is not supported on this platform. Requires OpenSSL 3.3.0 or later.");

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
    /// Context binding (inherited from FIPS 205) prevents replay attacks across protocol contexts.
    /// This mirrors the same behavior in ML-DSA (FIPS 204), making the two algorithms interoperable
    /// at the API design level despite their different mathematical foundations.
    /// </remarks>
    [Fact]
    public void When_SigningWithContext_Then_VerificationWithDifferentContextFails()
    {
        Assert.SkipUnless(SlhDsa.IsSupported,
            "SLH-DSA is not supported on this platform. Requires OpenSSL 3.3.0 or later.");

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
        Assert.SkipUnless(SlhDsa.IsSupported,
            "SLH-DSA is not supported on this platform. Requires OpenSSL 3.3.0 or later.");

        var original = fixture.KeyPair!;
        byte[] data = Encoding.UTF8.GetBytes("Data to Sign");

        // Sign with the original key.
        byte[] signature = original.SignData(data, context: []);

        // Export and re-import private key as PKCS#8.
        byte[] pkcs8 = original.ExportPkcs8PrivateKey();

        Output?.WriteLine("PKCS#8 size: {0} bytes", pkcs8.Length);

        using var imported = SlhDsa.ImportPkcs8PrivateKey(pkcs8);
        bool verified = imported.VerifyData(data, signature, Array.Empty<byte>());

        Assert.True(verified);
    }
}
