#pragma warning disable SYSLIB5006 // Some MLKem PKCS#8 methods are experimental in .NET 10.0

using System.Security.Cryptography;

namespace Examples.Cryptography.Tests.Pqc;

/// <summary>
/// Tests for ML-KEM (Module Lattice Key Encapsulation Mechanism) key exchange.
/// </summary>
/// <remarks>
/// ML-KEM is standardized in FIPS 203 as a quantum-resistant Key Encapsulation Mechanism (KEM).
/// It is designed to replace classical key exchange algorithms such as ECDH and RSA key transport
/// that are vulnerable to Shor's algorithm running on a quantum computer.
/// <para>
/// Advantages over classical key exchange (e.g., ECDH with P-256):
/// <list type="bullet">
///   <item>Quantum-resistant: secure against attacks by quantum computers.</item>
///   <item>
///     IND-CCA2 security: the shared secret remains indistinguishable from random
///     even if the ciphertext is manipulated by an adversary.
///   </item>
/// </list>
/// </para>
/// </remarks>
/// <param name="fixture">Key fixture.</param>
public class MLKemKeyExchangeTests(MLKemKeyFixture fixture) : IClassFixture<MLKemKeyFixture>
{
    private ITestOutputHelper? Output => TestContext.Current.TestOutputHelper;

    /// <summary>
    /// Verifies that the generated key sizes match the ML-KEM-768 specification (FIPS 203).
    /// </summary>
    [Fact]
    public void When_KeyIsGenerated_Then_SizesMatchSpecification()
    {
        Assert.SkipUnless(MLKem.IsSupported,
            "ML-KEM is not supported on this platform. Requires OpenSSL 3.3.0 or later.");

        var algorithm = fixture.KeyPair!.Algorithm;

        Output?.WriteLine("Algorithm: {0}", algorithm.Name);
        Output?.WriteLine("EncapsulationKeySizeInBytes: {0}", algorithm.EncapsulationKeySizeInBytes);
        Output?.WriteLine("DecapsulationKeySizeInBytes: {0}", algorithm.DecapsulationKeySizeInBytes);
        Output?.WriteLine("CiphertextSizeInBytes:       {0}", algorithm.CiphertextSizeInBytes);
        Output?.WriteLine("SharedSecretSizeInBytes:     {0}", algorithm.SharedSecretSizeInBytes);
        Output?.WriteLine("PrivateSeedSizeInBytes:      {0}", algorithm.PrivateSeedSizeInBytes);

        // ML-KEM-768 sizes per FIPS 203 Table 2.
        Assert.Multiple(
            () => Assert.Equal(MLKemAlgorithm.MLKem768, algorithm),
            () => Assert.Equal(1184, algorithm.EncapsulationKeySizeInBytes),
            () => Assert.Equal(2400, algorithm.DecapsulationKeySizeInBytes),
            () => Assert.Equal(1088, algorithm.CiphertextSizeInBytes),
            () => Assert.Equal(32, algorithm.SharedSecretSizeInBytes),
            () => Assert.Equal(64, algorithm.PrivateSeedSizeInBytes)
        );
    }

    /// <summary>
    /// Verifies that encapsulation and decapsulation produce the same shared secret.
    /// </summary>
    /// <remarks>
    /// ML-KEM key exchange flow:
    /// <list type="number">
    ///   <item>Bob generates a key pair and sends the encapsulation key (public key) to Alice.</item>
    ///   <item>Alice encapsulates a shared secret using Bob's encapsulation key,
    ///         producing a ciphertext and a shared secret.</item>
    ///   <item>Alice sends the ciphertext to Bob.</item>
    ///   <item>Bob decapsulates the shared secret using the ciphertext and his decapsulation key (private key).</item>
    ///   <item>Both parties now share the same secret, which can be used to derive a symmetric key.</item>
    /// </list>
    /// </remarks>
    [Fact]
    public void When_EncapsulatingAndDecapsulating_Then_SharedSecretsMatch()
    {
        Assert.SkipUnless(MLKem.IsSupported,
            "ML-KEM is not supported on this platform. Requires OpenSSL 3.3.0 or later.");

        var algorithm = fixture.KeyPair!.Algorithm;

        // Step 1: Bob holds the key pair; extract encapsulation key (public) to share with Alice.
        var bob = fixture.KeyPair!;
        byte[] encapKey = bob.ExportEncapsulationKey();

        // Step 2: Alice imports Bob's encapsulation key and encapsulates a shared secret.
        using var alice = MLKem.ImportEncapsulationKey(algorithm, encapKey);
        alice.Encapsulate(out byte[] ciphertext, out byte[] aliceSharedSecret);

        Output?.WriteLine("Ciphertext      ({0} bytes): {1}...",
            ciphertext.Length, Convert.ToHexString(ciphertext[..16]));
        Output?.WriteLine("Alice's shared secret ({0} bytes): {1}",
            aliceSharedSecret.Length, Convert.ToHexString(aliceSharedSecret));

        // Step 3: Bob decapsulates using Alice's ciphertext to derive the shared secret.
        byte[] bobSharedSecret = bob.Decapsulate(ciphertext);

        Output?.WriteLine("Bob's   shared secret ({0} bytes): {1}",
            bobSharedSecret.Length, Convert.ToHexString(bobSharedSecret));

        // Both parties derived the same shared secret.
        // This is the quantum-resistant equivalent of an ECDH key agreement.
        Assert.Equal(aliceSharedSecret, bobSharedSecret);
    }

    /// <summary>
    /// Verifies that the key can be exported as PKCS#8 and re-imported to perform decapsulation.
    /// </summary>
    [Fact]
    public void When_Pkcs8PrivateKeyIsExportedAndImported_Then_DecapsulationSucceeds()
    {
        Assert.SkipUnless(MLKem.IsSupported,
            "ML-KEM is not supported on this platform. Requires OpenSSL 3.3.0 or later.");

        var original = fixture.KeyPair!;
        var algorithm = original.Algorithm;

        // Export private key as PKCS#8 DER.
        byte[] pkcs8 = original.ExportPkcs8PrivateKey();

        // Encapsulate using the original key.
        original.Encapsulate(out byte[] ciphertext, out byte[] expectedSecret);

        // Import the private key from PKCS#8 and decapsulate.
        using var imported = MLKem.ImportPkcs8PrivateKey(pkcs8);
        byte[] actualSecret = imported.Decapsulate(ciphertext);

        Output?.WriteLine("PKCS#8 size:   {0} bytes", pkcs8.Length);
        Output?.WriteLine("Shared secret: {0}", Convert.ToHexString(actualSecret));

        Assert.Equal(expectedSecret, actualSecret);
    }
}
