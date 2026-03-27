using System.Security.Cryptography;

namespace Examples.Cryptography.Tests.Pqc;

/// <summary>
/// Fixture for ML-DSA (Module Lattice Digital Signature Algorithm) key pair.
/// ML-DSA is standardized in FIPS 204 and is designed to be secure against quantum computer attacks.
/// </summary>
/// <remarks>
/// ML-DSA parameter sets and sizes (per FIPS 204):
/// <list type="table">
///   <listheader>
///     <term>Algorithm</term>
///     <description>Security Level / Key and Signature Sizes</description>
///   </listheader>
///   <item>
///     <term>ML-DSA-44</term>
///     <description>Category 2 | PublicKey=1312B, PrivateKey=2560B, Signature=2420B</description>
///   </item>
///   <item>
///     <term>ML-DSA-65</term>
///     <description>Category 3 | PublicKey=1952B, PrivateKey=4032B, Signature=3309B</description>
///   </item>
///   <item>
///     <term>ML-DSA-87</term>
///     <description>Category 5 | PublicKey=2592B, PrivateKey=4896B, Signature=4627B</description>
///   </item>
/// </list>
/// ML-DSA-65 (Category 3, roughly equivalent to AES-192) is recommended for general use.
/// </remarks>
public class MLDsaKeyFixture : IDisposable
{
    /// <summary>
    /// Initializes a new instance of <see cref="MLDsaKeyFixture"/>.
    /// </summary>
    /// <remarks>
    /// Key generation is skipped on platforms where ML-DSA is not supported
    /// (requires OpenSSL 3.3.0 or later on Linux).
    /// </remarks>
    public MLDsaKeyFixture()
    {
        if (MLDsa.IsSupported)
        {
            KeyPair = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
        }
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        KeyPair?.Dispose();
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Gets the generated ML-DSA-65 key pair, or <see langword="null"/> if not supported.
    /// </summary>
    public MLDsa? KeyPair { get; }
}
