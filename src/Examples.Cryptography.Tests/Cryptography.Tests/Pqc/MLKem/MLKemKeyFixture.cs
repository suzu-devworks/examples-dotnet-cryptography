using System.Security.Cryptography;

namespace Examples.Cryptography.Tests.Pqc;

/// <summary>
/// Fixture for ML-KEM (Module Lattice Key Encapsulation Mechanism) key pair.
/// ML-KEM is standardized in FIPS 203 and is designed to be secure against quantum computer attacks.
/// </summary>
/// <remarks>
/// ML-KEM parameter sets and sizes (per FIPS 203):
/// <list type="table">
///   <listheader>
///     <term>Algorithm</term>
///     <description>Security Level / Key and Ciphertext Sizes</description>
///   </listheader>
///   <item>
///     <term>ML-KEM-512</term>
///     <description>Category 1 | EncapKey=800B, DecapKey=1632B, Ciphertext=768B, SharedSecret=32B</description>
///   </item>
///   <item>
///     <term>ML-KEM-768</term>
///     <description>Category 3 | EncapKey=1184B, DecapKey=2400B, Ciphertext=1088B, SharedSecret=32B</description>
///   </item>
///   <item>
///     <term>ML-KEM-1024</term>
///     <description>Category 5 | EncapKey=1568B, DecapKey=3168B, Ciphertext=1568B, SharedSecret=32B</description>
///   </item>
/// </list>
/// ML-KEM-768 (Category 3, roughly equivalent to AES-192) is recommended for general use.
/// </remarks>
public class MLKemKeyFixture : IDisposable
{
    /// <summary>
    /// Initializes a new instance of <see cref="MLKemKeyFixture"/>.
    /// </summary>
    /// <remarks>
    /// Key generation is skipped on platforms where ML-KEM is not supported
    /// (requires OpenSSL 3.3.0 or later on Linux).
    /// </remarks>
    public MLKemKeyFixture()
    {
        if (MLKem.IsSupported)
        {
            KeyPair = MLKem.GenerateKey(MLKemAlgorithm.MLKem768);
        }
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        KeyPair?.Dispose();
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Gets the generated ML-KEM-768 key pair, or <see langword="null"/> if not supported.
    /// </summary>
    public MLKem? KeyPair { get; }
}
