#pragma warning disable SYSLIB5006 // SlhDsa is an experimental API in .NET 10.0

using System.Security.Cryptography;

namespace Examples.Cryptography.Tests.Pqc;

/// <summary>
/// Fixture for SLH-DSA (Stateless Hash-Based Digital Signature Algorithm) key pair.
/// SLH-DSA is standardized in FIPS 205 and is designed to be secure against quantum computer attacks.
/// </summary>
/// <remarks>
/// SLH-DSA parameter sets and sizes (per FIPS 205):
/// <list type="table">
///   <listheader>
///     <term>Algorithm</term>
///     <description>Security Level / Key and Signature Sizes</description>
///   </listheader>
///   <item>
///     <term>SLH-DSA-SHA2-128s</term>
///     <description>Category 1 (small) | PublicKey=32B, PrivateKey=64B, Signature=7856B</description>
///   </item>
///   <item>
///     <term>SLH-DSA-SHA2-128f</term>
///     <description>Category 1 (fast)  | PublicKey=32B, PrivateKey=64B, Signature=17088B</description>
///   </item>
///   <item>
///     <term>SLH-DSA-SHA2-192s</term>
///     <description>Category 3 (small) | PublicKey=48B, PrivateKey=96B, Signature=16224B</description>
///   </item>
///   <item>
///     <term>SLH-DSA-SHA2-256s</term>
///     <description>Category 5 (small) | PublicKey=64B, PrivateKey=128B, Signature=29792B</description>
///   </item>
/// </list>
/// <para>
/// The "s" (small) variants produce smaller signatures at the cost of slower signing.
/// The "f" (fast) variants sign faster but produce larger signatures.
/// </para>
/// SLH-DSA-SHA2-128s is used here as the most signature-size-conscious Category 1 option.
/// </remarks>
public class SlhDsaKeyFixture : IDisposable
{
    /// <summary>
    /// Initializes a new instance of <see cref="SlhDsaKeyFixture"/>.
    /// </summary>
    /// <remarks>
    /// Key generation is skipped on platforms where SLH-DSA is not supported
    /// (requires OpenSSL 3.3.0 or later on Linux).
    /// SLH-DSA is an experimental API in .NET 10.0 (SYSLIB5006).
    /// </remarks>
    public SlhDsaKeyFixture()
    {
        if (SlhDsa.IsSupported)
        {
            KeyPair = SlhDsa.GenerateKey(SlhDsaAlgorithm.SlhDsaSha2_128s);
        }
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        KeyPair?.Dispose();
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Gets the generated SLH-DSA-SHA2-128s key pair, or <see langword="null"/> if not supported.
    /// </summary>
    public SlhDsa? KeyPair { get; }
}
