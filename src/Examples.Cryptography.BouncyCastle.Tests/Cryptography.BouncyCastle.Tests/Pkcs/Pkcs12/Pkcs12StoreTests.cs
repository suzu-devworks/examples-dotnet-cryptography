using Examples.Cryptography.BouncyCastle.Tests.Fixtures.OpenSsl;
using Examples.Cryptography.BouncyCastle.Tests.Helpers;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;

namespace Examples.Cryptography.BouncyCastle.Tests.Pkcs.Pkcs12;

public class Pkcs12StoreTests(
    Pkcs12StoreTests.Fixture fixture
    ) : IClassFixture<Pkcs12StoreTests.Fixture>
{
    public class Fixture : IAsyncLifetime
    {
        public async ValueTask InitializeAsync()
        {
            await CertChain.InitializeAsync();
        }

        public async ValueTask DisposeAsync()
        {
            await CertChain.DisposeAsync();
            GC.SuppressFinalize(this);
        }

        private EcdsaCertificateChainOpenSslFixture CertChain { get; } = new(includePrivateKeys: true);

        public X509Certificate RootCaCertificate => CertChain.RootCaCertificate;
        public X509Certificate IntermediateCaCertificate => CertChain.IntermediateCaCertificate;
        public X509Certificate EndEntityCertificate => CertChain.EndEntityCertificate;
        public AsymmetricCipherKeyPair EndEntityPrivateKey => CertChain.EndEntityPrivateKey!;
    }

    private TestFileOutputHelper FileOutput => TestFileOutputHelper.Instance;

    [Fact]
    public async Task When_ExportedToImported_WithMemoryStream_Then_StoreContainsSameKeyAndCertificates()
    {
        var rootCert = fixture.RootCaCertificate;
        var caCert = fixture.IntermediateCaCertificate;
        var entityCert = fixture.EndEntityCertificate;
        var entryKeyPair = fixture.EndEntityPrivateKey;
        var password = PasswordGenerator.Generate(12);

        var alias = "My Key";

        X509CertificateEntry[] chain = new[] {
            new X509CertificateEntry(entityCert),
            new X509CertificateEntry(caCert),
            new X509CertificateEntry(rootCert),
        };

        var bagAttr = new Dictionary<DerObjectIdentifier, Asn1Encodable>
        {
            [PkcsObjectIdentifiers.Pkcs9AtFriendlyName] = new DerBmpString(alias),
            [PkcsObjectIdentifiers.Pkcs9AtLocalKeyID] = X509ExtensionUtilities.CreateSubjectKeyIdentifier(entryKeyPair.Public),
        };

        Pkcs12Store store = new Pkcs12StoreBuilder()
            .SetUseDerEncoding(true)
            .SetKeyAlgorithm(NistObjectIdentifiers.IdAes256Cbc, PkcsObjectIdentifiers.IdHmacWithSha256)
            .SetCertAlgorithm(PkcsObjectIdentifiers.PbeWithShaAnd3KeyTripleDesCbc)
            //.SetCertAlgorithm(BCObjectIdentifiers.bc_pbe_sha256_pkcs12_aes256_cbc) // Not compatible with openssl.
            //.SetCertAlgorithm(NistObjectIdentifiers.IdAes256Cbc) // error?.
            .Build();

        store.SetKeyEntry(alias, new AsymmetricKeyEntry(entryKeyPair.Private, bagAttr), chain);

        // # export to pfx(.p12) file.
        using var stream = new MemoryStream();
        store.Save(stream, password.ToCharArray(), new SecureRandom());
        stream.Flush();

        await FileOutput.WriteFileAsync("bc-store.p12", stream.ToArray(),
            TestContext.Current.CancellationToken);
        await FileOutput.WriteFileAsync("bc-store.p12.secret", password,
            TestContext.Current.CancellationToken);

        // # import from pfx(.p12) file.
        // stream.Seek(0, SeekOrigin.Begin);
        // Pfx bag = Pfx.GetInstance(Asn1Object.FromStream(stream));

        var others = new Pkcs12StoreBuilder()
            .SetUseDerEncoding(true)
            .SetKeyAlgorithm(NistObjectIdentifiers.IdAes256Cbc, PkcsObjectIdentifiers.IdHmacWithSha256)
            .SetCertAlgorithm(PkcsObjectIdentifiers.PbeWithShaAnd3KeyTripleDesCbc)
            .Build();

        // # import from pfx(.p12) file.
        stream.Seek(0, SeekOrigin.Begin);
        others.Load(stream, password.ToArray());

        // # export private key.
        var importedKey = others.GetKey(alias);

        // # export cert.
        var importedCert = others.GetCertificate(alias);

        // # export cert chain.
        var importedChain = others.GetCertificateChain(alias);

        // Assert:

        // The loaded store should be a different instance from the original store.
        Assert.NotSame(store, others);

        // The loaded store should contain the same key and certificate information as the original store.
        Assert.Equal(1, others.Count);
        Assert.True(others.ContainsAlias(alias));
        Assert.Equal(entryKeyPair.Private, importedKey.Key);
        Assert.Equal(entityCert, importedCert.Certificate);
        Assert.Equal(chain.Length, importedChain.Length);
        for (int i = 0; i < chain.Length; i++)
        {
            Assert.Equal(chain[i].Certificate, importedChain[i].Certificate);
        }
    }

}
