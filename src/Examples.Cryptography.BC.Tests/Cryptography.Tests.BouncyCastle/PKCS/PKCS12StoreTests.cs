using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509.Extension;

namespace Examples.Cryptography.Tests.BouncyCastle.PKCS;

public class PKCS12StoreTests : IClassFixture<PKCSFixture>
{
    private readonly PKCSFixture _fixture;

    public PKCS12StoreTests(PKCSFixture fixture)
    {
        _fixture = fixture;
    }


    [Fact]
    public void WhenLoadFromSave_WithMemoryStream()
    {
        var password = "BadP@ssw0rd";

        // openssl pkcs12 -export -out my-store.p12 -inkey ee.key -in ee.crt -CAfile chai.pem -chain -legacy

        var (_, rootCert) = _fixture.RootCaSet;
        var (_, caCert) = _fixture.IntermediateCaSet;
        var (entiryKeyPair, entityCert) = _fixture.EndEntitySet;

        X509CertificateEntry[] chain = new[] {
            new X509CertificateEntry(entityCert),
            new X509CertificateEntry(caCert),
            new X509CertificateEntry(rootCert),
        };

        var bagAttr = new Dictionary<DerObjectIdentifier, Asn1Encodable>
        {
            [PkcsObjectIdentifiers.Pkcs9AtFriendlyName]
                = new DerBmpString("My Key"),
            [PkcsObjectIdentifiers.Pkcs9AtLocalKeyID]
                = new SubjectKeyIdentifierStructure(entiryKeyPair.Public),
        };

        Pkcs12Store store = new Pkcs12StoreBuilder()
            .SetUseDerEncoding(true)
            .SetKeyAlgorithm(NistObjectIdentifiers.IdAes256Cbc, PkcsObjectIdentifiers.IdHmacWithSha256)
            .SetCertAlgorithm(PkcsObjectIdentifiers.PbeWithShaAnd3KeyTripleDesCbc)
            //.SetCertAlgorithm(BCObjectIdentifiers.bc_pbe_sha256_pkcs12_aes256_cbc) // Not compatible with openssl.
            //.SetCertAlgorithm(NistObjectIdentifiers.IdAes256Cbc) // error?.
            .Build();

        store.SetKeyEntry("My Key", new AsymmetricKeyEntry(entiryKeyPair.Private, bagAttr), chain);

        // MAC: sha1, Iteration 1024. only ?
        // https://github.com/bcgit/bc-csharp/blob/master/crypto/src/pkcs/Pkcs12Store.cs#L950

        // using var stream = File.Create("my-store.p12");
        using var stream = new MemoryStream();

        // # export to pfx(.p12) file.
        store.Save(stream, password.ToCharArray(), new SecureRandom());
        stream.Flush();

        //File.WriteAllBytes(@"my-store.p12", stream.ToArray());

        stream.Seek(0, SeekOrigin.Begin);
        Pfx bag = Pfx.GetInstance(Asn1Object.FromStream(stream));

        var others = new Pkcs12StoreBuilder()
            .SetUseDerEncoding(true)
            .SetKeyAlgorithm(NistObjectIdentifiers.IdAes256Cbc, PkcsObjectIdentifiers.IdHmacWithSha256)
            .SetCertAlgorithm(PkcsObjectIdentifiers.PbeWithShaAnd3KeyTripleDesCbc)
            .Build();

        // # import from pfx(.p12) file.
        stream.Seek(0, SeekOrigin.Begin);
        others.Load(stream, password.ToArray());

        // # export private key.
        var importedKey = others.GetKey("My Key");

        // # export cert.
        var importedCert = others.GetCertificate("My Key");

        // # export cert chain.
        var importedChain = others.GetCertificateChain("My Key");

        others.Count.Is(1);
        others.Aliases.Is(new[] { "My Key" });

        importedKey.Key.Is(entiryKeyPair.Private);
        importedCert.Certificate.Is(entityCert);
        importedChain.Is(chain);

        return;
    }

}
