using Examples.Cryptography.BouncyCastle.PKCS;
using Examples.Cryptography.BouncyCastle.X509;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace Examples.Cryptography.Tests.BouncyCastle.PKCS;

public class PKCS10CertRequestTests : IClassFixture<PKCSFixture>
{
    private readonly PKCSFixture _fixture;

    public PKCS10CertRequestTests(PKCSFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public void WhenExport_WithECDSA()
    {
        var (keyPair, _) = _fixture.EndEntitySet;

        Pkcs10CertificationRequest request = new(
            signatureAlgorithm: X9ObjectIdentifiers.ECDsaWithSha512.Id,
            new X509Name("C=JP,CN=localhost"),
            publicKey: keyPair.Public,
            attributes: null,
            signingKey: keyPair.Private
        );

        request.Verify().IsTrue("Failed Verify.");
        request.Verify(keyPair.Public).IsTrue("Failed Verify with public key.");

        var pem = request.ExportCertificateRequestPem();

        pem.Is(x => x.StartsWith("-----BEGIN CERTIFICATE REQUEST-----")
            && x.EndsWith("-----END CERTIFICATE REQUEST-----"));

        return;
    }

    [Fact]
    public void WhenImportAndSign()
    {
        var pem = @"""-----BEGIN CERTIFICATE REQUEST-----
                MIIB0DCCAXUCAQAwITELMAkGA1UEBhMCSlAxEjAQBgNVBAMMCWxvY2FsaG9zdDCC
                AUswggEDBgcqhkjOPQIBMIH3AgEBMCwGByqGSM49AQECIQD/////AAAAAQAAAAAA
                AAAAAAAAAP///////////////zBbBCD/////AAAAAQAAAAAAAAAAAAAAAP//////
                /////////AQgWsY12Ko6k+ez671VdpiGvGUdBrDMU7D2O848PifSYEsDFQDEnTYI
                hucEk2pmeOETnSa3gZ9+kARBBGsX0fLhLEJH+Lzm5WOkQPJ3A32BLeszoPShOUXY
                mMKWT+NC4v4af5uO5+tKfA+eFivOM1drMV7Oy7ZAaDe/UfUCIQD/////AAAAAP//
                ////////vOb6racXnoTzucrC/GMlUQIBAQNCAAR10QJ4nNqJy8L0/6udQ6sZmj+D
                Xmf5SKMS/DtYMJcRvufLaO+90tdNlzAQXC6k1qm/wMrZXhiG7IRBnDGIFDGKMAoG
                CCqGSM49BAMEA0kAMEYCIQCRberErtkl4QevFUoOyP2LRZ/gfaEVCQwGAAWKOngI
                ZQIhAPpglB8ojoxJJ3lDNqHOSmKVoN7x59lLcBVcxMgiI+xw
                -----END CERTIFICATE REQUEST-----""";

        var (issuerKeyPair, issuerCert) = _fixture.RootCaSet;
        var now = DateTimeOffset.Now;
        var serial = new BigInteger(256, new SecureRandom());

        var request = Pkcs10CertificationRequestAgent.ImportCertificateRequestPem(pem);

        request.Verify().IsTrue();

        var cert = new X509V3CertificateGenerator()
           .WithEndEntity(
                request.GetPublicKey(),
                request.GetCertificationRequestInfo().Subject,
                issuerCert,
                serial)
           .SetValidity(now.UtcDateTime, days: 365)
           .Generate(new Asn1SignatureFactory("SHA256WithECDSA", issuerKeyPair.Private));

        // When receive your certificate, please verify that it is yours.
        cert.Verify(issuerKeyPair.Public);

        // var certPem = cert.ExportCertificatePem();
        // certPem.Is(x => x.StartsWith("-----BEGIN CERTIFICATE -----")
        //          && x.EndsWith("-----END CERTIFICATE -----"));

        return;
    }


}
