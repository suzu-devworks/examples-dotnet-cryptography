using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Examples.Cryptography.X509Certificates;

namespace Examples.Cryptography.Tests.X509;

public class X509CRLTests(
    X509CRLTests.Fixture fixture,
    ITestOutputHelper output)
    : IClassFixture<X509CRLTests.Fixture>
{
    public class Fixture : IDisposable
    {
        public Fixture()
        {
            X500DistinguishedName rootCaDname = new("C=JP, O=examples, CN=root CA");
            X500DistinguishedName targetDname = new("CN=*.examples.jp");

            var certificates = new Helper.X509CertificateChainBuilder(rootCaDname)
                .AddEndEntity(targetDname, req => req
                    .AddKeyUsageExtension(critical: false, X509KeyUsageFlags.DigitalSignature)
                )
                .Build(DateTimeOffset.UtcNow, days: 1);

            IssuerCertificate = certificates.First(x => x.SubjectName.Name == rootCaDname.Name);
            Certificate = certificates.First(x => x.SubjectName.Name == targetDname.Name);
        }

        public void Dispose()
        {
            Certificate.Dispose();
            IssuerCertificate.Dispose();
            GC.SuppressFinalize(this);
        }

        public X509Certificate2 IssuerCertificate { get; }
        public X509Certificate2 Certificate { get; }
    }

    [Fact]
    public void When_CreateCRLWithBuilder_Then_ReturnsDERBinaryArray()
    {
        var issuerCert = fixture.IssuerCertificate;
        var certificate = fixture.Certificate;
        var caCrlUpdateInterval = TimeSpan.FromDays(1);

        var builder = new CertificateRevocationListBuilder();
        builder.AddEntry(
            certificate,
            DateTimeOffset.Parse("2012-02-29"),
            X509RevocationReason.KeyCompromise);

        builder.AddEntry(
            new CertificateSerialNumber(new Random()).ToBytes(),
            DateTimeOffset.Parse("2016-02-29"),
            X509RevocationReason.WeakAlgorithmOrKey);

        byte[] crl = builder.Build(issuerCert,
            BigInteger.One,
            DateTimeOffset.UtcNow + caCrlUpdateInterval,
            HashAlgorithmName.SHA256);

        Dump(crl);
        // File.WriteAllBytes(@"test.crl", crl);

        // Assert:

        // TODO CRL Assertion Hmm...
        Assert.NotEmpty(crl);
    }

    private void Dump(byte[] crl)
    {
        // TODO 

#pragma warning disable IDE0059 // Remove unnecessary value assignment

        var reader = new AsnReader(crl, AsnEncodingRules.DER);

        var certificateList = reader.ReadSequence();
        var tbsCertList = certificateList.ReadSequence();
        // var signatureAlgId = certificateList.ReadEncodedValue();
        // var signature = certificateList.ReadBitString(out var unusedBitCount);

        var version = tbsCertList.ReadInteger();
        var signatureAlgId = tbsCertList.ReadEncodedValue(); // AlgorithmIdentifier
        var issuer = tbsCertList.ReadEncodedValue(); // Name
        var thisUpdate = tbsCertList.ReadUtcTime();
        var nextUpdate = tbsCertList.ReadUtcTime();
        output.WriteLine($"version: {version}");
        output.WriteLine($"thisUpdate: {thisUpdate:O}");
        output.WriteLine($"nextUpdate: {nextUpdate:O}");

        var revokedCertificates = tbsCertList.ReadSequence();
        output.WriteLine($"revokedCertificates:");
        while (revokedCertificates.HasData)
        {
            var sequence = revokedCertificates.ReadSequence();
            var userCertificate = sequence.ReadEncodedValue(); // CertificateSerialNumber
            var revocationDate = sequence.ReadUtcTime();
            var crlEntryExtensions = sequence.ReadEncodedValue();  // Extensions
            output.WriteLine($"  revocationDate: {revocationDate:O}");
        }

        var crlExtensions = tbsCertList.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
        output.WriteLine($"crlExtensions: [0]");
        while (crlExtensions.HasData)
        {
            var sequence = crlExtensions.ReadSequence();
        }
#pragma warning restore IDE0059 // Remove unnecessary value assignment
    }

}
