using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Examples.Cryptography.X509Certificates;

namespace Examples.Cryptography.Tests.X509;

using CertSets = ValueTuple<AsymmetricAlgorithm, X509Certificate2>;

public class X509DataFixture : IDisposable
{
    public X509DataFixture()
    {
        // ... lazy initialize data ...
        var notBefore = DateTimeOffset.Now.AddSeconds(-50);

        _rootCaSet = new(() => InitializeRootCaSets(notBefore));
        _interCaSets = new(() => InitializeIntermediateCaSets(notBefore, numOfCerts: 4));
        _endEntitySet = new(() => InitializeEESets(notBefore));
    }

    public CertSets RootCaSet => _rootCaSet.Value;
    private readonly Lazy<CertSets> _rootCaSet;

    public IEnumerable<CertSets> IntermediateCaSets => _interCaSets.Value;
    private readonly Lazy<IEnumerable<CertSets>> _interCaSets;

    public CertSets EndEntitySet => _endEntitySet.Value;
    private readonly Lazy<CertSets> _endEntitySet;

    public IEnumerable<X509Certificate> Certificates
        => Enumerable.Empty<CertSets>()
                .Append(RootCaSet)
                .Concat(IntermediateCaSets)
                .Append(EndEntitySet)
                .Select(x => x.Item2);

    public void Dispose()
    {
        GC.SuppressFinalize(this);
    }


    private static CertSets InitializeRootCaSets(
        DateTimeOffset notBefore,
        int days = 365)
    {
        var notAfter = notBefore.AddDays(days);

        var keyPair = RSA.Create(2048);

        var subject = new X500DistinguishedName("C=JP,CN=Test CA-root");
        var cert = new CertificateRequest(
            subject,
            keyPair,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1)
        .AddSubjectKeyIdentifierExtension()
        .AddAuthorityKeyIdentifierExtension()
        .AddExtension(X509BasicConstraintsExtension.CreateForCertificateAuthority())
        .CreateSelfSigned(notBefore, notAfter);

        //File.WriteAllText($"CAroot.crt", rootCert.ExportCertificatePem());

        return (keyPair, cert);
    }


    private IEnumerable<CertSets> InitializeIntermediateCaSets(
        DateTimeOffset notBefore,
        int days = 365,
        int numOfCerts = 3)
    {
        var notAfter = notBefore.AddDays(days);
        var (issuerKeyPair, issuerCert) = RootCaSet;

        var results = new List<CertSets>();

        foreach (var i in Enumerable.Range(1, numOfCerts - 2))
        {
            var keyPair = ECDsa.Create(ECCurve.NamedCurves.nistP256);

            var subject = new X500DistinguishedName($"C=JP,CN=Test CA-{255 + i}");
            var request = new CertificateRequest(
                    subject,
                    keyPair,
                    HashAlgorithmName.SHA256)
                .AddSubjectKeyIdentifierExtension()
                .AddAuthorityKeyIdentifierExtension(issuerCert)
                .AddExtension(X509BasicConstraintsExtension.CreateForCertificateAuthority(numOfCerts - 2 - i));

            var serial = new CertificateSerialNumber(255L + i).ToBytes();
            var cert = request.CreateCertificate(issuerCert.SubjectName, issuerKeyPair, notBefore, notAfter, serial);

            //File.WriteAllText($"CA-{255 + i}.crt", intermediateCert.ExportCertificatePem());

            results.Add((keyPair, cert));

            issuerKeyPair = keyPair;
            issuerCert = cert;
        }

        return results;
    }


    private CertSets InitializeEESets(
        DateTimeOffset notBefore,
         int days = 365)
    {
        var notAfter = notBefore.AddDays(days);
        var (issuerKeyPair, issuerCert) = IntermediateCaSets.Last();

        var keyPair = ECDsa.Create(ECCurve.NamedCurves.nistP521);

        var subject = new X500DistinguishedName("C=JP,CN=localhost");
        var request = new CertificateRequest(
                subject,
                keyPair,
                HashAlgorithmName.SHA256)
            .AddSubjectKeyIdentifierExtension()
            .AddAuthorityKeyIdentifierExtension(issuerCert)
            .AddExtension(X509BasicConstraintsExtension.CreateForEndEntity());

        var serial = new CertificateSerialNumber(100, new Random()).ToBytes();
        var cert = request.CreateCertificate(issuerCert.SubjectName, issuerKeyPair, notBefore, notAfter, serial);

        //File.WriteAllText($"EE.crt", intermediateCert.ExportCertificatePem());

        return (keyPair, cert);
    }

}
