using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Examples.Cryptography.Generics;
using Examples.Cryptography.X509Certificates;

namespace Examples.Cryptography.Tests.X509;

public class X509DataFixture : IDisposable
{
    public X509DataFixture()
    {
        var notBefore = DateTimeOffset.Now.AddSeconds(-50);

        _rootCaSet = new(() => InitializeRootCaSets(notBefore));
        _interCaSets = new(() => InitializeIntermediateCaSets(notBefore, numOfCerts: 4));
        _endEntitySet = new(() => InitializeEESets(notBefore));
    }

    public X509Certificate2 RootCACert => _rootCaSet.Value;
    private readonly Lazy<X509Certificate2> _rootCaSet;

    public IEnumerable<X509Certificate2> IntermediateCACert => _interCaSets.Value;
    private readonly Lazy<IEnumerable<X509Certificate2>> _interCaSets;

    public X509Certificate2 EndEntityCert => _endEntitySet.Value;
    private readonly Lazy<X509Certificate2> _endEntitySet;

    public IEnumerable<X509Certificate> Certificates
        => Enumerable.Empty<X509Certificate2>()
                .Append(RootCACert)
                .Concat(IntermediateCACert)
                .Append(EndEntityCert);

    public void Dispose()
    {
        _rootCaSet.DisposeIfValueCreated();
        _interCaSets.DisposeIfValueCreated();
        _endEntitySet.DisposeIfValueCreated();
        GC.SuppressFinalize(this);
    }


    private static X509Certificate2 InitializeRootCaSets(
        DateTimeOffset notBefore,
        int days = 365)
    {
        var notAfter = notBefore.AddDays(days);

        // X509Certificate2 has a private key.
        using var keyPair = RSA.Create(2048);

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

        return cert;
    }


    private IEnumerable<X509Certificate2> InitializeIntermediateCaSets(
        DateTimeOffset notBefore,
        int days = 365,
        int numOfCerts = 3)
    {
        var notAfter = notBefore.AddDays(days);
        var issuerCert = RootCACert;
        var issuerKeyPair = (AsymmetricAlgorithm?)issuerCert.GetRSAPrivateKey();

        var results = new List<X509Certificate2>();

        foreach (var i in Enumerable.Range(1, numOfCerts - 2))
        {
            using var keyPair = ECDsa.Create(ECCurve.NamedCurves.nistP256);

            var subject = new X500DistinguishedName($"C=JP,CN=Test CA-{255 + i}");
            var request = new CertificateRequest(
                    subject,
                    keyPair,
                    HashAlgorithmName.SHA256)
                .AddSubjectKeyIdentifierExtension()
                .AddAuthorityKeyIdentifierExtension(issuerCert)
                .AddExtension(X509BasicConstraintsExtension.CreateForCertificateAuthority(numOfCerts - 2 - i));

            var serial = new CertificateSerialNumber(255L + i).ToBytes();
            var cert = request.CreateCertificate(issuerCert.SubjectName, issuerKeyPair!, notBefore, notAfter, serial);

            // Append a private key.
            cert = X509Certificate2.CreateFromPem(cert.ExportCertificatePem(), keyPair.ExportECPrivateKeyPem());

            //File.WriteAllText($"CA-{255 + i}.crt", intermediateCert.ExportCertificatePem());

            results.Add(cert);

            issuerCert = cert;
            issuerKeyPair = issuerCert.GetECDsaPrivateKey();
        }

        return results;
    }


    private X509Certificate2 InitializeEESets(
        DateTimeOffset notBefore,
         int days = 365)
    {
        var notAfter = notBefore.AddDays(days);
        var issuerCert = IntermediateCACert.Last();
        var issuerKeyPair = (AsymmetricAlgorithm?)issuerCert.GetECDsaPrivateKey();

        // X509Certificate2 has a private key.
        using var keyPair = ECDsa.Create(ECCurve.NamedCurves.nistP521);

        var subject = new X500DistinguishedName("C=JP,CN=localhost");
        var request = new CertificateRequest(
                subject,
                keyPair,
                HashAlgorithmName.SHA256)
            .AddSubjectKeyIdentifierExtension()
            .AddAuthorityKeyIdentifierExtension(issuerCert)
            .AddExtension(X509BasicConstraintsExtension.CreateForEndEntity());

        var serial = new CertificateSerialNumber(100, new Random()).ToBytes();
        var cert = request.CreateCertificate(issuerCert.SubjectName, issuerKeyPair!, notBefore, notAfter, serial);

        // Append a private key.
        cert = X509Certificate2.CreateFromPem(cert.ExportCertificatePem(), keyPair.ExportECPrivateKeyPem());

        //File.WriteAllText($"EE.crt", intermediateCert.ExportCertificatePem());

        return cert;
    }

}
