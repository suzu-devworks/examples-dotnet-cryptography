#if OPENSSL_V3_ERROR

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Examples.Cryptography.X509Certificates;

namespace Examples.Cryptography.Tests.X509Certificates;

public class X509ChainTests : IDisposable
{
    private readonly ITestOutputHelper _output;
    private readonly IEnumerable<(AsymmetricAlgorithm, X509Certificate2)> _certResources;

    public X509ChainTests(ITestOutputHelper output)
    {
        _output = output;
        _certResources = CreateCertificates(DateTimeOffset.UtcNow, 4).ToArray();
    }

    public void Dispose()
    {
        foreach (var (k, c) in _certResources)
        {
            (c as IDisposable)?.Dispose();
            (k as IDisposable)?.Dispose();
        }
        GC.SuppressFinalize(this);
    }


    /// <seealso href="https://learn.microsoft.com/ja-jp/dotnet/api/system.security.cryptography.x509certificates.x509chain?view=net-7.0" />
    [Fact]
    public void WhenBuild_WithSelfMadeCertificate()
    {
        // Arrange.
        var (_, root) = _certResources.FirstOrDefault();
        var (_, ee) = _certResources.LastOrDefault();

        //Output chain information of the selected certificate.
        using var chain = X509Chain.Create();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(root);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.ExtraStore.AddRange(_certResources.Select(x => x.Item2).ToArray());

        // Act.
        var success = chain.Build(ee);

        Dump(chain);

        // Assert.
#if WINDOWS
        success.IsTrue();
#else
        // ExtraStore is disabled on Linux?
        success.IsFalse();
#endif

    }

    private void Dump(X509Chain chain)
    {
        //Output chain information of the selected certificate.
        _output.WriteLine("");
        _output.WriteLine("Chain Information");
        _output.WriteLine("  Chain revocation flag: {0}", chain.ChainPolicy.RevocationFlag);
        _output.WriteLine("  Chain revocation mode: {0}", chain.ChainPolicy.RevocationMode);
        _output.WriteLine("  Chain verification flag: {0}", chain.ChainPolicy.VerificationFlags);
        _output.WriteLine("  Chain verification time: {0}", chain.ChainPolicy.VerificationTime);
        _output.WriteLine("  Chain disable certificate downloads: {0}", chain.ChainPolicy.DisableCertificateDownloads);
        _output.WriteLine("  Chain application policy count: {0}", chain.ChainPolicy.ApplicationPolicy.Count);
        _output.WriteLine("  Chain certificate policy count: {0}", chain.ChainPolicy.CertificatePolicy.Count);

        _output.WriteLine("  Chain status length: {0}", chain.ChainStatus.Length);
        foreach (var s in chain.ChainStatus)
        {
            _output.WriteLine("    Status [{0}] {1}", s.Status, s.StatusInformation);
        }
        _output.WriteLine("");

        //Output chain element information.
        _output.WriteLine("Chain Element Information");
        _output.WriteLine("  Number of chain elements: {0}", chain.ChainElements.Count);
        _output.WriteLine("  Chain elements synchronized? {0}", chain.ChainElements.IsSynchronized);
        _output.WriteLine("");

        foreach (var element in chain.ChainElements)
        {
            _output.WriteLine("  Element issuer name: {0}", element.Certificate.Issuer);
            _output.WriteLine("  Element certificate valid until: {0}", element.Certificate.NotAfter);
            _output.WriteLine("  Element certificate is valid: {0}", element.Certificate.Verify());
            _output.WriteLine("  Element information: {0}", element.Information);

            _output.WriteLine("  Number of element extensions: {0}", element.Certificate.Extensions.Count);
            foreach (var e in element.Certificate.Extensions)
            {
                _output.WriteLine("    [{0}] {1}", e.Critical, e.Oid?.FriendlyName);
            }

            _output.WriteLine("  Element error status length: {0}", element.ChainElementStatus.Length);
            foreach (var s in element.ChainElementStatus)
            {
                _output.WriteLine("    Status [{0}] {1}", s.Status, s.StatusInformation);
            }
            _output.WriteLine("");
        }
    }

    private static IEnumerable<(AsymmetricAlgorithm, X509Certificate2)> CreateCertificates(DateTimeOffset now, int numOfCa)
    {
        var notBefore = now.AddSeconds(-50);
        var notAfter = now.AddDays(365);

        // root CA
        var rootKeyPair = RSA.Create(4096);
        var issuer = new X500DistinguishedName("C=JP,O=suzu-devworks CA,CN=Test CA");
        var rootCert = new CertificateRequest(
            issuer,
            rootKeyPair,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1)
        .AddSubjectKeyIdentifierExtension()
        .AddExtension(X509BasicConstraintsExtension.CreateForCertificateAuthority())
        .CreateSelfSigned(notBefore, notAfter);

        //_output.WriteLine(rootCert.ToString());
        yield return (rootKeyPair, rootCert);

        // CA
        AsymmetricAlgorithm caKeyPair = rootKeyPair;
        X509Certificate2 caCert = rootCert;

        foreach (var i in Enumerable.Range(1, numOfCa))
        {
            var intermediateKeyPair = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var subject = new X500DistinguishedName($"C=JP,O=suzu-devworks CA,CN=Test CA {255 + i}");
            var request = new CertificateRequest(
                    subject,
                    intermediateKeyPair,
                    HashAlgorithmName.SHA256)
                .AddSubjectKeyIdentifierExtension()
                .AddExtension(X509BasicConstraintsExtension.CreateForCertificateAuthority(numOfCa - i));

            var serial = (255L + i).ToSerialNumberBytes();
            var intermediateCert = request.Create(
                caCert.IssuerName, caKeyPair, notBefore, notAfter, serial);

            //_output.WriteLine(intermediateCert.ToString());
            yield return (intermediateKeyPair, intermediateCert);

            caKeyPair = intermediateKeyPair;
            caCert = intermediateCert;
        }

        // End Entity
        var eeKeyPair = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var eeSubject = new X500DistinguishedName($"C=JP,O=suzu-devworks,CN=localhost");
        var eeRequest = new CertificateRequest(
                eeSubject,
                eeKeyPair,
                HashAlgorithmName.SHA256)
            .AddAuthorityKeyIdentifierExtension(caCert)
            .AddSubjectKeyIdentifierExtension()
            .AddExtension(X509BasicConstraintsExtension.CreateForEndEntity());

        var eeSerial = new Random().CreateSerialNumber();
        var eeCert = eeRequest.Create(
                caCert.IssuerName, caKeyPair, notBefore, notAfter, eeSerial);

        //_output.WriteLine(eeCert.ToString());
        yield return (eeKeyPair, eeCert);
    }

}

#endif
