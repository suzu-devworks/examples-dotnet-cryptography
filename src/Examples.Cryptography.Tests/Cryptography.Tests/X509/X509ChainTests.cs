using System.Security.Cryptography.X509Certificates;
using Examples.Cryptography.X509Certificates;

namespace Examples.Cryptography.Tests.X509;

public class X509ChainTests(
    X509ChainTests.Fixture fixture,
    ITestOutputHelper output)
    : IClassFixture<X509ChainTests.Fixture>
{
    public class Fixture : IDisposable
    {
        public Fixture()
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();

            X500DistinguishedName rootCaDname = new("C=JP, O=examples, CN=root CA");
            X500DistinguishedName targetDname = new("CN=*.examples.jp");

            var certificates = new Helper.X509CertificateChainBuilder(rootCaDname)
                .AddIntermediateCA(new($"C=JP, O=examples, CN=intermediate CA 001"))
                .AddIntermediateCA(new($"C=JP, O=examples, CN=intermediate CA 002"))
                .AddIntermediateCA(new($"C=JP, O=examples, CN=intermediate CA 003"))
                .AddEndEntity(targetDname, req => req
                    .AddKeyUsageExtension(critical: false, X509KeyUsageFlags.DigitalSignature)
                    .AddExtendedKeyUsageExtension(critical: false, usage =>
                    {
                        usage.Add(X509ExtendedKeyUsages.IdKpServerAuth);
                        usage.Add(X509ExtendedKeyUsages.IdKpClientAuth);
                        usage.Add(X509ExtendedKeyUsages.IdKpCodeSigning);
                        usage.Add(X509ExtendedKeyUsages.IdKpEmailProtection);
                    })
                    .AddSubjectAlternativeName(san =>
                    {
                        san.AddDnsName("www.local-server.jp");
                        san.AddDnsName("local-server.jp");
                    }))
                .Build(DateTimeOffset.UtcNow, days: 1);

            sw.Stop();
            System.Diagnostics.Debug.WriteLine($"Certificates Build: {sw.Elapsed}");

            Certificates = [.. certificates];
            TrustAnchors = Certificates.Find(X509FindType.FindBySubjectDistinguishedName, rootCaDname.Name, validOnly: false);
            TargetCertificate = Certificates.Find(X509FindType.FindBySubjectDistinguishedName, targetDname.Name, validOnly: false)
                .First();
        }

        public void Dispose()
        {
            foreach (var cert in Certificates)
            {
                cert.Dispose();
            }
            GC.SuppressFinalize(this);
        }

        public X509Certificate2Collection Certificates { get; } = default!;
        public X509Certificate2Collection TrustAnchors { get; } = default!;
        public X509Certificate2 TargetCertificate { get; } = default!;
    }

    [Fact]
    public void When_ChainIsBuiltWithAllCertificates_Then_ChainCreationSucceeds()
    {
        var certs = fixture.Certificates;
        var trustAnchors = fixture.TrustAnchors;
        var target = fixture.TargetCertificate;

        //Output chain information of the selected certificate.
        using var chain = X509Chain.Create();
        chain.ChainPolicy.DisableCertificateDownloads = true;
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.AddRange(trustAnchors);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.ExtraStore.AddRange(certs);

        var success = chain.Build(target);

        Dump(chain);

        // Assert:

        Assert.True(success);

        Assert.Empty(chain.ChainStatus);
        Assert.Collection(chain.ChainElements,
            (elem) => Assert.Equal("CN=*.examples.jp", elem.Certificate.SubjectName.Name),
            (elem) => Assert.Equal("C=JP, O=examples, CN=intermediate CA 003", elem.Certificate.SubjectName.Name),
            (elem) => Assert.Equal("C=JP, O=examples, CN=intermediate CA 002", elem.Certificate.SubjectName.Name),
            (elem) => Assert.Equal("C=JP, O=examples, CN=intermediate CA 001", elem.Certificate.SubjectName.Name),
            (elem) => Assert.Equal("C=JP, O=examples, CN=root CA", elem.Certificate.SubjectName.Name)
        );
    }

    [Fact]
    public void When_ChainIsBuiltWithMissingCertificates_Then_ChainCreationFails()
    {
        var certs = fixture.Certificates.Where(x => x.SubjectName.Name.EndsWith("003")).ToArray();
        var trustAnchors = fixture.TrustAnchors;
        var target = fixture.TargetCertificate;

        //Output chain information of the selected certificate.
        using var chain = X509Chain.Create();
        chain.ChainPolicy.DisableCertificateDownloads = true;
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.AddRange(trustAnchors);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.ExtraStore.AddRange(certs);

        var success = chain.Build(target);

        Dump(chain);

        // Assert:

        Assert.False(success);

        var status = Assert.Single(chain.ChainStatus);
        Assert.Equal(X509ChainStatusFlags.PartialChain, status.Status);
        Assert.Equal("unable to get local issuer certificate", status.StatusInformation);

        Assert.Collection(chain.ChainElements,
            (elem) => Assert.Equal("CN=*.examples.jp", elem.Certificate.SubjectName.Name),
            (elem) => Assert.Equal("C=JP, O=examples, CN=intermediate CA 003", elem.Certificate.SubjectName.Name)
        );
    }

    private void Dump(X509Chain chain)
    {
        //Output chain information of the selected certificate.

        output.WriteLine("");
        output.WriteLine("Chain Information");
        output.WriteLine("  Chain revocation flag: {0}", chain.ChainPolicy.RevocationFlag);
        output.WriteLine("  Chain revocation mode: {0}", chain.ChainPolicy.RevocationMode);
        output.WriteLine("  Chain verification flag: {0}", chain.ChainPolicy.VerificationFlags);
        output.WriteLine("  Chain verification time: {0}", chain.ChainPolicy.VerificationTime);
        output.WriteLine("  Chain disable certificate downloads: {0}", chain.ChainPolicy.DisableCertificateDownloads);
        output.WriteLine("  Chain application policy count: {0}", chain.ChainPolicy.ApplicationPolicy.Count);
        output.WriteLine("  Chain certificate policy count: {0}", chain.ChainPolicy.CertificatePolicy.Count);

        output.WriteLine("  Chain status length: {0}", chain.ChainStatus.Length);
        foreach (var s in chain.ChainStatus)
        {
            output.WriteLine("    Status [{0}] {1}", s.Status, s.StatusInformation);
        }
        output.WriteLine("");

        //Output chain element information.
        output.WriteLine("Chain Element Information");
        output.WriteLine("  Number of chain elements: {0}", chain.ChainElements.Count);
        output.WriteLine("  Chain elements synchronized? {0}", chain.ChainElements.IsSynchronized);
        output.WriteLine("");

        foreach (var element in chain.ChainElements)
        {
            output.WriteLine("  Element issuer name: {0}", element.Certificate.Issuer);
            output.WriteLine("  Element certificate valid until: {0}", element.Certificate.NotAfter);
            output.WriteLine("  Element certificate is valid: {0}", element.Certificate.Verify());
            output.WriteLine("  Element information: {0}", element.Information);

            output.WriteLine("  Number of element extensions: {0}", element.Certificate.Extensions.Count);
            foreach (var e in element.Certificate.Extensions)
            {
                output.WriteLine("    [{0}] {1}", e.Critical, e.Oid?.FriendlyName ?? "");
            }

            output.WriteLine("  Element error status length: {0}", element.ChainElementStatus.Length);
            foreach (var s in element.ChainElementStatus)
            {
                output.WriteLine("    Status [{0}] {1}", s.Status, s.StatusInformation);
            }
            output.WriteLine("");
        }
    }

}
