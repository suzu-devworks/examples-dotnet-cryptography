using System.Security.Cryptography.X509Certificates;
using Examples.Cryptography.Extensions;
using Examples.Cryptography.Tests.X509.Helper;
using Examples.Cryptography.X509Certificates;

namespace Examples.Cryptography.Tests.X509;

public class X509ChainTests(
    X509ChainTests.Fixture fixture)
    : IClassFixture<X509ChainTests.Fixture>
{

    public class Fixture : IAsyncLifetime
    {
        public ValueTask InitializeAsync()
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();

            X500DistinguishedName rootCaDname = new("C=JP, O=examples, CN=root CA");
            X500DistinguishedName targetDname = new("CN=*.examples.jp");

            var certificates = new TestCertificateChainBuilder(rootCaDname)
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
            TestContext.Current.TestOutputHelper?.WriteLine($"Certificates Build: {sw.Elapsed}");

            Certificates = [.. certificates];
            TrustAnchors = Certificates
                .Find(X509FindType.FindBySubjectDistinguishedName, rootCaDname.Name, validOnly: false);
            TargetCertificate = Certificates
                .Find(X509FindType.FindBySubjectDistinguishedName, targetDname.Name, validOnly: false)
                .First();

            return ValueTask.CompletedTask;
        }

        public ValueTask DisposeAsync()
        {
            foreach (var cert in Certificates)
            {
                cert.Dispose();
            }
            GC.SuppressFinalize(this);
            return ValueTask.CompletedTask;
        }

        public X509Certificate2Collection Certificates { get; private set; } = default!;
        public X509Certificate2Collection TrustAnchors { get; private set; } = default!;
        public X509Certificate2 TargetCertificate { get; private set; } = default!;
    }

    [Fact]
    public void When_CertificateChainIsBuilt_WithAllCertificates_Then_ReturnsSuccess()
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
    public void When_CertificateChainIsBuilt_WithMissingCertificates_Then_ReturnsNotSuccess()
    {
        var certs = fixture.Certificates.Where(x => !x.SubjectName.Name.EndsWith("002")).ToArray();
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

    [Fact]
    public void When_CertificateChainIsBuilt_WithNoTrustAnchors_Then_ReturnsNotSuccess()
    {
        var certs = fixture.Certificates;
        // var trustAnchors = fixture.TrustAnchors;
        var target = fixture.TargetCertificate;

        //Output chain information of the selected certificate.
        using var chain = X509Chain.Create();
        chain.ChainPolicy.DisableCertificateDownloads = true;
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        // chain.ChainPolicy.CustomTrustStore.AddRange(trustAnchors);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.ExtraStore.AddRange(certs);

        var success = chain.Build(target);

        // Assert:

        Assert.False(success);

        var status = Assert.Single(chain.ChainStatus);
        Assert.Equal(X509ChainStatusFlags.UntrustedRoot, status.Status);
        Assert.Equal("self-signed certificate in certificate chain", status.StatusInformation);

        Assert.Collection(chain.ChainElements,
            (elem) => Assert.Equal("CN=*.examples.jp", elem.Certificate.SubjectName.Name),
            (elem) => Assert.Equal("C=JP, O=examples, CN=intermediate CA 003", elem.Certificate.SubjectName.Name),
            (elem) => Assert.Equal("C=JP, O=examples, CN=intermediate CA 002", elem.Certificate.SubjectName.Name),
            (elem) => Assert.Equal("C=JP, O=examples, CN=intermediate CA 001", elem.Certificate.SubjectName.Name),
            (elem) => Assert.Equal("C=JP, O=examples, CN=root CA", elem.Certificate.SubjectName.Name)
        );
    }

}
