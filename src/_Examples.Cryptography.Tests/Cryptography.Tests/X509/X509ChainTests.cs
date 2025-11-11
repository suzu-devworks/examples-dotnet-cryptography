using System.Security.Cryptography.X509Certificates;

namespace Examples.Cryptography.Tests.X509;

public class X509ChainTests : IClassFixture<X509DataFixture>
{
    private readonly ITestOutputHelper _output;
    private readonly X509DataFixture _fixture;

    public X509ChainTests(X509DataFixture fixture, ITestOutputHelper output)
    {
        /// ```shell
        /// dotnet test --logger "console;verbosity=detailed"
        /// ```
        _output = output;

        _fixture = fixture;
    }


    [Fact]
    public void WhenCallingBuild_WorksAsExpected()
    {
        /// <seealso href="https://learn.microsoft.com/ja-jp/dotnet/api/system.security.cryptography.x509certificates.x509chain?view=net-7.0" />

        // Arrange.
        var certs = _fixture.Certificates;

        var root = _fixture.RootCACert;
        var ee = _fixture.EndEntityCert;

        //Output chain information of the selected certificate.
        using var chain = X509Chain.Create();
        chain.ChainPolicy.DisableCertificateDownloads = true;
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(root);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.ExtraStore.AddRange(certs.ToArray());

        // Act.
        var success = chain.Build(ee);
        Dump(chain);

        // Assert.
        success.IsTrue();
        chain.ChainStatus.Length.Is(0);
        chain.ChainElements.Count.Is(4);
        chain.ChainElements[0].Certificate.SubjectName.Name.Is("C=JP, CN=localhost");
        chain.ChainElements[1].Certificate.SubjectName.Name.Is("C=JP, CN=Test CA-257");
        chain.ChainElements[2].Certificate.SubjectName.Name.Is("C=JP, CN=Test CA-256");
        chain.ChainElements[3].Certificate.SubjectName.Name.Is("C=JP, CN=Test CA-root");


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

}
