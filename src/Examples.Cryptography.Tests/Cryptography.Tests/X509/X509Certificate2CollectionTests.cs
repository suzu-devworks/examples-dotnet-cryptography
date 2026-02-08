using System.Security.Cryptography.X509Certificates;
using Examples.Cryptography.Tests.Helpers;

namespace Examples.Cryptography.Tests.X509;

/// <summary>
/// Tests for X509Certificate2Collection class.
/// </summary>
/// <param name="fixture"></param>
public class X509Certificate2CollectionTests(
    X509Certificate2CollectionTests.Fixture fixture)
    : IClassFixture<X509Certificate2CollectionTests.Fixture>
{
    public class Fixture : IAsyncLifetime
    {
        public ValueTask InitializeAsync()
        {
            return ValueTask.CompletedTask;
        }

        public ValueTask DisposeAsync()
        {
            foreach (var cert in Certificates)
            {
                cert.Dispose();
            }
            Certificates.Clear();
            GC.SuppressFinalize(this);
            return ValueTask.CompletedTask;
        }

        public X509Certificate2Collection Certificates { get; } = CreateCollection();

        private static X509Certificate2Collection CreateCollection()
        {
            var notBefore = DateTime.UtcNow.AddSeconds(-50);

            X509Certificate2Collection collection = [];
            collection.Add(TestCertificateFactory.CreateSelfSigned(new("CN=*.examples.jp"), notBefore));
            collection.Add(TestCertificateFactory.CreateSelfSigned(new("CN=*.second.examples.jp"), notBefore));
            collection.Add(TestCertificateFactory.CreateSelfSigned(new("CN=examples.com"), notBefore));
            return collection;
        }

    }

    private readonly X509Certificate2Collection _target = fixture.Certificates;

    // validOnly: If true, all necessary checks are performed on the certificate,
    // including whether it can be traced back to a trusted root authority,
    // so there's nothing you can do with a test certificate.

    [Fact]
    public void When_UsingFindByThumbprint_Then_ExpectedCertificateCountIsRetrieved()
    {
        var certificates = fixture.Certificates;

        {
            var input = certificates[0].Thumbprint;
            var collection = _target.Find(X509FindType.FindByThumbprint, input, validOnly: false);

            Assert.Single(collection);
        }

        {
            var input = "12345678901234567890123456789012345678901";
            var collection = _target.Find(X509FindType.FindByThumbprint, input, validOnly: false);

            Assert.Empty(collection);
        }
    }

    [Theory]
    [InlineData("CN=*.examples.jp", 0)]
    [InlineData("*.examples.jp", 1)]
    [InlineData("examples.jp", 2)]
    [InlineData("examples", 3)]
    [InlineData("*.EXAMPLES.jp", 1)]
    public void When_UsingFindBySubjectName_Then_ExpectedCertificateCountIsRetrieved(string findValue, int expectedCount)
    {
        var collection = _target.Find(X509FindType.FindBySubjectName, findValue, validOnly: false);

        Assert.Equal(expectedCount, collection.Count);
    }

    [Theory]
    [InlineData("CN=*.examples.jp", 1)]
    [InlineData("*.examples.jp", 0)]
    [InlineData("examples.jp", 0)]
    [InlineData("examples", 0)]
    [InlineData("CN=*.EXAMPLES.JP", 1)]
    public void When_UsingFindBySubjectDistinguishedName_Then_ExpectedCertificateCountIsRetrieved(string findValue, int expectedCount)
    {
        var collection = _target.Find(X509FindType.FindBySubjectDistinguishedName, findValue, validOnly: false);

        Assert.Equal(expectedCount, collection.Count);
    }

}
