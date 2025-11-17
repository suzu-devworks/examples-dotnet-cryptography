using System.Security.Cryptography.X509Certificates;

namespace Examples.Cryptography.Tests.X509;

public class X509Certificate2CollectionTests(X509Certificate2CollectionTests.Fixture fixture)
    : IClassFixture<X509Certificate2CollectionTests.Fixture>
{
    public class Fixture : IDisposable
    {
        public void Dispose()
        {
            foreach (var cert in Certificates)
            {
                cert.Dispose();
            }
            Certificates.Clear();
            GC.SuppressFinalize(this);
        }

        public X509Certificate2Collection Certificates { get; } = CreateCollection();

        private static X509Certificate2Collection CreateCollection()
        {
            var notBefore = DateTime.UtcNow.AddSeconds(-50);

            X509Certificate2Collection collection = [];
            collection.Add(Helper.TestCertificateFactory.CreateSelfSignedEntity(new("CN=*.examples.jp"), notBefore));
            collection.Add(Helper.TestCertificateFactory.CreateSelfSignedEntity(new("CN=*.second.examples.jp"), notBefore));
            collection.Add(Helper.TestCertificateFactory.GetStatic());

            return collection;
        }

    }

    private readonly X509Certificate2Collection _target = fixture.Certificates;

    [Theory]
    [InlineData("CEB765689BE077B587666897ADBB4E92A88FA0AE", 1)]
    [InlineData("0000000000000000000000000000000000000000", 0)]
    public void When_FindByThumbprint_Then_ExpectedCertificateCountIsRetrieved(string findValue, int expectedCount)
    {
        var collection = _target.Find(X509FindType.FindByThumbprint, findValue, validOnly: false);

        Assert.Equal(expectedCount, collection.Count);
    }

    [Theory]
    [InlineData("CN=*.examples.jp", 0)]
    [InlineData("*.examples.jp", 1)]
    [InlineData("examples.jp", 2)]
    [InlineData("examples", 3)]
    [InlineData("*.EXAMPLES.jp", 1)]
    public void When_FindBySubjectName_Then_ExpectedCertificateCountIsRetrieved(string findValue, int expectedCount)
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
    public void When_FindBySubjectDistinguishedName_Then_ExpectedCertificateCountIsRetrieved(string findValue, int expectedCount)
    {
        var collection = _target.Find(X509FindType.FindBySubjectDistinguishedName, findValue, validOnly: false);

        Assert.Equal(expectedCount, collection.Count);
    }

}
