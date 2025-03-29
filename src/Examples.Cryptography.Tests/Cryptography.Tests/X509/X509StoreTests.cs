using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Examples.Cryptography.Tests.X509;

public class X509StoreTests
{
    private readonly ITestOutputHelper _output;

    public X509StoreTests(ITestOutputHelper output)
    {
        _output = output;
    }

    [Fact]
    public void WhenEnumeratingStoreStatus_WorksAsExpected()
    {
        /// <seealso href="https://learn.microsoft.com/ja-jp/dotnet/api/system.security.cryptography.x509certificates?view=net-7.0"/>

        foreach (var message in EnumerateStoreStatus())
        {
            _output.WriteLine(message);
        }


    }

    private static IEnumerable<string> EnumerateStoreStatus()
    {
        yield return "";
        yield return "Exists Certs Name and Location";
        yield return "------ ----- -------------------------";

        foreach (var storeLocation in Enum.GetValues<StoreLocation>())
        {
            foreach (var storeName in Enum.GetValues<StoreName>())
            {
                using var store = new X509Store(storeName, storeLocation);

                string message;
                try
                {
                    store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

                    message = $"Yes    {store.Certificates.Count,4}  {store.Name}, {store.Location}";

                    store.Close();
                }
                catch (CryptographicException e)
                {
                    message = $"No           {store.Name}, {store.Location} -> {e.Message}";
                }

                yield return message;

            }

            yield return "";
        }
    }


    [Fact]
    public void WhenFindingFromStore_WorksAsExpected()
    {
        /// <seealso href="https://learn.microsoft.com/ja-jp/dotnet/api/system.security.cryptography.x509certificates.x509certificate2collection.find?view=net-7.0"/>

        using var store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

        var collection = store.Certificates;
        var fCollection = collection.Find(X509FindType.FindByTimeValid, DateTime.Now, false);
        var sCollection = fCollection.Find(X509FindType.FindByIssuerDistinguishedName,
            findValue: "CN=Microsoft RSA Root Certificate Authority 2017, O=Microsoft Corporation, C=US",
            validOnly: true);

        _output.WriteLine("");
        _output.WriteLine("Number of certificates: {0}", sCollection.Count);
        _output.WriteLine("");

        foreach (var x509 in sCollection)
        {
            try
            {
                byte[] rawData = x509.RawData;
                _output.WriteLine("Content Type: {0}{1}", X509Certificate2.GetCertContentType(rawData), Environment.NewLine);
                _output.WriteLine("Friendly Name: {0}{1}", x509.FriendlyName, Environment.NewLine);
                _output.WriteLine("Certificate Verified?: {0}{1}", x509.Verify(), Environment.NewLine);
                _output.WriteLine("Simple Name: {0}{1}", x509.GetNameInfo(X509NameType.SimpleName, true), Environment.NewLine);
                _output.WriteLine("Signature Algorithm: {0}{1}", x509.SignatureAlgorithm.FriendlyName, Environment.NewLine);
                _output.WriteLine("Public Key: {0}{1}", x509.PublicKey.GetRSAPublicKey()?.ToXmlString(false), Environment.NewLine);
                _output.WriteLine("Certificate Archived?: {0}{1}", x509.Archived, Environment.NewLine);
                _output.WriteLine("Length of Raw Data: {0}{1}", x509.RawData.Length, Environment.NewLine);

            }
            catch (CryptographicException)
            {
                _output.WriteLine("Information could not be written out for this certificate.");
            }
        }

        store.Close();


    }

}
