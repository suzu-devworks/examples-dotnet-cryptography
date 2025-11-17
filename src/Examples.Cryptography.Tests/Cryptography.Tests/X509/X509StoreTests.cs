using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Examples.Cryptography.Tests.X509;

public class X509StoreTests(ITestOutputHelper output)
{
    /// <summary>
    /// This example uses the Name, Location, and Certificates properties to display the number of certificates in the store.
    /// </summary>
    /// <seealso href="https://learn.microsoft.com/ja-jp/dotnet/api/system.security.cryptography.x509certificates.x509store"/>
    [Fact]
    public void When_CertCountIsEnumeratedStandardStores_Then_ReturnsCountForEachStoreLocation()
    {
        foreach (var message in EnumeratedStandardStores())
        {
            output.WriteLine(message);
        }

        static IEnumerable<string> EnumeratedStandardStores()
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
    }

    /// <summary>
    /// The following code example opens the current user's personal certificate store,
    /// finds only valid certificates, allows the user to select a certificate,
    /// and then writes certificate and certificate chain information to the console.
    /// </summary>
    /// <seealso href="https://learn.microsoft.com/ja-jp/dotnet/api/system.security.cryptography.x509certificates.x509certificate2collection.find"/>
    [Fact]
    public void When_RootStoreIsFilteredByValidityAndIssuer_Then_ReturnsListMatchingCriteria()
    {
        using var store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

        var collection = store.Certificates;
        var fCollection = collection.Find(X509FindType.FindByTimeValid, DateTime.Now, false);
        var sCollection = fCollection.Find(X509FindType.FindByIssuerDistinguishedName,
            findValue: "CN=Microsoft RSA Root Certificate Authority 2017, O=Microsoft Corporation, C=US",
            validOnly: true);

        output.WriteLine("");
        output.WriteLine("Number of certificates: {0}", sCollection.Count);
        output.WriteLine("");

        foreach (var x509 in sCollection)
        {
            try
            {
                byte[] rawData = x509.RawData;
                output.WriteLine("Content Type: {0}{1}", X509Certificate2.GetCertContentType(rawData), Environment.NewLine);
                output.WriteLine("Friendly Name: {0}{1}", x509.FriendlyName, Environment.NewLine);
                output.WriteLine("Certificate Verified?: {0}{1}", x509.Verify(), Environment.NewLine);
                output.WriteLine("Simple Name: {0}{1}", x509.GetNameInfo(X509NameType.SimpleName, true), Environment.NewLine);
                output.WriteLine("Signature Algorithm: {0}{1}", x509.SignatureAlgorithm.FriendlyName ?? "", Environment.NewLine);
                output.WriteLine("Public Key: {0}{1}", x509.PublicKey.GetRSAPublicKey()?.ToXmlString(false) ?? "", Environment.NewLine);
                output.WriteLine("Certificate Archived?: {0}{1}", x509.Archived, Environment.NewLine);
                output.WriteLine("Length of Raw Data: {0}{1}", x509.RawData.Length, Environment.NewLine);

            }
            catch (CryptographicException)
            {
                output.WriteLine("Information could not be written out for this certificate.");
            }
        }

        store.Close();
    }

}
