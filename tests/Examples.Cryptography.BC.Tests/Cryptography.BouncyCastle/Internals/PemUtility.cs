using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.OpenSsl;

namespace Examples.Cryptography.BouncyCastle.Internals;

internal static class PemUtility
{
    public static string ToPemString(object encodable)
    {
        var builder = new StringBuilder();
        //using var memory = new MemoryStream();
        //using (var writer = new PemWriter(new StreamWriter(memory, Encoding.ASCII)))
        using (var writer = new PemWriter(new StringWriter(builder)))
        {
            writer.WriteObject(encodable);
        }
        //var pem = Encoding.ASCII.GetString(memory.ToArray()).TrimEnd();
        var pem = builder.ToString().TrimEnd();

        return pem;
    }
}
