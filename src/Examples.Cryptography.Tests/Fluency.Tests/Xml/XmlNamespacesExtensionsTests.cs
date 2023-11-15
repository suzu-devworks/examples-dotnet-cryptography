using System.Security.Cryptography.Xml;
using System.Xml;
using System.Xml.Serialization;
using Examples.Fluency.Xml;

namespace Examples.Fluency.Tests.Xml;

public class XmlNamespacesExtensionsTests
{
    [Fact]
    public void WhenConvertToManager_ReturnsAsExpected()
    {
        var ns = new XmlSerializerNamespaces();
        ns.Add("ds", SignedXml.XmlDsigNamespaceUrl);
        ns.Add("xa", "http://uri.etsi.org/01903/v1.3.2#");
        ns.Add("xa141", "http://uri.etsi.org/01903/v1.4.1#");

        //# Act.
        var manager = ns.ToManager();

        var names = manager.Cast<string>();
        names.Count().Is(6);
        names.ElementAt(0).Is(prefix => (prefix == "")
            && (manager.LookupNamespace(prefix) == ""));
        names.ElementAt(1).Is(prefix => (prefix == "xmlns")
            && (manager.LookupNamespace(prefix) == "http://www.w3.org/2000/xmlns/"));
        names.ElementAt(2).Is(prefix => (prefix == "xml")
            && (manager.LookupNamespace(prefix) == "http://www.w3.org/XML/1998/namespace"));
        names.ElementAt(3).Is(prefix => (prefix == "ds")
            && (manager.LookupNamespace(prefix) == SignedXml.XmlDsigNamespaceUrl));
        names.ElementAt(4).Is(prefix => (prefix == "xa")
            && (manager.LookupNamespace(prefix) == "http://uri.etsi.org/01903/v1.3.2#"));
        names.ElementAt(5).Is(prefix => (prefix == "xa141")
            && (manager.LookupNamespace(prefix) == "http://uri.etsi.org/01903/v1.4.1#"));

        return;
    }

    [Fact]
    public void WhenConvertToSerializer_ReturnsAsExpected()
    {
        var manager = new XmlNamespaceManager(new NameTable());
        manager.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
        manager.AddNamespace("xa", "http://uri.etsi.org/01903/v1.3.2#");
        manager.AddNamespace("xa141", "http://uri.etsi.org/01903/v1.4.1#");

        //# Act: includeDefault: false.
        {
            var serializer = manager.ToSerializer();

            var qualifiedNames = serializer.ToArray();
            qualifiedNames.Length.Is(3);
            qualifiedNames[0].Is(x => (x.Name == "ds")
                && (x.Namespace == SignedXml.XmlDsigNamespaceUrl));
            qualifiedNames[1].Is(x => (x.Name == "xa")
                && (x.Namespace == "http://uri.etsi.org/01903/v1.3.2#"));
            qualifiedNames[2].Is(x => (x.Name == "xa141")
                && (x.Namespace == "http://uri.etsi.org/01903/v1.4.1#"));
        }

        // Act: includeDefault: true
        {
            //# Act.
            var serializer = manager.ToSerializer(includeDefault: true);

            var qualifiedNames = serializer.ToArray();
            qualifiedNames.Length.Is(6);
            qualifiedNames[0].Is(x => (x.Name == "")
                && (x.Namespace == ""));
            qualifiedNames[1].Is(x => (x.Name == "xmlns")
                && (x.Namespace == "http://www.w3.org/2000/xmlns/"));
            qualifiedNames[2].Is(x => (x.Name == "xml")
                && (x.Namespace == "http://www.w3.org/XML/1998/namespace"));
            qualifiedNames[3].Is(x => (x.Name == "ds")
                && (x.Namespace == SignedXml.XmlDsigNamespaceUrl));
            qualifiedNames[4].Is(x => (x.Name == "xa")
                && (x.Namespace == "http://uri.etsi.org/01903/v1.3.2#"));
            qualifiedNames[5].Is(x => (x.Name == "xa141")
                && (x.Namespace == "http://uri.etsi.org/01903/v1.4.1#"));
        }

        return;
    }
}
