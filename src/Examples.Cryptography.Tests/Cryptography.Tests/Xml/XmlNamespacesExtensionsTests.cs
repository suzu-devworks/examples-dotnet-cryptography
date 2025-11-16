using System.Security.Cryptography.Xml;
using System.Xml;
using System.Xml.Serialization;
using Examples.Cryptography.Xml;

namespace Examples.Cryptography.Tests.Xml;

public class XmlNamespacesExtensionsTests
{
    [Fact]
    public void ToNamespaceManager_WithMultipleNamespacesAdded_ReturnsConfiguredManager()
    {
        var ns = new XmlSerializerNamespaces();
        ns.Add("ds", SignedXml.XmlDsigNamespaceUrl);
        ns.Add("xa", "http://uri.etsi.org/01903/v1.3.2#");
        ns.Add("xa141", "http://uri.etsi.org/01903/v1.4.1#");

        var manager = ns.ToNamespaceManager();

        var names = manager.Cast<string>();
        Assert.Equal(6, names.Count());
        Assert.Collection(names,
            (prefix) =>
            {
                Assert.Equal("", prefix);
                Assert.Equal("", manager.LookupNamespace(prefix));
            },
            (prefix) =>
            {
                Assert.Equal("xmlns", prefix);
                Assert.Equal("http://www.w3.org/2000/xmlns/", manager.LookupNamespace(prefix));
            },
            (prefix) =>
            {
                Assert.Equal("xml", prefix);
                Assert.Equal("http://www.w3.org/XML/1998/namespace", manager.LookupNamespace(prefix));
            },
            (prefix) =>
            {
                Assert.Equal("ds", prefix);
                Assert.Equal(SignedXml.XmlDsigNamespaceUrl, manager.LookupNamespace(prefix));
            },
            (prefix) =>
            {
                Assert.Equal("xa", prefix);
                Assert.Equal("http://uri.etsi.org/01903/v1.3.2#", manager.LookupNamespace(prefix));
            },
            (prefix) =>
            {
                Assert.Equal("xa141", prefix);
                Assert.Equal("http://uri.etsi.org/01903/v1.4.1#", manager.LookupNamespace(prefix));
            });
    }

    [Fact]
    public void ToSerializerNamespaces_WithMultipleNamespacesAdded_ReturnsConfiguredSerializer()
    {
        var manager = new XmlNamespaceManager(new NameTable());
        manager.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
        manager.AddNamespace("xa", "http://uri.etsi.org/01903/v1.3.2#");
        manager.AddNamespace("xa141", "http://uri.etsi.org/01903/v1.4.1#");

        var serializer = manager.ToSerializerNamespaces();

        var qualifiedNames = serializer.ToArray();
        Assert.Equal(3, qualifiedNames.Length);
        Assert.Collection(qualifiedNames,
            (qualified) =>
            {
                Assert.Equal("ds", qualified.Name);
                Assert.Equal(SignedXml.XmlDsigNamespaceUrl, qualified.Namespace);
            },
            (qualified) =>
            {
                Assert.Equal("xa", qualified.Name);
                Assert.Equal("http://uri.etsi.org/01903/v1.3.2#", qualified.Namespace);
            },
            (qualified) =>
            {
                Assert.Equal("xa141", qualified.Name);
                Assert.Equal("http://uri.etsi.org/01903/v1.4.1#", qualified.Namespace);
            });
    }

    [Fact]
    public void ToSerializerNamespaces_WithIncludeDefault_ReturnsSerializerWithDefaultNamespaces()
    {
        var manager = new XmlNamespaceManager(new NameTable());
        manager.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
        manager.AddNamespace("xa", "http://uri.etsi.org/01903/v1.3.2#");
        manager.AddNamespace("xa141", "http://uri.etsi.org/01903/v1.4.1#");

        var serializer = manager.ToSerializerNamespaces(includeDefault: true);

        var qualifiedNames = serializer.ToArray();
        Assert.Equal(6, qualifiedNames.Length);
        Assert.Collection(qualifiedNames,
            (qualified) =>
            {
                Assert.Equal("", qualified.Name);
                Assert.Equal("", qualified.Namespace);
            },
            (qualified) =>
            {
                Assert.Equal("xmlns", qualified.Name);
                Assert.Equal("http://www.w3.org/2000/xmlns/", qualified.Namespace);
            },
            (qualified) =>
            {
                Assert.Equal("xml", qualified.Name);
                Assert.Equal("http://www.w3.org/XML/1998/namespace", qualified.Namespace);
            },
            (qualified) =>
            {
                Assert.Equal("ds", qualified.Name);
                Assert.Equal(SignedXml.XmlDsigNamespaceUrl, qualified.Namespace);
            },
            (qualified) =>
            {
                Assert.Equal("xa", qualified.Name);
                Assert.Equal("http://uri.etsi.org/01903/v1.3.2#", qualified.Namespace);
            },
            (qualified) =>
            {
                Assert.Equal("xa141", qualified.Name);
                Assert.Equal("http://uri.etsi.org/01903/v1.4.1#", qualified.Namespace);
            });

    }

}
