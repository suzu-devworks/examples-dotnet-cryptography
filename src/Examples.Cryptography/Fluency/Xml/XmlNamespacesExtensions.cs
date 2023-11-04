using System.Xml;
using System.Xml.Serialization;

namespace Examples.Fluency.Xml;

/// <summary>
/// Extension methods for XML namespace.
/// </summary>
public static class XmlNamespacesExtensions
{
    /// <summary>
    /// Converts an <see cref="XmlNamespaceManager" /> instance to <see cref="XmlSerializerNamespaces" /> instance.
    /// </summary>
    /// <param name="manager">The <see cref="XmlNamespaceManager" /> instance.</param>
    /// <param name="includeDefault">If true, include the default namespace that <see cref="XmlNamespaceManager" /> has.</param>
    /// <returns>An <see cref="XmlSerializerNamespaces" /> instance.</returns>
    public static XmlSerializerNamespaces ToSerializer(this XmlNamespaceManager manager,
        bool includeDefault = false)
    {
        var qualifiedNames = manager.Cast<string>()
            .Select(prefix => new XmlQualifiedName(prefix, manager.LookupNamespace(prefix)));

        if (!includeDefault)
        {
            var namespaceDefaults = new XmlNamespaceManager(new NameTable()).Cast<string>()
                .ToHashSet();
            qualifiedNames = qualifiedNames
                .Where(x => !namespaceDefaults.Contains(x.Name));
        }

        return new XmlSerializerNamespaces(qualifiedNames.ToArray());
    }

    /// <summary>
    /// Converts an <see cref="XmlSerializerNamespaces" /> instance to <see cref="XmlNamespaceManager" /> instance.
    /// </summary>
    /// <param name="serializer">The <see cref="XmlSerializerNamespaces" /> instance.</param>
    /// <param name="nameTable">The <see cref="XmlNameTable" /> instance from <see cref="XmlDocument" />.</param>
    /// <returns>An <see cref="XmlNamespaceManager" /> instance.</returns>
    public static XmlNamespaceManager ToManager(this XmlSerializerNamespaces serializer,
        XmlNameTable? nameTable = null)
    {
        var manager = new XmlNamespaceManager(nameTable ?? new NameTable());

        foreach (var qualified in serializer.ToArray())
        {
            manager.AddNamespace(qualified.Name, qualified.Namespace);
        }

        return manager;
    }

}
