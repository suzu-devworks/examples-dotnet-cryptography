using System.Text;
using System.Xml;
using System.Xml.Serialization;

namespace Examples.Cryptography.Xml;

/// <summary>
/// Extension methods for <see cref="XmlSerializer" />.
/// </summary>
public static class XmlSerializerExtensions
{
    /// <summary>
    /// Converts a serializable object to a <see cref="XmlElement" /> instance using a <see cref="XmlSerializer">.
    /// </summary>
    /// <param name="serializer">The <see cref="XmlSerializer" /> instance.</param>
    /// <param name="serializable">The serializable object instance.</param>
    /// <param name="ns">The <see cref="XmlSerializerNamespaces" />instance.</param>
    /// <typeparam name="T">The type of serializable object.</typeparam>
    /// <returns>An <see cref="XmlElement" /> instance or null.</returns>
    public static XmlElement? ToXmlElement<T>(this XmlSerializer serializer,
        T serializable,
        XmlSerializerNamespaces? ns = null)
    {

        var xml = serializer.ToXml(serializable, ns);
        if (xml is null)
        {
            return null;
        }

        var document = new XmlDocument();
        document.LoadXml(xml);
        return document.DocumentElement;
    }

    /// <summary>
    /// Converts a serializable object to a XML string using a <see cref="XmlSerializer">.
    /// </summary>
    /// <param name="serializer">The <see cref="XmlSerializer" /> instance.</param>
    /// <param name="serializable">The serializable object instance.</param>
    /// <param name="ns">The <see cref="XmlSerializerNamespaces" />instance.</param>
    /// <param name="actionSettings">The delegate method for configuring writer.</param>
    /// <typeparam name="T">The type of serializable object.</typeparam>
    /// <returns>A XML string.</returns>
    public static string ToXml<T>(this XmlSerializer serializer,
        T serializable,
        XmlSerializerNamespaces? ns = null,
        Action<XmlWriterSettings>? actionSettings = null)
    {
        XmlWriterSettings settings = new();
        actionSettings?.Invoke(settings);

        StringBuilder builder = new();
        using (var writer = XmlWriter.Create(builder, settings))
        {
            serializer.Serialize(writer, serializable, ns);
        }
        var xml = builder.ToString();

        return xml;
    }

}
