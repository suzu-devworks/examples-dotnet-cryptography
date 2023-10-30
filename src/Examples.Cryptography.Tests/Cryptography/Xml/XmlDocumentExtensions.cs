using System.Xml;

namespace Examples.Cryptography.Xml;

/// <summary>
/// Extension methods for <see cref="XmlDocument" />.
/// </summary>
public static class XmlDocumentExtensions
{
    /// <summary>
    /// Converts an <see cref="XmlNode" /> to a formatted XML string.
    /// </summary>
    /// <param name="xml">The <see cref="XmlNode" /> instance.</param>
    /// <param name="actionWriterSettings">The delegate method for configuring writer.</param>
    /// <returns>A formatted XML string.</returns>
    public static string ToFormattedOuterXml(this XmlNode xml,
        Action<XmlTextWriter>? actionWriterSettings = null)
    {
        using StringWriter innerWriter = new();
        using XmlTextWriter writer = new(innerWriter);

        writer.Formatting = Formatting.Indented;

        actionWriterSettings?.Invoke(writer);

        xml.WriteTo(writer);
        writer.Flush();

        var output = innerWriter.ToString();

        return output;
    }

}
