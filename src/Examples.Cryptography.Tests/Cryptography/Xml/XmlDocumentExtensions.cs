using System.Text;
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
    /// <param name="actionSettings">The delegate method for configuring writer.</param>
    /// <returns>A formatted XML string.</returns>
    public static string ToFormattedOuterXml(this XmlNode xml,
        Action<XmlWriterSettings>? actionSettings = null)
    {
        XmlWriterSettings settings = new()
        {
            Indent = true,
        };
        actionSettings?.Invoke(settings);

        StringBuilder builder = new();
        using (var writer = XmlWriter.Create(builder, settings))
        {
            xml.WriteTo(writer);
        }

        var output = builder.ToString();

        return output;
    }

}
