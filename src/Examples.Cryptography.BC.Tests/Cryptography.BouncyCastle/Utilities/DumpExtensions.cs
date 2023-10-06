using System.Text;
using Examples.Fluency;

namespace Examples.Cryptography.BouncyCastle.Utilities;

/// <summary>
/// Extension methods for output dump.
/// </summary>
public static class DumpExtensions
{
    /// <summary>
    /// Appends the key value pair and  line terminator
    ///     to the end of the current <see cref="StringBuilder" /> object.
    /// </summary>
    /// <param name="builder">A <see cref="StringBuilder" /> object.</param>
    /// <param name="lebel">A indent level number.</param>
    /// <param name="key">A key to output.</param>
    /// <param name="value">A value to output.</param>
    public static void AppendLebelLine(this StringBuilder builder, int lebel, string key, string? value = null)
    {
        var indent = Enumerable.Repeat("  ", lebel).ToSeparatedString("");
        var indentedKey = $"{indent}{key}".PadRight(32);

        builder.Append(indentedKey);
        if (value is not null)
        {
            builder.Append($" = {value}");
        }
        builder.AppendLine();

    }

}
