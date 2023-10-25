using System.Text;
using Examples.Fluency;

namespace Examples.Cryptography.BouncyCastle.Logging;

internal static class StringBuilderLoggingExtensions
{
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
