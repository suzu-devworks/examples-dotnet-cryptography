using System.Text;
using Examples.Fluency;

namespace Examples.Cryptography.BouncyCastle.Logging;

internal static class StringBuilderLoggingExtensions
{
    public static void AppendLevelLine(this StringBuilder builder, int level, string key, string? value = null)
    {
        var indent = Enumerable.Repeat("  ", level).ToSeparatedString("");
        var indentedKey = $"{indent}{key}".PadRight(32);

        builder.Append(indentedKey);
        if (value is not null)
        {
            builder.Append($" = {value}");
        }
        builder.AppendLine();

    }

}
