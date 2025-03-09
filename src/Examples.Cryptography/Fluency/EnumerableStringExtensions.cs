using System.Collections.Generic;

namespace Examples.Fluency;

/// <summary>
/// Extension methods for <see cref="IEnumerable{T}" /> collection of type <see cref="string" />.
/// </summary>
public static class EnumerableStringExtensions
{
    /// <summary>
    ///  Concatenates the members of a constructed <see cref="IEnumerable{T}" /> collection of type <see cref="string" />,
    ///  using the specified separator between each member.
    /// </summary>
    /// <param name="source">A sequence of values to concatenate.</param>
    /// <param name="separator">The string to use as a separator.</param>
    /// <returns>Concatenated string.</returns>
    public static string? ToSeparatedString(this IEnumerable<string?> source, string separator)
    {
        var converted = string.Join(separator, source);
        return converted;
    }

}
