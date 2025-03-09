using System;

namespace Examples.Fluency;

/// <summary>
/// Extension methods for <see cref="Convert" /> class methods.
/// </summary>
public static class ConvertStringExtensions
{
    /// <summary>
    /// Converts an array of 8-bit unsigned integers to its equivalent string representation
    /// that is encoded with base-64 digits.
    /// </summary>
    /// <param name="source">The array of 8-bit unsigned integers.</param>
    /// <returns>A string encoded with base-64 digits.</returns>
    public static string ToBase64String(this byte[] source)
        => Convert.ToBase64String(source);

    /// <summary>
    /// Converts the specified string, which encodes binary data as base-64 digits, to
    /// an equivalent 8-bit unsigned integer array.
    /// </summary>
    /// <param name="source">The string encoded with base-64 digits.</param>
    /// <returns>An array of 8-bit unsigned integers.</returns>
    public static byte[] ToBase64Bytes(this string source)
        => Convert.FromBase64String(source);

}
