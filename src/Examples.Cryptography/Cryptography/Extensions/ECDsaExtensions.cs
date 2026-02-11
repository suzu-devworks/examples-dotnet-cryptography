using System.Security.Cryptography;

namespace Examples.Cryptography.Extensions;

/// <summary>
/// Extension methods for <see cref="ECDsa" /> class methods.
/// </summary>
public static class ECDsaExtensions
{
    /// <summary>
    /// Compares two ECDsa instances for equality of their parameters.
    /// </summary>
    /// <param name="me"></param>
    /// <param name="other"></param>
    /// <param name="includePrivateParameters"></param>
    /// <returns></returns>
    public static bool EqualsParameters(this ECDsa me, ECDsa? other, bool includePrivateParameters = false)
    {
        if (other is null) { return false; }
        var p1 = me.ExportParameters(includePrivateParameters);
        var p2 = other.ExportParameters(includePrivateParameters);

        if (p1.Curve.Oid.Value != p2.Curve.Oid.Value) { return false; }
        if (!p1.Q.X!.SequenceEqual(p2.Q.X!)) { return false; }
        if (!p1.Q.Y!.SequenceEqual(p2.Q.Y!)) { return false; }

        if (includePrivateParameters && !p1.D!.SequenceEqual(p2.D!)) { return false; }

        return true;
    }

}
