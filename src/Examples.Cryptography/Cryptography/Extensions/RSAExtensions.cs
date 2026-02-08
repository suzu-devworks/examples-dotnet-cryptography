using System.Security.Cryptography;

namespace Examples.Cryptography.Extensions;

/// <summary>
/// Extension methods for <see cref="RSA" /> class methods.
/// </summary>
public static class RSAExtensions
{
    /// <summary>
    /// Compares two RSA instances for equality of their parameters.
    /// </summary>
    /// <param name="me"></param>
    /// <param name="other"></param>
    /// <param name="includePrivateParameters"></param>
    /// <returns></returns>
    public static bool EqualsParameters(this RSA me, RSA other, bool includePrivateParameters = false)
    {
        var p1 = me.ExportParameters(includePrivateParameters);
        var p2 = other.ExportParameters(includePrivateParameters);

        if (p1.Exponent?.Length != p2.Exponent?.Length || !p1.Exponent!.SequenceEqual(p2.Exponent!))
        { return false; }

        if (p1.Modulus?.Length != p2.Modulus?.Length || !p1.Modulus!.SequenceEqual(p2.Modulus!))
        { return false; }

        if (includePrivateParameters)
        {
            if (p1.D?.Length != p2.D?.Length || !p1.D!.SequenceEqual(p2.D!))
            { return false; }

            if (p1.P?.Length != p2.P?.Length || !p1.P!.SequenceEqual(p2.P!))
            { return false; }

            if (p1.Q?.Length != p2.Q?.Length || !p1.Q!.SequenceEqual(p2.Q!))
            { return false; }

            if (p1.DP?.Length != p2.DP?.Length || !p1.DP!.SequenceEqual(p2.DP!))
            { return false; }

            if (p1.DQ?.Length != p2.DQ?.Length || !p1.DQ!.SequenceEqual(p2.DQ!))
            { return false; }

            if (p1.InverseQ?.Length != p2.InverseQ?.Length || !p1.InverseQ!.SequenceEqual(p2.InverseQ!))
            { return false; }
        }

        return true;
    }
}
