using System.Security.Cryptography.X509Certificates;

namespace Examples.Cryptography.X509Certificates;

public static class X509BuildersExtensions
{
    public static X500DistinguishedNameBuilder Configure(this X500DistinguishedNameBuilder builder, Action<X500DistinguishedNameBuilder> configure)
    {
        configure?.Invoke(builder);
        return builder;
    }


    public static byte[] ToSerialNumberBytes(this long value)
        => BitConverter.IsLittleEndian
                ? BitConverter.GetBytes(value).Reverse().ToArray()
                : BitConverter.GetBytes(value);


    public static byte[] CreateSerialNumber(this Random generator)
    {
        var number = generator.NextInt64(minValue: 1, maxValue: long.MaxValue);
        return number.ToSerialNumberBytes();
    }

}
