using System.Text;

namespace Examples.Fluency.Text;

public static class EncodingExtensions
{
    public static byte[] RemovePreamble(this byte[] source, Encoding? encoding = null)
    {
        encoding ??= Encoding.UTF8;

        var bom = encoding.GetPreamble();
        if (source[..bom.Length].SequenceEqual(bom))
        {
            return source[bom.Length..];
        }

        return source;
    }

}
