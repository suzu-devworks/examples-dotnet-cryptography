using System.Text;
using Examples.Fluency.Text;

namespace Examples.Tests.Fluency.Text;

public class EncodingExtensionsTests
{
    [Fact]
    public void WhenRemoveUTF8BOM()
    {
        // Arrange.
        var phrase = Encoding.UTF8.GetBytes("TEST文字列");
        using var stream = new MemoryStream();
        stream.Write(Encoding.UTF8.GetPreamble());
        stream.Write(phrase);

        // Act.
        var actual1 = phrase.RemovePreamble(Encoding.UTF8);

        stream.Seek(0, SeekOrigin.Begin);
        var actual2 = stream.ToArray().RemovePreamble();

        stream.Seek(0, SeekOrigin.Begin);
        using var reader2 = new BinaryReader(stream, Encoding.UTF8);
        var actual3 = reader2.ReadBytes(255).RemovePreamble();

        // StreamReader is auto remove?
        stream.Seek(0, SeekOrigin.Begin);
        using var reader = new StreamReader(stream, Encoding.UTF8);
        var actual4s = reader.ReadLine();

        // Assert.
        Assert.Multiple(
            () => actual1.Is(phrase),
            () => actual2.Is(phrase),
            () => actual3.Is(phrase),
            () => actual4s.Is("TEST文字列"));
    }
}
