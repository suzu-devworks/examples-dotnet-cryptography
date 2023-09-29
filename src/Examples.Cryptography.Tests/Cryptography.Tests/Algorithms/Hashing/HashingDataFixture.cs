namespace Examples.Cryptography.Tests.Algorithms.Hashing;

public class HashingDataFixture : IDisposable
{
    public HashingDataFixture()
    {

        _millionSameCharacterData = new(() => GenerateSameCharacterData('@', size: 1_000_000));
    }

    public byte[] MillionSameCharacterData => _millionSameCharacterData.Value;
    private readonly Lazy<byte[]> _millionSameCharacterData;

    private static byte[] GenerateSameCharacterData(char ch, int size)
    {
        using var mem = new MemoryStream(capacity: size);
        foreach (var _ in Enumerable.Range(0, mem.Capacity))
        {
            mem.WriteByte((byte)ch);
        }
        mem.Flush();
        return mem.ToArray();
    }

    public void Dispose()
    {
        GC.SuppressFinalize(this);
    }
}
