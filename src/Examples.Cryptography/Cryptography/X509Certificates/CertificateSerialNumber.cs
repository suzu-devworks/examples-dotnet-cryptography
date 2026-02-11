using System.Security.Cryptography;

namespace Examples.Cryptography.X509Certificates;

/// <summary>
/// Indicates the serial number defined in RFC 5280 Serial Number.
/// </summary>
/// <see href="https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.2" />
public class CertificateSerialNumber
{
    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateSerialNumber" /> class
    /// with a concrete value.
    /// </summary>
    /// <param name="value">The concrete value.</param>
    public CertificateSerialNumber(long value)
        => (Value) = (value);

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateSerialNumber" /> class
    /// using a cryptographic random generator.
    /// </summary>
    public CertificateSerialNumber()
        : this(1, long.MaxValue)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateSerialNumber" /> class
    /// using a cryptographic random generator with specified minimum and maximum values.
    /// </summary>
    /// <param name="min">The minimum value.</param>
    /// <param name="max">The maximum value.</param>
    public CertificateSerialNumber(long min, long max)
        : this(NextInt64(min, max))
    {
    }

    /// <summary>
    /// Gets serial number value.
    /// </summary>
    public long Value { get; }

    /// <summary>
    /// Gets the serial number as a byte array in big-endian format.
    /// The result is trimmed of leading zero bytes and, if the most significant bit
    /// of the first byte is set, a <c>0x00</c> byte is prepended to ensure the value
    /// is interpreted as a positive integer in ASN.1 DER encoding.
    /// </summary>
    /// <returns>A byte array representing the serial number in ASN.1 DER-compatible format.</returns>
    public byte[] ToBytes()
    {
        Span<byte> bytes = stackalloc byte[sizeof(long)];
        System.Buffers.Binary.BinaryPrimitives.WriteInt64BigEndian(bytes, Value);

        // Trim leading zero bytes, but keep at least one byte.
        bytes = bytes.TrimStart((byte)0);
        if (bytes.IsEmpty)
        {
            return [0];
        }

        // Prepend 0x00 if the MSB is set to ensure a positive ASN.1 INTEGER.
        if ((bytes[0] & 0x80) != 0)
        {
            var result = new byte[bytes.Length + 1];
            bytes.CopyTo(result.AsSpan(1));
            return result;
        }

        return bytes.ToArray();
    }

    /// <summary>
    /// Creates a new <see cref="CertificateSerialNumber" /> with a cryptographically random value.
    /// </summary>
    /// <param name="min">The minimum value.</param>
    /// <returns>A new <see cref="CertificateSerialNumber" /> instance.</returns>
    public static CertificateSerialNumber CreateRandom(long min = 1)
        => new(min, long.MaxValue);

    private static long NextInt64(long min, long max)
    {
        Span<byte> bytes = stackalloc byte[sizeof(long)];
        RandomNumberGenerator.Fill(bytes);
        var value = BitConverter.ToInt64(bytes) & long.MaxValue;
        return min + (value % (max - min));
    }
}
