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
    /// using a random generator.
    /// </summary>
    /// <param name="random">The random generator.</param>
    public CertificateSerialNumber(Random random)
        : this(1, long.MaxValue, random)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateSerialNumber" /> class
    /// using a random generator with a specified minimum value.
    /// </summary>
    /// <param name="min"The minimum value.</param>
    /// <param name="random">The random generator.</param>
    public CertificateSerialNumber(long min, Random random)
        : this(min, long.MaxValue, random)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateSerialNumber" /> class
    /// using a random generator with a specified minimum and maximum values.
    /// </summary>
    /// <param name="min"The minimum value.</param>
    /// <param name="max">The minimum value.</param>
    /// <param name="random">The random generator.</param>
    public CertificateSerialNumber(long min, long max, Random random)
        : this(random.NextInt64(min, max))
    {
    }

    /// <summary>
    /// Gets serial number value.
    /// </summary>
    public long Value { get; }

    /// <summary>
    /// Get the serial number as a byte array.
    /// </summary>
    /// <returns>A serial number as a byte array.</returns>
    public byte[] ToBytes()
        => BitConverter.IsLittleEndian
            ? BitConverter.GetBytes(Value).Reverse().ToArray()
            : BitConverter.GetBytes(Value);

}
