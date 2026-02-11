using System.Numerics;
using System.Security.Cryptography;

namespace Examples.Cryptography.X509Certificates;

/// <summary>
/// Represents a certificate serial number as defined in RFC 5280.
/// </summary>
/// <remarks>
/// Serial numbers MUST be a positive integer no more than 20 octets (160 bits).
/// </remarks>
/// <see href="https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.2" />
public class CertificateSerialNumber
{
    private const int MaxOctets = 20;

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateSerialNumber" /> class
    /// with a concrete value.
    /// </summary>
    /// <param name="value">The concrete value.</param>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when the value is negative or exceeds 20 octets.
    /// </exception>
    public CertificateSerialNumber(BigInteger value)
    {
        if (value < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(value), "Serial number must be positive (>= 1).");
        }

        var bytes = value.ToByteArray(isUnsigned: true, isBigEndian: true);
        if (bytes.Length > MaxOctets)
        {
            throw new ArgumentOutOfRangeException(nameof(value), $"Serial number must not exceed {MaxOctets} octets.");
        }

        // RFC 5280: Serial number must be positive and encoded in no more than 20 octets.
        // A 20-octet value with MSB set will require a leading 0x00 byte in DER encoding,
        // resulting in 21 octets, which violates the limit.
        if (bytes.Length == MaxOctets && (bytes[0] & 0x80) != 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(value),
                $"Serial number would require {MaxOctets + 1} octets in DER encoding. " +
                $"The value must encode to no more than {MaxOctets} octets.");
        }

        Value = value;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateSerialNumber" /> class
    /// with a concrete value.
    /// </summary>
    /// <param name="value">The concrete value.</param>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when the value is less than 1 (not positive).
    /// </exception>
    public CertificateSerialNumber(long value)
        : this(new BigInteger(value))
    {
    }

    /// <summary>
    /// Gets the serial number value.
    /// </summary>
    public BigInteger Value { get; }

    /// <summary>
    /// Gets the serial number as a big-endian byte array.
    /// If the most significant bit would indicate a negative value, a <c>0x00</c>
    /// byte is prepended to preserve a positive ASN.1 DER integer.
    /// </summary>
    /// <returns>A byte array representing the serial number in ASN.1 DER-compatible format.</returns>
    public byte[] ToByteArray()
    {
        var byteCount = Value.GetByteCount(isUnsigned: true);

        if (byteCount == 0)
        {
            return [0];
        }

        // Allocate space for a possible padding byte.
        var buffer = new byte[byteCount + 1];
        Value.TryWriteBytes(buffer.AsSpan(1, byteCount), out _, isUnsigned: true, isBigEndian: true);

        // If the MSB is set, include the padding byte.
        if ((buffer[1] & 0x80) != 0)
        {
            // buffer[0] is already 0, return full array with padding
            return buffer;
        }

        // MSB not set - return exact size without padding.
        var result = new byte[byteCount];
        buffer.AsSpan(1, byteCount).CopyTo(result);
        return result;
    }

    /// <summary>
    /// Creates a new <see cref="CertificateSerialNumber" /> with a cryptographically random value.
    /// </summary>
    /// <param name="bytesLength">The number of bytes for the random serial number (default is 20).</param>
    /// <returns>A new <see cref="CertificateSerialNumber" /> instance.</returns>
    public static CertificateSerialNumber CreateRandom(int bytesLength = MaxOctets)
        => new(GenerateRandomValue(bytesLength));

    private static BigInteger GenerateRandomValue(int bytesLength)
    {
        if (bytesLength < 1 || bytesLength > MaxOctets)
        {
            throw new ArgumentOutOfRangeException(
                nameof(bytesLength),
                $"Bytes length must be between 1 and {MaxOctets}.");
        }

        Span<byte> bytes = stackalloc byte[bytesLength];
        RandomNumberGenerator.Fill(bytes);

        // Ensure a positive, non-zero value.
        bytes[0] &= 0x7F; // Clear the sign bit.
        if (bytes[0] == 0)
        {
            bytes[0] = 0x40; // Set a bit to ensure non-zero.
        }

        return new BigInteger(bytes, isUnsigned: true, isBigEndian: true);
    }
}
