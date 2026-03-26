using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Examples.Cryptography.BouncyCastle.Tests.Algorithms.Hashing
{
    public class HmacSha2Tests
    {
        private static readonly string Message = "This is a test using a larger than block-size key " +
                                                 "and a larger than block-size data. The key needs to be hashed " +
                                                 "before being used by the HMAC algorithm.";
        private static IDigest CreateDigest(string name)
        {
            return name switch
            {
                "SHA-256" => new Sha256Digest(),
                "SHA-384" => new Sha384Digest(),
                "SHA-512" => new Sha512Digest(),
                _ => throw new ApplicationException("no expected pattern.")
            };
        }

        private static byte[] CreateSecretKey(long bytes)
        {
            SecureRandom random = new();
            byte[] secureRandomBytes = new byte[bytes];
            random.NextBytes(secureRandomBytes);
            return secureRandomBytes;
        }

        private static byte[] ComputeHmac(string name, byte[] message, byte[] secretKey)
        {
            HMac hmac = new(CreateDigest(name));
            Span<byte> buffer = stackalloc byte[hmac.GetMacSize()];
            hmac.Init(new KeyParameter(secretKey));
            hmac.BlockUpdate(message.AsSpan());
            hmac.DoFinal(buffer);
            var output = buffer.ToArray();

            return output;
        }

        [Theory]
        [InlineData("SHA-256")]
        [InlineData("SHA-384")]
        [InlineData("SHA-512")]
        public void When_HMACGenerated_WithTheSameKey_Then_GetsSameValue(string name)
        {
            var message = Encoding.ASCII.GetBytes(Message);
            var secretKey = CreateSecretKey(64);

            var output = ComputeHmac(name, message, secretKey);
            var verify = ComputeHmac(name, message, secretKey);

            // Assert:

            Assert.Equal(output, verify);
        }

        [Theory]
        [InlineData("SHA-256")]
        public void When_HMACGenerated_WithDifferentKeys_Then_GetsDifferentValues(string name)
        {
            var message = Encoding.ASCII.GetBytes(Message);
            var secretKey1 = CreateSecretKey(64);
            var secretKey2 = CreateSecretKey(64);

            var output = ComputeHmac(name, message, secretKey1);
            var verify = ComputeHmac(name, message, secretKey2);

            // Assert:

            Assert.NotEqual(output, verify);
        }

        [Theory]
        [InlineData("SHA-256")]
        public void When_HMACGenerated_WithMessagesAreTampered_Then_GetsDifferentValues(string name)
        {
            var message = Encoding.ASCII.GetBytes(Message);
            var secretKey = CreateSecretKey(64);

            var output = ComputeHmac(name, message, secretKey);

            // Tamper with the message
            message[0] ^= 0xFF; // Flip the first byte

            var verify = ComputeHmac(name, message, secretKey);

            // Assert:

            Assert.NotEqual(output, verify);
        }
    }
}
