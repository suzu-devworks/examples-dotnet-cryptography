using System.Text;
using Examples.Fluency;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace Examples.Cryptography.BouncyCastle.Tests.Algorithms.Hashing
{
    public class Sha2HMACTests
    {
        public static IEnumerable<object[]> GenerateDigestData()
        {
            yield return new object[] { new Sha256Digest(), "SHA-256/HMAC", 32,
            "eNotB427jx8dqeX6oqRAJenDdufDpSzszoDwfarD9+E=" };
        }

        [Theory]
        [MemberData(nameof(GenerateDigestData))]
        public void WhenGeneratingHMAC(IDigest digest, string name, int size, string expected)
        {
            var message = "This is a test using a larger than block-size key " +
                          "and a larger than block-size data. The key needs to be hashed " +
                          "before being used by the HMAC algorithm.";
            byte[] key = "RBDc0q3nQ5ys+xmRvtn1h8gj7BhrVBHa5cizWcPSEU4=".ToBase64Bytes();

            HMac hmac = new(digest);
            Span<byte> buffer = stackalloc byte[hmac.GetMacSize()];
            hmac.Init(new KeyParameter(key));

            var span = Encoding.ASCII.GetBytes(message).AsSpan();
            hmac.BlockUpdate(span);
            hmac.DoFinal(buffer);
            var output = buffer.ToArray(); //boxing ?

            hmac.AlgorithmName.Is(name);
            hmac.GetMacSize().Is(size);
            output.ToBase64String().Is(expected);

            return;
        }
    }
}
