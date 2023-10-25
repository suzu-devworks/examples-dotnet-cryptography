using Examples.Cryptography.BouncyCastle.Internals;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math.EC.Multiplier;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Xunit.Sdk;

namespace Examples.Cryptography.BouncyCastle.Tests.PKCS;

public class PKCS8PackageTests : IClassFixture<PKCSDataFixture>
{
    private readonly ITestOutputHelper _output;
    private readonly PKCSDataFixture _fixture;

    public PKCS8PackageTests(PKCSDataFixture fixture, ITestOutputHelper output)
    {
        _fixture = fixture;

        // ```
        // dotnet test --logger "console;verbosity=detailed"
        // ```
        _output = output;
    }


    [Fact]
    public void WhenExportingEncryptPkcs8_WithPem()
    {
        // https://github.com/bcgit/bc-csharp/blob/master/crypto/src/pkcs/Pkcs12Store.cs#L659

        var keyPair = _fixture.KeyPair!;
        var password1 = "password";

        var ramdom = new SecureRandom();
        var salt = ramdom.GenerateSeed(20);
        var iterationCount = 2048;

        var keyAlgorithm = NistObjectIdentifiers.IdAes256Cbc;
        var keyPrfAlgorithm = PkcsObjectIdentifiers.IdHmacWithSha256;

        var bagData = EncryptedPrivateKeyInfoFactory.CreateEncryptedPrivateKeyInfo(
            keyAlgorithm, keyPrfAlgorithm, password1.ToCharArray(),
             salt, iterationCount, new SecureRandom(), keyPair.Private);
        //var data = bagData.GetEncryptedData();

        var pkcs8enc = new Pkcs8EncryptedPrivateKeyInfo(bagData);
        var pkcs8encPem = PemUtility.ToPemString(pkcs8enc);
        pkcs8encPem.Is(x => x.StartsWith("-----BEGIN ENCRYPTED PRIVATE KEY-----")
                    && x.EndsWith("-----END ENCRYPTED PRIVATE KEY-----"));

        _output.WriteLine(pkcs8encPem);

        // write PKCS #8 with PKCS #5?
        //File.AppendAllText("pkcs8-enc-1.p8e", pkcs8encPem);

        // https://datatracker.ietf.org/doc/html/rfc5958#appendix-A

        // EncryptedPrivateKeyInfo ::= SEQUENCE {
        //      encryptionAlgorithm  EncryptionAlgorithmIdentifier,
        //      encryptedData        EncryptedData }
        //
        // EncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
        //                                  { CONTENT-ENCRYPTION,
        //                                  { KeyEncryptionAlgorithms } }
        //
        //   EncryptedData ::= OCTET STRING -- Encrypted PrivateKeyInfo

        var info = pkcs8enc.ToAsn1Structure();
        info.EncryptionAlgorithm.Algorithm.Is(PkcsObjectIdentifiers.IdPbeS2);

        // https://datatracker.ietf.org/doc/html/rfc8018#appendix-A.4
        var pbes2 = info.EncryptionAlgorithm.Parameters.IsInstanceOf<PbeS2Parameters>();

        // PBES2-params ::= SEQUENCE {
        //     keyDerivationFunc AlgorithmIdentifier { { PBES2-KDFs } },
        //     encryptionScheme AlgorithmIdentifier { { PBES2-Encs } }
        // }
        //
        // PBES2-KDFs ALGORITHM-IDENTIFIER ::=
        //       { {PBKDF2-params IDENTIFIED BY id-PBKDF2}, ... }
        // PBES2-Encs ALGORITHM-IDENTIFIER ::= { ... }

        pbes2.KeyDerivationFunc.Algorithm.Is(PkcsObjectIdentifiers.IdPbkdf2);

        // https://datatracker.ietf.org/doc/html/rfc8018#appendix-A.2
        var pbkdf2 = pbes2.KeyDerivationFunc.Parameters.IsInstanceOf<Pbkdf2Params>();

        // PBKDF2-params ::= SEQUENCE {
        //      salt CHOICE {
        //          specified OCTET STRING,
        //          otherSource AlgorithmIdentifier {{PBKDF2-SaltSources}}
        //      },
        //      iterationCount INTEGER (1..MAX),
        //      keyLength INTEGER (1..MAX) OPTIONAL,
        //      prf AlgorithmIdentifier {{PBKDF2-PRFs}} DEFAULT
        //          algid-hmacWithSHA1 }

        pbkdf2.IsDefaultPrf.IsFalse();
        pbkdf2.GetSalt().Is(salt);
        pbkdf2.IterationCount.IntValue.Is(iterationCount);
        pbkdf2.KeyLength.IsNull();
        pbkdf2.Prf.Algorithm.Is(keyPrfAlgorithm);
        pbkdf2.Prf.Parameters.Is(DerNull.Instance);

        pbes2.EncryptionScheme.Algorithm.Is(keyAlgorithm);
        var ocstr = pbes2.EncryptionScheme.Parameters.IsInstanceOf<DerOctetString>();
        ocstr.GetEncoded().Length.Is(16 + 2);

        //info.GetEncryptedData().Length.Is(1232);

        return;
    }


    [Fact]
    public void WhenExportingEncryptPkcs8_WithPkcs8GeneratorPem()
    {
        // https://github.com/bcgit/bc-csharp/blob/master/crypto/src/openssl/Pkcs8Generator.cs

        var keyPair = _fixture.KeyPair!;
        var ramdom = new SecureRandom();

        PrivateKeyInfo keyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyPair.Private);

        // PKCS #1.
        var pkcs1pem = PemUtility.ToPemString(keyInfo);
        var pkcs1pem2 = PemUtility.ToPemString(keyPair);
        var pkcs1pem3 = PemUtility.ToPemString(keyPair.Private);
        pkcs1pem.Is(x => x.StartsWith("-----BEGIN RSA PRIVATE KEY-----")
                    && x.EndsWith("-----END RSA PRIVATE KEY-----"));
        pkcs1pem2.Is(pkcs1pem);
        pkcs1pem3.Is(pkcs1pem);

        // PKCS #8 ???
        var pkcs8 = new Pkcs8Generator(keyPair.Private).Generate();
        var pkcs8pem = PemUtility.ToPemString(pkcs8);
        pkcs8pem.Is(x => x.StartsWith("-----BEGIN PRIVATE KEY-----")
                    && x.EndsWith("-----END PRIVATE KEY-----"));

        // PKCS #8 encripption ???
        // version 1.x ???
        var password = "password";
        //var alg = BCObjectIdentifiers.bc_pbe_sha256_pkcs12_aes256_cbc;
        var alg = PkcsObjectIdentifiers.PbeWithShaAnd3KeyTripleDesCbc;

        var pkcs8enc = new Pkcs8Generator(keyPair.Private, alg.Id)
        {
            SecureRandom = ramdom,
            Password = password.ToCharArray(),
        }
        .Generate();

        var pkcs8encPem = PemUtility.ToPemString(pkcs8enc);
        pkcs8encPem.Is(x => x.StartsWith("-----BEGIN ENCRYPTED PRIVATE KEY-----")
                    && x.EndsWith("-----END ENCRYPTED PRIVATE KEY-----"));

        _output.WriteLine(pkcs8encPem);

        // write PKCS #8 for PKCS #12 ... v1.5?
        //File.AppendAllText("pkcs8-enc-2.p8e", pkcs8encPem);

        // ```
        // openssl pkcs8 -in rsa-4096-private.key -out rsa-4096-private.pkcs8 -topk8 -v1 PBE-SHA1-3DES
        // ```

        // https://datatracker.ietf.org/doc/html/rfc5958#appendix-A

        // EncryptedPrivateKeyInfo ::= SEQUENCE {
        //      encryptionAlgorithm  EncryptionAlgorithmIdentifier,
        //      encryptedData        EncryptedData }
        //
        // EncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
        //                                  { CONTENT-ENCRYPTION,
        //                                  { KeyEncryptionAlgorithms } }
        //
        //   EncryptedData ::= OCTET STRING -- Encrypted PrivateKeyInfo

        var info = EncryptedPrivateKeyInfo.GetInstance(pkcs8enc.Content);
        info.EncryptionAlgorithm.Algorithm.Is(alg);

        var param = Asn1Sequence.GetInstance(info.EncryptionAlgorithm.Parameters);
        Asn1OctetString.GetInstance(param[0]).GetEncoded().Length.Is(20 + 2);
        DerInteger.GetInstance(param[1]).IntValueExact.Is(2048);

        // info.GetEncryptedData().Length.Is(1224);

        return;
    }


    [Fact]
    public void WhenExportingEncryptPkcs8_WithFactoryPem()
    {
        // https://github.com/bcgit/bc-csharp/blob/master/crypto/test/src/test/EncryptedPrivateKeyInfoTest.cs

        var keyPair = _fixture.KeyPair!;

        PrivateKeyInfo keyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyPair.Private);

        var alg = PkcsObjectIdentifiers.PbeWithShaAnd3KeyTripleDesCbc;
        var password = "password";
        byte[] salt = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
        var iterationCount = 1024;

        EncryptedPrivateKeyInfo encInfo = EncryptedPrivateKeyInfoFactory.CreateEncryptedPrivateKeyInfo(
            alg.Id, password.ToCharArray(), salt, iterationCount, keyInfo);
        PrivateKeyInfo info = PrivateKeyInfoFactory.CreatePrivateKeyInfo(
            password.ToArray(), encInfo);

        // RSA PrivateKeyInfo is PKCS #1.
        var pem = PemUtility.ToPemString(info);
        pem.Is(x => x.StartsWith("-----BEGIN RSA PRIVATE KEY-----")
                    && x.EndsWith("-----END RSA PRIVATE KEY-----"));

        // To PKCS #8 ??
        var pkcs8 = new Org.BouncyCastle.Utilities.IO.Pem.PemObject("PRIVATE KEY", info.GetEncoded());
        var pkcs8Pem = PemUtility.ToPemString(pkcs8);
        pkcs8Pem.Is(x => x.StartsWith("-----BEGIN PRIVATE KEY-----")
                    && x.EndsWith("-----END PRIVATE KEY-----"));

        AsymmetricKeyParameter key = PrivateKeyFactory.CreateKey(info);
        key.Equals(keyPair.Private).IsTrue();

        return;
    }

    [Fact]
    public void WhenImportingEncriptyPkcs8_WithPem()
    {
        var pem = """
                -----BEGIN ENCRYPTED PRIVATE KEY-----
                MIHsMFcGCSqGSIb3DQEFDTBKMCkGCSqGSIb3DQEFDDAcBAhDwEJAoDjVNQICCAAw
                DAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEERGEzQp4YoqMP8jz3/ZAH0EgZAu
                u7PgwcB8D8vMHr5lZ9+JUOHX4geGkbH+OKbn6/AmdsmkVdVmMWYgOVj22dTsIIXQ
                yGuURcHhD0NebpY6U7CODNUgIixO/q69b9CTO6GHJdjxa7RWqiwu3gWe3e5SlYbq
                V6hQB2/eS2vIvQfOEzbX3sgsK4qbv0Bk888rZFBYjz5aQTTLO64Urb5KFEz7Fjo=
                -----END ENCRYPTED PRIVATE KEY-----
                """;

        var password1 = "password";

        //TODO var key = AsymmetricCipherKeyPairAgent.ImportPrivateKeyPem(pem, password1.ToCharArray());
        using var reader = new PemReader(new StringReader(pem), new Password(password1));
        var loaded = reader.ReadObject();
        if (loaded is not ECPrivateKeyParameters privateKey)
        {
            throw new XunitException("error");
        }

        // create public key
        var ec = privateKey.Parameters;
        var q = new FixedPointCombMultiplier().Multiply(ec.G, privateKey.D);

        var publicKey = (privateKey.PublicKeyParamSet is null)
            ? new ECPublicKeyParameters(privateKey.AlgorithmName, q, ec)
            : new ECPublicKeyParameters(privateKey.AlgorithmName, q, privateKey.PublicKeyParamSet)
            ;

        var keyPair = new AsymmetricCipherKeyPair(publicKey, privateKey);

        keyPair.IsNotNull();

        return;
    }

    private class Password : IPasswordFinder
    {
        private readonly char[] _password;

        public Password(string password)
        {
            _password = password.ToCharArray();
        }

        public char[] GetPassword()
        {
            return (char[])_password.Clone();
        }
    }

}
