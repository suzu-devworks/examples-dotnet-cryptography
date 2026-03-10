using Org.BouncyCastle.X509;

namespace Examples.Cryptography.BouncyCastle.X509;

public static class X509V2CrlGeneratorExtensions
{
    public static X509V2CrlGenerator Configure(this X509V2CrlGenerator generator,
           Action<X509V2CrlGenerator> configure)
    {
        configure(generator);
        return generator;
    }
}
