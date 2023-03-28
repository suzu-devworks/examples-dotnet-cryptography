using System.Security.Cryptography;

namespace Examples.Cryptography.X509Certificates;

public class X509ExtendedKeyUsages
{
    public static readonly Oid IdKpServerAuth = new("1.3.6.1.5.5.7.3.1");
    public static readonly Oid IdKpClientAuth = new("1.3.6.1.5.5.7.3.2");
    public static readonly Oid IdKpCodeSigning = new("1.3.6.1.5.5.7.3.3");
    public static readonly Oid IdKpEmailProtection = new("1.3.6.1.5.5.7.3.4");
    public static readonly Oid IdKpTimeStamping = new("1.3.6.1.5.5.7.3.8");
    public static readonly Oid IdKpOCSPSigning = new("1.3.6.1.5.5.7.3.9");

}
