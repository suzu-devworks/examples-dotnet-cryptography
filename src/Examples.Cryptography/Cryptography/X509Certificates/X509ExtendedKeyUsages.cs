using System.Security.Cryptography;

namespace Examples.Cryptography.X509Certificates;

/// <summary>
/// Defines OBJECT IDENTIFIER for Extended Key Usage as described in RFC 5280.
/// </summary>
public class X509ExtendedKeyUsages
{
    /// <summary>
    /// id-kp-serverAuth -- TLS WWW server authentication.
    /// </summary>
    public static readonly Oid IdKpServerAuth = new("1.3.6.1.5.5.7.3.1");

    /// <summary>
    /// id-kp-clientAuth -- TLS WWW client authentication.
    /// </summary>
    public static readonly Oid IdKpClientAuth = new("1.3.6.1.5.5.7.3.2");

    /// <summary>
    /// id-kp-codeSigning -- Signing of downloadable executable code.
    /// </summary>
    public static readonly Oid IdKpCodeSigning = new("1.3.6.1.5.5.7.3.3");

    /// <summary>
    /// id-kp-emailProtection -- Email protection.
    /// </summary>
    public static readonly Oid IdKpEmailProtection = new("1.3.6.1.5.5.7.3.4");

    /// <summary>
    /// id-kp-timeStamping -- Binding the hash of an object to a time.
    /// </summary>
    public static readonly Oid IdKpTimeStamping = new("1.3.6.1.5.5.7.3.8");

    /// <summary>
    /// id-kp-OCSPSigning -- Signing OCSP responses.
    /// </summary>
    public static readonly Oid IdKpOCSPSigning = new("1.3.6.1.5.5.7.3.9");

}
