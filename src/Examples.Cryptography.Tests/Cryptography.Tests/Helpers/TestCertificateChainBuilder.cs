using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Examples.Cryptography.Extensions;
using Examples.Cryptography.X509Certificates;

namespace Examples.Cryptography.Tests.X509.Helper;

/// <summary>
/// X.509 Certificate Chain Builder.
/// </summary>
/// <example>
/// <code>
/// var certificates = new TestCertificateChainBuilder(new("C=JP, CN=root-ca.example"))
///    .AddIntermediateCA(new($"C=JP, CN=intermediate-ca-001.example"))
///    .AddIntermediateCA(new($"C=JP, CN=intermediate-ca-002.example"))
///    .AddIntermediateCA(new($"C=JP, CN=intermediate-ca-003.example"))
///    .AddEndEntity(new("CN=*.example"), req => req
///        .AddKeyUsageExtension(critical: false, X509KeyUsageFlags.DigitalSignature)
///        .AddSubjectAlternativeName(san =>
///        {
///            san.AddDnsName("www.local-server.jp");
///            san.AddDnsName("local-server.jp");
///        }))
///    .Build(DateTimeOffset.UtcNow, days: 1);
/// </code>
/// </example>
/// <remarks>
/// This class is used to build a chain of X.509 certificates.
/// </remarks>
/// <param name="rootCaSubject">Root CA subject</param>
public sealed class TestCertificateChainBuilder(X500DistinguishedName rootCaSubject)
{
    private readonly X500DistinguishedName _rootCaSubject = rootCaSubject;

    /// <summary>
    /// Builds the certificate chain.
    /// </summary>
    /// <param name="timestamp"></param>
    /// <param name="days"></param>
    /// <returns></returns>
    public IEnumerable<X509Certificate2> Build(DateTimeOffset timestamp, int days)
    {
        var root = CreateRootCA(_rootCaSubject, timestamp, days);
        var issuer = root;

        List<X509Certificate2> intermediates = [];
        var pathLength = _intermediateSubjects.Count;
        foreach (var subject in _intermediateSubjects)
        {
            var cert = CreateIntermediateCA(subject, issuer, pathLength, timestamp, days);
            intermediates.Add(cert);

            --pathLength;
            issuer = cert;
        }

        List<X509Certificate2> entities = [];
        foreach (var (subject, action) in _entities)
        {
            var cert = CreateEndEntity(subject, issuer, action, timestamp, days);
            entities.Add(cert);
        }

        return [root, .. intermediates, .. entities];
    }

    /// <summary>
    /// Adds a CA certificate to the chain.
    /// </summary>
    /// <param name="intermediateCaSubject"></param>
    /// <returns></returns>
    public TestCertificateChainBuilder AddIntermediateCA(X500DistinguishedName intermediateCaSubject)
    {
        _intermediateSubjects.Add(intermediateCaSubject);
        return this;
    }
    private readonly List<X500DistinguishedName> _intermediateSubjects = [];

    /// <summary>
    /// Adds an end entity certificate to the chain.
    /// </summary>
    /// <param name="subject"></param>
    /// <param name="action"></param>
    /// <returns></returns>
    public TestCertificateChainBuilder AddEndEntity(X500DistinguishedName subject, Action<CertificateRequest> action)
    {
        _entities.Add((subject, action));
        return this;
    }
    private readonly List<(X500DistinguishedName, Action<CertificateRequest>)> _entities = [];

    private static X509Certificate2 CreateRootCA(
        X500DistinguishedName subject,
        DateTimeOffset timestamp,
        int days)
    {
        using var keyPair = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var req = new CertificateRequest(
            subject,
            keyPair,
            HashAlgorithmName.SHA256)
            .AddSubjectKeyIdentifierExtension()
            .AddAuthorityKeyIdentifierExtension()
            .AddExtension(X509BasicConstraintsExtension.CreateForCertificateAuthority());

        var notBefore = timestamp.AddSeconds(-50);
        var notAfter = notBefore.AddDays(days);

        // X509Certificate2 has a private key.
        return req.CreateSelfSigned(notBefore, notAfter);
    }

    private static X509Certificate2 CreateIntermediateCA(
        X500DistinguishedName subject,
        X509Certificate2 issuer,
        int pathLength,
        DateTimeOffset timestamp,
        int days)
    {
        using var keyPair = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var req = new CertificateRequest(
            subject,
            keyPair,
            HashAlgorithmName.SHA256)
            .AddSubjectKeyIdentifierExtension()
            .AddAuthorityKeyIdentifierExtension(issuer)
            .AddExtension(X509BasicConstraintsExtension.CreateForCertificateAuthority(pathLength));

        var notBefore = timestamp.AddSeconds(-50);
        var notAfter = notBefore.AddDays(days);
        var serial = new CertificateSerialNumber(100L - pathLength).ToBytes();

        var cert = req.CreateCertificate(
            issuer.SubjectName,
            issuer.GetECDsaPrivateKey()!,
            notBefore,
            notAfter,
            serial);

        // Append a private key.
        return cert.CopyWithPrivateKey(keyPair);
    }

    private static X509Certificate2 CreateEndEntity(
        X500DistinguishedName subject,
        X509Certificate2 issuer,
        Action<CertificateRequest> action,
        DateTimeOffset timestamp,
        int days)
    {
        using var keyPair = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var req = new CertificateRequest(
            subject,
            keyPair,
            HashAlgorithmName.SHA256)
            .AddSubjectKeyIdentifierExtension()
            .AddAuthorityKeyIdentifierExtension(issuer)
            .AddExtension(X509BasicConstraintsExtension.CreateForEndEntity());

        action.Invoke(req);

        var notBefore = timestamp.AddSeconds(-50);
        var notAfter = timestamp.AddDays(days);
        var serial = CertificateSerialNumber.CreateRandom(200L).ToBytes();

        var cert = req.CreateCertificate(
            issuer.SubjectName,
            issuer.GetECDsaPrivateKey()!,
            notBefore,
            notAfter,
            serial);

        // Append a private key.
        return cert.CopyWithPrivateKey(keyPair);
    }
}
