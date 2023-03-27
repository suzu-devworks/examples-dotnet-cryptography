using System.Security.Cryptography.X509Certificates;

namespace Examples.Cryptography.X509Certificates;

public static class CertificateRequestExtensions
{
    public static CertificateRequest SetBasicConstraints(this CertificateRequest req,
     bool isCa = true, int maxPathLength = 0)
    {
        // basicConstraints       = critical, CA:true

        if (maxPathLength < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maxPathLength),
                "value is positive or zero.");
        }

        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(
            certificateAuthority: isCa,
            hasPathLengthConstraint: (maxPathLength > 0),
            pathLengthConstraint: maxPathLength,
            critical: true));

        return req;
    }

}
