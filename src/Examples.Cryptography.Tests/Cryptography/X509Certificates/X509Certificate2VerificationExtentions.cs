using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Examples.Cryptography.X509Certificates;

/// <summary>
/// Extension methods for <see cref="X509Certificate2" />.
/// </summary>
public static class X509Certificate2VerificationExtensions
{
    /// <summary>
    /// Validates the certificate signature using the signer certificate,
    /// Generates an exception if it fails.
    /// </summary>
    /// <param name="certificate">The Certificate to verify.</param>
    /// <param name="signer">The signed certificate.</param>
    /// <exception cref="NotSupportedException">If you are using an unsupported signature algorithm.</exception>
    public static void ValidateSignature(this X509Certificate2 certificate,
        X509Certificate2 signer)
    {
        if (!certificate.VerifiesSignature(signer))
        {
            throw new InvalidDataException("A public key was presented that is not for certificate signing.");
        }
    }

    /// <summary>
    /// Verifies the certificate signature with the signer certificate.
    /// </summary>
    /// <param name="certificate">The Certificate to verify.</param>
    /// <param name="signer">The signed certificate.</param>
    /// <returns>true if signature matches the signature computed using the specified hash algorithm;
    /// otherwise, false.</returns>
    /// <exception cref="NotSupportedException">If you are using an unsupported signature algorithm.</exception>
    /// <seealso href="https://security.stackexchange.com/questions/43172/evaluate-the-signature-of-an-x509-certificate-in-net" />
    public static bool VerifiesSignature(this X509Certificate2 certificate,
        X509Certificate2 signer)
    {
        var signature = certificate.Signature();
        var tbs = certificate.TbsCertificate();
        var hash = SignatureAlgorithms.GetHashAlgorithmName(certificate.SignatureAlgorithm)
            ?? throw new NotSupportedException($"Unsupported SignatureAlgorithm \"{certificate.SignatureAlgorithm.FriendlyName}\".");

        using var rsa = signer.GetRSAPublicKey();
        using var ecdsa = signer.GetECDsaPublicKey();

        var algo = certificate.SignatureAlgorithm;
        switch (algo)
        {
            case var _ when algo.Value == SignatureAlgorithms.sha1RSA.Value:
            case var _ when algo.Value == SignatureAlgorithms.sha256RSA.Value:
            case var _ when algo.Value == SignatureAlgorithms.sha384RSA.Value:
            case var _ when algo.Value == SignatureAlgorithms.sha512RSA.Value:

                return rsa?.VerifyData(tbs, signature, hash, RSASignaturePadding.Pkcs1) ?? false;

            case var _ when algo.Value == SignatureAlgorithms.sha256ECDSA.Value:
            case var _ when algo.Value == SignatureAlgorithms.sha384ECDSA.Value:
            case var _ when algo.Value == SignatureAlgorithms.sha512ECDSA.Value:

                return ecdsa?.VerifyData(tbs, signature, hash, DSASignatureFormat.Rfc3279DerSequence) ?? false;

            default:
                throw new NotSupportedException($"Unsupported AsymmetricAlgorithm \"{algo.Value}\".");
        }
    }


    private static byte[] Signature(this X509Certificate2 certificate,
        AsnEncodingRules encodingRules = AsnEncodingRules.BER)
    {
        // https://tex2e.github.io/rfc-translater/html/rfc5280.html#4-1--Basic-Certificate-Fields
        //
        // Certificate  ::=  SEQUENCE  {
        //     tbsCertificate TBSCertificate (SEQUENCE),
        //     signatureAlgorithm   AlgorithmIdentifier (SEQUENCE),
        //     signatureValue BIT STRING
        // }

        var signedData = certificate.RawDataMemory;
        AsnDecoder.ReadSequence(
            signedData.Span,
            encodingRules,
            out var offset,
            out var length,
            out _
            );

        var certificateSpan = signedData.Span[offset..(offset + length)];
        AsnDecoder.ReadSequence(
            certificateSpan,
            encodingRules,
            out var tbsOffset,
            out var tbsLength,
            out _
            );

        var offsetSpan = certificateSpan[(tbsOffset + tbsLength)..];
        AsnDecoder.ReadSequence(
            offsetSpan,
            encodingRules,
            out var algOffset,
            out var algLength,
            out _
            );

        return AsnDecoder.ReadBitString(
            offsetSpan[(algOffset + algLength)..],
            encodingRules,
            out _,
            out _
            );
    }

    private static ReadOnlySpan<byte> TbsCertificate(this X509Certificate2 certificate,
        AsnEncodingRules encodingRules = AsnEncodingRules.BER)
    {
        var signedData = certificate.RawDataMemory;
        AsnDecoder.ReadSequence(
            signedData.Span,
            encodingRules,
            out var offset,
            out var length,
            out _
            );

        var certificateSpan = signedData.Span[offset..(offset + length)];
        AsnDecoder.ReadSequence(
            certificateSpan,
            encodingRules,
            out var tbsOffset,
            out var tbsLength,
            out _
            );

        // include ASN1 4 byte header to get WHOLE TBS Cert
        return certificateSpan[..(tbsLength + tbsOffset)];
    }

}
