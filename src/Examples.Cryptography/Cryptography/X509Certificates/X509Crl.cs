using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Examples.Cryptography.X509Certificates;

/// <summary>
/// Represents a Certificate Revocation List (CRL) as defined in RFC 5280.
/// </summary>
public class X509Crl
{
    public X509Crl(byte[] bytes)
    {
        var reader = new AsnReader(bytes, AsnEncodingRules.DER);

        var certificateList = reader.ReadSequence();

        // CertificateList  ::=  SEQUENCE  {
        //      tbsCertList          TBSCertList,
        //      signatureAlgorithm   AlgorithmIdentifier,
        //      signatureValue       BIT STRING  }

        TbsCertList = new TBSCertList(certificateList.ReadSequence());
        SignatureAlgorithm = new AlgorithmIdentifier(certificateList.ReadSequence());
        SignatureValue = certificateList.ReadBitString(out var _);

        if (certificateList.HasData || reader.HasData)
        {
            throw new CryptographicException("Unexpected data after parsing X509 CRL.");
        }

    }

    /// <summary>
    /// Represents the AlgorithmIdentifier structure defined in RFC 5280 Section 4.1.
    /// </summary>
    public class AlgorithmIdentifier
    {
        internal AlgorithmIdentifier(AsnReader reader)
        {
            // AlgorithmIdentifier  ::= SEQUENCE  {
            //      algorithm            OBJECT IDENTIFIER,
            //      parameters           ANY DEFINED BY algorithm OPTIONAL  }
            //                              -- contains a value of the type
            //                              -- registered for use with the
            //                              -- algorithm object identifier value

            Algorithm = new Oid(reader.ReadObjectIdentifier());
            if (reader.HasData)
            {
                Parameters = reader.ReadEncodedValue();
            }
        }

        public Oid Algorithm { get; }
        public ReadOnlyMemory<byte>? Parameters { get; }
    }

    /// <summary>
    /// Represents the TBSCertList structure defined in RFC 5280 Section 5.1.
    /// </summary>
    public class TBSCertList
    {
        internal TBSCertList(AsnReader tbsCertList)
        {
            // TBSCertList  ::= SEQUENCE  {
            //      version             Version OPTIONAL,
            //                              -- if present, MUST be v2
            //      signature           AlgorithmIdentifier,
            //      issuer              Name,
            //      thisUpdate          Time,
            //      nextUpdate          Time OPTIONAL,
            //      revokedCertificates SEQUENCE OF SEQUENCE  {
            //          userCertificate     CertificateSerialNumber,
            //          revocationDate      Time,
            //          crlEntryExtensions  Extensions OPTIONAL
            //                              -- if present, version MUST be v2
            //                            } OPTIONAL,
            //      crlExtensions       [0] Extensions OPTIONAL }
            //                              -- if present, version MUST be v2

            Version = tbsCertList.ReadInteger();
            Signature = new AlgorithmIdentifier(tbsCertList.ReadSequence());
            Issuer = new X500DistinguishedName(tbsCertList.ReadEncodedValue().Span);

            ThisUpdate = ReadTime(tbsCertList);

            // nextUpdate Time OPTIONAL
            if (tbsCertList.HasData && IsTimeTag(tbsCertList.PeekTag()))
            {
                NextUpdate = ReadTime(tbsCertList);
            }

            // revokedCertificates SEQUENCE OF SEQUENCE { ... } OPTIONAL
            var revokedEntries = new List<RevokedCertificateEntry>();
            if (tbsCertList.HasData
                && tbsCertList.PeekTag().TagClass == TagClass.Universal
                && tbsCertList.PeekTag().TagValue == (int)UniversalTagNumber.Sequence)
            {
                var revokedCertificates = tbsCertList.ReadSequence();
                while (revokedCertificates.HasData)
                {
                    var sequence = revokedCertificates.ReadSequence();
                    var userCertificate = sequence.ReadInteger();
                    var revocationDate = ReadTime(sequence);
                    ReadOnlyMemory<byte>? crlEntryExtensions = sequence.HasData
                        ? sequence.ReadEncodedValue()
                        : null;

                    revokedEntries.Add(new RevokedCertificateEntry(
                        userCertificate, revocationDate, crlEntryExtensions));
                }
            }
            RevokedCertificates = revokedEntries;

            // crlExtensions [0] Extensions OPTIONAL
            if (tbsCertList.HasData)
            {
                // TODO: parse individual extensions if needed
                _ = tbsCertList.ReadSequence(
                    new Asn1Tag(TagClass.ContextSpecific, 0));
            }
        }

        public BigInteger Version { get; }
        public AlgorithmIdentifier Signature { get; }
        public X500DistinguishedName Issuer { get; }
        public DateTimeOffset ThisUpdate { get; }
        public DateTimeOffset? NextUpdate { get; }
        public IReadOnlyList<RevokedCertificateEntry> RevokedCertificates { get; }

        private static DateTimeOffset ReadTime(AsnReader reader)
        {
            var tag = reader.PeekTag();
            if (tag.TagValue == (int)UniversalTagNumber.GeneralizedTime)
            {
                return reader.ReadGeneralizedTime();
            }

            return reader.ReadUtcTime();
        }

        private static bool IsTimeTag(Asn1Tag tag)
            => tag.TagClass == TagClass.Universal
            && (tag.TagValue == (int)UniversalTagNumber.UtcTime
                || tag.TagValue == (int)UniversalTagNumber.GeneralizedTime);
    }

    /// <summary>
    /// Represents a revoked certificate entry in the CRL.
    /// </summary>
    public record RevokedCertificateEntry(
        BigInteger SerialNumber,
        DateTimeOffset RevocationDate,
        ReadOnlyMemory<byte>? Extensions);

    public TBSCertList TbsCertList { get; }
    public AlgorithmIdentifier? SignatureAlgorithm { get; }
    public byte[] SignatureValue { get; }

    /// <summary>
    /// Dumps the CRL information in a human-readable format.
    /// </summary>
    public string Dump()
    {
        var sb = new StringBuilder();
        sb.AppendLine();
        sb.AppendLine($"  version: {TbsCertList.Version}");
        sb.AppendLine($"  signatureAlgorithm: {(SignatureAlgorithm?.Algorithm is not null
                ? SignatureAlgorithms.GetAlgorithmName(SignatureAlgorithm.Algorithm)
                : "unknown")}");
        sb.AppendLine($"  issuer: {TbsCertList.Issuer.Name}");
        sb.AppendLine($"  thisUpdate: {TbsCertList.ThisUpdate:O}");
        sb.AppendLine($"  nextUpdate: {TbsCertList.NextUpdate:O}");
        sb.AppendLine($"  revokedCertificates: [count={TbsCertList.RevokedCertificates.Count}]");
        foreach (var entry in TbsCertList.RevokedCertificates)
        {
            sb.AppendLine($"    serialNumber: {entry.SerialNumber}");
            sb.AppendLine($"    revocationDate: {entry.RevocationDate:O}");
        }
        return sb.ToString();
    }

}
