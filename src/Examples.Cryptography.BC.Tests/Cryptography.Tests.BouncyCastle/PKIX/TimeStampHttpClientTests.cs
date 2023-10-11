#if false
#define USE_HTTP_CLIENT
#pragma warning disable IDE0052

#else
using System.Net;
using System.Net.Http.Headers;
using Moq.Protected;
using Org.BouncyCastle.OpenSsl;

#endif

using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Examples.Cryptography.BouncyCastle;
using Examples.Cryptography.BouncyCastle.PKIX;
using Examples.Cryptography.BouncyCastle.Utilities;
using Examples.Cryptography.BouncyCastle.X509;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Tsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using Xunit.Sdk;

namespace Examples.Cryptography.Tests.BouncyCastle.PKIX;

public class TimeStampHttpClientTests : IClassFixture<TimeStampFixture>
{
    private static readonly TimeSpan OnlineTimeout = TimeSpan.FromSeconds(5);

    private readonly TimeStampFixture _fixture;
    private readonly IServiceProvider _services;
    private readonly ITestOutputHelper _output;

    public TimeStampHttpClientTests(TimeStampFixture fixture, ITestOutputHelper output)
    {
        _fixture = fixture;
        _services = InitializeServiceProvider();

        // ```
        // dotnet test --logger "console;verbosity=detailed"
        // ```
        _output = output;
    }

    [Fact]
    public async Task WhenRequestTimestampToken_UsingFreeTsaOrg_ResponseOk()
    {
        // I will try to get the TimeStampToken using the actual TSA server(FreeTSA.org).

        // ### Arrange. ###
        var data = Encoding.UTF8.GetBytes("TEST MESSAGE PHRASE");

        //```
        // $ openssl ts -query -data file.png -no_nonce -sha512 -cert -out file.tsq
        //```
        // Make a request as above.
        var algorithm = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha512);
        var digest = DigestUtilities.CalculateDigest(algorithm.Algorithm, data);
        var message = new MessageImprint(algorithm, digest);

        var request = new TimeStampRequestGenerator()
            .Configure(gen => gen.SetCertReq(true))
            .Generate(
                digestAlgorithm: message.HashAlgorithm.Algorithm,
                digest: message.GetHashedMessage()
            );

        // ### Act. ###
        var url = new Uri("https://freetsa.org/tsr");
        //var url = new Uri("http://ts.ssl.com");
        var httpClientFactory = _services.GetRequiredService<IHttpClientFactory>();
        var response = await new TimeStampHttpClient(httpClientFactory)
            .RequestAsync(url, request, OnlineTimeout);

        // ### Assert. ###
        response.Validate(request);

        var tat = response.TimeStampToken;
        _output.WriteLine($"# TimeStampToken({url}):");
        _output.WriteLine(tat.DumpAsString());

        var genDate = tat.TimeStampInfo.GenTime;

        var tsaCert = tat.FindTSACertificate()
            ?? throw new XunitException($"Illigal data in TimeStampInfo.");
        _output.WriteLine($"# TSA Certificate({url}):");
        _output.WriteLine($"{tsaCert.DumpAsString()}");

        tsaCert.CheckValidity(time: genDate);
        tat.Validate(tsaCert);

        var issuer = await DownloadIssuerCertificateAsync(tsaCert!);
        _output.WriteLine($"# TSA Issuer Certificate({url}):");
        _output.WriteLine($"{issuer.DumpAsString()}");

        issuer.CheckValidity(time: genDate);

        var tsaOcsp = await FindTsaRevocationWithOcsp(tsaCert, issuer);
        if (tsaOcsp is not null)
        {
            _output.WriteLine($"# OCSP ({url}):");
            _output.WriteLine($"{tsaOcsp.DumpAsString()}");

            tsaOcsp.Validate(issuer, time: genDate);

            var basic = (BasicOcspResp)tsaOcsp.GetResponseObject();
            var single = basic.Responses.First();
            var status = single.GetCertStatus();
            var success = status == Org.BouncyCastle.Ocsp.CertificateStatus.Good;
            if (!success)
            {
                var revoked = status as Org.BouncyCastle.Ocsp.RevokedStatus;
                var unknown = status as Org.BouncyCastle.Ocsp.UnknownStatus;
                throw new XunitException($"OCSP status is {revoked}{unknown}.");
            }
        }

        var tsaCrl = await FindTsaRevocationWithCrl(tsaCert);
        if (tsaCrl is not null)
        {
            _output.WriteLine($"# CRL ({url}):");
            _output.WriteLine($"{tsaCrl.DumpAsString()}");

            tsaCrl.Verify(issuer.GetPublicKey());

            var entry = tsaCrl.CertificateList.GetRevokedCertificateEnumeration()
                .Where(x => x.UserCertificate.Value.Equals(tsaCert.SerialNumber))
                .Where(x => x.RevocationDate.ToDateTime() < genDate)
                .FirstOrDefault();

            if (entry is not null)
            {
                var time = entry.RevocationDate.ToDateTime();
                var code = entry.Extensions.GetExtension(X509Extensions.ReasonCode);
                CrlReason? reason = null;
                if (code is not null)
                {
                    reason = new CrlReason(
                        DerEnumerated.GetInstance(
                            X509ExtensionUtilities.FromExtensionValue(code.Value)));
                }

                throw new XunitException($"Certificate revo in CRL: {reason} at {time}.");
            }
        }

        return;
    }

    private async Task<X509Certificate> DownloadIssuerCertificateAsync(X509Certificate tsaCert)
    {
        var issuerUri = tsaCert.GetAuthorityInfoAccessUri(AccessDescription.IdADCAIssuers)
            ?? throw new XunitException($"Illigal data in TSA Certificate.");

        var httpClientFactory = _services.GetRequiredService<IHttpClientFactory>();
        var downloaded = await new HttpDownloader(httpClientFactory)
                .DownloadAsync(issuerUri, OnlineTimeout);

        var issuer = new X509Certificate(downloaded);

        return issuer;
    }

    public async Task<OcspResp?> FindTsaRevocationWithOcsp(X509Certificate tsaCert,
        X509Certificate issuerCert)
    {
        var ocspUri = tsaCert.GetAuthorityInfoAccessUri(AccessDescription.IdADOcsp);
        if (ocspUri is null)
        {
            return null;
        }

        var request = new OcspReqGenerator()
            .Configure(gen =>
            {
                gen.AddRequest(new CertificateID(
                    CertificateID.HashSha1, issuerCert, tsaCert!.SerialNumber));

#if USE_HTTP_CLIENT
                gen.AddNonce(BigInteger.ValueOf(DateTime.Now.Ticks));

#else
                gen.AddNonce(BigInteger.One);

#endif

            })
            .Generate();

        var httpClientFactory = _services.GetRequiredService<IHttpClientFactory>();
        var response = await new OcspHttpClient(httpClientFactory)
            .RequestAsync(ocspUri, request, OnlineTimeout);

        response.Validate(request);

        return response;
    }

    public async Task<X509Crl?> FindTsaRevocationWithCrl(X509Certificate tsaCert)
    {
        var crlUri = tsaCert.GetCrlDistributionPointsUri();
        if (crlUri is null)
        {
            return null;
        }

        var httpClientFactory = _services.GetRequiredService<IHttpClientFactory>();
        var downloaded = await new HttpDownloader(httpClientFactory)
                .DownloadAsync(crlUri, OnlineTimeout);
        var revocation = new X509Crl(downloaded);

        return revocation;
    }


#if USE_HTTP_CLIENT

    private static IServiceProvider InitializeServiceProvider()
    {
        IServiceCollection services = new ServiceCollection();
        services.AddHttpClient(); // use IHttpClientFactory
        return services.BuildServiceProvider();
    }

#else

    public interface IHttpMessageHandler
    {
        Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken);
    }

    private IServiceProvider InitializeServiceProvider()
    {
        var (_, cACert) = _fixture.CaSet;
        var tstResponse = _fixture.TimeStampResponse;
        var caOcspResponse = _fixture.CaOcspResp;
        var caCrl = _fixture.CaCrl;

        var mockTstHandler = new Mock<HttpMessageHandler>();
        mockTstHandler.Protected()
                .As<IHttpMessageHandler>()
                .Setup(m => m.SendAsync(It.IsAny<HttpRequestMessage>(), It.IsAny<CancellationToken>()))
                .Returns(() =>
                {
                    var response = new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new ByteArrayContent(tstResponse.GetEncoded()),
                    };
                    return Task.FromResult(response);
                });

        var mockDownloadHandler = new Mock<HttpMessageHandler>();
        mockDownloadHandler.Protected()
                .As<IHttpMessageHandler>()
                .SetupSequence(m => m.SendAsync(It.IsAny<HttpRequestMessage>(), It.IsAny<CancellationToken>()))
                .Returns(() =>
                {
                    using var memory = new MemoryStream();
                    using (var writer = new PemWriter(new StreamWriter(memory, Encoding.ASCII)))
                    {
                        writer.WriteObject(cACert);
                    }

                    var response = new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StreamContent(new MemoryStream(memory.ToArray())),
                    };
                    response.Content.Headers.ContentType
                        = MediaTypeHeaderValue.Parse("application/x-pem-file");

                    return Task.FromResult(response);
                })
                .Returns(() =>
                {
                    var response = new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new ByteArrayContent(caCrl.GetEncoded()),
                    };
                    return Task.FromResult(response);
                });

        var mockOcspHandler = new Mock<HttpMessageHandler>();
        mockOcspHandler.Protected()
                .As<IHttpMessageHandler>()
                .Setup(m => m.SendAsync(It.IsAny<HttpRequestMessage>(), It.IsAny<CancellationToken>()))
                .Returns(() =>
                {
                    var response = new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new ByteArrayContent(caOcspResponse.GetEncoded()),
                    };
                    return Task.FromResult(response);
                });

        IServiceCollection services = new ServiceCollection();

        services.AddHttpClient(nameof(TimeStampHttpClient))
            .ConfigurePrimaryHttpMessageHandler(_ => mockTstHandler.Object);
        services.AddHttpClient(nameof(HttpDownloader))
            .ConfigurePrimaryHttpMessageHandler(_ => mockDownloadHandler.Object);
        services.AddHttpClient(nameof(OcspHttpClient))
            .ConfigurePrimaryHttpMessageHandler(_ => mockOcspHandler.Object);

        return services.BuildServiceProvider();
    }

#endif

}

