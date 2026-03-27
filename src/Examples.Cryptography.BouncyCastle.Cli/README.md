# Examples.Cryptography.BouncyCastle.Cli

A CLI tool for cryptographic operations using BouncyCastle.

## Commands

```shell
Usage: [command] [-h|--help] [--version]

Commands:
  ocsp check     Checks certificate revocation status via OCSP.
  tsa request    Requests a timestamp token from a TSA server.
  version        Prints version information.
```

---

## `ocsp check`

Checks the revocation status of a certificate by sending an OCSP request to the OCSP responder.

The OCSP endpoint URL is automatically extracted from the certificate's AIA (Authority Information Access) extension.
You can also specify the URL explicitly with `--url`.

```shell
Usage: ocsp check [options...] [-h|--help] [--version]

Options:
  -c, --cert     <string>    Path to the target certificate file (PEM). [Required]
  -i, --issuer   <string>    Path to the issuer certificate file (PEM). [Required]
  -u, --url      <string?>   OCSP endpoint URL. If not specified, extracted from the certificate AIA extension.
  -o, --output   <string?>   Output file path to save the DER-encoded OCSP response.
```

### Examples

```shell
# Check using the URL from the certificate AIA extension
dotnet run --project src/Examples.Cryptography.BouncyCastle.Cli -- ocsp check \
  --cert path/to/cert.pem \
  --issuer path/to/issuer.pem

# Specify the OCSP endpoint URL explicitly
dotnet run --project src/Examples.Cryptography.BouncyCastle.Cli -- ocsp check \
  --cert path/to/cert.pem \
  --issuer path/to/issuer.pem \
  --url http://ocsp.example.com

# Save the DER-encoded OCSP response to a file
dotnet run --project src/Examples.Cryptography.BouncyCastle.Cli -- ocsp check \
  --cert path/to/cert.pem \
  --issuer path/to/issuer.pem \
  --output ocsp-response.der
```

### Sample output

```console
Certificate status: GOOD
ThisUpdate       : 2026-03-27T00:00:00.0000000Z
NextUpdate       : 2026-03-28T00:00:00.0000000Z

OCSPResponse ::= {
          responseStatus: 0
       responseBytes [0]: ...
...
```

With OpenSSL, equivalent operations look like:

```shell
openssl ocsp \
  -issuer issuer.pem \
  -cert cert.pem \
  -url http://ocsp.example.com \
  -text
```

---

## `tsa request`

Requests a timestamp token from a TSA (Time Stamping Authority) server.

The request follows [RFC 3161](https://datatracker.ietf.org/doc/html/rfc3161).
A nonce is included in every request to prevent replay attacks.

```shell
Usage: tsa request [options...] [-h|--help] [--version]

Options:
  -u, --url        <string>    TSA server URL. [Required]
  -d, --data       <string?>   Data to timestamp as a string. If not specified, uses a default message.
  -a, --algorithm  <string>    Hash algorithm (SHA-256 | SHA-384 | SHA-512). [Default: SHA-256]
  -o, --output     <string?>   Output file path to save the DER-encoded timestamp token.
```

### Examples

```shell
# Request a timestamp token with default settings
dotnet run --project src/Examples.Cryptography.BouncyCastle.Cli -- tsa request \
  --url http://timestamp.example.com

# Timestamp specific data with SHA-512
dotnet run --project src/Examples.Cryptography.BouncyCastle.Cli -- tsa request \
  --url http://timestamp.example.com \
  --data "my important document content" \
  --algorithm SHA-512

# Save the timestamp token to a file
dotnet run --project src/Examples.Cryptography.BouncyCastle.Cli -- tsa request \
  --url http://timestamp.example.com \
  --data "my important document content" \
  --output timestamp.tsr
```

### Sample output

```console
SerialNumber : 1
GenTime      : 2026-03-27T12:34:56.0000000Z
Policy       : 1.3.6.1.4.1.13762.3
Algorithm    : 2.16.840.1.101.3.4.2.1

TimeStampToken ::= {
             contentType: id-signedData(1.2.840.113549.1.7.2)
...
```

With OpenSSL, equivalent operations look like:

```shell
# Create a timestamp request
openssl ts -query -data myfile.txt -sha256 -cert -out request.tsq

# Send it to a TSA server
curl -H "Content-Type: application/timestamp-query" \
  --data-binary @request.tsq \
  http://timestamp.example.com \
  -o response.tsr

# Display the timestamp token
openssl ts -reply -in response.tsr -text
```

---

## References

- [RFC 6960: Online Certificate Status Protocol (OCSP)](https://datatracker.ietf.org/doc/html/rfc6960)
- [RFC 3161: Internet X.509 PKI Time-Stamp Protocol (TSP)](https://datatracker.ietf.org/doc/html/rfc3161)
- [BouncyCastle.Cryptography NuGet](https://www.nuget.org/packages/BouncyCastle.Cryptography)
