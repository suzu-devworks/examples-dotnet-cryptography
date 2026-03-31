# ca-certificates (on Ubuntu)

## Table of Contents <!-- omit in toc -->

- [Overview](#overview)
- [Install and Trust a Local CA Certificate](#install-and-trust-a-local-ca-certificate)
- [Verify the System Trust Store](#verify-the-system-trust-store)
- [Remove the Imported Certificate](#remove-the-imported-certificate)
- [Read Trusted Certificates in .NET](#read-trusted-certificates-in-net)
- [Find a Certificate by Thumbprint in .NET](#find-a-certificate-by-thumbprint-in-net)
- [References](#references)

## Overview

On Ubuntu, the `ca-certificates` package manages the system trust store used by many tools and runtimes.

By adding a local CA certificate to `/usr/local/share/ca-certificates` and running `update-ca-certificates`, the certificate is added to the OS trust store.

In .NET on Linux, these trusted CA certificates can be read from `StoreName.Root` and `StoreLocation.LocalMachine`.

## Install and Trust a Local CA Certificate

Install package and trust a local CA certificate.

```shell
sudo apt install -y ca-certificates
sudo cp local-ca.crt /usr/local/share/ca-certificates
sudo update-ca-certificates
```

## Verify the System Trust Store

Confirm the certificate is imported into the system trust store.

```shell
ls -l /etc/ssl/certs | grep -i local-ca
sudo grep -n "BEGIN CERTIFICATE" /etc/ssl/certs/ca-certificates.crt | head
```

## Remove the Imported Certificate

Remove the certificate if needed.

```shell
sudo rm /usr/local/share/ca-certificates/local-ca.crt
sudo update-ca-certificates --fresh
```

## Read Trusted Certificates in .NET

In .NET on Linux, machine trust certificates can be read from the Root store.

```cs
using System.Security.Cryptography.X509Certificates;

using var store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
store.Open(OpenFlags.ReadOnly);

foreach (var cert in store.Certificates)
{
 Console.WriteLine($"Subject: {cert.Subject}");
 Console.WriteLine($"Issuer : {cert.Issuer}");
 Console.WriteLine($"SHA256 : {cert.GetCertHashString(System.Security.Cryptography.HashAlgorithmName.SHA256)}");
 Console.WriteLine();
}
```

## Find a Certificate by Thumbprint in .NET

Find an imported certificate by thumbprint.

```cs
using System.Security.Cryptography.X509Certificates;

const string thumbprint = "PUT_YOUR_THUMBPRINT_HERE";

using var store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
store.Open(OpenFlags.ReadOnly);

var found = store.Certificates.Find(
 X509FindType.FindByThumbprint,
 thumbprint,
 validOnly: false);

if (found.Count == 0)
{
 Console.WriteLine("Certificate was not found.");
 return;
}

var cert = found[0];
Console.WriteLine($"Found: {cert.Subject}");
```

You can verify the thumbprint with OpenSSL and compare it to .NET output.

```shell
openssl x509 -in local-ca.crt -noout -subject -issuer -fingerprint -sha256
```

## References

- [Ubuntu Packages: ca-certificates](https://packages.ubuntu.com/search?keywords=ca-certificates)
- [manpages: update-ca-certificates](https://manpages.ubuntu.com/manpages/noble/en/man8/update-ca-certificates.8.html)
- [Microsoft Learn: X509Store class](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509store)
- [Microsoft Learn: StoreName enum](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.storename)
- [Microsoft Learn: StoreLocation enum](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.storelocation)
