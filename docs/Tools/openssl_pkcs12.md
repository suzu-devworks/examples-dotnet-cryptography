# PKCS 12 with OpenSSL

 OpenSSL 3.0.2 15 Mar 2022 (Library: OpenSSL 3.0.2 15 Mar 2022)

## PKCS #12 

```shell
# create(export)
openssl pkcs12 -export -out my-store.p12 -inkey ee.key -in ee.crt

# create chain ??
openssl pkcs12 -export -out my-store.p12 -inkey ee.key -in ee.crt -CAfile chain.pem -chain -legacy

# show information
openssl pkcs12 -info -in my-store.p12 -noout
openssl asn1parse -in my-store.p12 -inform der -i

# get private key.
openssl pkcs12 -in my-store.p12 -out out.key -nocerts -noenc

# get encript private key.
openssl pkcs12 -in my-store.p12 -out out.key -nocerts -aes256

# get EE certificates.
openssl pkcs12 -in my-store.p12 -clcerts -nokeys -out out-ee.crt

# get CA certificates.
openssl pkcs12 -in my-store.p12 -cacerts -nokeys -out out-ca.crt

```

## OpenSSL v1 vs v3 

*OpenSSL v3*

```console
> openssl pkcs12 -info -in my-store.p12 

Enter Import Password:
MAC: sha256, Iteration 2048
MAC length: 32, salt length: 8
PKCS7 Encrypted data: PBES2, PBKDF2, AES-256-CBC, Iteration 2048, PRF hmacWithSHA256
Certificate bag
Bag Attributes
    localKeyID: C0 16 4F C0 6F 3F 3C 05 8F 17 0D 7A F8 CE 32 DC B9 64 87 00 
subject=C = JP, CN = end-entity
issuer=C = JP, CN = ca-int2
-----BEGIN CERTIFICATE-----
MI...
-----END CERTIFICATE-----
PKCS7 Data
Shrouded Keybag: PBES2, PBKDF2, AES-256-CBC, Iteration 2048, PRF hmacWithSHA256
Bag Attributes
    localKeyID: C0 16 4F C0 6F 3F 3C 05 8F 17 0D 7A F8 CE 32 DC B9 64 87 00 
Key Attributes: <No Attributes>
Enter PEM pass phrase:
Verifying - Enter PEM pass phrase:
-----BEGIN ENCRYPTED PRIVATE KEY-----
MI...
-----END ENCRYPTED PRIVATE KEY-----
```

*OpenSSL v1*

```console
> openssl pkcs12 -info -in my-store-legacy.p12 -legacy

MAC: sha1, Iteration 2048
MAC length: 20, salt length: 8
PKCS7 Encrypted data: pbeWithSHA1And40BitRC2-CBC, Iteration 2048
Certificate bag
Bag Attributes
    localKeyID: C0 16 4F C0 6F 3F 3C 05 8F 17 0D 7A F8 CE 32 DC B9 64 87 00 
subject=C = JP, CN = end-entity
issuer=C = JP, CN = ca-int2
-----BEGIN CERTIFICATE-----
MI...
-----END CERTIFICATE-----
PKCS7 Data
Shrouded Keybag: pbeWithSHA1And3-KeyTripleDES-CBC, Iteration 2048
Bag Attributes
    localKeyID: C0 16 4F C0 6F 3F 3C 05 8F 17 0D 7A F8 CE 32 DC B9 64 87 00 
Key Attributes: <No Attributes>
Enter PEM pass phrase:
Verifying - Enter PEM pass phrase:
-----BEGIN ENCRYPTED PRIVATE KEY-----
MI...
-----END ENCRYPTED PRIVATE KEY-----
```
