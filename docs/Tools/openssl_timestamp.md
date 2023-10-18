# TimestampToken with OpenSSL

 OpenSSL 3.0.2 15 Mar 2022 (Library: OpenSSL 3.0.2 15 Mar 2022)

## Free TSA.

- [freeTSA.org](https://freetsa.org/index_en.php)

### Basics: TCP-based client.

Create a tsq (TimeStampRequest) file, which contains a hash of the file you want to sign.

```shell
openssl ts -query -data file.png -no_nonce -sha512 -cert -out file.tsq
```

Send the TimeStampRequest to freeTSA.org and receive a tsr (TimeStampResponse) file.


```shell
curl -H "Content-Type: application/timestamp-query" --data-binary '@file.tsq' https://freetsa.org/tsr > file.tsr
```

With the public Certificates you can verify the TimeStampRequest.

```shell
openssl ts -verify -in file.tsr -queryfile file.tsq -CAfile cacert.pem -untrusted tsa.crt

```

### Confirm the contents

Show TimeStampRequest.

```console
$ openssl ts -query -text -in file.tsq

Using configuration from /usr/lib/ssl/openssl.cnf
Version: 1
Hash Algorithm: sha512
Message data:
    0000 - a2 4a 34 52 73 7b fd a3-87 e2 5a 2a 23 51 7b f7   .J4Rs{....Z*#Q{.
    0010 - 33 19 a3 3a 3e 63 97 db-4d 81 2f 71 fa 44 ef 9e   3..:>c..M./q.D..
    0020 - 37 f6 c4 7a 20 d3 a4 7b-b1 27 ef 67 14 02 f6 e1   7..z ..{.'.g....
    0030 - 72 e2 a6 99 85 20 64 cc-5c 19 ec 3d 88 14 53 cd   r.... d.\..=..S.
Policy OID: unspecified
Nonce: unspecified
Certificate required: yes
Extensions:
```

is ASN.1.

```console
 $ openssl asn1parse -inform der -in file.tsq 

    0:d=0  hl=2 l=  89 cons: SEQUENCE          
    2:d=1  hl=2 l=   1 prim: INTEGER           :01
    5:d=1  hl=2 l=  81 cons: SEQUENCE          
    7:d=2  hl=2 l=  13 cons: SEQUENCE          
    9:d=3  hl=2 l=   9 prim: OBJECT            :sha512
   20:d=3  hl=2 l=   0 prim: NULL              
   22:d=2  hl=2 l=  64 prim: OCTET STRING      [HEX DUMP]:A24A3452737BFDA387E25A2A23517BF73319A33A3E6397DB4D812F71FA44EF9E37F6C47A20D3A47BB127EF671402F6E172E2A699852064CC5C19EC3D881453CD
   88:d=1  hl=2 l=   1 prim: BOOLEAN           :255
```

Show TimeStampResponse.

```console
$ openssl ts -reply -in file.tsr -text

Using configuration from /usr/lib/ssl/openssl.cnf
Status info:
Status: Granted.
Status description: unspecified
Failure info: unspecified

TST info:
Version: 1
Policy OID: tsa_policy1
Hash Algorithm: sha512
Message data:
    0000 - a2 4a 34 52 73 7b fd a3-87 e2 5a 2a 23 51 7b f7   .J4Rs{....Z*#Q{.
    0010 - 33 19 a3 3a 3e 63 97 db-4d 81 2f 71 fa 44 ef 9e   3..:>c..M./q.D..
    0020 - 37 f6 c4 7a 20 d3 a4 7b-b1 27 ef 67 14 02 f6 e1   7..z ..{.'.g....
    0030 - 72 e2 a6 99 85 20 64 cc-5c 19 ec 3d 88 14 53 cd   r.... d.\..=..S.
Serial number: 0xA30ADF
Time stamp: Sep 30 12:40:13 2023 GMT
Accuracy: unspecified
Ordering: yes
Nonce: unspecified
TSA: DirName:/O=Free TSA/OU=TSA/description=This certificate digitally signs documents and time stamp requests made using the freetsa.org online services/CN=www.freetsa.org/emailAddress=busilezas@gmail.com/L=Wuerzburg/C=DE/ST=Bayern
Extensions:
```
