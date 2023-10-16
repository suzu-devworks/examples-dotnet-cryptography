# OpenSSL.

 OpenSSL 3.0.2 15 Mar 2022 (Library: OpenSSL 3.0.2 15 Mar 2022)

### Create Certificates chain 

```shell
## Root CA
openssl ecparam -genkey -name prime256v1 -noout -out ca-root.key
openssl req -new -x509 -key ca-root.key -out ca-root.crt -sha256 -days 365 -subj="/C=JP/CN=ca-root"
openssl x509 -text -noout -in ca-root.crt
openssl verify -trusted ca-root.crt --show_chain ca-root.crt


## Level1 intermidiate CA
openssl ecparam -genkey -name prime256v1 -noout -out ca-int1.key
openssl req -new -key ca-int1.key -out ca-int1.csr -sha256 -subj="/C=JP/CN=ca-int1" 
openssl x509 -req -in ca-int1.csr -out ca-int1.crt -CA ca-root.crt -CAkey ca-root.key -sha256 -days 365 --extfile /usr/lib/ssl/openssl.cnf -extensions v3_ca
openssl x509 -text -noout -in ca-int1.crt
openssl verify -trusted ca-root.crt --show_chain ca-int1.crt


## Level2 intermidiate CA
openssl ecparam -genkey -name prime256v1 -noout -out ca-int2.key
openssl req -new -key ca-int2.key -out ca-int2.csr -sha256 -subj="/C=JP/CN=ca-int2"
openssl x509 -req -in ca-int2.csr -out ca-int2.crt -CA ca-int1.crt -CAkey ca-int1.key -sha256 -days 365 --extfile /usr/lib/ssl/openssl.cnf -extensions v3_ca
openssl x509 -text -noout -in ca-int2.crt
openssl verify -trusted ca-root.crt -untrusted ca-int1.crt --show_chain ca-int2.crt


## end entity certificate
openssl ecparam -genkey -name prime256v1 -noout -out ee.key
openssl req -new -key ee.key -sha256 -out ee.csr -subj="/C=JP/CN=end-entity"
openssl x509 -req -in ee.csr  -out ee.crt -CA ca-int2.crt -CAkey ca-int2.key -sha256 -days 365
openssl x509 -text -noout -in ee.crt
openssl verify -trusted ca-root.crt -untrusted ca-int1.crt -untrusted ca-int2.crt --show_chain ee.crt

```

If successful you will see something like this:

```console
$ openssl verify -trusted ca-root.crt -untrusted ca-int1.crt -untrusted ca-int2.crt --show_chain ee.crt

ee.crt: OK
Chain:
depth=0: C = JP, CN = end-entity (untrusted)
depth=1: C = JP, CN = ca-int2 (untrusted)
depth=2: C = JP, CN = ca-int1 (untrusted)
depth=3: C = JP, CN = ca-root
```

If extension is not specified in the intermediate certificate：

```console
$ openssl verify -trusted ca-root.crt --show_chain ca-int1.crt
ca-int1.crt: OK
Chain:
depth=0: C = JP, CN = ca-int1 (untrusted)
depth=1: C = JP, CN = ca-root

$ openssl verify -trusted ca-root.crt -untrusted ca-int1.crt --show_chain ca-int2.crt
C = JP, CN = ca-int1
error 79 at 1 depth lookup: invalid CA certificate
error ca-int2.crt: verification failed
```

This seems to happen if there is no v3 extension stored in the certificate.

```console
 $ openssl x509 -text -noout -in ca-int2.crt
Certificate:
    ...
        X509v3 extensions:
            X509v3 Subject Key Identifier: 
                DE:7D:15:84:05:2C:50:29:9C:73:96:BB:72:7B:5B:A2:F5:F1:AB:7C
            X509v3 Authority Key Identifier: 
                55:80:E3:73:E9:6B:47:5A:90:DB:8E:E5:35:11:5D:22:54:1D:BE:CE
            X509v3 Basic Constraints: critical
                CA:TRUE
    ...
```
