# ca-certificates (on Ubuntu)

```shell
sudo apt install -y ca-certificates
sudo cp local-ca.crt /usr/local/share/ca-certificates
sudo update-ca-certificates
```

## X509 Store

```cs
using var store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
```
