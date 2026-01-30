#!/bin/sh
# spell-checker: disable
echo "Generating OpenSSL files..."
openssl version

FILE_DIR=$(dirname "$0")
IN_DIR="${1:-.}"
echo "Input From: ${IN_DIR}"

# ed25519
echo "=== ed25519 Key ==="
openssl pkey -in ${IN_DIR}/localhost.ed25519.key -text -noout
echo "=== ed25519 Public Key ==="
openssl pkey -in ${IN_DIR}/localhost.ed25519.key -pubout -outform PEM
echo "=== ed25519 CSR ==="
openssl req -in ${IN_DIR}/localhost.ed25519.csr -text -noout
echo "=== ed25519 Certificate ==="
openssl x509 -in ${IN_DIR}/localhost.ed25519.crt -text -noout

echo End of output.
