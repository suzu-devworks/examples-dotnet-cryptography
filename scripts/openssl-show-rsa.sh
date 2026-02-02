#!/bin/sh
# spell-checker: disable
echo "Generating OpenSSL files..."
openssl version

FILE_DIR=$(dirname "$0")
IN_DIR="${1:-.}"
echo "Input From: ${IN_DIR}"

# RSA
echo "=== RSA Key ==="
openssl rsa -in ${IN_DIR}/localhost.rsa.key -text -noout
echo "=== RSA Public Key ==="
openssl rsa -in ${IN_DIR}/localhost.rsa.key -pubout -outform PEM
echo "=== RSA CSR ==="
openssl req -in ${IN_DIR}/localhost.rsa.csr -text -noout
echo "=== RSA Certificate ==="
openssl x509 -in ${IN_DIR}/localhost.rsa.crt -text -noout

echo End of output.
