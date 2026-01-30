#!/bin/sh
# spell-checker: disable
echo "Generating OpenSSL files..."
openssl version

FILE_DIR=$(dirname "$0")
IN_DIR="${1:-.}"
echo "Input From: ${IN_DIR}"

# ECDSA
echo "=== ECDSA Key ==="
openssl ec -in ${IN_DIR}/localhost.ecdsa.key -text -noout
echo "=== ECDSA Public Key ==="
openssl ec -in ${IN_DIR}/localhost.ecdsa.key -pubout -outform PEM
echo "=== ECDSA CSR ==="
openssl req -in ${IN_DIR}/localhost.ecdsa.csr -text -noout
echo "=== ECDSA Certificate ==="
openssl x509 -in ${IN_DIR}/localhost.ecdsa.crt -text -noout

echo End of output.
