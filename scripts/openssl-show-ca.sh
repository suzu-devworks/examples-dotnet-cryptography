#!/bin/sh
# spell-checker: disable
echo "Generating OpenSSL files..."
openssl version

FILE_DIR=$(dirname "$0")
IN_DIR="${1:-.}"
echo "Input From: ${IN_DIR}"

# Self signed CA (ECDSA)
echo "=== CA Key ==="
openssl ec -in ${IN_DIR}/localhost.ca.key -text -noout

echo "=== CA Certificate ==="
openssl x509 -in ${IN_DIR}/localhost.ca.crt -text -noout

echo End of output.