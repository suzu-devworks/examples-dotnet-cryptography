#!/bin/sh
# spell-checker: disable
echo "Show OpenSSL files..."
openssl version

FILE_DIR=$(dirname "$0")
IN_DIR="${2:-./assets}"
echo "Input From: ${IN_DIR}"

show_root_ca() {
    echo "=== Root CA Key ==="
    openssl ec -in ${IN_DIR}/example.ca-root.key -text -noout

    echo "=== Root CA Certificate ==="
    openssl x509 -in ${IN_DIR}/example.ca-root.crt -text -noout
    echo ""
}

show_intermediate_ca() {
    echo "=== Intermediate CA Key ==="
    openssl ec -in ${IN_DIR}/example.ca-intermediate.key -text -noout

    echo "=== Intermediate CA Certificate ==="
    openssl x509 -in ${IN_DIR}/example.ca-intermediate.crt -text -noout
    echo ""
}

show_rsa_cert() {
    echo "=== RSA Key ==="
    openssl rsa -in ${IN_DIR}/example.rsa.key -text -noout
    echo "=== RSA Certificate ==="
    openssl x509 -in ${IN_DIR}/example.rsa.crt -text -
    echo ""
}

show_ecdsa_cert() {
    echo "=== ECDSA Key ==="
    openssl ec -in ${IN_DIR}/example.ecdsa.key -text -noout
    echo "=== ECDSA Certificate ==="
    openssl x509 -in ${IN_DIR}/example.ecdsa.crt -text -noout
    echo ""
}

show_edd25519_cert() {
    echo "=== ed25519 Key ==="
    openssl pkey -in ${IN_DIR}/example.ed25519.key -text -noout
    echo "=== ed25519 Certificate ==="
    openssl x509 -in ${IN_DIR}/example.ed25519.crt -text
    echo ""
}

case "$1" in
    root)
        show_root_ca
        ;;
    intermediate)
        show_intermediate_ca
        ;;
    rsa)
        show_rsa_cert
        ;;
    ecdsa)
        show_ecdsa_cert
        ;;
    ed25519)
        show_edd25519_cert
        ;;
    all|"")
        show_root_ca
        show_intermediate_ca
        show_rsa_cert
        show_ecdsa_cert
        show_edd25519_cert
        ;;
    *)
        echo "Usage: $0 [root|intermediate|rsa|ecdsa|ed25519|all]"
        exit 1
        ;;
esac

echo End of output.