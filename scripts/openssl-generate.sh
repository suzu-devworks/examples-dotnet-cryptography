#!/bin/sh
# spell-checker: disable
echo "Generating OpenSSL files..."
openssl version

FILE_DIR=$(dirname "$0")
TARGET_DIR="${1:-./assets}"
mkdir -p "$TARGET_DIR"
OUT_DIR=$(cd "$TARGET_DIR" && pwd)
echo "Output To: ${OUT_DIR}"

CONF_FILE=${FILE_DIR}/openssl-test.cnf

DAYS=3
echo "Certificate valid for ${DAYS} days"

# Generate a random password file
head -c 500 /dev/urandom | LC_CTYPE=C tr -dc 'a-zA-Z0-9!@#\$%&/:;\^()_+\-=<>?' | head -c 24 > ${OUT_DIR}/.password
chmod 600 "${OUT_DIR}/.password"
wc -c < ${OUT_DIR}/.password | awk '{print "Password length: " $1}'
echo ""

# Self signed root CA (ECDSA)
openssl ecparam -genkey -name secp384r1 -noout -out ${OUT_DIR}/example.ca-root.key
openssl req -new -x509 -config ${CONF_FILE} -batch \
    -subj "/C=JP/O=examples/CN=Example Root CA" \
    -key ${OUT_DIR}/example.ca-root.key \
    -out ${OUT_DIR}/example.ca-root.crt -days ${DAYS} -extensions v3_ca

# Intermediate CA (ECDSA)
openssl ecparam -genkey -name prime256v1 -noout -out ${OUT_DIR}/example.ca-intermediate.key
openssl req -new -config ${CONF_FILE} -batch \
    -subj "/C=JP/O=examples/CN=Example Intermediate CA" \
    -key ${OUT_DIR}/example.ca-intermediate.key \
    -out ${OUT_DIR}/example.ca-intermediate.csr
openssl x509 -req -in ${OUT_DIR}/example.ca-intermediate.csr \
    -CA ${OUT_DIR}/example.ca-root.crt -CAkey ${OUT_DIR}/example.ca-root.key -CAcreateserial \
    -extfile ${CONF_FILE} -extensions v3_intermediate_ca \
    -out ${OUT_DIR}/example.ca-intermediate.crt -days ${DAYS}

# RSA
openssl genrsa -traditional -out ${OUT_DIR}/example.rsa.key 4096
openssl req -new -config ${CONF_FILE} -batch \
    -subj "/C=JP/CN=*.rsa.example.com" \
    -key ${OUT_DIR}/example.rsa.key \
    -out ${OUT_DIR}/example.rsa.csr
openssl x509 -req -in ${OUT_DIR}/example.rsa.csr \
    -CA ${OUT_DIR}/example.ca-intermediate.crt -CAkey ${OUT_DIR}/example.ca-intermediate.key -CAcreateserial \
    -extfile ${CONF_FILE} -extensions v3_cert \
    -out ${OUT_DIR}/example.rsa.crt -days ${DAYS}

# ECDSA
openssl ecparam -genkey -name prime256v1 -noout -out ${OUT_DIR}/example.ecdsa.key
openssl req -new -config ${CONF_FILE} -batch \
    -subj "/C=JP/CN=*.ecdsa.example.com" \
    -key ${OUT_DIR}/example.ecdsa.key \
    -out ${OUT_DIR}/example.ecdsa.csr
openssl x509 -req -in ${OUT_DIR}/example.ecdsa.csr \
    -CA ${OUT_DIR}/example.ca-intermediate.crt -CAkey ${OUT_DIR}/example.ca-intermediate.key -CAcreateserial \
    -extfile ${CONF_FILE} -extensions v3_cert \
    -out ${OUT_DIR}/example.ecdsa.crt -days ${DAYS}

# ed25519 key
openssl genpkey -algorithm ed25519 -out ${OUT_DIR}/example.ed25519.key
openssl req -new -config ${CONF_FILE} -batch \
    -subj "/C=JP/CN=*.ed25519.example.com" \
    -key ${OUT_DIR}/example.ed25519.key \
    -out ${OUT_DIR}/example.ed25519.csr
openssl x509 -req -in ${OUT_DIR}/example.ed25519.csr \
    -CA ${OUT_DIR}/example.ca-intermediate.crt -CAkey ${OUT_DIR}/example.ca-intermediate.key -CAcreateserial \
    -extfile ${CONF_FILE} -extensions v3_cert \
    -out ${OUT_DIR}/example.ed25519.crt -days ${DAYS}

# PKCS 7
openssl crl2pkcs7 -nocrl \
    -certfile ${OUT_DIR}/example.ecdsa.crt \
    -certfile ${OUT_DIR}/example.ca-intermediate.crt \
    -certfile ${OUT_DIR}/example.ca-root.crt \
    -out ${OUT_DIR}/example.ecdsa.p7b
openssl pkcs7 -print_certs -in ${OUT_DIR}/example.ecdsa.p7b -out ${OUT_DIR}/example.ecdsa.p7b.crt

# PKCS 8
openssl pkcs8 -topk8 -nocrypt -in ${OUT_DIR}/example.ecdsa.key -out ${OUT_DIR}/example.ecdsa.pk8
openssl ec -in ${OUT_DIR}/example.ecdsa.pk8 -pubout -out ${OUT_DIR}/example.ecdsa.pk8.pub

# PKCS 12
openssl pkcs12 -export -in ${OUT_DIR}/example.ecdsa.crt -inkey ${OUT_DIR}/example.ecdsa.key \
    -out ${OUT_DIR}/example.ecdsa.p12 -passout file:${OUT_DIR}/.password
openssl pkcs12 -in ${OUT_DIR}/example.ecdsa.p12 -nocerts -nodes \
    -out ${OUT_DIR}/example.ecdsa.p12.key -passin file:${OUT_DIR}/.password
openssl pkcs12 -in ${OUT_DIR}/example.ecdsa.p12 -clcerts -nokeys \
    -out ${OUT_DIR}/example.ecdsa.p12.crt -passin file:${OUT_DIR}/.password

echo ""
echo "OpenSSL files generated."
ls -l ${OUT_DIR}/example.*