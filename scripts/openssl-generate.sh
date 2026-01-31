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

DAYS=10
echo "Certificate valid for ${DAYS} days"

# Generate a random password file
head -c 500 /dev/urandom | LC_CTYPE=C tr -dc 'a-zA-Z0-9!@#\$%&/:;\^()_+\-=<>?' | head -c 24 > ${OUT_DIR}/.password
chmod 600 "${OUT_DIR}/.password"
wc -c < ${OUT_DIR}/.password | awk '{print "Password length: " $1}'

# Self signed CA (ECDSA)
openssl ecparam -genkey -name prime256v1 -noout -out ${OUT_DIR}/localhost.ca.key
openssl req -new -x509 -config ${CONF_FILE} -batch \
    -subj "/C=JP/O=examples/CN=Example Test CA" \
    -key ${OUT_DIR}/localhost.ca.key -out ${OUT_DIR}/localhost.ca.crt -days ${DAYS}

# RSA
openssl genrsa -traditional -out ${OUT_DIR}/localhost.rsa.key 4096
openssl req -new -config ${CONF_FILE} -batch \
    -subj "/C=JP/CN=*.rsa.example.com" \
    -key ${OUT_DIR}/localhost.rsa.key -out ${OUT_DIR}/localhost.rsa.csr
openssl x509 -req -in ${OUT_DIR}/localhost.rsa.csr -CA ${OUT_DIR}/localhost.ca.crt \
    -CAkey ${OUT_DIR}/localhost.ca.key -CAcreateserial -out ${OUT_DIR}/localhost.rsa.crt -days ${DAYS}

# ECDSA
openssl ecparam -genkey -name prime256v1 -noout -out ${OUT_DIR}/localhost.ecdsa.key
openssl req -new -config ${CONF_FILE} -batch \
    -subj "/C=JP/CN=*.ecdsa.example.com" \
    -key ${OUT_DIR}/localhost.ecdsa.key -out ${OUT_DIR}/localhost.ecdsa.csr
openssl x509 -req -in ${OUT_DIR}/localhost.ecdsa.csr -CA ${OUT_DIR}/localhost.ca.crt \
    -CAkey ${OUT_DIR}/localhost.ca.key -CAcreateserial -out ${OUT_DIR}/localhost.ecdsa.crt -days ${DAYS}

# ed25519 key
openssl genpkey -algorithm ed25519 -out ${OUT_DIR}/localhost.ed25519.key
openssl req -new -config ${CONF_FILE} -batch \
    -subj "/C=JP/CN=*.ed25519.example.com" \
    -key ${OUT_DIR}/localhost.ed25519.key -out ${OUT_DIR}/localhost.ed25519.csr
openssl x509 -req -in ${OUT_DIR}/localhost.ed25519.csr -CA ${OUT_DIR}/localhost.ca.crt \
    -CAkey ${OUT_DIR}/localhost.ca.key -CAcreateserial -out ${OUT_DIR}/localhost.ed25519.crt -days ${DAYS}

# PKCS 7
openssl crl2pkcs7 -nocrl -certfile ${OUT_DIR}/localhost.ecdsa.crt -out ${OUT_DIR}/localhost.ecdsa.p7b -certfile ${OUT_DIR}/localhost.ca.crt
openssl pkcs7 -print_certs -in ${OUT_DIR}/localhost.ecdsa.p7b -out ${OUT_DIR}/localhost.ecdsa.fromp7b.crt

# PKCS 8
openssl pkcs8 -topk8 -nocrypt -in ${OUT_DIR}/localhost.ecdsa.key -out ${OUT_DIR}/localhost.ecdsa.pk8
openssl ec -in ${OUT_DIR}/localhost.ecdsa.pk8 -pubout -out ${OUT_DIR}/localhost.ecdsa.pk8.pub

# PKCS 12
openssl pkcs12 -export -in ${OUT_DIR}/localhost.ecdsa.crt -inkey ${OUT_DIR}/localhost.ecdsa.key \
    -out ${OUT_DIR}/localhost.ecdsa.p12 -passout file:${OUT_DIR}/.password

# Set environment variable for test assets path
export TEST_ASSETS_PATH=${OUT_DIR}

echo ""
echo "OpenSSL files generated."
ls -l ${OUT_DIR}/localhost.*
