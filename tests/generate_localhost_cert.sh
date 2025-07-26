#!/bin/sh
# generate_localhost_cert.sh - creates a self-signed certificate for 'localhost'.
#
# The generated files will be:
#   - localhost_cert.pem
#   - localhost_key.pem
#
# Run this script from its directory. Requires OpenSSL.

OPENSSL_BIN=${OPENSSL_BIN:-openssl}

$OPENSSL_BIN req -x509 -nodes -newkey rsa:2048 -sha256 \
  -keyout localhost_key.pem \
  -out localhost_cert.pem \
  -days 365 \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost"

echo "Self-signed certificate generated: localhost_cert.pem and localhost_key.pem"
